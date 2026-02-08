// Package main provides a command-line tool for compiling YARA files.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
	"github.com/cawalch/go-yara/token"
	"github.com/cawalch/go-yara/utils/fs"
)

const (
	modeCompile = "compile"
	modeLex     = "lex"
	modeParse   = "parse"
	modeExecute = "execute"
)

// formatToken formats a token for display
func formatToken(tok token.Token) string {
	if tok.Type == token.EOF {
		return fmt.Sprintf("{EOF @ %d:%d}", tok.Pos.Line, tok.Pos.Column)
	}
	return fmt.Sprintf("{%v %q @ %d:%d}", tok.Type, tok.Literal, tok.Pos.Line, tok.Pos.Column)
}

func main() {
	args := parseArgs()
	if args == nil {
		return
	}

	content := readFileContent(args.filename)
	if content == nil {
		return
	}

	runMode(args.mode, content, args)
}

type commandArgs struct {
	filename         string
	mode             string
	dataFile         string
	enableStreaming  bool
	chunkSize        int
	maxConcurrency   int
	earlyTermination bool
}

func parseArgs() *commandArgs {
	if len(os.Args) < 2 {
		printUsage()
		return nil
	}

	args := &commandArgs{
		filename:         os.Args[1],
		mode:             modeCompile, // default mode
		enableStreaming:  false,       // disabled by default
		chunkSize:        1024 * 1024, // 1MB default
		maxConcurrency:   4,           // default concurrency
		earlyTermination: false,       // disabled by default
	}

	if err := parseModeFlags(args); err != nil {
		fmt.Printf("Error parsing arguments: %v\n", err)
		return nil
	}

	if err := validateFilename(args.filename); err != nil {
		fmt.Printf("Error: %v\n", err)
		return nil
	}

	return args
}

func printUsage() {
	fmt.Println("Usage: go run cmd/main.go <yara-file> [--lex|--parse|--compile|--execute] [--data <data-file>]")
	fmt.Println("  --lex     : Show lexer tokens only")
	fmt.Println("  --parse   : Show parser AST only")
	fmt.Println("  --compile : Full compilation (default)")
	fmt.Println("  --execute : Execute rules against data (requires --data)")
	fmt.Println("  --data    : Data file to match against (for --execute mode)")
	fmt.Println("")
	fmt.Println("Streaming options (for --execute mode):")
	fmt.Println("  --streaming        : Enable streaming processing for large files")
	fmt.Println("  --chunk-size <n>   : Set chunk size in bytes (default: 1MB)")
	fmt.Println("  --max-concurrency <n> : Set maximum concurrent goroutines (default: 4)")
	fmt.Println("  --early-termination : Enable early termination when matches found")
	os.Exit(1)
}

// parseModeFlag parses mode flags and returns whether the flag was handled
func parseModeFlag(arg string, args *commandArgs) bool {
	switch arg {
	case "--lex":
		args.mode = modeLex
		return true
	case "--parse":
		args.mode = modeParse
		return true
	case "--compile":
		args.mode = modeCompile
		return true
	case "--execute":
		args.mode = modeExecute
		return true
	case "--streaming":
		args.enableStreaming = true
		return true
	case "--early-termination":
		args.earlyTermination = true
		return true
	default:
		return false
	}
}

// parseValueFlag parses flags that take a value argument
func parseValueFlag(arg string, args *commandArgs, i *int) error {
	switch arg {
	case "--data":
		return parseStringFlag(arg, &args.dataFile, i, "filename")
	case "--chunk-size":
		return parseIntFlag(arg, &args.chunkSize, i, "size value")
	case "--max-concurrency":
		return parseIntFlag(arg, &args.maxConcurrency, i, "value")
	default:
		return nil
	}
}

// parseStringFlag parses a flag that takes a string value
func parseStringFlag(flag string, target *string, i *int, desc string) error {
	if *i+1 >= len(os.Args) {
		return fmt.Errorf("--%s requires a %s", flag, desc)
	}
	*target = os.Args[*i+1]
	*i++ // Skip next argument
	return nil
}

// parseIntFlag parses a flag that takes a positive integer value
func parseIntFlag(flag string, target *int, i *int, desc string) error {
	if *i+1 >= len(os.Args) {
		return fmt.Errorf("--%s requires a %s", flag, desc)
	}
	n, err := fmt.Sscanf(os.Args[*i+1], "%d", target)
	if err != nil || n != 1 || *target <= 0 {
		return fmt.Errorf("--%s requires a positive integer", flag)
	}
	*i++ // Skip next argument
	return nil
}

func parseModeFlags(args *commandArgs) error {
	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]

		// Try to parse as mode flag first
		if parseModeFlag(arg, args) {
			continue
		}

		// Try to parse as value flag
		if err := parseValueFlag(arg, args, &i); err != nil {
			return err
		}
	}
	return nil
}

func validateFilename(filename string) error {
	if filename == "" {
		return errors.New("empty filename")
	}
	// Basic path traversal protection
	if strings.Contains(filename, "..") || strings.HasPrefix(filename, "/") {
		return errors.New("invalid filename: potential path traversal")
	}
	return nil
}

func readFileContent(filename string) []byte {
	content, err := fs.ReadFile("", filename) // #nosec G304 - file reading is intentional
	if err != nil {
		fmt.Printf("Error reading file %s: %v\n", filename, err)
		os.Exit(1)
	}
	return content
}

func runMode(mode string, content []byte, args *commandArgs) {
	fmt.Printf("Processing YARA file: %s (mode: %s)\n", args.filename, mode)
	fmt.Printf("File content:\n%s\n\n", string(content))

	switch mode {
	case modeLex:
		runLexerMode(string(content))
	case modeParse:
		runParserMode(string(content))
	case modeCompile:
		runCompileMode(string(content), args.filename)
	case modeExecute:
		runExecuteMode(string(content), args.dataFile, args.filename, args)
	default:
		fmt.Printf("Unknown mode: %s\n", mode)
		os.Exit(1)
	}
}

func runLexerMode(content string) {
	// Create lexer
	l := lexer.New(content)

	// Parse all tokens
	fmt.Println("Tokens:")
	for {
		tok := l.NextToken()
		fmt.Printf("  %s\n", formatToken(tok))
		if tok.Type == token.EOF {
			break
		}
	}

	// Check for lexer errors
	lexerErrors := l.Errors()
	if len(lexerErrors) > 0 {
		fmt.Printf("\nLexer errors (%d):\n", len(lexerErrors))
		for _, err := range lexerErrors {
			fmt.Printf("  %s\n", err.Error())
		}
		os.Exit(1)
	}

	fmt.Printf("\nSuccessfully lexed with no errors!\n")
}

func runParserMode(content string) {
	program := parseContent(content)
	if program == nil {
		return
	}

	processIncludes(program)
	printParseSummary(program)
}

func parseContent(content string) *ast.Program {
	l := lexer.New(content)
	p := parser.New(l)

	program, err := p.ParseRulesWithContext(context.Background())
	if err != nil {
		printParserErrors(p, err)
		os.Exit(1)
	}

	if parseErr := checkForParserErrors(p); parseErr != nil {
		os.Exit(1)
	}

	return program
}

func printParserErrors(p *parser.Parser, mainErr error) {
	fmt.Printf("Parser error: %v\n", mainErr)
	parserErrors := p.Errors()
	if len(parserErrors) > 0 {
		fmt.Printf("\nParser errors (%d):\n", len(parserErrors))
		for _, err := range parserErrors {
			fmt.Printf("  %s\n", err.Error())
		}
	}
}

func checkForParserErrors(p *parser.Parser) error {
	parserErrors := p.Errors()
	if len(parserErrors) > 0 {
		fmt.Printf("\nParser errors (%d):\n", len(parserErrors))
		for _, err := range parserErrors {
			fmt.Printf("  %s\n", err.Error())
		}
		return errors.New("parser errors detected")
	}
	return nil
}

func processIncludes(program *ast.Program) {
	if len(program.Includes) == 0 {
		return
	}

	comp := compiler.NewCompiler()
	comp.SetBaseDir(filepath.Dir(os.Args[1]))

	if err := comp.ProcessIncludes(program); err != nil {
		fmt.Printf("Error processing includes: %v\n", err)
		os.Exit(1)
	}
}

func printParseSummary(program *ast.Program) {
	fmt.Printf("Successfully parsed!\n")
	fmt.Printf("Program contains %d rules\n", len(program.Rules))
	fmt.Printf("Program contains %d includes\n", len(program.Includes))

	printRuleSummary(program.Rules)
	printIncludeSummary(program.Includes)
}

func printRuleSummary(rules []*ast.Rule) {
	for i, rule := range rules {
		fmt.Printf("  Rule %d: %s\n", i+1, rule.Name)
		if len(rule.Tags) > 0 {
			fmt.Printf("    Tags: %v\n", rule.Tags)
		}
		if len(rule.Strings) > 0 {
			fmt.Printf("    Strings: %d patterns\n", len(rule.Strings))
		}
	}
}

func printIncludeSummary(includes []*ast.Include) {
	for i, include := range includes {
		fmt.Printf("  Include %d: %s\n", i+1, include.File)
	}
}

func runCompileMode(content, filename string) {
	// Create compiler
	comp := compiler.NewCompiler()
	// Set base directory for resolving includes
	comp.SetBaseDir(filepath.Dir(filename))

	// Compile program (this includes parsing, semantic analysis, and code generation)
	compiledProgram, err := comp.CompileSourceWithContext(context.Background(), content)
	if err != nil {
		fmt.Printf("Compilation error: %v\n", err)
		// Print detailed errors
		compilationErrors := comp.GetErrors()
		if len(compilationErrors) > 0 {
			fmt.Printf("\nCompilation errors (%d):\n", len(compilationErrors))
			for _, cerr := range compilationErrors {
				fmt.Printf("  [%s] %s\n", cerr.Phase, cerr.Message)
			}
		}
		os.Exit(1)
	}

	compilationErrors := comp.GetErrors()
	if len(compilationErrors) > 0 {
		fmt.Printf("\nCompilation errors (%d):\n", len(compilationErrors))
		for _, cerr := range compilationErrors {
			fmt.Printf("  [%s] %s\n", cerr.Phase, cerr.Message)
		}
		os.Exit(1)
	}

	fmt.Printf("Compilation: Successfully compiled %d rules\n", len(compiledProgram.Rules))

	// Print compilation summary
	for i, rule := range compiledProgram.Rules {
		fmt.Printf("  Rule %d: %s (%d bytes)\n", i+1, rule.GetName(), len(rule.GetBytecode()))
	}
}

func runExecuteMode(content, dataFile, filename string, args *commandArgs) {
	data := validateAndReadDataFile(dataFile)
	if data == nil {
		return
	}

	printDataSummary(dataFile, data)

	compiledProgram := compileRules(content, filename)
	if compiledProgram == nil {
		return
	}

	executeRules(compiledProgram, data, args)
}

func validateAndReadDataFile(dataFile string) []byte {
	// Validate data file is provided
	if dataFile == "" {
		fmt.Println("Error: --execute mode requires --data <data-file>")
		os.Exit(1)
	}

	// Use centralized file reading utility with validation
	data, err := fs.ReadFile("", dataFile) // #nosec G304 - file reading is intentional
	if err != nil {
		fmt.Printf("Error reading data file %s: %v\n", dataFile, err)
		return nil
	}

	return data
}

func printDataSummary(dataFile string, data []byte) {
	fmt.Printf("Data file: %s (%d bytes)\n", dataFile, len(data))
	fmt.Printf("Data content (first 256 bytes):\n")
	if len(data) > 256 {
		fmt.Printf("%s...\n\n", string(data[:256]))
	} else {
		fmt.Printf("%s\n\n", string(data))
	}
}

func compileRules(content, filename string) *compiler.CompiledProgram {
	comp := compiler.NewCompiler()
	comp.SetBaseDir(filepath.Dir(filename))
	compiledProgram, err := comp.CompileSourceWithContext(context.Background(), content)
	if err != nil {
		fmt.Printf("Compilation error: %v\n", err)
		return nil
	}

	compilationErrors := comp.GetErrors()
	if len(compilationErrors) > 0 {
		fmt.Printf("\nCompilation errors (%d):\n", len(compilationErrors))
		for _, cerr := range compilationErrors {
			fmt.Printf("  [%s] %s\n", cerr.Phase, cerr.Message)
		}
		return nil
	}

	fmt.Printf("Compilation: Successfully compiled %d rules\n\n", len(compiledProgram.Rules))
	return compiledProgram
}

func executeRules(compiledProgram *compiler.CompiledProgram, data []byte, args *commandArgs) {
	if args.enableStreaming {
		executeRulesStreaming(compiledProgram, data, args)
		return
	}

	// Traditional execution
	totalMatches := 0
	ruleResults := make(map[string]bool)

	for _, rule := range compiledProgram.Rules {
		fmt.Printf("Executing rule: %s\n", rule.GetName())

		matchContext, printEntries := findPatternMatches(rule, data)
		totalMatches += printPatternMatches(printEntries)

		interpreter := setupInterpreter(rule, data, ruleResults, compiledProgram.Rules, matchContext)
		executeSingleRule(interpreter, rule)

		fmt.Println()
	}

	fmt.Printf("Total matches found: %d\n", totalMatches)
}

func findPatternMatches(rule *compiler.CompiledRule, data []byte) (*compiler.MatchContext, []printEntry) {
	ctx := compiler.BuildMatchContext(rule, data)
	return ctx, matchContextEntries(ctx)
}

func matchContextEntries(ctx *compiler.MatchContext) []printEntry {
	if ctx == nil {
		return nil
	}
	entries := make([]printEntry, 0)
	for id, matches := range ctx.Matches {
		for _, m := range matches {
			entries = append(entries, printEntry{
				id:     id,
				offset: int(m.Offset),
				length: m.Length,
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].offset != entries[j].offset {
			return entries[i].offset < entries[j].offset
		}
		if entries[i].id != entries[j].id {
			return entries[i].id < entries[j].id
		}
		return entries[i].length < entries[j].length
	})
	return entries
}

func printPatternMatches(printEntries []printEntry) int {
	fmt.Printf("  Pattern matches: %d\n", len(printEntries))
	totalMatches := 0
	for _, e := range printEntries {
		fmt.Printf("    - %s at offset %d (length: %d)\n", e.id, e.offset, e.length)
		totalMatches++
	}
	return totalMatches
}

func setupInterpreter(rule *compiler.CompiledRule, data []byte, ruleResults map[string]bool,
	compiledRules []*compiler.CompiledRule, matchContext *compiler.MatchContext) *compiler.Interpreter {
	interp := compiler.NewInterpreter(rule.GetBytecode())

	// Set file size and data in match context
	if matchContext != nil {
		interp.SetMatchContext(matchContext)
	} else {
		interp.GetMatchContext().FileSize = int64(len(data))
		interp.GetMatchContext().Data = data
	}

	// Set up rule tracking
	interp.SetRuleResults(ruleResults)
	interp.SetCurrentRule(rule.GetName())
	interp.SetCompiledRules(compiledRules)

	// Initialize VM memory slots
	if rule.Automaton != nil {
		for idx, s := range rule.Automaton.Strings {
			interp.SetMemoryString(idx, s.Identifier)
		}
	}

	return interp
}

func executeSingleRule(interp *compiler.Interpreter, _ *compiler.CompiledRule) {
	execErr := interp.Execute()
	if execErr != nil {
		fmt.Printf("  Execution error: %v\n", execErr)
	} else {
		fmt.Printf("  Execution: Success\n")
	}

	// Print stack result
	stack := interp.GetStack()
	if len(stack) > 0 {
		result := stack[len(stack)-1]
		if result.Type == compiler.ValueTypeInt {
			if result.IntVal != 0 {
				fmt.Printf("  Result: MATCH (value: %d)\n", result.IntVal)
			} else {
				fmt.Printf("  Result: NO MATCH\n")
			}
		}
	}
}

// executeRulesStreaming executes rules using streaming approach
func executeRulesStreaming(compiledProgram *compiler.CompiledProgram, data []byte, args *commandArgs) {
	fmt.Printf("Streaming execution enabled (chunk size: %d bytes, concurrency: %d)\n", args.chunkSize, args.maxConcurrency)

	// Configure streaming
	compiledProgram.EnableStreaming(true)
	compiledProgram.SetStreamingChunkSize(args.chunkSize)
	compiledProgram.SetStreamingConcurrency(args.maxConcurrency)
	compiledProgram.EnableStreamingEarlyTermination(args.earlyTermination)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Process with streaming
	start := time.Now()
	matches, err := compiledProgram.ProcessBytesStreaming(ctx, data)
	if err != nil {
		fmt.Printf("Error during streaming execution: %v\n", err)
		return
	}
	elapsed := time.Since(start)

	// Print results
	fmt.Printf("\nStreaming Results:\n")
	fmt.Printf("  Processing time: %v\n", elapsed)
	fmt.Printf("  Total matches: %d\n", len(matches))

	if len(matches) > 0 {
		fmt.Printf("  Matches found:\n")
		for _, match := range matches {
			fmt.Printf("    Rule: %s, Pattern: %s, Offset: %d, Length: %d\n",
				match.Rule, match.Pattern, match.Offset, match.Length)
		}
	}

	// Show final progress
	processed, total, percent, _ := compiledProgram.GetStreamingProgress()
	fmt.Printf("  Progress: %d/%d bytes (%.1f%%)\n", processed, total, percent)

	if elapsed > 0 {
		throughput := float64(len(data)) / elapsed.Seconds() / 1024 / 1024
		fmt.Printf("  Throughput: %.2f MB/s\n", throughput)
	}
}

type printEntry struct {
	id     string
	offset int
	length int
}
