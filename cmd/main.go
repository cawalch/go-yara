// Package main provides a command-line tool for compiling YARA files.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

type commandArgs struct {
	filename         string
	mode             string
	dataFile         string
	enableStreaming  bool
	chunkSize        int
	maxConcurrency   int
	earlyTermination bool
}

func main() {
	args, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	content := readFileContent(args.filename)
	if content == nil {
		return
	}

	runMode(args.mode, content, args)
}

func parseArgs(rawArgs []string) (*commandArgs, error) {
	fs := flag.NewFlagSet("go-yara", flag.ExitOnError)

	mode := fs.String("mode", modeCompile, "processing mode: lex, parse, compile, execute")
	dataFile := fs.String("data", "", "data file to match against (for --execute mode)")
	streaming := fs.Bool("streaming", false, "enable streaming processing for large files")
	chunkSize := fs.Int("chunk-size", 1024*1024, "chunk size in bytes (default: 1MB)")
	maxConcurrency := fs.Int("max-concurrency", 4, "maximum concurrent goroutines (default: 4)")
	earlyTermination := fs.Bool("early-termination", false, "enable early termination when matches found")

	// Legacy shorthand flags (--lex, --parse, --compile, --execute) mapped to --mode
	lexFlag := fs.Bool("lex", false, "shorthand for --mode=lex")
	parseFlag := fs.Bool("parse", false, "shorthand for --mode=parse")
	compileFlag := fs.Bool("compile", false, "shorthand for --mode=compile")
	executeFlag := fs.Bool("execute", false, "shorthand for --mode=execute")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: go-yara <yara-file> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nModes:\n")
		fmt.Fprintf(os.Stderr, "  --lex       Show lexer tokens only (shorthand for --mode=lex)\n")
		fmt.Fprintf(os.Stderr, "  --parse     Show parser AST only (shorthand for --mode=parse)\n")
		fmt.Fprintf(os.Stderr, "  --compile   Full compilation (default, shorthand for --mode=compile)\n")
		fmt.Fprintf(os.Stderr, "  --execute   Execute rules against data (shorthand for --mode=execute)\n")
		fmt.Fprintf(os.Stderr, "\nStreaming options (for --execute mode):\n")
		fmt.Fprintf(os.Stderr, "  --streaming           Enable streaming processing for large files\n")
		fmt.Fprintf(os.Stderr, "  --chunk-size <n>      Set chunk size in bytes (default: 1MB)\n")
		fmt.Fprintf(os.Stderr, "  --max-concurrency <n> Set maximum concurrent goroutines (default: 4)\n")
		fmt.Fprintf(os.Stderr, "  --early-termination   Enable early termination when matches found\n")
	}

	if len(rawArgs) == 0 {
		fs.Usage()
		os.Exit(1)
		return nil, nil
	}

	// Extract the positional filename (first non-flag argument)
	filename := rawArgs[0]
	flagArgs := rawArgs[1:]
	// If the first arg looks like a flag, there's no positional filename
	if len(flagArgs) == 0 && len(rawArgs) > 0 && rawArgs[0][0] == '-' {
		fs.Usage()
		os.Exit(1)
		return nil, nil
	}
	if len(flagArgs) == 0 {
		flagArgs = nil
	}

	if err := fs.Parse(flagArgs); err != nil {
		return nil, err
	}

	// Resolve effective mode from shorthands
	effectiveMode := *mode
	switch {
	case *lexFlag:
		effectiveMode = modeLex
	case *parseFlag:
		effectiveMode = modeParse
	case *compileFlag:
		effectiveMode = modeCompile
	case *executeFlag:
		effectiveMode = modeExecute
	}

	// Validate mode
	switch effectiveMode {
	case modeLex, modeParse, modeCompile, modeExecute:
		// ok
	default:
		return nil, fmt.Errorf("unknown mode %q", effectiveMode)
	}

	// Validate --data is provided for execute mode
	if effectiveMode == modeExecute && *dataFile == "" {
		return nil, fmt.Errorf("--execute mode requires --data <data-file>")
	}

	return &commandArgs{
		filename:         filename,
		mode:             effectiveMode,
		dataFile:         *dataFile,
		enableStreaming:  *streaming,
		chunkSize:        *chunkSize,
		maxConcurrency:   *maxConcurrency,
		earlyTermination: *earlyTermination,
	}, nil
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
		return fmt.Errorf("parser errors detected")
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

//nolint:revive // argument-limit: CLI entry point
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

	result, err := compiledProgram.Scan(data)
	if err != nil {
		fmt.Printf("Execution error: %v\n", err)
		return
	}

	totalMatches := 0
	for _, rule := range compiledProgram.Rules {
		fmt.Printf("Executing rule: %s\n", rule.GetName())

		printEntries := matchEntriesFromMatches(rule, result.Matches[rule.GetName()])
		totalMatches += printPatternMatches(printEntries)

		fmt.Printf("  Execution: Success\n")
		if result.RuleResults[rule.GetName()] {
			fmt.Printf("  Result: MATCH (value: 1)\n")
		} else {
			fmt.Printf("  Result: NO MATCH\n")
		}

		fmt.Println()
	}

	fmt.Printf("Total matches found: %d\n", totalMatches)
}

func matchEntriesFromMatches(rule *compiler.CompiledRule, matchesByID map[string][]compiler.Match) []printEntry {
	entries := make([]printEntry, 0)
	for id, matches := range matchesByID {
		if rule != nil && rule.IsPrivateString(id) {
			continue
		}
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
