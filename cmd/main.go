// Package main provides a command-line tool for compiling YARA files.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
	"github.com/cawalch/go-yara/regex"
	"github.com/cawalch/go-yara/token"
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
	filename string
	mode     string
	dataFile string
}

func parseArgs() *commandArgs {
	if len(os.Args) < 2 {
		printUsage()
		return nil
	}

	args := &commandArgs{
		filename: os.Args[1],
		mode:     modeCompile, // default mode
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
	os.Exit(1)
}

func parseModeFlags(args *commandArgs) error {
	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--lex":
			args.mode = modeLex
		case "--parse":
			args.mode = modeParse
		case "--compile":
			args.mode = modeCompile
		case "--execute":
			args.mode = modeExecute
		case "--data":
			if i+1 < len(os.Args) {
				args.dataFile = os.Args[i+1]
				i++ // Skip next argument
			} else {
				return errors.New("--data requires a filename")
			}
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
	content, err := os.ReadFile(filename)
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
		runExecuteMode(string(content), args.dataFile, args.filename)
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

	program, err := p.ParseRules()
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
	compiledProgram, err := comp.CompileSource(content)
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

func runExecuteMode(content, dataFile, filename string) {
	data := validateAndReadDataFile(dataFile)
	if data == nil {
		return
	}

	printDataSummary(dataFile, data)

	compiledProgram := compileRules(content, filename)
	if compiledProgram == nil {
		return
	}

	executeRules(compiledProgram, data)
}

func validateAndReadDataFile(dataFile string) []byte {
	// Validate data file is provided
	if dataFile == "" {
		fmt.Println("Error: --execute mode requires --data <data-file>")
		os.Exit(1)
	}

	// Validate dataFile to prevent path traversal
	if strings.Contains(dataFile, "..") || strings.HasPrefix(dataFile, "/") {
		fmt.Printf("Error: invalid data file path: potential path traversal\n")
		os.Exit(1)
	}

	data, err := os.ReadFile(dataFile)
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
	compiledProgram, err := comp.CompileSource(content)
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

func executeRules(compiledProgram *compiler.CompiledProgram, data []byte) {
	totalMatches := 0
	ruleResults := make(map[string]bool)

	for _, rule := range compiledProgram.Rules {
		fmt.Printf("Executing rule: %s\n", rule.GetName())

		printEntries := findPatternMatches(rule, data)
		totalMatches += printPatternMatches(printEntries)

		interpreter := setupInterpreter(rule, data, ruleResults, compiledProgram.Rules, printEntries)
		executeSingleRule(interpreter, rule)

		fmt.Println()
	}

	fmt.Printf("Total matches found: %d\n", totalMatches)
}

func findPatternMatches(rule *compiler.CompiledRule, data []byte) []printEntry {
	var printEntries []printEntry

	if rule.Automaton == nil {
		return printEntries
	}

	// AC matches (for text/hex patterns)
	acRaw := rule.Automaton.Search(data)
	for _, match := range acRaw {
		if match.StringIndex >= 0 && match.StringIndex < len(rule.Automaton.Strings) {
			si := rule.Automaton.Strings[match.StringIndex]
			printEntries = append(printEntries, printEntry{
				id:     si.Identifier,
				offset: match.Backtrack,
				length: si.Length,
			})
		}
	}

	// Regex matches
	printEntries = append(printEntries, findRegexMatches(rule.Automaton.Strings, data)...)

	return printEntries
}

func findRegexMatches(matchStrings []compiler.ACStringInfo, data []byte) []printEntry {
	var printEntries []printEntry

	for _, s := range matchStrings {
		if !s.IsRegex {
			continue
		}

		flags := s.Flags | regex.FlagsScan
		searchStart := 0
		for searchStart <= len(data) {
			ok, start, end := regex.ExecMatch(s.Data, data[searchStart:], flags)
			if !ok {
				break
			}
			absStart := searchStart + start
			absEnd := searchStart + end
			printEntries = append(printEntries, printEntry{
				id:     s.Identifier,
				offset: absStart,
				length: absEnd - absStart,
			})
			// Advance by one to allow overlapping matches
			if absStart+1 > searchStart {
				searchStart = absStart + 1
			} else {
				searchStart++
			}
		}
	}

	return printEntries
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
	compiledRules []*compiler.CompiledRule, printEntries []printEntry) *compiler.Interpreter {
	interp := compiler.NewInterpreter(rule.GetBytecode())

	// Set file size and data in match context
	interp.GetMatchContext().FileSize = int64(len(data))
	interp.GetMatchContext().Data = data

	// Set up rule tracking
	interp.SetRuleResults(ruleResults)
	interp.SetCurrentRule(rule.GetName())
	interp.SetCompiledRules(compiledRules)

	// Populate match context with matches
	for _, e := range printEntries {
		interp.GetMatchContext().AddMatch(compiler.Match{
			Pattern: e.id,
			Offset:  int64(e.offset),
			Length:  e.length,
			Base:    0,
		})
	}

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

type printEntry struct {
	id     string
	offset int
	length int
}
