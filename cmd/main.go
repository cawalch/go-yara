// Package main provides a command-line tool for compiling YARA files.
package main

import (
	"fmt"
	"os"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
	"github.com/cawalch/go-yara/regex"
	"github.com/cawalch/go-yara/semantic"
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
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run cmd/main.go <yara-file> [--lex|--parse|--compile|--execute] [--data <data-file>]")
		fmt.Println("  --lex     : Show lexer tokens only")
		fmt.Println("  --parse   : Show parser AST only")
		fmt.Println("  --compile : Full compilation (default)")
		fmt.Println("  --execute : Execute rules against data (requires --data)")
		fmt.Println("  --data    : Data file to match against (for --execute mode)")
		os.Exit(1)
	}

	filename := os.Args[1]
	mode := modeCompile // default mode
	var dataFile string

	// Check for mode flags
	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--lex":
			mode = modeLex
		case "--parse":
			mode = modeParse
		case "--compile":
			mode = modeCompile
		case "--execute":
			mode = modeExecute
		case "--data":
			if i+1 < len(os.Args) {
				dataFile = os.Args[i+1]
				i++ // Skip next argument
			}
		}
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("Error reading file %s: %v\n", filename, err)
		os.Exit(1)
	}

	fmt.Printf("Processing YARA file: %s (mode: %s)\n", filename, mode)
	fmt.Printf("File content:\n%s\n\n", string(content))

	switch mode {
	case modeLex:
		runLexerMode(string(content))
	case modeParse:
		runParserMode(string(content))
	case modeCompile:
		runCompileMode(string(content))
	case modeExecute:
		runExecuteMode(string(content), dataFile)
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
	// Create lexer
	l := lexer.New(content)

	// Create parser
	p := parser.New(l)

	// Parse rules
	program, err := p.ParseRules()
	if err != nil {
		fmt.Printf("Parser error: %v\n", err)
		os.Exit(1)
	}

	// Check for parser errors
	parserErrors := p.Errors()
	if len(parserErrors) > 0 {
		fmt.Printf("\nParser errors (%d):\n", len(parserErrors))
		for _, err := range parserErrors {
			fmt.Printf("  %s\n", err.Error())
		}
		os.Exit(1)
	}

	fmt.Printf("Successfully parsed!\n")
	fmt.Printf("Program contains %d rules\n", len(program.Rules))

	// Print AST summary
	for i, rule := range program.Rules {
		fmt.Printf("  Rule %d: %s\n", i+1, rule.Name)
		if len(rule.Tags) > 0 {
			fmt.Printf("    Tags: %v\n", rule.Tags)
		}
		if len(rule.Strings) > 0 {
			fmt.Printf("    Strings: %d patterns\n", len(rule.Strings))
		}
	}
}

func runCompileMode(content string) {
	// Create lexer
	l := lexer.New(content)

	// Create parser
	p := parser.New(l)

	// Parse rules
	program, err := p.ParseRules()
	if err != nil {
		fmt.Printf("Parser error: %v\n", err)
		os.Exit(1)
	}

	// Check for parser errors
	parserErrors := p.Errors()
	if len(parserErrors) > 0 {
		fmt.Printf("\nParser errors (%d):\n", len(parserErrors))
		for _, err := range parserErrors {
			fmt.Printf("  %s\n", err.Error())
		}
		os.Exit(1)
	}

	fmt.Printf("Parser: Successfully parsed %d rules\n", len(program.Rules))

	// Create semantic analyzer
	sa := semantic.NewValidator()

	// Validate program
	semanticErrors := sa.ValidateProgram(program)
	if len(semanticErrors) > 0 {
		fmt.Printf("\nSemantic analysis errors (%d):\n", len(semanticErrors))
		for _, err := range semanticErrors {
			fmt.Printf("  %s\n", err.Error())
		}
		os.Exit(1)
	}

	fmt.Printf("Semantic analysis: Valid\n")

	// Create compiler
	comp := compiler.NewCompiler()

	// Compile program
	compiledProgram, err := comp.CompileSource(content)
	if err != nil {
		fmt.Printf("Compilation error: %v\n", err)
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

func runExecuteMode(content string, dataFile string) {
	// Validate data file is provided
	if dataFile == "" {
		fmt.Println("Error: --execute mode requires --data <data-file>")
		return
	}

	// Read data file
	data, err := os.ReadFile(dataFile)
	if err != nil {
		fmt.Printf("Error reading data file %s: %v\n", dataFile, err)
		return
	}

	fmt.Printf("Data file: %s (%d bytes)\n", dataFile, len(data))
	fmt.Printf("Data content (first 256 bytes):\n")
	if len(data) > 256 {
		fmt.Printf("%s...\n\n", string(data[:256]))
	} else {
		fmt.Printf("%s\n\n", string(data))
	}

	// Compile the rules
	comp := compiler.NewCompiler()
	compiledProgram, err := comp.CompileSource(content)
	if err != nil {
		fmt.Printf("Compilation error: %v\n", err)
		return
	}

	compilationErrors := comp.GetErrors()
	if len(compilationErrors) > 0 {
		fmt.Printf("\nCompilation errors (%d):\n", len(compilationErrors))
		for _, cerr := range compilationErrors {
			fmt.Printf("  [%s] %s\n", cerr.Phase, cerr.Message)
		}
		return
	}

	fmt.Printf("Compilation: Successfully compiled %d rules\n\n", len(compiledProgram.Rules))

	// Execute each rule
	totalMatches := 0
	for _, rule := range compiledProgram.Rules {
		fmt.Printf("Executing rule: %s\n", rule.GetName())

		// Aggregate matches from AC automaton (text/hex) and regex VM for this rule
		type printEntry struct {
			id     string
			offset int
			length int
		}
		printEntries := make([]printEntry, 0, 16)

		var acRaw []compiler.ACMatch
		if rule.Automaton != nil {
			// AC matches (for text/hex patterns)
			acRaw = rule.Automaton.Search(data)
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

			// Regex matches (execute VM with stored flags and bytecode)
			for _, s := range rule.Automaton.Strings {
				if s.IsRegex {
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
			}
		}

		// Print summary and individual matches
		fmt.Printf("  Pattern matches: %d\n", len(printEntries))
		for _, e := range printEntries {
			fmt.Printf("    - %s at offset %d (length: %d)\n", e.id, e.offset, e.length)
			totalMatches++
		}

		// Execute bytecode with match context
		interp := compiler.NewInterpreter(rule.GetBytecode())

		// Populate match context with both AC and regex-derived matches
		for _, e := range printEntries {
			interp.GetMatchContext().AddMatch(compiler.Match{
				Pattern: e.id,
				Offset:  int64(e.offset),
				Length:  e.length,
				Base:    0,
			})
		}

            // Initialize VM memory slots with string identifiers by index
            if rule.Automaton != nil {
                for idx, s := range rule.Automaton.Strings {
                    interp.SetMemoryString(idx, s.Identifier)
                }
            }


		// Execute the bytecode
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
		fmt.Println()
	}

	fmt.Printf("Total matches found: %d\n", totalMatches)
}
