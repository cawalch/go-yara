// Package main provides a command-line tool for lexing YARA files.
package main

import (
	"fmt"
	"os"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
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
		fmt.Println("Usage: go run cmd/main.go <yara-file>")
		os.Exit(1)
	}

	filename := os.Args[1]
	content, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("Error reading file %s: %v\n", filename, err)
		os.Exit(1)
	}

	fmt.Printf("Parsing YARA file: %s\n", filename)
	fmt.Printf("File content:\n%s\n\n", string(content))

	// Create lexer
	l := lexer.New(string(content))

	// Parse all tokens
	fmt.Println("Tokens:")
	tokens := make([]token.Token, 0, 100) // Pre-allocate with reasonable capacity
	for {
		tok := l.NextToken()
		tokens = append(tokens, tok)
		fmt.Printf("  %s\n", formatToken(tok))
		if tok.Type == token.EOF {
			break
		}
	}

	checkAndReportErrors(l, tokens)
}

func checkAndReportErrors(l *lexer.Lexer, tokens []token.Token) {
	lexerErrors := l.Errors()
	if len(lexerErrors) > 0 {
		fmt.Printf("\nParse errors (%d):\n", len(lexerErrors))
		for _, err := range lexerErrors {
			fmt.Printf("  %s\n", err.Error())
		}
		os.Exit(1)
	}

	fmt.Printf("\nSuccessfully parsed %d tokens with no errors!\n", len(tokens))
}
