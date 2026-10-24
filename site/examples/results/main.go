package main

import (
	"context"
	"fmt"
	"log"

	"github.com/cawalch/go-yara/compiler"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	program, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), `
rule present { strings: $a = "hello" condition: $a }
rule gated { strings: $a = "hello" condition: $a and filesize > 100 }`)
	if err != nil {
		return err
	}
	scanner := program.NewScanner(compiler.WithMatchData(2))
	defer scanner.Close()
	data := []byte("--hello--")
	result, err := scanner.Scan(data)
	if err != nil {
		return err
	}
	for _, name := range []string{"present", "gated"} {
		matches := result.Matches[name]["$a"]
		fmt.Printf("%s: condition=%t occurrences=%d\n", name, result.RuleResults[name], len(matches))
		for _, match := range matches {
			fmt.Printf("  offset=%d length=%d copied=%q truncated=%t\n", match.Offset, match.Length, match.MatchedData, match.MatchedDataTruncated)
		}
	}
	// These methods perform separate scans with smaller result contracts.
	anyMatch, err := scanner.Matches(data)
	if err != nil {
		return err
	}
	fmt.Printf("any rule matched: %t\n", anyMatch)
	names, err := scanner.MatchingRules(data)
	if err != nil {
		return err
	}
	for _, match := range names {
		fmt.Printf("matched rule: %s\n", match.Rule)
	}
	return nil
}
