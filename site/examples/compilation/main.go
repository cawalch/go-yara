package main

import (
	"context"
	"fmt"
	"log"
	"sort"

	"github.com/cawalch/go-yara/compiler"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	const source = `
rule broken { condition: missing_identifier }
rule dependent { condition: broken }
rule good { condition: true }`
	_, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), source)
	fmt.Printf("strict compilation fails: %t\n", err != nil)
	c := compiler.NewCompiler(compiler.WithIgnoreInvalidRules(true))
	program, err := c.CompileSourceWithContext(context.Background(), source)
	if err != nil {
		return err
	} // Fatal errors still stop compilation.
	ignored := c.GetIgnoredRules()
	sort.Slice(ignored, func(i, j int) bool { return ignored[i].Rule < ignored[j].Rule })
	for _, diagnostic := range ignored {
		fmt.Printf("omitted: %s\n", diagnostic.Rule)
		// A diagnostic also carries Phase, Message, Line, and Column for reports.
	}
	matches, err := program.MatchingRules(nil)
	if err != nil {
		return err
	}
	for _, match := range matches {
		fmt.Printf("matched: %s\n", match.Rule)
	}
	return nil
}
