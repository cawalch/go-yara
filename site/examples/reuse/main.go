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
rule marker { strings: $a = "marker" condition: $a }`)
	if err != nil {
		return err
	}
	scanner := program.NewScanner(compiler.WithoutMatches(), compiler.WithoutRuleResults())
	defer scanner.Close()
	for _, data := range [][]byte{[]byte("clean"), []byte("a marker")} {
		matched, err := scanner.Matches(data)
		if err != nil {
			return err
		}
		fmt.Println(matched)
	}
	return nil
}
