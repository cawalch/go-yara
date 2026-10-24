package main

import (
	"context"
	"fmt"
	"log"

	"github.com/cawalch/go-yara/compiler"
)

func main() {
	program, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), `
rule greeting {
    strings:
        $text = "hello" nocase
    condition:
        $text
}`)
	if err != nil {
		log.Fatal(err)
	}
	result, err := program.Scan([]byte("Hello from Go"))
	if err != nil {
		log.Fatal(err)
	}
	for _, match := range result.MatchedRules {
		fmt.Println(match.Rule)
	}
}
