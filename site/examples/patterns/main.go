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
rule text_count {
 strings: $word = "hello" nocase fullword
 condition: #word == 2 and @word[2] == 11
}
rule hex_header {
 strings: $header = { 4D 5A [3] 68 65 6C 6C 6F }
 condition: $header at 0
}
rule numeric_id {
 strings: $id = /id=[0-9]{2}/
 condition: uint16(0) == 0x5a4d and $id in (17..21)
}`)
	if err != nil {
		return err
	}
	for _, sample := range []struct{ name, input string }{
		{"numeric", "MZ\x00\x00 hello HELLO id=42"},
		{"letters", "MZ\x00\x00 hello HELLO id=ab"},
	} {
		result, err := program.Scan([]byte(sample.input))
		if err != nil {
			return err
		}
		fmt.Printf("%s: text=%t hex=%t regex=%t\n", sample.name,
			result.RuleResults["text_count"], result.RuleResults["hex_header"], result.RuleResults["numeric_id"])
	}
	return nil
}
