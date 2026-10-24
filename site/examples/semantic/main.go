package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/semantic"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cases := []struct{ name, source string }{
		{"forward reference", `rule first { condition: second } rule second { condition: true }`},
		{"unknown name", `rule bad { condition: missing_identifier }`},
		{"argument type", `import "math" rule bad { condition: math.in_range("x", 0.0, 1.0) }`},
		{"dependency cycle", `rule first { condition: second } rule second { condition: first }`},
		{"capture group", `rule bad { strings: $a = /(a)/ capture(value = 2) condition: $a }`},
	}
	for _, example := range cases {
		c := compiler.NewCompiler()
		_, err := c.CompileSourceWithContext(context.Background(), example.source)
		if err == nil {
			fmt.Printf("%s: accepted\n", example.name)
			continue
		}
		var diagnostic *semantic.Error
		if !errors.As(err, &diagnostic) {
			return err
		}
		fmt.Printf("%s: %s\n", example.name, diagnostic.Code)
		// GetErrors returns all compiler diagnostics, with Phase, Code, Line,
		// Column, and Message. The wrapped semantic.Error above is the first.
		for _, item := range c.GetErrors() {
			if item.Phase != "semantic" || item.Line < 1 || item.Column < 1 {
				return fmt.Errorf("missing semantic diagnostic location: %+v", item)
			}
		}
	}
	// A well-typed call can still produce undefined for a particular value.
	program, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), `
import "string"
rule conversion { condition: defined string.to_int("oops") }`)
	if err != nil {
		return err
	}
	matched, err := program.Matches(nil)
	if err != nil {
		return err
	}
	fmt.Printf("runtime conversion: compiled=true defined=%t\n", matched)
	return nil
}
