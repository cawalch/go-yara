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
external environment
external enabled
rule production_marker {
 strings: $a = "marker"
 condition: defined enabled and enabled and environment == "production" and $a
}`)
	if err != nil {
		return err
	}
	scanner := program.NewScanner()
	defer scanner.Close()
	for _, values := range []map[string]any{
		{"environment": "staging", "enabled": true},
		{"environment": "production", "enabled": true},
		{"environment": "production"}, // Replaces the previous map; enabled is now undefined.
	} {
		if err := scanner.SetExternalVariables(values); err != nil {
			return err
		}
		matched, err := scanner.Matches([]byte("marker"))
		if err != nil {
			return err
		}
		fmt.Printf("environment=%s enabled=%v matched=%t\n", values["environment"], values["enabled"], matched)
	}
	return nil
}
