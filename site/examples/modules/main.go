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
	telemetry := compiler.Module{
		Name: "telemetry",
		Schema: &compiler.ModuleSchema{Fields: map[string]compiler.ModuleField{
			"score": {Kind: compiler.ModuleFloat},
		}},
	}
	program, err := compiler.NewCompiler(compiler.WithModule(telemetry)).CompileSourceWithContext(context.Background(), `
import "telemetry"
rule elevated { condition: telemetry.score > 0.9 }`)
	if err != nil {
		return err
	}
	scanner := program.NewScanner(compiler.WithModuleData("telemetry", map[string]any{"score": 0.95}))
	defer scanner.Close()
	result, err := scanner.Scan(nil)
	if err != nil {
		return err
	}
	fmt.Println(result.RuleResults["elevated"])
	return nil
}
