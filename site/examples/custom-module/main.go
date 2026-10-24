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
	// A pure byte lookup. Undefined is a valid return for an absent offset.
	module := compiler.Module{Name: "sample", Functions: map[string]compiler.ModuleFunction{
		"byte_at": {
			Signatures: []compiler.ModuleSignature{{Arguments: []compiler.ModuleValueType{compiler.ModuleInteger}}},
			ReturnType: compiler.ModuleInteger,
			Evaluate: func(ctx compiler.ModuleContext, args []compiler.ModuleValue) (compiler.ModuleValue, error) {
				offset := args[0].Integer
				if offset < 0 || offset >= int64(len(ctx.Data)) {
					return compiler.ModuleValue{}, nil
				}
				return compiler.IntegerValue(int64(ctx.Data[offset])), nil
			},
		},
	}}
	program, err := compiler.NewCompiler(compiler.WithModule(module)).CompileSourceWithContext(context.Background(), `
import "sample"
external enabled
rule magic { condition: enabled and defined sample.byte_at(0) and sample.byte_at(0) == 0x4d }`)
	if err != nil {
		return err
	}
	blob, err := program.MarshalBinary()
	if err != nil {
		return err
	}
	_, err = compiler.UnmarshalCompiledProgram(blob)
	fmt.Printf("load without callback fails: %t\n", err != nil)
	// Supply compatible callbacks while loading, then bind runtime values.
	loaded, err := compiler.UnmarshalCompiledProgram(blob, module)
	if err != nil {
		return err
	}
	scanner := loaded.NewScanner(compiler.WithExternalVariables(map[string]any{"enabled": true}))
	defer scanner.Close()
	for _, input := range [][]byte{nil, []byte("MZ")} {
		matched, err := scanner.Matches(input)
		if err != nil {
			return err
		}
		fmt.Printf("input=%q matched=%t\n", input, matched)
	}
	return nil
}
