package main

import (
	"context"
	"fmt"
	"log"

	"github.com/cawalch/go-yara/compiler"
)

func main() {
	program, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), `
rule small { condition: filesize < 1024 }`)
	if err != nil {
		log.Fatal(err)
	}
	encoded, err := program.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	loaded, err := compiler.UnmarshalCompiledProgram(encoded)
	if err != nil {
		log.Fatal(err)
	}
	matched, err := loaded.Matches([]byte("sample"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(matched)
}
