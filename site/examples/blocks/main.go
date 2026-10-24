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
rule sparse {
 strings: $header = "MZ" $payload = "needle"
 condition: $header at 0 and $payload at 0x1000 and filesize == 0x2000
}`)
	if err != nil {
		return err
	}
	scanner := program.NewBlockScanner()
	defer scanner.Close()
	if err := scanner.SetFileSize(0x2000); err != nil {
		return err
	}
	if err := scanner.Scan(0, []byte("MZ")); err != nil {
		return err
	}
	if err := scanner.Scan(0x1000, []byte("needle")); err != nil {
		return err
	}
	result, err := scanner.Finish()
	if err != nil {
		return err
	}
	fmt.Printf("sparse: %t; payload offset=%#x\n", result.RuleResults["sparse"], result.Matches["sparse"]["$payload"][0].Offset)

	// Reset drops the previous blocks, matches, and logical file size.
	scanner.Reset()
	if err := scanner.SetFileSize(0x2000); err != nil {
		return err
	}
	for _, block := range []compiler.MemoryBlock{
		{Base: 0, Data: []byte("MZ")},
		{Base: 0x1000, Data: []byte("nee")},
		{Base: 0x1003, Data: []byte("dle")},
	} {
		if err := scanner.Scan(block.Base, block.Data); err != nil {
			return err
		}
	}
	result, err = scanner.Finish()
	if err != nil {
		return err
	}
	fmt.Printf("split without overlap: %t\n", result.RuleResults["sparse"])
	// Supply a window containing the entire boundary-crossing pattern.
	if err := scanner.Scan(0x1000, []byte("needle")); err != nil {
		return err
	}
	result, err = scanner.Finish()
	if err != nil {
		return err
	}
	fmt.Printf("with complete overlapping window: %t\n", result.RuleResults["sparse"])
	return nil
}
