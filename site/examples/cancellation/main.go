package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/cawalch/go-yara/compiler"
)

var errTooLarge = errors.New("input exceeds byte limit")

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errTooLarge
	}
	return data, nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	program, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), `rule marker { strings: $a="marker" condition: $a }`)
	if err != nil {
		return err
	}
	scanner := program.NewScanner()
	defer scanner.Close()
	// Read one extra byte to detect oversized input instead of silently scanning a prefix.
	const limit = 8
	_, err = readBounded(bytes.NewBufferString("marker plus extra"), limit)
	fmt.Printf("oversized input rejected: %t\n", errors.Is(err, errTooLarge))
	data, err := readBounded(bytes.NewBufferString("marker"), limit)
	if err != nil {
		return err
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = scanner.ScanWithContext(cancelled, data)
	fmt.Printf("cancelled: %t\n", errors.Is(err, context.Canceled))
	// The cancelled call did not establish a rule outcome. A new context can be used next.
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	result, err := scanner.ScanWithContext(ctx, data)
	if err != nil {
		return err
	}
	fmt.Printf("next scan matched: %t\n", result.RuleResults["marker"])
	return nil
}
