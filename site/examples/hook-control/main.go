package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cawalch/go-yara/compiler"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	program, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), `
rule first { strings: $a = "marker" condition: $a }
rule second { strings: $a = "marker" condition: $a }`)
	if err != nil {
		return err
	}
	stopped := false
	first := compiler.NewScanner(program, compiler.WithMatchHook(func(*compiler.CompiledRule, compiler.RuleMatch) compiler.MatchAction {
		stopped = true // Track incomplete rule coverage separately from the error.
		return compiler.MatchActionStopScan
	}))
	defer first.Close()
	result, err := first.Scan([]byte("marker"))
	if err != nil {
		return err
	}
	fmt.Printf("stop on match: rules=%d stopped=%t error=false\n", len(result.MatchedRules), stopped)

	abort := compiler.NewScanner(program, compiler.WithPollHook(func(context.Context, compiler.PollProgress) (compiler.PollAction, time.Duration) {
		return compiler.PollAbort, 0
	}, 1))
	defer abort.Close()
	_, err = abort.Scan([]byte("marker"))
	if err == nil {
		return errors.New("poll abort unexpectedly succeeded")
	}
	if !errors.Is(err, compiler.ErrScanAborted) {
		return fmt.Errorf("expected poll abort: %w", err)
	}
	fmt.Printf("poll abort: ErrScanAborted=%t\n", errors.Is(err, compiler.ErrScanAborted))
	return nil
}
