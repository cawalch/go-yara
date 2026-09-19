package compiler

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRegexConditionDeadline(t *testing.T) {
	// A literal condition input isolates cancellation inside OpMatches from
	// pattern scanning and from the interpreter's periodic opcode poll.
	source := `rule expensive { condition: "` + strings.Repeat("a", 8192) + `" matches /a+b/ }`
	program, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(program)
	defer scanner.Close()
	blocks := NewBlockScanner(program)
	defer blocks.Close()
	scans := map[string]func(context.Context) error{
		"BlockScannerFinish": func(ctx context.Context) error { _, err := blocks.FinishWithContext(ctx); return err },
		"Scan":               func(ctx context.Context) error { _, err := scanner.ScanWithContext(ctx, nil); return err },
		"Matches":            func(ctx context.Context) error { _, err := scanner.MatchesWithContext(ctx, nil); return err },
		"MatchingRules":      func(ctx context.Context) error { _, err := scanner.MatchingRulesWithContext(ctx, nil); return err },
		"MatchingRulesInBlock": func(ctx context.Context) error {
			_, err := scanner.MatchingRulesInBlockWithContext(ctx, MemoryBlock{}, 0)
			return err
		},
	}
	for name, scan := range scans {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
			defer cancel()
			start := time.Now()
			err := scan(ctx)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("error = %v, want DeadlineExceeded", err)
			}
			if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
				t.Fatalf("deadline took %v to interrupt regex", elapsed)
			}
		})
	}
}

func BenchmarkRegexConditionReject(b *testing.B) {
	for _, size := range []int{2048, 4096, 8192} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			source := `rule expensive { condition: "` + strings.Repeat("a", size) + `" matches /a+b/ }`
			program, err := NewCompiler().CompileSource(source)
			if err != nil {
				b.Fatal(err)
			}
			scanner := NewScanner(program)
			defer scanner.Close()
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := scanner.Matches(nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestRegexMatchContentDeadlineAndReuse(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule expensive { strings: $a = /^a+$/ condition: $a matches /a+b/ }`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(program)
	defer scanner.Close()
	data := []byte(strings.Repeat("a", 8192))
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	matched, err := scanner.MatchesWithContext(ctx, data)
	if matched || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Matches = (%v,%v), want deadline", matched, err)
	}
	matched, err = scanner.Matches([]byte("b"))
	if matched || err != nil {
		t.Fatalf("reuse after deadline = (%v,%v)", matched, err)
	}
}

func TestCancellationDuringLastInstruction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	module := Module{Name: "stop", Functions: map[string]ModuleFunction{
		"now": {Signatures: []ModuleSignature{{Arguments: []ModuleValueType{ModuleInteger}}}, ReturnType: ModuleBoolean,
			Evaluate: func(ModuleContext, []ModuleValue) (ModuleValue, error) { cancel(); return BooleanValue(true), nil },
		},
	}}
	program, err := NewCompiler(WithModule(module)).CompileSource(`import "stop" rule last { condition: stop.now(0) }`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(program)
	defer scanner.Close()
	matched, err := scanner.MatchesWithContext(ctx, nil)
	if matched || !errors.Is(err, context.Canceled) {
		t.Fatalf("Matches = (%v,%v), want cancellation after last instruction", matched, err)
	}
}

func TestAnchoredRegexDeadline(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule anchored { strings: $a = /^a+$/ condition: $a at 0 }`)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(strings.Repeat("a", 8<<20))
	scanner := NewScanner(program)
	defer scanner.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	start := time.Now()
	matched, err := scanner.MatchesWithContext(ctx, data)
	if matched || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("anchored match = (%v,%v), want deadline", matched, err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("anchored deadline took %v", elapsed)
	}
	matched, err = scanner.Matches([]byte("aaa"))
	if !matched || err != nil {
		t.Fatalf("reuse after anchored deadline = (%v,%v)", matched, err)
	}
}
