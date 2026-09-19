package compiler

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRegexConditionDeadline(t *testing.T) {
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

func TestRegexPatternDeadlineAndReuse(t *testing.T) {
	for _, test := range []struct {
		condition string
		size      int
		reuse     string
		want      bool
	}{
		{`$a matches /a+b/`, 8192, "b", false},
		{`$a at 0`, 8 << 20, "aaa", true},
	} {
		t.Run(test.condition, func(t *testing.T) {
			program, err := NewCompiler().CompileSource(`rule r { strings: $a = /^a+$/ condition: ` + test.condition + ` }`)
			if err != nil {
				t.Fatal(err)
			}
			scanner := NewScanner(program)
			defer scanner.Close()
			data := []byte(strings.Repeat("a", test.size))
			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
			defer cancel()
			start := time.Now()
			matched, err := scanner.MatchesWithContext(ctx, data)
			if matched || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Matches = (%v,%v), want deadline", matched, err)
			}
			if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
				t.Fatalf("deadline took %v", elapsed)
			}
			matched, err = scanner.Matches([]byte(test.reuse))
			if matched != test.want || err != nil {
				t.Fatalf("reuse = (%v,%v), want %v", matched, err, test.want)
			}
		})
	}
}
