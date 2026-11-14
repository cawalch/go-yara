package compiler

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cawalch/go-yara/regex"
)

func TestModuleRegexSignatureAndSchemaContracts(t *testing.T) {
	t.Run("rejects ModuleRegex return type", func(t *testing.T) {
		bad := Module{
			Name: "demo",
			Functions: map[string]ModuleFunction{
				"ret": {
					Signatures: []ModuleSignature{{Arguments: nil}},
					ReturnType: ModuleRegex,
					Evaluate: func(ModuleContext, []ModuleValue) (ModuleValue, error) {
						return ModuleValue{}, nil
					},
				},
			},
		}
		if _, err := compileModuleFunctions(map[string]Module{"demo": bad}); err == nil {
			t.Fatal("expected ModuleRegex return type error")
		}
	})

	t.Run("rejects ModuleRegex overload specialization", func(t *testing.T) {
		bad := Module{
			Name: "demo",
			Functions: map[string]ModuleFunction{
				"spec": {
					Signatures: []ModuleSignature{{
						ReturnType: ModuleRegex,
						Arguments:  []ModuleValueType{ModuleRegex},
					}},
					ReturnType: ModuleInteger,
					Evaluate: func(ModuleContext, []ModuleValue) (ModuleValue, error) {
						return IntegerValue(1), nil
					},
				},
			},
		}
		if _, err := compileModuleFunctions(map[string]Module{"demo": bad}); err == nil {
			t.Fatal("expected ModuleRegex overload return type error")
		}
	})

	t.Run("rejects ModuleRegex schema field", func(t *testing.T) {
		schema := &ModuleSchema{
			Fields: map[string]ModuleField{
				"pattern": {Kind: ModuleRegex},
			},
		}
		if err := validateModuleSchema(schema); err == nil {
			t.Fatal("expected ModuleRegex schema field error")
		}
	})

	t.Run("semantic type checking and compile-time regex validation", func(t *testing.T) {
		demo := Module{
			Name: "demo",
			Functions: map[string]ModuleFunction{
				"only_regex": {
					Signatures: []ModuleSignature{{Arguments: []ModuleValueType{ModuleRegex}}},
					ReturnType: ModuleBoolean,
					Evaluate: func(ModuleContext, []ModuleValue) (ModuleValue, error) {
						return BooleanValue(true), nil
					},
				},
				"only_string": {
					Signatures: []ModuleSignature{{Arguments: []ModuleValueType{ModuleString}}},
					ReturnType: ModuleBoolean,
					Evaluate: func(ModuleContext, []ModuleValue) (ModuleValue, error) {
						return BooleanValue(true), nil
					},
				},
			},
		}

		invalidSources := []struct {
			name   string
			source string
		}{
			{"string passed to regex param", `import "demo" rule r { condition: demo.only_regex("abc") }`},
			{"regex passed to string param", `import "demo" rule r { condition: demo.only_string(/abc/) }`},
			{"wrong arity", `import "demo" rule r { condition: demo.only_regex(/a/, /b/) }`},
			{"unclosed character class", `import "demo" rule r { condition: demo.only_regex(/[unclosed/) }`},
			{"invalid quantifier", `import "demo" rule r { condition: demo.only_regex(/+/) }`},
			{"unsupported flag m", `import "demo" rule r { condition: demo.only_regex(/foo/m) }`},
		}
		for _, tc := range invalidSources {
			t.Run(tc.name, func(t *testing.T) {
				if _, err := NewCompiler(WithModule(demo)).CompileSource(tc.source); err == nil {
					t.Fatalf("expected compile error for %s", tc.name)
				}
			})
		}
	})
}

func TestCompileModuleRegexFlagsAndEdgeCases(t *testing.T) {
	t.Run("valid literals flags NUL and escapes", func(t *testing.T) {
		cases := []struct {
			name    string
			literal string
			input   []byte
			want    bool
		}{
			{name: "basic match", literal: `/CreateFile/`, input: []byte("NtCreateFileW"), want: true},
			{name: "basic miss", literal: `/CreateFile/`, input: []byte("createfile"), want: false},
			{name: "nocase", literal: `/createfile/i`, input: []byte("NtCreateFileW"), want: true},
			{name: "dot excludes newline", literal: `/a.b/`, input: []byte("a\nb"), want: false},
			{name: "dotall matches newline", literal: `/a.b/s`, input: []byte("a\nb"), want: true},
			{name: "nocase dotall combined", literal: `/a.b/is`, input: []byte("A\nB"), want: true},
			{name: "anchored match", literal: `/^Exact$/`, input: []byte("Exact"), want: true},
			{name: "anchored miss", literal: `/^Exact$/`, input: []byte("xExact"), want: false},
			{name: "escaped slash", literal: `/a\/b/`, input: []byte("a/b"), want: true},
			{name: "trailing escaped backslash", literal: `/abc\\/`, input: []byte(`abc\`), want: true},
			{name: "embedded NUL escape", literal: `/a\x00b/`, input: []byte("a\x00b"), want: true},
			{name: "embedded NUL rejects non-NUL", literal: `/a\x00b/`, input: []byte("axb"), want: false},
			{name: "embedded NUL rejects truncated", literal: `/a\x00b/`, input: []byte("a"), want: false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				re, err := CompileModuleRegex(tc.literal)
				if err != nil {
					t.Fatalf("CompileModuleRegex(%q) error = %v", tc.literal, err)
				}
				got, err := re.Match(tc.input)
				if err != nil || got != tc.want {
					t.Fatalf("Match(%q) = (%t, %v), want (%t, nil)", tc.input, got, err, tc.want)
				}
				gotStr, err := re.MatchString(string(tc.input))
				if err != nil || gotStr != tc.want {
					t.Fatalf("MatchString(%q) = (%t, %v), want (%t, nil)", tc.input, gotStr, err, tc.want)
				}
			})
		}
	})

	t.Run("invalid literals rejected", func(t *testing.T) {
		for _, literal := range []string{
			"",
			"/",
			"abc",
			"/unterminated",
			`/escaped\/`,
			"/foo/m",
			"/foo/g",
			"/[unclosed/",
			"/+/",
		} {
			if _, err := CompileModuleRegex(literal); err == nil {
				t.Fatalf("CompileModuleRegex(%q) unexpectedly succeeded", literal)
			}
		}
	})

	t.Run("zero-value ownership guards", func(t *testing.T) {
		var zero CompiledRegex
		if matched, err := zero.Match([]byte("anything")); matched || err == nil {
			t.Fatalf("zero.Match = (%t, %v), want (false, error)", matched, err)
		}
		if _, ok := (ModuleValue{}).CompiledRegex(); ok {
			t.Fatal("zero ModuleValue reported CompiledRegex")
		}
		if _, ok := (ModuleValue{Type: ModuleRegex}).CompiledRegex(); ok {
			t.Fatal("uninitialized ModuleRegex value reported CompiledRegex")
		}
		re, err := CompileModuleRegex(`/ok/`)
		if err != nil {
			t.Fatal(err)
		}
		mv := RegexValue(re)
		got, ok := mv.CompiledRegex()
		if !ok {
			t.Fatal("RegexValue did not yield CompiledRegex")
		}
		if matched, err := got.MatchString("ok"); err != nil || !matched {
			t.Fatalf("got.MatchString = (%t, %v), want (true, nil)", matched, err)
		}
	})
}

func TestModuleRegexExecutionSerializationAndDeduplication(t *testing.T) {
	demo := Module{
		Name: "demo",
		Functions: map[string]ModuleFunction{
			"find": {
				Signatures: []ModuleSignature{
					{Arguments: []ModuleValueType{ModuleString}},
					{Arguments: []ModuleValueType{ModuleRegex}},
				},
				ReturnType: ModuleBoolean,
				Evaluate: func(ctx ModuleContext, args []ModuleValue) (ModuleValue, error) {
					if args[0].Type == ModuleString {
						return BooleanValue(bytes.Contains(ctx.Data, []byte(args[0].String))), nil
					}
					re, ok := args[0].CompiledRegex()
					if !ok {
						return ModuleValue{}, errors.New("expected CompiledRegex")
					}
					matched, err := re.Match(ctx.Data)
					if err != nil {
						return ModuleValue{}, err
					}
					return BooleanValue(matched), nil
				},
			},
			"pair": {
				Signatures: []ModuleSignature{{
					Arguments: []ModuleValueType{ModuleInteger, ModuleRegex, ModuleRegex},
				}},
				ReturnType: ModuleBoolean,
				Evaluate: func(ctx ModuleContext, args []ModuleValue) (ModuleValue, error) {
					if args[0].Integer != 4 {
						return BooleanValue(false), nil
					}
					re1, ok1 := args[1].CompiledRegex()
					re2, ok2 := args[2].CompiledRegex()
					if !ok1 || !ok2 {
						return ModuleValue{}, errors.New("expected CompiledRegex arguments")
					}
					m1, err := re1.Match(ctx.Data)
					if err != nil {
						return ModuleValue{}, err
					}
					m2, err := re2.Match(ctx.Data)
					if err != nil {
						return ModuleValue{}, err
					}
					return BooleanValue(m1 && m2), nil
				},
			},
		},
	}

	source := `
import "demo"
rule match_overload_and_comments {
    condition:
        demo.find("HEADER") and
        demo.find(/alpha.*omega/is) and
        demo.pair(8 / 2, /* first */ /kernel32\.dll/i, // line comment
            /Create.*W/) and
        demo.pair(4, /same/i, /same/i)
}
`
	program, err := NewCompiler(WithModule(demo)).CompileSource(source)
	if err != nil {
		t.Fatalf("CompileSource error = %v", err)
	}
	if got := len(program.Rules[0].moduleRegexes); got != 4 {
		// Unique regex literals in rule: /alpha.*omega/is, /kernel32\.dll/i, /Create.*W/, /same/i (deduped).
		t.Fatalf("rule moduleRegexes count = %d, want 4 (with /same/i deduplicated)", got)
	}

	blob, err := program.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary error = %v", err)
	}
	if version := binary.BigEndian.Uint16(blob[len(compiledProgramMagic):]); version != compiledProgramVersion {
		t.Fatalf("serialized version = %d, want %d", version, compiledProgramVersion)
	}
	loaded, err := UnmarshalCompiledProgram(blob, demo)
	if err != nil {
		t.Fatalf("UnmarshalCompiledProgram error = %v", err)
	}

	matchingInput := []byte("HEADER ALPHA\nOMEGA KERNEL32.DLL CreateFileW SAME")
	nonMatchingInput := []byte("HEADER ALPHA\nOMEGA KERNEL32.DLL CreateFileA SAME")
	for _, candidate := range []*CompiledProgram{program, loaded} {
		if yes, err := candidate.Matches(matchingInput); err != nil || !yes {
			t.Fatalf("Matches(matchingInput) = (%t, %v), want (true, nil)", yes, err)
		}
		if yes, err := candidate.Matches(nonMatchingInput); err != nil || yes {
			t.Fatalf("Matches(nonMatchingInput) = (%t, %v), want (false, nil)", yes, err)
		}
	}

	// Mutating a recompiled string-only module must fail signature compatibility on load.
	stringOnlyDemo := Module{
		Name: "demo",
		Functions: map[string]ModuleFunction{
			"find": {
				Signatures: []ModuleSignature{{Arguments: []ModuleValueType{ModuleString}}},
				ReturnType: ModuleBoolean,
				Evaluate:   demo.Functions["find"].Evaluate,
			},
			"pair": demo.Functions["pair"],
		},
	}
	if _, err := UnmarshalCompiledProgram(blob, stringOnlyDemo); err == nil {
		t.Fatal("expected incompatible module signature error when ModuleRegex overload removed")
	}

	// Rule Validate() and deserializeModuleRegexes() reject empty code / unknown flags cleanly.
	if err := validateCompiledModuleRegex(&compiledModuleRegex{code: nil}); err == nil {
		t.Fatal("expected empty bytecode validation error")
	}
	if err := validateCompiledModuleRegex(&compiledModuleRegex{code: []byte{regex.OpMatch}, flags: regex.FlagsWide}); err == nil {
		t.Fatal("expected invalid flag validation error")
	}
	if _, err := deserializeModuleRegexes([]serializedModuleRegex{{Code: nil, Flags: 0}}); err == nil {
		t.Fatal("expected deserializeModuleRegexes to reject empty bytecode")
	}
}

func TestModuleRegexConcurrentScansCancellationAndReuse(t *testing.T) {
	var savedMu sync.Mutex
	var savedRegex CompiledRegex

	demo := Module{
		Name: "demo",
		Functions: map[string]ModuleFunction{
			"save_and_match": {
				Signatures: []ModuleSignature{{Arguments: []ModuleValueType{ModuleRegex}}},
				ReturnType: ModuleBoolean,
				Evaluate: func(ctx ModuleContext, args []ModuleValue) (ModuleValue, error) {
					select {
					case <-ctx.Done():
						return ModuleValue{}, context.Canceled
					default:
					}
					re, _ := args[0].CompiledRegex()
					savedMu.Lock()
					savedRegex = re
					savedMu.Unlock()
					matched, err := re.Match(ctx.Data)
					if err != nil {
						return ModuleValue{}, err
					}
					return BooleanValue(matched), nil
				},
			},
		},
	}

	program, err := NewCompiler(WithModule(demo)).CompileSource(`
import "demo"
rule pathological {
    condition:
        demo.save_and_match(/((a+)+)+b/)
}
`)
	if err != nil {
		t.Fatalf("CompileSource error = %v", err)
	}

	// 1. Pre-canceled scan fails with context.Canceled and must not poison subsequent scans.
	canceledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	s := NewScanner(program)
	defer s.Close()
	if matched, err := s.MatchesWithContext(canceledCtx, []byte("aaab")); matched || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled MatchesWithContext = (%t, %v), want (false, context.Canceled)", matched, err)
	}

	// Reusing the same scanner without cancellation must match normally.
	if matched, err := s.MatchesWithContext(context.Background(), []byte("aaab")); err != nil || !matched {
		t.Fatalf("reused MatchesWithContext = (%t, %v), want (true, nil)", matched, err)
	}

	// 2. Capture a regex during an expired deadline scan and check deadline behavior under large input.
	hugeNoMatch := bytes.Repeat([]byte{'a'}, 512*1024)
	start := time.Now()
	if matched, err := s.Matches(hugeNoMatch); err != nil || matched {
		t.Fatalf("pathological non-match = (%t, %v), want (false, nil)", matched, err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("pathological Thompson NFA scan took too long: %v", elapsed)
	}

	deadlineCtx, cancelDeadline := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancelDeadline()
	time.Sleep(time.Millisecond)
	if _, err := s.MatchesWithContext(deadlineCtx, hugeNoMatch); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline MatchesWithContext err = %v, want DeadlineExceeded", err)
	}

	// Cancel deterministically during condition evaluation so Evaluate executes
	// with a closed cancelDone channel: first call cancels ctx, second invokes Match.
	midCtx, cancelMid := context.WithCancel(context.Background())
	defer cancelMid()
	matchOnlyDemo := Module{
		Name: "demo",
		Functions: map[string]ModuleFunction{
			"cancel_now": {
				Signatures: []ModuleSignature{{}},
				ReturnType: ModuleBoolean,
				Evaluate: func(ModuleContext, []ModuleValue) (ModuleValue, error) {
					cancelMid()
					return BooleanValue(true), nil
				},
			},
			"match_only": {
				Signatures: []ModuleSignature{{Arguments: []ModuleValueType{ModuleRegex}}},
				ReturnType: ModuleBoolean,
				Evaluate: func(ctx ModuleContext, args []ModuleValue) (ModuleValue, error) {
					re, _ := args[0].CompiledRegex()
					savedMu.Lock()
					savedRegex = re
					savedMu.Unlock()
					matched, err := re.Match(ctx.Data)
					if err != nil {
						return ModuleValue{}, err
					}
					return BooleanValue(matched), nil
				},
			},
		},
	}
	matchProg, err := NewCompiler(WithModule(matchOnlyDemo)).CompileSource(`
import "demo"
rule r {
    condition:
        demo.cancel_now() and demo.match_only(/((a+)+)+b/)
}
`)
	if err != nil {
		t.Fatal(err)
	}
	matchScanner := NewScanner(matchProg)
	defer matchScanner.Close()
	if _, err := matchScanner.MatchesWithContext(midCtx, []byte("aaab")); !errors.Is(err, context.Canceled) {
		t.Fatalf("match_only canceled err = %v, want context.Canceled", err)
	}
	// Calling Match on the saved handle from scan 1 observes scan 1's cancellation,
	// whereas running a fresh scan with the same scanner and shared CompiledProgram works cleanly.
	savedMu.Lock()
	capturedFromCanceledScan := savedRegex
	savedMu.Unlock()
	if matched, err := capturedFromCanceledScan.Match([]byte("aaab")); matched || !errors.Is(err, context.Canceled) {
		t.Fatalf("saved handle from canceled scan = (%t, %v), want (false, context.Canceled)", matched, err)
	}

	// Reusing the same scanner for an active scan must succeed cleanly.
	noCancelProg, err := NewCompiler(WithModule(Module{
		Name: "demo",
		Functions: map[string]ModuleFunction{
			"cancel_now": {
				Signatures: []ModuleSignature{{}},
				ReturnType: ModuleBoolean,
				Evaluate:   func(ModuleContext, []ModuleValue) (ModuleValue, error) { return BooleanValue(true), nil },
			},
			"match_only": matchOnlyDemo.Functions["match_only"],
		},
	})).CompileSource(`import "demo" rule r { condition: demo.cancel_now() and demo.match_only(/((a+)+)+b/) }`)
	if err != nil {
		t.Fatal(err)
	}
	// Concurrent goroutines sharing one CompiledProgram with distinct inputs.
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			local := NewScanner(noCancelProg)
			defer local.Close()
			for iter := range 25 {
				want := (id+iter)%2 == 0
				input := []byte("ccccc")
				if want {
					input = []byte("aaaaab")
				}
				got, scanErr := local.Matches(input)
				if scanErr != nil || got != want {
					t.Errorf("concurrent scan (%d,%d) = (%t, %v), want (%t, nil)", id, iter, got, scanErr, want)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestInterpreterPushRegexRejectsInvalidIndex(t *testing.T) {
	interp := NewInterpreter([]byte{byte(OpPushRegex), 0, 0, 0, 0, byte(OpHalt)})
	defer interp.Release()

	err := interp.Execute()
	var interpErr *InterpreterError
	if !errors.As(err, &interpErr) || interpErr.Type != ErrorInvalidBytecode {
		t.Fatalf("Execute() error = %v, want ErrorInvalidBytecode", err)
	}
}
