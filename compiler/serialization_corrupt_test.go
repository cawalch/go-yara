package compiler

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestUnmarshalCorruptHeaderErrorsReturnErrCorruptProgram(t *testing.T) {
	compiled, err := NewCompiler().CompileSource(`rule r { strings: $a = "hello" condition: $a }`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	valid, err := compiled.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	cases := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "short_header", data: []byte("GOY")},
		{name: "bad_magic", data: append([]byte("BADMAG\x00"), valid[len(compiledProgramMagic):]...)},
		{name: "truncated_version", data: []byte(compiledProgramMagic + "\x00")},
		{name: "future_version", data: func() []byte {
			mut := slices.Clone(valid)
			binary.BigEndian.PutUint16(mut[len(compiledProgramMagic):len(compiledProgramMagic)+2], compiledProgramVersion+1)
			return mut
		}()},
		{name: "truncated_gob", data: valid[:len(valid)-5]},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, loadErr := UnmarshalCompiledProgram(tc.data)
			if !errors.Is(loadErr, ErrCorruptProgram) {
				t.Fatalf("UnmarshalCompiledProgram() error = %v, want ErrCorruptProgram", loadErr)
			}
		})
	}
}

func TestCompiledPatternMatchesAtWithCancelNilGuards(t *testing.T) {
	data := []byte("hello world")

	missingKind := &CompiledRule{Name: "missing_kind", StringKinds: map[string]StringKind{}}
	if compiledPatternMatchesAtWithCancel(missingKind, "$a", data, 0, nil) {
		t.Fatal("expected false when StringKinds entry is missing")
	}

	nilAutomaton := &CompiledRule{
		Name:        "nil_automaton",
		StringKinds: map[string]StringKind{"$a": StringKindText},
	}
	if compiledPatternMatchesAtWithCancel(nilAutomaton, "$a", data, 0, nil) {
		t.Fatal("expected false when automaton is nil")
	}

	missingRegex := &CompiledRule{
		Name:        "missing_regex",
		StringKinds: map[string]StringKind{"$r": StringKindRegex},
	}
	if compiledPatternMatchesAtWithCancel(missingRegex, "$r", data, 0, nil) {
		t.Fatal("expected false when regex pattern is missing")
	}
}

func TestCompiledProgramRejectsCorruptRuleCrossReferences(t *testing.T) {
	base := func() *CompiledRule {
		return &CompiledRule{
			Name:        "test",
			Bytecode:    []byte{byte(OpPush8), 1, byte(OpHalt)},
			StringKinds: map[string]StringKind{},
		}
	}

	cases := []struct {
		name  string
		build func() *CompiledRule
	}{
		{
			name: "header_string_missing_kind",
			build: func() *CompiledRule {
				r := base()
				r.HeaderConstraints = []HeaderConstraint{{Kind: HeaderStringAt, String: "$a", Offset: 0}}
				return r
			},
		},
		{
			name: "header_string_nil_automaton",
			build: func() *CompiledRule {
				r := base()
				r.StringKinds["$a"] = StringKindText
				r.HeaderConstraints = []HeaderConstraint{{Kind: HeaderStringAt, String: "$a", Offset: 0}}
				return r
			},
		},
		{
			name: "header_string_missing_regex",
			build: func() *CompiledRule {
				r := base()
				r.StringKinds["$r"] = StringKindRegex
				r.HeaderConstraints = []HeaderConstraint{{Kind: HeaderStringAt, String: "$r", Offset: 0}}
				return r
			},
		},
		{
			name: "header_negative_offset",
			build: func() *CompiledRule {
				r := base()
				r.HeaderConstraints = []HeaderConstraint{{Kind: HeaderIntegerEquals, Offset: -1, Width: 2}}
				return r
			},
		},
		{
			name: "header_invalid_width",
			build: func() *CompiledRule {
				r := base()
				r.HeaderConstraints = []HeaderConstraint{{Kind: HeaderIntegerEquals, Offset: 0, Width: 3}}
				return r
			},
		},
		{
			name: "anonymous_string_missing_kind",
			build: func() *CompiledRule {
				r := base()
				r.AnonymousStrings = []string{"$anon"}
				return r
			},
		},
		{
			name: "string_set_missing_kind",
			build: func() *CompiledRule {
				r := base()
				r.StringSets = [][]string{{"$missing"}}
				return r
			},
		},
		{
			name: "required_string_missing_kind",
			build: func() *CompiledRule {
				r := base()
				r.requiredStrings = []string{"$missing"}
				return r
			},
		},
		{
			name: "forbidden_string_missing_kind",
			build: func() *CompiledRule {
				r := base()
				r.forbiddenStrings = []string{"$missing"}
				return r
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := tc.build()
			if err := rule.Validate(); err == nil {
				t.Fatal("Validate() succeeded, want error")
			}

			program := &CompiledProgram{Rules: []*CompiledRule{rule}}
			payload, err := serializeProgram(program)
			if err != nil {
				t.Fatalf("serializeProgram() error = %v", err)
			}
			var buf bytes.Buffer
			buf.WriteString(compiledProgramMagic)
			if err := binary.Write(&buf, binary.BigEndian, compiledProgramVersion); err != nil {
				t.Fatal(err)
			}
			if err := gob.NewEncoder(&buf).Encode(payload); err != nil {
				t.Fatal(err)
			}
			_, loadErr := UnmarshalCompiledProgram(buf.Bytes())
			if !errors.Is(loadErr, ErrCorruptProgram) {
				t.Fatalf("UnmarshalCompiledProgram() error = %v, want ErrCorruptProgram", loadErr)
			}
		})
	}
}

func TestCompiledProgramRejectsCorruptBytecode(t *testing.T) {
	u32 := func(v uint32) []byte {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], v)
		return b[:]
	}
	i32 := func(v int32) []byte {
		return u32(uint32(v)) // #nosec G115 -- signed relative jump offset encoding
	}

	cases := []struct {
		name     string
		bytecode []byte
		setup    func(*CompiledRule)
	}{
		{
			name:     "unsupported_opcode",
			bytecode: []byte{byte(OpPush), byte(OpHalt)},
		},
		{
			name:     "truncated_operand",
			bytecode: []byte{byte(OpPush32), 1, 2},
		},
		{
			name:     "string_literal_out_of_range",
			bytecode: append(append([]byte{byte(OpPushStr)}, u32(1)...), byte(OpHalt)),
		},
		{
			name:     "module_regex_out_of_range",
			bytecode: append(append([]byte{byte(OpPushRegex)}, u32(0)...), byte(OpHalt)),
		},
		{
			name:     "module_access_out_of_range",
			bytecode: append(append([]byte{byte(OpModuleLoad)}, u32(0)...), byte(OpHalt)),
		},
		{
			name:     "assertion_out_of_range",
			bytecode: append(append([]byte{byte(OpAssertFilesize)}, u32(0)...), byte(OpHalt)),
		},
		{
			name:     "eval_assertions_empty",
			bytecode: []byte{byte(OpEvalAssertions), byte(OpHalt)},
		},
		{
			name:     "memory_slot_out_of_range",
			bytecode: append(append([]byte{byte(OpPushM)}, u32(interpreterMemorySlotCount)...), byte(OpHalt)),
		},
		{
			name:     "builtin_call_zero_args",
			bytecode: append(append([]byte{byte(OpCall)}, u32(0)...), byte(OpHalt)),
		},
		{
			name:     "unknown_module_call",
			bytecode: append(append([]byte{byte(OpCall)}, u32(uint32(firstModuleFunctionID)<<builtinArgShift|1)...), byte(OpHalt)),
		},
		{
			name:     "backward_conditional_jump",
			bytecode: append(append([]byte{byte(OpPush8), 0, byte(OpJzP)}, i32(-7)...), byte(OpHalt)),
		},
		{
			name:     "out_of_bounds_jump",
			bytecode: append(append([]byte{byte(OpPush8), 0, byte(OpJzP)}, i32(50)...), byte(OpHalt)),
		},
		{
			name:     "unaligned_jump_into_operand",
			bytecode: append(append([]byte{byte(OpPush8), 0, byte(OpJzP)}, i32(1)...), byte(OpPush8), 1, byte(OpHalt)),
		},
		{
			name:     "rule_ref_out_of_range",
			bytecode: []byte{byte(OpPushRuleRef), 2, byte(OpHalt)},
		},
		{
			name:     "wide_rule_ref_out_of_range",
			bytecode: []byte{byte(OpPushRule32), 0, 1, 0, 0, byte(OpHalt)},
		},
		{
			name:     "wide_rule_ref_truncated",
			bytecode: []byte{byte(OpPushRule32), 0, 1, byte(OpHalt)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := &CompiledRule{Name: "r", Bytecode: tc.bytecode}
			if tc.setup != nil {
				tc.setup(rule)
			}
			program := &CompiledProgram{Rules: []*CompiledRule{rule}}
			if err := program.Validate(); err == nil {
				t.Fatal("Validate() succeeded, want error")
			}
		})
	}
}

func TestInterpreterRejectsCorruptLoopTargetAndStepLimit(t *testing.T) {
	t.Run("iter_next_backward_into_iter_start", func(t *testing.T) {
		var slot [4]byte
		binary.LittleEndian.PutUint32(slot[:], 0)
		// Push start=0, end=2; OpIterStartIntRange slot 0; Push8 0 (target BEFORE StartIP); OpIterNext
		bc := []byte{
			byte(OpPush8), 0,
			byte(OpPush8), 2,
			byte(OpIterStartIntRange), slot[0], slot[1], slot[2], slot[3],
			byte(OpPush8), 4, // points directly at OpIterStartIntRange (< StartIP=9)
			byte(OpIterNext),
			byte(OpHalt),
		}
		interp := NewInterpreter(bc)
		defer interp.Release()
		if err := interp.Execute(); err == nil {
			t.Fatal("Execute() succeeded, want invalid bytecode error")
		}
	})

	t.Run("step_limit_terminates_large_loop", func(t *testing.T) {
		program, err := NewCompiler().CompileSource(`
rule huge_loop {
	condition:
		for all i in (0..10000000) : (i >= 0)
}`)
		if err != nil {
			t.Fatalf("CompileSource() error = %v", err)
		}
		_, err = program.Scan([]byte("x"))
		if err == nil {
			t.Fatal("Scan() succeeded, want bytecode step limit error")
		}
	})
}

func TestCorruptedSerializedArtifactOneByteMutationSweep(t *testing.T) {
	pureSrc := `
rule r1 {
	strings:
		$a = "alpha" nocase
		$h = { 4D 5A [1-2] 90 }
		$r = /test[0-9]+/
	condition:
		uint16(0) == 0x5A4D and $a at 4 and ($h or $r) and for any i in (1..3) : (i == 2)
}
rule r2 {
	condition:
		r1 or for any of them : ($ at 0)
}
`
	moduleSrc := `
import "math"
` + pureSrc + `
rule r3 {
	condition:
		math.min(1, 2) == 1
}
`
	sample := []byte("MZ\x01\x00alpha\x90test123")
	for _, tc := range []struct {
		name      string
		src       string
		hasModule bool
	}{
		{name: "pure_rules", src: pureSrc, hasModule: false},
		{name: "module_rules", src: moduleSrc, hasModule: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			compiled, err := NewCompiler().CompileSource(tc.src)
			if err != nil {
				t.Fatalf("CompileSource() error = %v", err)
			}
			valid, err := compiled.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			for offset := range valid {
				for _, mask := range []byte{0x01, 0x80, 0xff} {
					mutated := slices.Clone(valid)
					mutated[offset] ^= mask

					func() {
						defer func() {
							if r := recover(); r != nil {
								t.Fatalf("panic at offset %d mask 0x%02x: %v", offset, mask, r)
							}
						}()
						prog, loadErr := UnmarshalCompiledProgram(mutated)
						if loadErr != nil {
							if !errors.Is(loadErr, ErrCorruptProgram) && (!tc.hasModule || !isModuleBindingError(loadErr)) {
								t.Fatalf("offset %d mask 0x%02x: error = %v, want ErrCorruptProgram", offset, mask, loadErr)
							}
							return
						}
						ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
						defer cancel()
						_, _ = prog.ScanWithContext(ctx, sample)
					}()
				}
			}
		})
	}
}

func isModuleBindingError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "is not registered") ||
		strings.Contains(msg, "incompatible signature") ||
		strings.Contains(msg, "incompatible schema")
}

func FuzzUnmarshalCompiledProgram(f *testing.F) {
	src := `
rule fuzz_seed {
	strings:
		$a = "MZ"
		$r = /abc[0-9]+/
		$h = { 41 ?? 43 }
	condition:
		$a at 0 and ($r or $h) and for any i in (1..2) : (i == 1)
}
`
	if compiled, err := NewCompiler().CompileSource(src); err == nil {
		if data, err := compiled.MarshalBinary(); err == nil {
			f.Add(data)
		}
	}
	f.Add([]byte("GOYARA\x00\x00\x13corrupt"))

	sample := []byte("MZtest abc123 A\x01C")
	f.Fuzz(func(t *testing.T, data []byte) {
		prog, err := UnmarshalCompiledProgram(data)
		if err != nil {
			if !errors.Is(err, ErrCorruptProgram) && !isModuleBindingError(err) {
				t.Fatalf("UnmarshalCompiledProgram() error = %v, want ErrCorruptProgram", err)
			}
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		_, _ = prog.ScanWithContext(ctx, sample)
	})
}

func TestRegexMetadataRejectedByBothLoaders(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule sample { strings: $r = /[ab][cd]/ condition: $r }`)
	for _, legacy := range []bool{false, true} {
		payload, err := serializeDeterministicProgram(program)
		if err != nil {
			t.Fatal(err)
		}
		rule := &payload.Rules[0]
		// An inconsistent count is sufficient to exercise the loader boundary.
		rule.RegexPatternEntries[0].Value.ByteSetCount++
		version := compiledProgramVersion
		if legacy {
			version = 19
			rule.RegexPatterns = map[string]serializedRegexPattern{"$r": rule.RegexPatternEntries[0].Value}
			rule.RegexPatternEntries = nil
		}
		var encoded bytes.Buffer
		encoded.WriteString(compiledProgramMagic)
		if err := binary.Write(&encoded, binary.BigEndian, version); err != nil {
			t.Fatal(err)
		}
		if err := gob.NewEncoder(&encoded).Encode(payload); err != nil {
			t.Fatal(err)
		}
		if _, err := UnmarshalCompiledProgram(encoded.Bytes()); !errors.Is(err, ErrCorruptProgram) {
			t.Fatalf("format %d UnmarshalCompiledProgram: %v", version, err)
		}
		if _, err := ReadCompiledProgram(bytes.NewReader(encoded.Bytes())); !errors.Is(err, ErrCorruptProgram) {
			t.Fatalf("format %d ReadCompiledProgram: %v", version, err)
		}
	}
}
