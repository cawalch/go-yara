package compiler

import (
	"context"
	"crypto/md5" // #nosec G501 -- testing hash.md5 output against standard MD5
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestModuleLoopVariableDoesNotShadowAfterLoop(t *testing.T) {
	custom := Module{
		Name: "custom",
		Schema: &ModuleSchema{Fields: map[string]ModuleField{
			"items": {
				Kind: ModuleArray,
				Element: &ModuleField{
					Kind:   ModuleStruct,
					Struct: &ModuleSchema{Fields: map[string]ModuleField{"x": {Kind: ModuleInteger}}},
				},
			},
		}},
	}
	source := `
import "custom"
import "pe"
rule r {
	condition:
		(for any pe in custom.items : (pe.x == 1)) and pe.is_pe == 0
}`
	program, err := NewCompiler(WithModule(custom)).CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	data := map[string]any{"items": []map[string]any{{"x": 1}}}
	scanner := program.NewScanner(WithModuleData("custom", data))
	defer scanner.Close()
	if yes, err := scanner.Matches([]byte("plain")); err != nil || !yes {
		t.Fatalf("scan failed: matched=%t err=%v", yes, err)
	}

	// Verify nested loops and sibling integer loops also restore variable scopes and slots.
	nestedSource := `
import "custom"
import "pe"
rule nested {
	condition:
		(for any outer in custom.items : (
			(for any pe in custom.items : (pe.x == outer.x)) and pe.is_pe == 0
		)) and (for any pe in (1..2) : (pe == 1)) and pe.is_pe == 0
}`
	nestedProgram, err := NewCompiler(WithModule(custom)).CompileSourceWithContext(context.Background(), nestedSource)
	if err != nil {
		t.Fatalf("nested compile failed: %v", err)
	}
	nestedScanner := nestedProgram.NewScanner(WithModuleData("custom", data))
	defer nestedScanner.Close()
	if yes, err := nestedScanner.Matches([]byte("plain")); err != nil || !yes {
		t.Fatalf("nested scan failed: matched=%t err=%v", yes, err)
	}
}

func TestModuleOverloadExactMatchPrecedesCoercion(t *testing.T) {
	var called string
	custom := Module{
		Name: "over",
		Functions: map[string]ModuleFunction{
			"fn": {
				ReturnType: ModuleString,
				Signatures: []ModuleSignature{
					{Arguments: []ModuleValueType{ModuleFloat}},
					{Arguments: []ModuleValueType{ModuleInteger}},
				},
				Evaluate: func(_ ModuleContext, args []ModuleValue) (ModuleValue, error) {
					called = args[0].Type.String()
					if args[0].Type == ModuleInteger {
						return StringValue(fmt.Sprintf("int:%d", args[0].Integer)), nil
					}
					return StringValue(fmt.Sprintf("float:%.1f", args[0].Float)), nil
				},
			},
			"ret": {
				ReturnType: ModuleInteger,
				Signatures: []ModuleSignature{
					{Arguments: []ModuleValueType{ModuleFloat}, ReturnType: ModuleFloat},
					{Arguments: []ModuleValueType{ModuleInteger}},
				},
				Evaluate: func(_ ModuleContext, args []ModuleValue) (ModuleValue, error) {
					if args[0].Type == ModuleFloat {
						return FloatValue(args[0].Float + 0.5), nil
					}
					return IntegerValue(args[0].Integer), nil
				},
			},
		},
	}
	source := `
import "over"
rule r {
	condition: over.fn(42) == "int:42" and over.fn(42.5) == "float:42.5" and over.ret(42) == 42 and over.ret(1.0) == 1.5
}`
	program, err := NewCompiler(WithModule(custom)).CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	if yes, err := program.Matches(nil); err != nil || !yes {
		t.Fatalf("overload match failed: matched=%t err=%v called=%q", yes, err, called)
	}

	// Coercion still works when only a float signature exists.
	args := []ModuleValue{IntegerValue(7)}
	if !normalizeModuleArguments([]ModuleSignature{{Arguments: []ModuleValueType{ModuleFloat}}}, args) {
		t.Fatal("expected coercion fallback to float")
	}
	if args[0].Type != ModuleFloat || args[0].Float != 7.0 {
		t.Fatalf("unexpected coerced arg: %+v", args[0])
	}

	// Exact integer match is preferred over boolean coercion too.
	argsBool := []ModuleValue{IntegerValue(1)}
	if !normalizeModuleArguments([]ModuleSignature{
		{Arguments: []ModuleValueType{ModuleBoolean}},
		{Arguments: []ModuleValueType{ModuleInteger}},
	}, argsBool) {
		t.Fatal("expected exact integer match")
	}
	if argsBool[0].Type != ModuleInteger {
		t.Fatalf("expected ModuleInteger without boolean coercion, got %s", argsBool[0].Type)
	}

	// Coercion to boolean still works when only boolean signature exists.
	argsBoolOnly := []ModuleValue{IntegerValue(1)}
	if !normalizeModuleArguments([]ModuleSignature{{Arguments: []ModuleValueType{ModuleBoolean}}}, argsBoolOnly) {
		t.Fatal("expected boolean coercion fallback")
	}
	if argsBoolOnly[0].Type != ModuleBoolean || !argsBoolOnly[0].Boolean {
		t.Fatalf("unexpected boolean coerced arg: %+v", argsBoolOnly[0])
	}
}

func TestModuleDataBindingFixes(t *testing.T) {
	schema := &ModuleSchema{Fields: map[string]ModuleField{
		"header": {
			Kind:   ModuleStruct,
			Struct: &ModuleSchema{Fields: map[string]ModuleField{"val": {Kind: ModuleInteger}}},
		},
		"foo":     {Kind: ModuleString},
		"embed":   {Kind: ModuleInteger},
		"ptrval":  {Kind: ModuleString},
		"absent":  {Kind: ModuleInteger},
		"ignored": {Kind: ModuleString},
	}}
	custom := Module{Name: "custom", Schema: schema}
	program, err := NewCompiler(WithModule(custom)).CompileSourceWithContext(
		context.Background(),
		`import "custom"
rule r {
	condition:
		custom.header.val == 7 and
		custom.foo == "tagged" and
		custom.embed == 11 and
		custom.ptrval == "fromptr" and
		not defined custom.absent and
		not defined custom.ignored
}`,
	)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	// 1. SetModuleData clears earlier WithModuleData error.
	scanner := program.NewScanner(WithModuleData("custom", 123))
	defer scanner.Close()
	if _, err := scanner.Matches(nil); err == nil {
		t.Fatal("expected initial WithModuleData error")
	}

	// 2. Passing IntegerValue(5) or *ModuleValue for a ModuleStruct field returns an error.
	badStructPtr := IntegerValue(5)
	for _, badHeader := range []any{IntegerValue(5), &badStructPtr} {
		err := scanner.SetModuleData("custom", map[string]any{"header": badHeader})
		if err == nil {
			t.Fatalf("expected error passing %T for ModuleStruct field", badHeader)
		}
	}

	// 3 & 4. Explicit yara:"foo" wins over earlier untagged Foo, and embedded structs (value, non-nil ptr, nil ptr) work.
	type EmbeddedVal struct {
		Embed int
	}
	type EmbeddedPtr struct {
		PtrVal string
	}
	type EmbeddedNil struct {
		Absent int
	}
	type Header struct {
		Val int
	}
	type Payload struct {
		Header Header
		Foo    string
		Bar    string `yara:"foo"`
		EmbeddedVal
		*EmbeddedPtr
		*EmbeddedNil
		Ignored string `yara:"-"`
	}
	valid := Payload{
		Header:      Header{Val: 7},
		Foo:         "untagged",
		Bar:         "tagged",
		EmbeddedVal: EmbeddedVal{Embed: 11},
		EmbeddedPtr: &EmbeddedPtr{PtrVal: "fromptr"},
		EmbeddedNil: nil,
		Ignored:     "hidden",
	}
	if err := scanner.SetModuleData("custom", valid); err != nil {
		t.Fatalf("SetModuleData failed: %v", err)
	}
	if yes, err := scanner.Matches(nil); err != nil || !yes {
		t.Fatalf("expected scan to match after SetModuleData recovery, got matched=%t err=%v", yes, err)
	}
}

func TestMathModeEmptyRangeAndHashEmptyBlock(t *testing.T) {
	// Match libyara parity: math.mode(0, 0) on non-empty input returns 0,
	// while math.mode(0, 0) on empty input is undefined.
	mathProg, err := NewCompiler().CompileSourceWithContext(
		context.Background(),
		`import "math"
rule zero_len_nonempty { condition: math.mode(0, 0) == 0 }
rule zero_len_undef { condition: not defined math.mode(0, 0) }`,
	)
	if err != nil {
		t.Fatalf("compile math failed: %v", err)
	}
	resNonEmpty, err := mathProg.Scan([]byte("abc"))
	if err != nil || !resNonEmpty.RuleResults["zero_len_nonempty"] {
		t.Fatalf("math.mode(0, 0) on non-empty input did not return 0: res=%v err=%v", resNonEmpty, err)
	}
	resEmpty, err := mathProg.Scan(nil)
	if err != nil || !resEmpty.RuleResults["zero_len_undef"] {
		t.Fatalf("math.mode(0, 0) on empty input did not evaluate to undefined: res=%v err=%v", resEmpty, err)
	}

	// hash.md5(0, 8) across blocks [0,4), [4,4), [4,8) must succeed.
	expected := fmt.Sprintf("%x", md5.Sum([]byte("abcdefgh"))) // #nosec G401 -- standard MD5 check
	hashFn := hashModule().Functions["md5"]
	blocks := []MemoryBlock{
		{Base: 0, Data: []byte("abcd")},
		{Base: 4, Data: []byte{}},
		{Base: 4, Data: []byte("efgh")},
	}
	got, err := hashFn.Evaluate(ModuleContext{Blocks: blocks}, []ModuleValue{IntegerValue(0), IntegerValue(8)})
	if err != nil {
		t.Fatalf("hash.md5 across empty block failed: %v", err)
	}
	if got.Type != ModuleString || got.String != expected {
		t.Fatalf("hash.md5 got %+v, want %q", got, expected)
	}
}

func TestModuleRegexAndSchemaNaNAndPELoad(t *testing.T) {
	if _, err := CompileModuleRegex("/foo/bar/i"); err == nil {
		t.Fatal("CompileModuleRegex accepted unescaped '/' before closing delimiter")
	}
	for _, tc := range []struct {
		literal string
		input   string
		want    bool
	}{
		{`/foo\/bar/i`, "FOO/BAR", true},
		{`/foo[/]bar/i`, "FOO/BAR", true},
		{`/[^]/]/i`, "x", true},
		{`/[^]/]/i`, "/", false},
	} {
		re, err := CompileModuleRegex(tc.literal)
		if err != nil {
			t.Fatalf("CompileModuleRegex(%q) unexpected error: %v", tc.literal, err)
		}
		matched, err := re.MatchString(tc.input)
		if err != nil || matched != tc.want {
			t.Fatalf("CompileModuleRegex(%q).MatchString(%q) = %t, %v; want %t", tc.literal, tc.input, matched, err, tc.want)
		}
	}

	// NaN constant in module schema must be rejected.
	nanVal := FloatValue(math.NaN())
	nanMod := Module{
		Name: "nanmod",
		Schema: &ModuleSchema{Fields: map[string]ModuleField{
			"bad": {Kind: ModuleFloat, Constant: &nanVal},
		}},
	}
	_, err := NewCompiler(WithModule(nanMod)).CompileSourceWithContext(
		context.Background(),
		`import "nanmod" rule r { condition: not defined nanmod.bad }`,
	)
	if err == nil || !strings.Contains(err.Error(), "NaN") {
		t.Fatalf("expected NaN schema constant error, got %v", err)
	}
}
