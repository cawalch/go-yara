package compiler

import (
	"context"
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestMathNumericOverloads(t *testing.T) {
	for _, condition := range []string{
		`math.min(-1,1) == 1 and math.max(-1,1) == -1`,
		`math.min(-1.5,2.5) == -1.5 and math.max(-1.5,2.5) == 2.5`,
		`math.min(-1,2.5) == -1.0 and math.max(-1.5,2) == 2.0`,
		`math.max(math.min(-1.5,2.5),3.5) + 0.5 == 4.0`,
		`math.min(1.5,2.5) * 2 == 3.0`,
	} {
		c := NewCompiler()
		program, err := c.CompileSourceWithContext(context.Background(), `import "math" rule r {condition:`+condition+`}`)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := program.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := UnmarshalCompiledProgram(encoded)
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range []*CompiledProgram{program, loaded} {
			if yes, err := candidate.Matches(nil); err != nil || !yes {
				t.Fatalf("%s: %t %v", condition, yes, err)
			}
		}
	}
	for _, name := range []string{"min", "max"} {
		function := mathModule().Functions[name]
		got, err := function.Evaluate(ModuleContext{}, []ModuleValue{FloatValue(math.NaN()), FloatValue(1)})
		if err != nil || !math.IsNaN(got.Float) {
			t.Fatalf("%s NaN: %v %v", name, got, err)
		}
	}
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), `import "math" external x external y rule r {condition: math.min(x,y) > 0}`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := program.NewScanner(WithExternalVariables(map[string]any{"x": 1, "y": 2}))
	defer scanner.Close()
	if yes, err := scanner.Matches(nil); err != nil || !yes {
		t.Fatalf("legacy external integers: %t %v", yes, err)
	}
}

func TestModuleOverloadSignatureCompatibility(t *testing.T) {
	function := mathModule().Functions["min"]
	old := serializedModuleFunction{Signatures: [][]ModuleValueType{{ModuleInteger, ModuleInteger}}, ReturnType: ModuleInteger}
	if !moduleFunctionCompatible(function, old) {
		t.Fatal("old integer signature rejected")
	}
	current := serializeModuleFunction(function)
	current.ReturnTypes[1] = ModuleInteger
	if moduleFunctionCompatible(function, current) {
		t.Fatal("changed overload result accepted")
	}
}

func TestDuplicateHashRulesDoNotAddScanAllocations(t *testing.T) {
	allocations := func(count int) float64 {
		var source strings.Builder
		source.WriteString(`import "hash" `)
		for index := 0; index < count; index++ {
			fmt.Fprintf(&source, `rule r%d {condition:hash.sha256(0,filesize)=="never"} `, index)
		}
		program, err := NewCompiler().CompileSourceWithContext(context.Background(), source.String())
		if err != nil {
			t.Fatal(err)
		}
		scanner := program.NewScanner(WithoutMatches(), WithoutRuleResults())
		defer scanner.Close()
		data := []byte("clean")
		return testing.AllocsPerRun(100, func() {
			if yes, err := scanner.Matches(data); err != nil || yes {
				panic("unexpected match")
			}
		})
	}
	single, many := allocations(1), allocations(100)
	if many != single {
		t.Fatalf("duplicate rules add allocations: one=%g, hundred=%g", single, many)
	}
	t.Logf("one uncached digest plus cache hits: %g allocations per scan at either rule count", many)
}

func TestSHA512KnownAnswer(t *testing.T) {
	const digest = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
	function := hashModule().Functions["sha512"]
	value, err := function.Evaluate(ModuleContext{}, []ModuleValue{StringValue("abc")})
	if err != nil || value.Type != ModuleString || value.String != digest {
		t.Fatalf("SHA-512 known answer: %v %v", value, err)
	}
}
