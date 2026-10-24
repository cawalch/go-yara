package compiler

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
)

func TestExpandedModuleSmoke(t *testing.T) {
	source := `import "hash" import "math" import "string" import "time"
 rule expanded { condition:
 hash.crc32("abc") == 891568578 and hash.checksum32("abc") == 294 and
 math.count(97, 0, filesize) == 1 and math.mode(0, filesize) == 97 and
 math.to_number(true) == 1 and math.to_string(255, 16) == "ff" and
 string.length("a\x00b") == 3 and string.to_int("0xff") == 255 and time.now() > 0
 }`
	c := NewCompiler()
	program, err := c.CompileSource(source)
	if err != nil {
		t.Fatalf("%v: %+v", err, c.GetErrors())
	}
	result, err := program.Scan([]byte("abc"))
	if err != nil {
		t.Fatalf("%v: %+v", err, c.GetErrors())
	}
	if !result.RuleResults["expanded"] {
		t.Fatal("expanded module rule did not match")
	}
}

func TestModuleRangeCacheAcrossRulesAndScans(t *testing.T) {
	var source strings.Builder
	source.WriteString(`import "hash" import "math" `)
	for index := 0; index < 100; index++ {
		fmt.Fprintf(&source, `rule r%d { condition: hash.sha256(0, filesize) == "%s" and math.entropy(0, filesize) == 0.0 } `, index, fmt.Sprintf("%x", sha256.Sum256([]byte("AAAA"))))
	}
	program, err := NewCompiler().CompileSource(source.String())
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]int{}
	// All rules share the function table. Count actual evaluations, not just
	// cache occupancy, so a lookup that still computes the digest cannot pass.
	for id, function := range program.Rules[0].ModuleFunctions {
		name := program.Rules[0].ModuleNames[id]
		evaluate := function.Evaluate
		function.Evaluate = func(ctx ModuleContext, args []ModuleValue) (ModuleValue, error) {
			calls[name]++
			return evaluate(ctx, args)
		}
		program.Rules[0].ModuleFunctions[id] = function
	}
	scanner := program.NewScanner()
	defer scanner.Close()
	for _, data := range [][]byte{[]byte("AAAA"), []byte("AAAA"), []byte("BBBB")} {
		clear(calls)
		result, err := scanner.Scan(data)
		if err != nil {
			t.Fatal(err)
		}
		want := 100
		if data[0] == 'B' {
			want = 0
		}
		if len(result.MatchedRules) != want {
			t.Fatalf("matched %d rules, want %d", len(result.MatchedRules), want)
		}
		if calls["hash.sha256"] != 1 {
			t.Fatalf("SHA-256 evaluated %d times", calls["hash.sha256"])
		}
		if want == 100 && calls["math.entropy"] != 1 {
			t.Fatalf("entropy evaluated %d times", calls["math.entropy"])
		}
	}
}

func TestModuleCacheCustomFunctionsRemainUncached(t *testing.T) {
	calls := 0
	module := Module{Name: "hash", Functions: map[string]ModuleFunction{
		"sha256": {Signatures: []ModuleSignature{{Arguments: []ModuleValueType{ModuleInteger, ModuleInteger}}}, ReturnType: ModuleString,
			Evaluate: func(ctx ModuleContext, _ []ModuleValue) (ModuleValue, error) {
				calls++
				return StringValue(ctx.RuleName), nil
			}},
	}}
	program, err := NewCompiler(WithModule(module)).CompileSource(`import "hash"
 rule a { condition: hash.sha256(0, 1) == "a" }
 rule b { condition: hash.sha256(0, 1) == "b" }`)
	if err != nil {
		t.Fatal(err)
	}
	result, err := program.Scan([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.MatchedRules) != 2 || calls != 2 {
		t.Fatalf("matched %d, calls %d", len(result.MatchedRules), calls)
	}
}

func TestModuleCacheHitAllocations(t *testing.T) {
	function := mathModule().Functions["entropy"]
	interp := NewInterpreter(nil)
	defer interp.Release()
	var cache moduleCallCache
	interp.matchContext = &MatchContext{Data: []byte("abc"), moduleCache: &cache}
	interp.currentCompiledRule = &CompiledRule{ModuleNames: map[builtinFunction]string{128: "math.entropy"}}
	args := []Value{{Type: ValueTypeInt}, {Type: ValueTypeInt, IntVal: 3}}
	allocations := testing.AllocsPerRun(100, func() {
		interp.stack = interp.stack[:0]
		if err := interp.executeModuleCall(128, function, args); err != nil {
			panic(err)
		}
	})
	if allocations != 0 {
		t.Fatalf("cache hits allocate: %g", allocations)
	}
}

func TestModuleCacheBoundedAndReset(t *testing.T) {
	var cache moduleCallCache
	for offset := int64(0); offset < 100; offset++ {
		key, _ := moduleCallKey("hash.crc32", []ModuleValue{IntegerValue(offset), IntegerValue(1)})
		cache.put(key, IntegerValue(offset))
	}
	if cache.count != len(cache.entries) {
		t.Fatal("cache grew beyond its bound")
	}
	key, _ := moduleCallKey("hash.crc32", []ModuleValue{IntegerValue(0), IntegerValue(1)})
	if _, ok := cache.lookup(key); !ok {
		t.Fatal("frequent early call was evicted")
	}
	cache.reset()
	if _, ok := cache.lookup(key); ok {
		t.Fatal("cache retained an old scan result")
	}
}

func TestExpandedModulesSerializationAndBlockScans(t *testing.T) {
	const source = `import "hash" import "math" import "string" import "time"
 rule probe { condition: hash.crc32(100, 3) == 891568578 and math.count(97, 100, 3) == 1 and string.to_int("42") == 42 and time.now() > 0 }`
	program, err := NewCompiler().CompileSource(source)
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
	for _, p := range []*CompiledProgram{program, loaded} {
		scanner := p.NewScanner()
		for _, data := range []string{"abc", "xyz", "abc"} {
			matches, err := scanner.MatchingRulesInBlock(MemoryBlock{Base: 100, Data: []byte(data)}, 1000)
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if data == "abc" {
				want = 1
			}
			if len(matches) != want {
				t.Fatalf("matched %d, want %d", len(matches), want)
			}
		}
		scanner.Close()
	}
}

func TestModuleRangeBlocks(t *testing.T) {
	function := hashModule().Functions["crc32"]
	backing := []byte("abcXYZ")
	cases := []struct {
		name   string
		blocks []MemoryBlock
		want   ModuleValue
	}{
		{"contiguous", []MemoryBlock{{Base: 100, Data: backing[:3]}, {Base: 103, Data: []byte("def")}}, IntegerValue(1267612143)},
		{"gap", []MemoryBlock{{Base: 100, Data: backing[:3]}, {Base: 104, Data: []byte("def")}}, ModuleValue{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := function.Evaluate(ModuleContext{Blocks: tc.blocks}, []ModuleValue{IntegerValue(100), IntegerValue(6)})
			if err != nil || got != tc.want {
				t.Fatalf("got %+v, %v; want %+v", got, err, tc.want)
			}
			if string(backing) != "abcXYZ" {
				t.Fatal("module modified caller block capacity")
			}
		})
	}
}

func TestSHA512Extension(t *testing.T) {
	sum := sha512.Sum512([]byte("abc"))
	source := fmt.Sprintf(`import "hash" rule probe { condition: hash.sha512("abc") == "%x" and hash.sha512(0, filesize) == "%x" }`, sum, sum)
	program, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	result, err := program.Scan([]byte("abc"))
	if err != nil || !result.RuleResults["probe"] {
		t.Fatalf("result %+v, error %v", result, err)
	}
}

func BenchmarkRepeatedModuleRanges(b *testing.B) {
	for _, cached := range []bool{false, true} {
		b.Run(fmt.Sprintf("cache=%t", cached), func(b *testing.B) {
			var source strings.Builder
			source.WriteString(`import "hash" import "math" `)
			for index := 0; index < 100; index++ {
				fmt.Fprintf(&source, `rule r%d { condition: hash.sha256(0, filesize) == "never" or math.entropy(0, filesize) > 8.0 } `, index)
			}
			program, err := NewCompiler().CompileSource(source.String())
			if err != nil {
				b.Fatal(err)
			}
			for id, function := range program.Rules[0].ModuleFunctions {
				function.Cacheable = cached && function.Cacheable
				program.Rules[0].ModuleFunctions[id] = function
			}
			scanner := program.NewScanner(WithoutMatches(), WithoutRuleResults())
			defer scanner.Close()
			data := bytes.Repeat([]byte("abcdefgh"), 10*1024*1024/8)
			if _, err := scanner.Scan(data); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := scanner.Scan(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestExpandedModuleArgumentValidation(t *testing.T) {
	for _, condition := range []string{
		`time.now(1) > 0`, `string.length(1) > 0`, `string.to_int("1", 2.0) > 0`,
		`math.min(1.0, 2.0) > 0`, `math.in_range(1, 0, 2)`, `math.to_number(1) == 1`,
		`math.count() > 0`, `hash.crc32() > 0`,
	} {
		t.Run(condition, func(t *testing.T) {
			_, err := NewCompiler().CompileSource(`import "hash" import "math" import "time" import "string" rule probe { condition: ` + condition + ` }`)
			if err == nil {
				t.Fatal("invalid signature compiled")
			}
		})
	}
}

func TestModuleCacheConcurrentScanners(t *testing.T) {
	program, err := NewCompiler().CompileSource(`import "hash"
 rule a { condition: hash.crc32(0, filesize) == hash.crc32("abc") }
 rule b { condition: hash.crc32(0, filesize) == hash.crc32("abc") }`)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 8; index++ {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			t.Parallel()
			scanner := program.NewScanner()
			defer scanner.Close()
			for count := 0; count < 20; count++ {
				data, want := []byte("abc"), 2
				if (count+index)%2 == 0 {
					data, want = []byte("xyz"), 0
				}
				result, err := scanner.Scan(data)
				if err != nil || len(result.MatchedRules) != want {
					t.Fatalf("result %v, error %v, want %d matches", result, err, want)
				}
			}
		})
	}
}

func TestModuleCachePreservesFloatSign(t *testing.T) {
	function := ModuleFunction{Signatures: []ModuleSignature{{Arguments: []ModuleValueType{ModuleFloat}}}, ReturnType: ModuleBoolean, Cacheable: true,
		Evaluate: func(_ ModuleContext, args []ModuleValue) (ModuleValue, error) {
			return BooleanValue(math.Signbit(args[0].Float)), nil
		},
	}
	interp := NewInterpreter(nil)
	defer interp.Release()
	var cache moduleCallCache
	interp.matchContext = &MatchContext{moduleCache: &cache}
	interp.currentCompiledRule = &CompiledRule{ModuleNames: map[builtinFunction]string{128: "custom.signbit"}}
	for _, value := range []float64{0, math.Copysign(0, -1), 0} {
		interp.stack = interp.stack[:0]
		if err := interp.executeModuleCall(128, function, []Value{{Type: ValueTypeDouble, DoubleVal: value}}); err != nil {
			t.Fatal(err)
		}
		if interp.stack[0].IntVal != boolToInt(math.Signbit(value)) {
			t.Fatal("cache conflated positive and negative zero")
		}
	}
}
