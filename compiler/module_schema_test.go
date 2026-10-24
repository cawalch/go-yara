package compiler

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func telemetryModule() Module {
	flag := IntegerValue(42)
	return Module{Name: "telemetry", Schema: &ModuleSchema{Fields: map[string]ModuleField{
		"FLAG":   {Kind: ModuleInteger, Constant: &flag},
		"header": {Kind: ModuleStruct, Struct: &ModuleSchema{Fields: map[string]ModuleField{"type": {Kind: ModuleInteger}}}},
		"items": {Kind: ModuleArray, Element: &ModuleField{Kind: ModuleStruct, Struct: &ModuleSchema{Fields: map[string]ModuleField{
			"name": {Kind: ModuleString}, "metric": {Kind: ModuleFloat}, "val": {Kind: ModuleInteger},
		}}}},
		"env":     {Kind: ModuleDictionary, Element: &ModuleField{Kind: ModuleString}},
		"numbers": {Kind: ModuleArray, Element: &ModuleField{Kind: ModuleInteger}},
	}}}
}

func telemetryData() map[string]any {
	return map[string]any{
		"header":  map[string]any{"type": 42},
		"items":   []map[string]any{{"name": "code", "metric": 0.95, "val": 11}, {"name": "data", "metric": 0.2, "val": 2}},
		"env":     map[string]string{"PATH": "/usr/bin", "USER": "analyst"},
		"numbers": []int{1, 2, 3},
	}
}

func compileTelemetry(t testing.TB, condition string) *CompiledProgram {
	t.Helper()
	c := NewCompiler(WithModule(telemetryModule()))
	program, err := c.CompileSourceWithContext(context.Background(), `import "telemetry" rule r { condition: `+condition+` }`)
	if err != nil {
		t.Fatalf("compile %s: %v (%v)", condition, err, c.GetErrors())
	}
	return program
}

func TestStructuredModuleAccess(t *testing.T) {
	conditions := []string{
		`telemetry.header.type == 42`, `telemetry.FLAG == 42`,
		`telemetry.items[0].val > 10`, `telemetry.items[1].name == "data"`,
		`telemetry.items[0].metric > 0.9`, `telemetry.items[0].metric + 0.1 > 1.0`,
		`telemetry.env["PATH"] contains "bin"`, `telemetry.env["USER"] matches /analyst/`,
		`not defined telemetry.env["MISSING"]`, `not defined telemetry.items[9].name`,
		`not defined telemetry.items[-1]`, `not defined telemetry.items[0x7fffffffffffffff]`,
		`telemetry.numbers[telemetry.items[1].val] == 3`,
		`for any item in telemetry.items : (item.metric > 0.9)`,
		`for all item in telemetry.items : (item.val > 0)`,
		`for none item in telemetry.items : (item.val < 0)`,
		`for 2 item in telemetry.items : (item.val > 0)`,
		`for any key,value in telemetry.env : (key == "PATH" and value contains "bin")`,
		`for any item in telemetry.items : (for any n in telemetry.numbers : (n == item.val))`,
	}
	for _, condition := range conditions {
		t.Run(condition, func(t *testing.T) {
			program := compileTelemetry(t, condition)
			scanner := program.NewScanner(WithModuleData("telemetry", telemetryData()))
			defer scanner.Close()
			for range 2 {
				result, err := scanner.Scan(nil)
				if err != nil || len(result.MatchedRules) != 1 {
					t.Fatalf("result=%v err=%v", result, err)
				}
				yes, err := scanner.Matches(nil)
				if err != nil || !yes {
					t.Fatalf("Matches=%t err=%v", yes, err)
				}
			}
		})
	}
}

func TestStructuredModuleDiagnostics(t *testing.T) {
	for _, condition := range []string{
		`telemetry.items == telemetry.items`, `telemetry.header and true`, `for any item in telemetry.items : (item)`, `for any x in (1..2) : (telemetry.items)`,
		`telemetry.header.missing == 1`, `telemetry.items["bad"].val == 1`, `telemetry.env[1] == "x"`,
		`telemetry.header[0] == 1`, `telemetry.items[0].val.bad == 1`,
		`for any item in telemetry.header : (true)`, `for any key,value in telemetry.items : (true)`,
		`for any item in telemetry.env : (true)`, `for any item in telemetry.items : (item.missing == 1)`,
	} {
		t.Run(condition, func(t *testing.T) {
			c := NewCompiler(WithModule(telemetryModule()))
			_, err := c.CompileSourceWithContext(context.Background(), `import "telemetry" rule r { condition: `+condition+` }`)
			if err == nil {
				t.Fatal("invalid access accepted")
			}
			if !strings.Contains(err.Error(), "semantic") {
				t.Fatalf("expected semantic diagnostic: %v", err)
			}
		})
	}
}

func TestStructuredModuleSnapshot(t *testing.T) {
	program := compileTelemetry(t, `telemetry.items[0].val == 11`)
	data := telemetryData()
	scanner := program.NewScanner(WithModuleData("telemetry", data))
	defer scanner.Close()
	data["items"].([]map[string]any)[0]["val"] = 0
	yes, err := scanner.Matches(nil)
	if err != nil || !yes {
		t.Fatalf("caller mutation affected snapshot: %t %v", yes, err)
	}
	if err := scanner.SetModuleData("telemetry", data); err != nil {
		t.Fatal(err)
	}
	yes, err = scanner.Matches(nil)
	if err != nil || yes {
		t.Fatalf("replacement not applied: %t %v", yes, err)
	}
}

func TestStructuredModuleSerialization(t *testing.T) {
	original := compileTelemetry(t, `telemetry.FLAG == 42 and for any item in telemetry.items : (item.metric > 0.9 and item.name == "code")`)
	encoded, err := original.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	scanner := loaded.NewScanner(WithModuleData("telemetry", telemetryData()))
	defer scanner.Close()
	if yes, err := scanner.Matches(nil); err != nil || !yes {
		t.Fatalf("loaded result: %t %v", yes, err)
	}
	missing := loaded.NewScanner()
	defer missing.Close()
	if yes, err := missing.Matches(nil); err != nil || yes {
		t.Fatalf("runtime data unexpectedly persisted: %t %v", yes, err)
	}
	mismatch := telemetryModule()
	mismatch.Schema.Fields["FLAG"] = ModuleField{Kind: ModuleString}
	if _, err := UnmarshalCompiledProgram(encoded, mismatch); err == nil {
		t.Fatal("mismatched schema accepted")
	}
	if _, err := UnmarshalCompiledProgram(encoded, telemetryModule()); err != nil {
		t.Fatal(err)
	}
}

func TestStructuredModuleShortCircuit(t *testing.T) {
	for _, tc := range []struct {
		condition string
		want      bool
	}{
		{`for any item in telemetry.items : (item.val > 10)`, true},
		{`for all item in telemetry.items : (item.val < 10)`, false},
		{`for none item in telemetry.items : (item.val > 10)`, false},
		{`for 1 item in telemetry.items : (item.val > 10)`, true},
		{`for 0 item in telemetry.items : (item.val > 10)`, true},
	} {
		t.Run(tc.condition, func(t *testing.T) {
			scanner := compileTelemetry(t, tc.condition).NewScanner(WithModuleData("telemetry", telemetryData()), WithItersmax(1))
			defer scanner.Close()
			if yes, err := scanner.Matches(nil); err != nil || yes != tc.want {
				t.Fatalf("got %t %v", yes, err)
			}
		})
	}
}

func TestStructuredModuleLoopShadowing(t *testing.T) {
	for _, condition := range []string{
		`for any telemetry in (1..2) : (telemetry == 1)`,
		`for any item in telemetry.items : ((for any item in (1..2) : (item == 1)) and item.metric > 0.9)`,
		`for any item in telemetry.items : ((for any item in ("text") : (item == "text")) and item.metric > 0.9)`,
		`for any item in telemetry.items : ((for any item in telemetry.numbers : (item == 1)) and item.metric > 0.9)`,
	} {
		scanner := compileTelemetry(t, condition).NewScanner(WithModuleData("telemetry", telemetryData()))
		yes, err := scanner.Matches(nil)
		scanner.Close()
		if err != nil || !yes {
			t.Fatalf("%s: %t %v", condition, yes, err)
		}
	}
}

func TestStructuredModuleGoStructAndBindingErrors(t *testing.T) {
	type header struct {
		Code uint64 `yara:"type"`
	}
	data := struct {
		Header  *header
		Numbers []int
	}{Header: &header{42}, Numbers: []int{1, 2, 3}}
	scanner := compileTelemetry(t, `telemetry.header.type == 42 and telemetry.numbers[2] == 3 and not defined telemetry.items`).NewScanner(WithModuleData("telemetry", data))
	defer scanner.Close()
	if yes, err := scanner.Matches(nil); err != nil || !yes {
		t.Fatalf("struct binding: %t %v", yes, err)
	}
	var cycle any
	cycle = &cycle
	for _, bad := range []any{42, map[string]any{"header": map[string]any{"type": uint64(1) << 63}}, map[string]any{"numbers": []string{"bad"}}, cycle} {
		if err := scanner.SetModuleData("telemetry", bad); err == nil {
			t.Fatal("invalid data accepted")
		}
	}
	if yes, err := scanner.Matches(nil); err != nil || !yes {
		t.Fatalf("failed binding replaced snapshot: %t %v", yes, err)
	}
	if err := scanner.SetModuleData("unknown", nil); err == nil {
		t.Fatal("unknown module accepted")
	}
	invalid := compileTelemetry(t, `telemetry.header.type == 42`).NewScanner(WithModuleData("telemetry", 42))
	defer invalid.Close()
	if _, err := invalid.Scan(nil); err == nil {
		t.Fatal("option binding error lost")
	}
}

func TestStructuredModuleSchemaOwnership(t *testing.T) {
	module := telemetryModule()
	c := NewCompiler(WithModule(module))
	module.Schema.Fields["header"] = ModuleField{Kind: ModuleString}
	program, err := c.CompileSourceWithContext(context.Background(), `import "telemetry" rule r {condition: telemetry.header.type == 42}`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := program.NewScanner(WithModuleData("telemetry", telemetryData()))
	defer scanner.Close()
	if yes, err := scanner.Matches(nil); err != nil || !yes {
		t.Fatalf("schema mutated: %t %v", yes, err)
	}
}

func TestStructuredModuleInvalidSchemas(t *testing.T) {
	recursive := &ModuleSchema{Fields: map[string]ModuleField{}}
	recursive.Fields["self"] = ModuleField{Kind: ModuleStruct, Struct: recursive}
	badConstant := StringValue("bad")
	for _, schema := range []*ModuleSchema{
		recursive,
		{Fields: map[string]ModuleField{"x": {Kind: ModuleArray}}},
		{Fields: map[string]ModuleField{"x": {Kind: ModuleDictionary}}},
		{Fields: map[string]ModuleField{"x": {Kind: ModuleStruct}}},
		{Fields: map[string]ModuleField{"x": {Kind: ModuleInteger, Constant: &badConstant}}},
		{Fields: map[string]ModuleField{"x": {Kind: ModuleInteger, Element: &ModuleField{Kind: ModuleInteger}}}},
		{Fields: map[string]ModuleField{"x.y": {Kind: ModuleInteger}}},
		{Fields: map[string]ModuleField{"x": {Kind: ModuleUndefined}}},
	} {
		c := NewCompiler(WithModule(Module{Name: "telemetry", Schema: schema}))
		if _, err := c.CompileSourceWithContext(context.Background(), `import "telemetry" rule r {condition:true}`); err == nil {
			t.Fatal("invalid schema accepted")
		}
	}
}

func TestStructuredModuleAccessAllocations(t *testing.T) {
	scanner := compileTelemetry(t, `telemetry.items[0].val == 11 and telemetry.env["PATH"] == "/usr/bin"`).NewScanner(WithModuleData("telemetry", telemetryData()))
	defer scanner.Close()
	if allocs := testing.AllocsPerRun(100, func() {
		if yes, err := scanner.Matches(nil); err != nil || !yes {
			t.Fatalf("scan: %t %v", yes, err)
		}
	}); allocs != 0 {
		t.Fatalf("access allocated: %g", allocs)
	}
}

func TestStructuredModuleMalformedOperands(t *testing.T) {
	for _, opcode := range []Opcode{OpModuleLoad, OpModuleGetField, OpIterStartModuleArray} {
		for _, operand := range [][]byte{nil, {0}, {0, 0, 0}, {255, 255, 255, 255}, {0, 0, 0, 0}} {
			interpreter := NewInterpreter(append([]byte{byte(opcode)}, operand...))
			interpreter.currentCompiledRule = &CompiledRule{}
			err := interpreter.Execute()
			var invalid *InterpreterError
			if !errors.As(err, &invalid) || invalid.Type != ErrorInvalidBytecode {
				t.Fatalf("%v %x: %v", opcode, operand, err)
			}
		}
	}
	for _, plan := range []moduleIterationPlan{
		{Kind: ModuleArray, ValueSlot: -1, KeySlot: -1, Quantifier: QuantifierAny},
		{Kind: ModuleArray, ValueSlot: 0, KeySlot: 0, Quantifier: QuantifierAny},
		{Kind: ModuleDictionary, ValueSlot: 0, KeySlot: 0, Quantifier: QuantifierAny},
		{Kind: ModuleStruct, ValueSlot: 0, KeySlot: -1, Quantifier: QuantifierAny},
		{Kind: ModuleArray, ValueSlot: 0, KeySlot: -1, Quantifier: "2", Target: 3},
	} {
		if err := plan.validate(); err == nil {
			t.Fatalf("accepted invalid plan: %+v", plan)
		}
	}
	interpreter := NewInterpreter([]byte{byte(OpModuleGetIndex)})
	if err := interpreter.Execute(); err == nil {
		t.Fatal("stack underflow accepted")
	}
}

func TestStructuredModuleIndexedStringReferences(t *testing.T) {
	c := NewCompiler(WithModule(telemetryModule()))
	program, err := c.CompileSourceWithContext(context.Background(), `import "telemetry" rule r {strings: $a="MZ" condition:telemetry.numbers[#a] == 2}`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := program.NewScanner(WithModuleData("telemetry", telemetryData()))
	defer scanner.Close()
	if yes, err := scanner.Matches([]byte("MZ")); err != nil || !yes {
		t.Fatalf("lost index string reference: %t %v", yes, err)
	}
	block := program.NewBlockScanner(WithModuleData("telemetry", telemetryData()))
	defer block.Close()
	if err := block.Scan(100, []byte("MZ")); err != nil {
		t.Fatal(err)
	}
	if result, err := block.Finish(); err != nil || len(result.MatchedRules) != 1 {
		t.Fatalf("block result: %v %v", result, err)
	}
}

func TestStructuredModuleEmptyCollections(t *testing.T) {
	for _, condition := range []string{
		`not (for any item in telemetry.items : (item.val > 0))`,
		`for all item in telemetry.items : (item.val > 0)`,
		`for none item in telemetry.items : (item.val > 0)`,
		`not (for 1 item in telemetry.items : (item.val > 0))`,
	} {
		scanner := compileTelemetry(t, condition).NewScanner(WithModuleData("telemetry", map[string]any{"items": []any{}}))
		yes, err := scanner.Matches(nil)
		scanner.Close()
		if err != nil || !yes {
			t.Fatalf("%s: %t %v", condition, yes, err)
		}
	}
}

func BenchmarkStructuredModuleAccess(b *testing.B) {
	scanner := compileTelemetry(b, `telemetry.items[0].val == 11 and telemetry.env["PATH"] == "/usr/bin"`).NewScanner(WithModuleData("telemetry", telemetryData()))
	defer scanner.Close()
	b.ReportAllocs()
	for b.Loop() {
		if yes, err := scanner.Matches(nil); err != nil || !yes {
			b.Fatalf("scan: %t %v", yes, err)
		}
	}
}

func FuzzStructuredModuleAccess(f *testing.F) {
	program := compileTelemetry(f, `telemetry.numbers[int32(0)] == int8(4)`)
	f.Add([]byte{0, 0, 0, 0, 42, 42})
	f.Add([]byte{255, 255, 255, 255, 42, 42})
	f.Add([]byte{0, 0, 0, 0, 255, 255})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 5 || len(data) > 69 {
			t.Skip()
		}
		numbers := make([]int64, len(data)-5)
		for n, value := range data[5:] {
			numbers[n] = int64(int8(value))
		}
		index := int64(int32(binary.LittleEndian.Uint32(data)))
		want := index >= 0 && index < int64(len(numbers)) && numbers[index] == int64(int8(data[4]))
		scanner := program.NewScanner(WithModuleData("telemetry", map[string]any{"numbers": numbers}))
		defer scanner.Close()
		if got, err := scanner.Matches(data); err != nil || got != want {
			t.Fatalf("index=%d numbers=%v: got %t %v, want %t", index, numbers, got, err, want)
		}
	})
}

func TestStructuredModuleDiagnosticPositions(t *testing.T) {
	for _, tc := range []struct{ expression, token string }{
		{`telemetry.header.missing == 1`, `.missing`},
		{`telemetry.items["bad"].val == 1`, `"bad"`},
	} {
		line := "    " + tc.expression
		c := NewCompiler(WithModule(telemetryModule()))
		_, err := c.CompileSourceWithContext(context.Background(), "import \"telemetry\"\nrule r {\ncondition:\n"+line+"\n}")
		if err == nil {
			t.Fatal("invalid access accepted")
		}
		diagnostics := c.GetErrors()
		if len(diagnostics) == 0 || diagnostics[0].Line != 4 || diagnostics[0].Column != strings.Index(line, tc.token)+1 {
			t.Fatalf("incorrect diagnostic position: %+v", diagnostics)
		}
	}
}
