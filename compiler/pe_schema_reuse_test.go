package compiler

import (
	"bytes"
	"reflect"
	"testing"
)

func TestLoadedPESchemaReuse(t *testing.T) {
	custom := cloneModuleSchema(peSchema)
	custom.Fields["host_field"] = ModuleField{Kind: ModuleString}
	for _, tc := range []struct {
		name   string
		schema *ModuleSchema
		native bool
	}{
		{"current", peSchema, true},
		{"legacy", peHeaderSchema, true},
		{"custom", custom, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program, err := NewCompiler(WithModule(Module{Name: "pe", Schema: tc.schema})).CompileSource(
				`import "pe" rule machine { condition: pe.machine == 0x14c } rule plain { condition: true }`)
			if err != nil {
				t.Fatal(err)
			}
			blob, err := program.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			hostSchema := cloneModuleSchema(tc.schema)
			loaded, err := UnmarshalCompiledProgram(blob, Module{Name: "pe", Schema: hostSchema})
			if err != nil {
				t.Fatal(err)
			}
			for _, rule := range loaded.Rules {
				schema := rule.moduleSchemas["pe"]
				if (schema == peSchema) != (tc.name == "current") || !reflect.DeepEqual(schema, tc.schema) {
					t.Fatal("loaded schema was incorrectly canonicalized")
				}
				if rule.nativePE != tc.native {
					t.Fatalf("native PE = %v, want %v", rule.nativePE, tc.native)
				}
			}
			// Host-owned maps must not become the program's shared schema.
			hostSchema.Fields["machine"] = ModuleField{Kind: ModuleString}
			if loaded.moduleSchemas["pe"].Fields["machine"].Kind != ModuleInteger {
				t.Fatal("host mutation changed loaded schema")
			}
			if _, err := UnmarshalCompiledProgram(blob, Module{Name: "pe", Schema: hostSchema}); err == nil {
				t.Fatal("incompatible host schema accepted")
			}
			roundtrip, err := loaded.MarshalBinary()
			if err != nil || !bytes.Equal(blob, roundtrip) {
				t.Fatalf("schema reuse changed serialized bytes: %v", err)
			}
		})
	}
}
