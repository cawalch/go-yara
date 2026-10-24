package compiler

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cawalch/go-yara/semantic"
)

// ModuleSchema declares the fields available on a module or nested structure.
// Schemas are copied during registration and must be finite (not recursive).
type ModuleSchema struct{ Fields map[string]ModuleField }

// ModuleStructDef is the schema of a nested structure.
type ModuleStructDef = ModuleSchema

// ModuleField declares a scalar, structure, array, or string-keyed dictionary.
// Element is required for arrays/dictionaries; Struct is required for structures.
// Constant may specify an immutable scalar instead of runtime data.
type ModuleField struct {
	Kind     ModuleValueType
	Struct   *ModuleStructDef
	Element  *ModuleField
	Constant *ModuleValue
}

type moduleObject struct {
	kind     ModuleValueType
	fields   map[string]ModuleValue
	elements []ModuleValue
	keys     []string
}

// Clone with memoization so invalid recursive input can be diagnosed later.
func cloneModuleSchema(schema *ModuleSchema) *ModuleSchema {
	schemas := map[*ModuleSchema]*ModuleSchema{}
	fields := map[*ModuleField]*ModuleField{}
	var cloneSchema func(*ModuleSchema) *ModuleSchema
	var cloneField func(*ModuleField) *ModuleField
	cloneField = func(field *ModuleField) *ModuleField {
		if field == nil {
			return nil
		}
		if prior := fields[field]; prior != nil {
			return prior
		}
		out := *field
		fields[field] = &out
		out.Struct = cloneSchema(field.Struct)
		out.Element = cloneField(field.Element)
		if field.Constant != nil {
			value := *field.Constant
			out.Constant = &value
		}
		return &out
	}
	cloneSchema = func(schema *ModuleSchema) *ModuleSchema {
		if schema == nil {
			return nil
		}
		if prior := schemas[schema]; prior != nil {
			return prior
		}
		out := &ModuleSchema{Fields: make(map[string]ModuleField, len(schema.Fields))}
		schemas[schema] = out
		for name, field := range schema.Fields {
			out.Fields[name] = *cloneField(&field)
		}
		return out
	}
	return cloneSchema(schema)
}

func validateModuleSchema(schema *ModuleSchema) error {
	if schema == nil {
		return nil
	}
	return validateModuleField(ModuleField{Kind: ModuleStruct, Struct: schema}, 0)
}

func validateModuleField(field ModuleField, depth int) error {
	if depth > 32 {
		return errors.New("module schema is recursive or exceeds 32 levels")
	}
	if field.Constant != nil {
		if field.Kind < ModuleInteger || field.Kind > ModuleBoolean || field.Constant.Type != field.Kind {
			return errors.New("module constant must match its scalar field type")
		}
	}
	switch field.Kind {
	case ModuleInteger, ModuleFloat, ModuleString, ModuleBoolean:
		if field.Struct != nil || field.Element != nil {
			return errors.New("scalar field has a collection schema")
		}
	case ModuleStruct:
		if field.Struct == nil || field.Element != nil {
			return errors.New("structure field requires a struct schema")
		}
		for name, child := range field.Struct.Fields {
			if name == "" || strings.ContainsAny(name, ".[]") {
				return fmt.Errorf("invalid module field name %q", name)
			}
			if err := validateModuleField(child, depth+1); err != nil {
				return fmt.Errorf("field %s: %w", name, err)
			}
		}
	case ModuleArray, ModuleDictionary:
		if field.Element == nil || field.Struct != nil {
			return errors.New("collection field requires an element schema")
		}
		return validateModuleField(*field.Element, depth+1)
	default:
		return fmt.Errorf("invalid module field kind %d", field.Kind)
	}
	return nil
}

func moduleFieldType(field ModuleField) *semantic.TypeInfo {
	info := &semantic.TypeInfo{DataType: moduleSemanticType(field.Kind)}
	if field.Struct != nil {
		info.Fields = make(map[string]*semantic.TypeInfo, len(field.Struct.Fields))
		for name, child := range field.Struct.Fields {
			info.Fields[name] = moduleFieldType(child)
		}
	}
	if field.Element != nil {
		info.Element = moduleFieldType(*field.Element)
	}
	return info
}

func semanticModuleSchemas(modules map[string]Module) map[string]*semantic.TypeInfo {
	out := map[string]*semantic.TypeInfo{}
	for name, module := range modules {
		if module.Schema != nil && validateModuleSchema(module.Schema) == nil {
			out[name] = moduleFieldType(ModuleField{Kind: ModuleStruct, Struct: module.Schema})
		}
	}
	return out
}

func registeredModuleSchemas(modules map[string]Module) map[string]*ModuleSchema {
	out := map[string]*ModuleSchema{}
	for name, module := range modules {
		if module.Schema != nil {
			out[name] = module.Schema
		}
	}
	return out
}
