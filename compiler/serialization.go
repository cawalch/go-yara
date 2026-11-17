package compiler

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"maps"
	"reflect"
	"slices"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
)

const (
	compiledProgramMagic = "GOYARA\x00"
	// Version 20 replaces map wire fields with sorted entry slices for byte-deterministic output.
	compiledProgramVersion = uint16(20)
)

// ErrCorruptProgram indicates a malformed, truncated, incompatible-version, or
// internally inconsistent serialized CompiledProgram artifact.
var ErrCorruptProgram = errors.New("corrupt compiled program")

// MarshalBinary serializes a compiled program using the current versioned
// go-yara format. Runtime external-variable values are deliberately omitted.
// Output is byte-identical for equal compilation inputs.
func (cp *CompiledProgram) MarshalBinary() ([]byte, error) {
	if cp == nil {
		return nil, errors.New("cannot serialize a nil compiled program")
	}
	if err := cp.Validate(); err != nil {
		return nil, fmt.Errorf("serializing invalid compiled program: %w", err)
	}

	payload, err := serializeDeterministicProgram(cp)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	output.Grow(8192 + len(cp.Rules)*1024 + len(cp.moduleSchemas)*10240)
	if _, err := output.WriteString(compiledProgramMagic); err != nil {
		return nil, err
	}
	if err := binary.Write(&output, binary.BigEndian, compiledProgramVersion); err != nil {
		return nil, fmt.Errorf("writing compiled program version: %w", err)
	}
	if err := gob.NewEncoder(&output).Encode(payload); err != nil {
		return nil, fmt.Errorf("encoding compiled program: %w", err)
	}
	return output.Bytes(), nil
}

// WriteTo writes the versioned compiled-program representation to writer.
// Output is byte-identical for equal compilation inputs.
func (cp *CompiledProgram) WriteTo(writer io.Writer) (int64, error) {
	data, err := cp.MarshalBinary()
	if err != nil {
		return 0, err
	}
	written, err := io.Copy(writer, bytes.NewReader(data))
	if err != nil {
		return written, fmt.Errorf("writing compiled program: %w", err)
	}
	return written, nil
}

// UnmarshalCompiledProgram loads a compiled program. Built-in modules are
// rebound automatically; pass custom modules used by the original compiler.
func UnmarshalCompiledProgram(data []byte, modules ...Module) (*CompiledProgram, error) {
	return ReadCompiledProgram(bytes.NewReader(data), modules...)
}

// ReadCompiledProgram reads a versioned compiled program. Built-in modules are
// rebound automatically; pass custom modules used by the original compiler.
func ReadCompiledProgram(reader io.Reader, modules ...Module) (*CompiledProgram, error) {
	magic := make([]byte, len(compiledProgramMagic))
	if _, err := io.ReadFull(reader, magic); err != nil {
		return nil, fmt.Errorf("%w: reading compiled program header: %w", ErrCorruptProgram, err)
	}
	if string(magic) != compiledProgramMagic {
		return nil, fmt.Errorf("%w: invalid compiled program magic", ErrCorruptProgram)
	}
	var version uint16
	if err := binary.Read(reader, binary.BigEndian, &version); err != nil {
		return nil, fmt.Errorf("%w: reading compiled program version: %w", ErrCorruptProgram, err)
	}
	if version < 4 || version > compiledProgramVersion {
		return nil, fmt.Errorf("%w: unsupported compiled program version %d; rebuild with format version %d", ErrCorruptProgram, version, compiledProgramVersion)
	}

	if _, ok := reader.(io.ByteReader); !ok {
		reader = compiledProgramReader{reader}
	}
	var payload serializedProgram
	if err := gob.NewDecoder(reader).Decode(&payload); err != nil {
		return nil, fmt.Errorf("%w: decoding compiled program: %w", ErrCorruptProgram, err)
	}
	return deserializeProgram(payload, modules)
}

// ReadByte prevents gob from buffering bytes belonging to the next artifact.
type compiledProgramReader struct{ io.Reader }

func (reader compiledProgramReader) ReadByte() (byte, error) {
	var data [1]byte
	_, err := io.ReadFull(reader.Reader, data[:])
	return data[0], err
}

type keyedEntry[K cmp.Ordered] interface {
	entryKey() K
}

func compareKeyedEntries[K cmp.Ordered, E keyedEntry[K]](a, b E) int {
	return cmp.Compare(a.entryKey(), b.entryKey())
}

func sortedMapEntries[K cmp.Ordered, V any, E keyedEntry[K]](values map[K]V, build func(K, V) E) []E {
	if len(values) == 0 {
		return nil
	}
	out := make([]E, 0, len(values))
	for key, val := range values {
		out = append(out, build(key, val))
	}
	if len(out) > 1 {
		slices.SortFunc(out, compareKeyedEntries[K, E])
	}
	return out
}

func sortedMapEntriesErr[K cmp.Ordered, V any, E keyedEntry[K]](values map[K]V, build func(K, V) (E, error)) ([]E, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]E, 0, len(values))
	for key, val := range values {
		entry, err := build(key, val)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	if len(out) > 1 {
		slices.SortFunc(out, compareKeyedEntries[K, E])
	}
	return out, nil
}

type entryMapSpec[K comparable, S, V, E any] struct {
	allocateEmpty bool
	unpack        func(E) (K, V, error)
	fromLegacy    func(K, S) (V, error)
}

func decodeEntryMap[K comparable, S, V, E any](
	entries []E,
	legacy map[K]S,
	spec entryMapSpec[K, S, V, E],
) (map[K]V, error) {
	if len(entries) > 0 {
		out := make(map[K]V, len(entries))
		for _, entry := range entries {
			key, value, err := spec.unpack(entry)
			if err != nil {
				return nil, err
			}
			if _, dup := out[key]; dup {
				return nil, fmt.Errorf("%w: duplicate serialized map key %v", ErrCorruptProgram, key)
			}
			out[key] = value
		}
		return out, nil
	}
	if legacy == nil && !spec.allocateEmpty {
		return nil, nil
	}
	out := make(map[K]V, len(legacy))
	for key, raw := range legacy {
		value, err := spec.fromLegacy(key, raw)
		if err != nil {
			return nil, err
		}
		out[key] = value
	}
	return out, nil
}

func decodeScalarEntryMap[K comparable, V, E any](
	entries []E,
	legacy map[K]V,
	unpack func(E) (K, V),
) (map[K]V, error) {
	return decodeEntryMap(entries, legacy, entryMapSpec[K, V, V, E]{
		unpack:     func(e E) (K, V, error) { k, v := unpack(e); return k, v, nil },
		fromLegacy: func(_ K, v V) (V, error) { return v, nil },
	})
}

type convertedMapSpec[K comparable, S, V, E any] struct {
	allocateEmpty bool
	unpack        func(E) (K, S)
	convert       func(K, S) (V, error)
}

func decodeConvertedMap[K comparable, S, V, E any](
	entries []E,
	legacy map[K]S,
	spec convertedMapSpec[K, S, V, E],
) (map[K]V, error) {
	return decodeEntryMap(entries, legacy, entryMapSpec[K, S, V, E]{
		allocateEmpty: spec.allocateEmpty,
		unpack: func(entry E) (K, V, error) {
			key, raw := spec.unpack(entry)
			val, err := spec.convert(key, raw)
			return key, val, err
		},
		fromLegacy: spec.convert,
	})
}

func serializeModuleSchema(schema *ModuleSchema, depth int) (*serializedModuleSchema, error) {
	if schema == nil {
		return nil, nil
	}
	if depth > 32 {
		return nil, errors.New("module schema is recursive or exceeds 32 levels")
	}
	fields, err := sortedMapEntriesErr(schema.Fields, func(name string, field ModuleField) (serializedModuleFieldEntry, error) {
		sf, err := serializeModuleField(field, depth+1)
		if err != nil {
			return serializedModuleFieldEntry{}, err
		}
		return serializedModuleFieldEntry{Key: name, Value: sf}, nil
	})
	if err != nil {
		return nil, err
	}
	return &serializedModuleSchema{Fields: fields}, nil
}

func serializeModuleField(field ModuleField, depth int) (serializedModuleField, error) {
	if depth > 32 {
		return serializedModuleField{}, errors.New("module schema is recursive or exceeds 32 levels")
	}
	nested, err := serializeModuleSchema(field.Struct, depth)
	if err != nil {
		return serializedModuleField{}, err
	}
	var elem *serializedModuleField
	if field.Element != nil {
		encodedElem, err := serializeModuleField(*field.Element, depth+1)
		if err != nil {
			return serializedModuleField{}, err
		}
		elem = &encodedElem
	}
	return serializedModuleField{
		Kind:     field.Kind,
		Struct:   nested,
		Element:  elem,
		Constant: field.Constant,
	}, nil
}

func deserializeModuleSchema(serialized *serializedModuleSchema, depth int) (*ModuleSchema, error) {
	if serialized == nil {
		return nil, nil
	}
	if depth > 32 {
		return nil, fmt.Errorf("%w: module schema exceeds maximum nesting depth", ErrCorruptProgram)
	}
	fields, err := decodeEntryMap(serialized.Fields, nil, entryMapSpec[string, ModuleField, ModuleField, serializedModuleFieldEntry]{
		allocateEmpty: true,
		unpack: func(entry serializedModuleFieldEntry) (string, ModuleField, error) {
			field, err := deserializeModuleField(entry.Value, depth+1)
			return entry.Key, field, err
		},
		fromLegacy: func(_ string, v ModuleField) (ModuleField, error) { return v, nil },
	})
	if err != nil {
		return nil, err
	}
	return &ModuleSchema{Fields: fields}, nil
}

func deserializeModuleField(serialized serializedModuleField, depth int) (ModuleField, error) {
	if depth > 32 {
		return ModuleField{}, fmt.Errorf("%w: module schema exceeds maximum nesting depth", ErrCorruptProgram)
	}
	nested, err := deserializeModuleSchema(serialized.Struct, depth)
	if err != nil {
		return ModuleField{}, err
	}
	var elem *ModuleField
	if serialized.Element != nil {
		decodedElem, err := deserializeModuleField(*serialized.Element, depth+1)
		if err != nil {
			return ModuleField{}, err
		}
		elem = &decodedElem
	}
	var constant *ModuleValue
	if serialized.Constant != nil {
		copyVal := *serialized.Constant
		constant = &copyVal
	}
	return ModuleField{
		Kind:     serialized.Kind,
		Struct:   nested,
		Element:  elem,
		Constant: constant,
	}, nil
}

func serializeDeterministicProgram(cp *CompiledProgram) (serializedProgram, error) {
	schemaEntries, err := sortedMapEntriesErr(cp.moduleSchemas, func(name string, schema *ModuleSchema) (serializedModuleSchemaEntry, error) {
		encoded, err := serializeModuleSchema(schema, 0)
		if err != nil {
			return serializedModuleSchemaEntry{}, fmt.Errorf("serializing module schema %q: %w", name, err)
		}
		return serializedModuleSchemaEntry{Key: name, Value: encoded}, nil
	})
	if err != nil {
		return serializedProgram{}, err
	}

	dependencyEntries := sortedMapEntries(cp.DependencyGraph(), func(ruleName string, deps []string) serializedStringSliceEntry {
		cloned := slices.Clone(deps)
		slices.Sort(cloned)
		return serializedStringSliceEntry{Key: ruleName, Value: cloned}
	})

	payload := serializedProgram{
		ModuleSchemaEntries: schemaEntries,
		Rules:               make([]serializedRule, len(cp.Rules)),
		DependencyEntries:   dependencyEntries,
	}
	for index, rule := range cp.Rules {
		serialized, err := serializeRule(rule)
		if err != nil {
			return serializedProgram{}, fmt.Errorf("serializing rule %q: %w", rule.Name, err)
		}
		payload.Rules[index] = serialized
	}
	return payload, nil
}

// serializeProgram returns a legacy map-populated serializedProgram for white-box
// format-compatibility tests that mutate legacy map fields before encoding.
func serializeProgram(cp *CompiledProgram) (serializedProgram, error) {
	payload, err := serializeDeterministicProgram(cp)
	if err != nil {
		return serializedProgram{}, err
	}
	schemas := make(map[string]*ModuleSchema, len(payload.ModuleSchemaEntries))
	for _, entry := range payload.ModuleSchemaEntries {
		schema, err := deserializeModuleSchema(entry.Value, 0)
		if err != nil {
			return serializedProgram{}, err
		}
		schemas[entry.Key] = schema
	}
	payload.ModuleSchemas = schemas
	payload.Dependencies = entriesToMap(payload.DependencyEntries, false, func(e serializedStringSliceEntry) (string, []string) { return e.Key, e.Value })
	payload.ModuleSchemaEntries = nil
	payload.DependencyEntries = nil
	for index := range payload.Rules {
		ruleToLegacyMaps(&payload.Rules[index])
	}
	return payload, nil
}

func entriesToMap[K comparable, V, E any](entries []E, allocateEmpty bool, unpack func(E) (K, V)) map[K]V {
	if len(entries) == 0 && !allocateEmpty {
		return nil
	}
	out := make(map[K]V, len(entries))
	for _, entry := range entries {
		key, val := unpack(entry)
		out[key] = val
	}
	return out
}

func ruleToLegacyMaps(rule *serializedRule) {
	rule.Strings = entriesToMap(rule.StringEntries, true, func(e serializedByteEntry) (string, []byte) { return e.Key, e.Value })
	rule.StringKinds = entriesToMap(rule.StringKindEntries, false, func(e serializedStringKindEntry) (string, StringKind) { return e.Key, e.Value })
	rule.StringModifiers = entriesToMap(rule.StringModifierEntries, true, func(e serializedStringModifierEntry) (string, []serializedStringModifier) {
		return e.Key, e.Value
	})
	rule.CaptureBindings = entriesToMap(rule.CaptureBindingEntries, true, func(e serializedCaptureBindingEntry) (string, []serializedCaptureBinding) {
		return e.Key, e.Value
	})
	rule.TextPatterns = entriesToMap(rule.TextPatternEntries, true, func(e serializedByteEntry) (string, []byte) { return e.Key, e.Value })
	rule.RegexPatterns = entriesToMap(rule.RegexPatternEntries, true, func(e serializedRegexPatternEntry) (string, serializedRegexPattern) {
		return e.Key, e.Value
	})
	rule.HexPatterns = entriesToMap(rule.HexPatternEntries, true, func(e serializedHexPatternEntry) (string, serializedHexPattern) {
		return e.Key, e.Value
	})
	rule.Stats = entriesToMap(rule.StatEntries, true, func(e serializedIntEntry) (string, int) { return e.Key, e.Value })
	rule.ExternalSlots = entriesToMap(rule.ExternalSlotEntries, false, func(e serializedIntEntry) (string, int) { return e.Key, e.Value })
	rule.GlobalSlots = entriesToMap(rule.GlobalSlotEntries, false, func(e serializedIntEntry) (string, int) { return e.Key, e.Value })
	rule.GlobalValues = entriesToMap(rule.GlobalValueEntries, true, func(e serializedGlobalValueEntry) (string, serializedGlobalValue) {
		return e.Key, e.Value
	})
	rule.Meta = entriesToMap(rule.MetaEntries, true, func(e serializedScalarEntry) (string, serializedScalar) { return e.Key, e.Value })
	rule.FixedOffsets = entriesToMap(rule.FixedOffsetEntries, false, func(e serializedInt64Entry) (string, int64) { return e.Key, e.Value })
	rule.ModuleNames = entriesToMap(rule.ModuleNameEntries, false, func(e serializedModuleNameEntry) (uint8, string) { return e.Key, e.Value })
	rule.ModuleSignatures = entriesToMap(rule.ModuleSignatureEntries, false, func(e serializedModuleSignatureEntry) (uint8, serializedModuleFunction) {
		return e.Key, e.Value
	})
	rule.StringEntries = nil
	rule.StringKindEntries = nil
	rule.StringModifierEntries = nil
	rule.CaptureBindingEntries = nil
	rule.TextPatternEntries = nil
	rule.RegexPatternEntries = nil
	rule.HexPatternEntries = nil
	rule.StatEntries = nil
	rule.ExternalSlotEntries = nil
	rule.GlobalSlotEntries = nil
	rule.GlobalValueEntries = nil
	rule.MetaEntries = nil
	rule.FixedOffsetEntries = nil
	rule.ModuleNameEntries = nil
	rule.ModuleSignatureEntries = nil
}

func serializeRule(rule *CompiledRule) (serializedRule, error) {
	modifierEntries, err := serializeStringModifierEntries(rule.StringModifiers)
	if err != nil {
		return serializedRule{}, err
	}
	metaEntries, err := serializeScalarEntries(rule.Meta)
	if err != nil {
		return serializedRule{}, fmt.Errorf("serializing metadata: %w", err)
	}

	serialized := serializedRule{
		ModuleAccessNames: slices.Clone(rule.moduleAccessNames),
		ModuleIterations:  slices.Clone(rule.moduleIterations),
		Name:              rule.Name,
		Index:             rule.Index,
		Bytecode:          slices.Clone(rule.Bytecode),
		StringCount:       rule.StringCount,
		StringEntries: sortedMapEntries(rule.Strings, func(id string, data []byte) serializedByteEntry {
			return serializedByteEntry{Key: id, Value: slices.Clone(data)}
		}),
		StringSets:       cloneStringSlices(rule.StringSets),
		TextStringSets:   cloneStringSlices(rule.TextStringSets),
		AnonymousStrings: slices.Clone(rule.AnonymousStrings),
		StringLiterals:   slices.Clone(rule.StringLiterals),
		ModuleRegexes:    serializeModuleRegexes(rule.moduleRegexes),
		StringKindEntries: sortedMapEntries(rule.StringKinds, func(id string, kind StringKind) serializedStringKindEntry {
			return serializedStringKindEntry{Key: id, Value: kind}
		}),
		StringModifierEntries: modifierEntries,
		CaptureBindingEntries: serializeCaptureBindingEntries(rule.CaptureBindings),
		EvidencePlans:         serializeEvidencePlans(rule.EvidencePlans),
		TextPatternEntries: sortedMapEntries(rule.TextPatterns, func(id string, data []byte) serializedByteEntry {
			return serializedByteEntry{Key: id, Value: slices.Clone(data)}
		}),
		RegexPatternEntries: sortedMapEntries(rule.RegexPatterns, func(id string, pat RegexPattern) serializedRegexPatternEntry {
			return serializedRegexPatternEntry{Key: id, Value: serializeRegexPattern(pat)}
		}),
		HexPatternEntries:   sortedMapEntries(rule.HexPatterns, serializeHexPatternEntry),
		StatEntries:         serializeIntegerStatEntries(rule.Stats),
		ExternalSlotEntries: sortedMapEntries(rule.ExternalSlots, func(name string, slot int) serializedIntEntry { return serializedIntEntry{Key: name, Value: slot} }),
		GlobalSlotEntries:   sortedMapEntries(rule.GlobalSlots, func(name string, slot int) serializedIntEntry { return serializedIntEntry{Key: name, Value: slot} }),
		GlobalValueEntries:  sortedMapEntries(rule.GlobalValues, serializeGlobalValueEntry),
		Tags:                slices.Clone(rule.Tags),
		MetaEntries:         metaEntries,
		IsGlobal:            rule.IsGlobal,
		IsPrivate:           rule.IsPrivate,
		FastScanSafe:        rule.FastScanSafe,
		ConditionMonotonic:  rule.ConditionMonotonic,
		RequiresStringMatch: rule.RequiresStringMatch,
		HeaderConstraints:   slices.Clone(rule.HeaderConstraints),
		FixedOffsetEntries: sortedMapEntries(rule.fixedOffsets, func(id string, offset int64) serializedInt64Entry {
			return serializedInt64Entry{Key: id, Value: offset}
		}),
		Assertions:          slices.Clone(rule.assertions),
		AssertionProgram:    slices.Clone(rule.assertionProgram),
		MandatoryAssertions: slices.Clone(rule.mandatoryAssertions),
		RequiredStrings:     slices.Clone(rule.requiredStrings),
		ForbiddenStrings:    slices.Clone(rule.forbiddenStrings),
	}
	if rule.automaton != nil {
		serialized.AutomatonStrings = cloneacStringInfos(rule.automaton.strings)
	}
	serialized.ModuleNameEntries, serialized.ModuleSignatureEntries = serializeRuleModules(rule.ModuleNames, rule.ModuleFunctions)
	return serialized, nil
}

func serializeRuleModules(
	moduleNames map[builtinFunction]string,
	moduleFunctions map[builtinFunction]ModuleFunction,
) ([]serializedModuleNameEntry, []serializedModuleSignatureEntry) {
	if len(moduleNames) == 0 {
		return nil, nil
	}
	nameEntries := make([]serializedModuleNameEntry, 0, len(moduleNames))
	var sigEntries []serializedModuleSignatureEntry
	if len(moduleFunctions) > 0 {
		sigEntries = make([]serializedModuleSignatureEntry, 0, len(moduleFunctions))
	}
	for id, name := range moduleNames {
		rawID := uint8(id)
		nameEntries = append(nameEntries, serializedModuleNameEntry{Key: rawID, Value: name})
		if function, exists := moduleFunctions[id]; exists {
			sigEntries = append(sigEntries, serializedModuleSignatureEntry{
				Key:   rawID,
				Value: serializeModuleFunction(function),
			})
		}
	}
	if len(nameEntries) > 1 {
		slices.SortFunc(nameEntries, compareKeyedEntries[uint8, serializedModuleNameEntry])
	}
	if len(sigEntries) > 1 {
		slices.SortFunc(sigEntries, compareKeyedEntries[uint8, serializedModuleSignatureEntry])
	}
	return nameEntries, sigEntries
}

func serializeHexPatternEntry(identifier string, pattern *HexPattern) serializedHexPatternEntry {
	if pattern == nil {
		return serializedHexPatternEntry{Key: identifier}
	}
	return serializedHexPatternEntry{
		Key: identifier,
		Value: serializedHexPattern{
			Present:  true,
			Tokens:   cloneHexTokens(pattern.Tokens),
			XorKeys:  slices.Clone(pattern.XorKeys),
			XorRange: slices.Clone(pattern.XorRange),
			CacheKey: pattern.cacheKey,
		},
	}
}

func serializeGlobalValueEntry(name string, value compiledGlobalValue) serializedGlobalValueEntry {
	return serializedGlobalValueEntry{
		Key: name,
		Value: serializedGlobalValue{
			Type: value.valueType, Int: value.intVal, Double: value.doubleVal, String: value.stringVal,
		},
	}
}

func deserializeProgram(payload serializedProgram, modules []Module) (*CompiledProgram, error) {
	bindings, err := moduleBindingsForLoad(modules)
	if err != nil {
		return nil, err
	}
	rawSchemas, err := decodeEntryMap(
		payload.ModuleSchemaEntries,
		payload.ModuleSchemas,
		entryMapSpec[string, *ModuleSchema, *ModuleSchema, serializedModuleSchemaEntry]{
			allocateEmpty: true,
			unpack: func(entry serializedModuleSchemaEntry) (string, *ModuleSchema, error) {
				schema, err := deserializeModuleSchema(entry.Value, 0)
				return entry.Key, schema, err
			},
			fromLegacy: func(_ string, schema *ModuleSchema) (*ModuleSchema, error) {
				return cloneModuleSchema(schema), nil
			},
		},
	)
	if err != nil {
		return nil, err
	}
	schemas := make(map[string]*ModuleSchema, len(rawSchemas))
	for _, name := range slices.Sorted(maps.Keys(rawSchemas)) {
		schema := rawSchemas[name]
		if err := validateModuleSchema(schema); err != nil {
			return nil, fmt.Errorf("%w: loading module %s: %w", ErrCorruptProgram, name, err)
		}
		for _, module := range modules {
			if module.Name == name && module.Schema != nil && !reflect.DeepEqual(module.Schema, schema) {
				return nil, fmt.Errorf("module %s has an incompatible schema", name)
			}
		}
		// Reuse only the exact current built-in schema after validation and
		// host compatibility checks. Older and custom schemas remain owned copies.
		if name == "pe" && reflect.DeepEqual(schema, peSchema) {
			schemas[name] = peSchema
		} else {
			schemas[name] = cloneModuleSchema(schema)
		}
	}
	dependenciesMap, err := decodeEntryMap(
		payload.DependencyEntries,
		payload.Dependencies,
		entryMapSpec[string, []string, []string, serializedStringSliceEntry]{
			unpack: func(entry serializedStringSliceEntry) (string, []string, error) {
				return entry.Key, slices.Clone(entry.Value), nil
			},
			fromLegacy: func(_ string, deps []string) ([]string, error) {
				return slices.Clone(deps), nil
			},
		},
	)
	if err != nil {
		return nil, err
	}
	rules := make([]*CompiledRule, len(payload.Rules))
	for index, serialized := range payload.Rules {
		rule, err := deserializeRule(serialized, bindings)
		if err != nil {
			return nil, fmt.Errorf("loading rule %q: %w", serialized.Name, err)
		}
		if dependencies, known := dependenciesMap[rule.Name]; known {
			rule.dependencies = append([]string{}, dependencies...)
		}
		rule.moduleSchemas = schemas
		rules[index] = rule
	}

	program := newCompiledProgram(rules)
	program.Stats = map[string]any{
		"rule_count":          len(rules),
		"total_bytecode_size": program.GetTotalBytecodeSize(),
	}
	if err := program.preparationErr; err != nil {
		return nil, fmt.Errorf("%w: validating loaded compiled program: %w", ErrCorruptProgram, err)
	}
	return program, nil
}

func deserializeRule(serialized serializedRule, bindings map[string]compiledModuleFunction) (*CompiledRule, error) {
	automaton, err := deserializeAutomaton(serialized.AutomatonStrings)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCorruptProgram, err)
	}
	modifiers, err := deserializeStringModifiers(serialized.StringModifierEntries, serialized.StringModifiers)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCorruptProgram, err)
	}
	meta, err := deserializeScalars(serialized.MetaEntries, serialized.Meta)
	if err != nil {
		return nil, fmt.Errorf("%w: loading metadata: %w", ErrCorruptProgram, err)
	}
	moduleRegexes, err := deserializeModuleRegexes(serialized.ModuleRegexes)
	if err != nil {
		return nil, fmt.Errorf("%w: loading module regexes: %w", ErrCorruptProgram, err)
	}

	stringsMap, err := decodeByteMap(serialized.StringEntries, serialized.Strings)
	if err != nil {
		return nil, err
	}
	textPatternsMap, err := decodeByteMap(serialized.TextPatternEntries, serialized.TextPatterns)
	if err != nil {
		return nil, err
	}
	stringKindsMap, err := decodeScalarEntryMap(serialized.StringKindEntries, serialized.StringKinds, func(e serializedStringKindEntry) (string, StringKind) { return e.Key, e.Value })
	if err != nil {
		return nil, err
	}
	captureBindingsMap, err := deserializeCaptureBindings(serialized.CaptureBindingEntries, serialized.CaptureBindings)
	if err != nil {
		return nil, err
	}
	regexPatternsMap, err := decodeConvertedMap(
		serialized.RegexPatternEntries,
		serialized.RegexPatterns,
		convertedMapSpec[string, serializedRegexPattern, RegexPattern, serializedRegexPatternEntry]{
			allocateEmpty: true,
			unpack:        func(e serializedRegexPatternEntry) (string, serializedRegexPattern) { return e.Key, e.Value },
			convert:       func(_ string, p serializedRegexPattern) (RegexPattern, error) { return deserializeRegexPattern(p), nil },
		},
	)
	if err != nil {
		return nil, err
	}
	hexPatternsMap, err := deserializeHexPatterns(serialized.HexPatternEntries, serialized.HexPatterns)
	if err != nil {
		return nil, err
	}
	statsMap, err := deserializeIntegerStats(serialized.StatEntries, serialized.Stats)
	if err != nil {
		return nil, err
	}
	externalSlotsMap, err := decodeIntMap(serialized.ExternalSlotEntries, serialized.ExternalSlots)
	if err != nil {
		return nil, err
	}
	globalSlotsMap, err := decodeIntMap(serialized.GlobalSlotEntries, serialized.GlobalSlots)
	if err != nil {
		return nil, err
	}
	globalValuesMap, err := deserializeGlobalValues(serialized.GlobalValueEntries, serialized.GlobalValues)
	if err != nil {
		return nil, err
	}
	legacyFixedOffsets := serialized.FixedOffsets
	if legacyFixedOffsets == nil {
		legacyFixedOffsets = serialized.FixedTextOffsets
	}
	fixedOffsetsMap, err := decodeScalarEntryMap(serialized.FixedOffsetEntries, legacyFixedOffsets, func(e serializedInt64Entry) (string, int64) { return e.Key, e.Value })
	if err != nil {
		return nil, err
	}

	rawModuleNames, err := decodeScalarEntryMap(serialized.ModuleNameEntries, serialized.ModuleNames, func(e serializedModuleNameEntry) (uint8, string) { return e.Key, e.Value })
	if err != nil {
		return nil, err
	}
	rawModuleSignatures, err := decodeScalarEntryMap(serialized.ModuleSignatureEntries, serialized.ModuleSignatures, func(e serializedModuleSignatureEntry) (uint8, serializedModuleFunction) {
		return e.Key, e.Value
	})
	if err != nil {
		return nil, err
	}

	var moduleFunctions map[builtinFunction]ModuleFunction
	var moduleNames map[builtinFunction]string
	if len(rawModuleNames) > 0 {
		moduleFunctions = make(map[builtinFunction]ModuleFunction, len(rawModuleNames))
		moduleNames = make(map[builtinFunction]string, len(rawModuleNames))
	}

	rule := &CompiledRule{
		moduleAccessNames:   slices.Clone(serialized.ModuleAccessNames),
		moduleIterations:    slices.Clone(serialized.ModuleIterations),
		Name:                serialized.Name,
		Index:               serialized.Index,
		Bytecode:            slices.Clone(serialized.Bytecode),
		StringCount:         serialized.StringCount,
		Strings:             stringsMap,
		automaton:           automaton,
		StringSets:          cloneStringSlices(serialized.StringSets),
		TextStringSets:      cloneStringSlices(serialized.TextStringSets),
		AnonymousStrings:    slices.Clone(serialized.AnonymousStrings),
		StringLiterals:      slices.Clone(serialized.StringLiterals),
		moduleRegexes:       moduleRegexes,
		StringKinds:         stringKindsMap,
		StringModifiers:     modifiers,
		CaptureBindings:     captureBindingsMap,
		EvidencePlans:       deserializeEvidencePlans(serialized.EvidencePlans),
		TextPatterns:        textPatternsMap,
		RegexPatterns:       regexPatternsMap,
		HexPatterns:         hexPatternsMap,
		Stats:               statsMap,
		ExternalSlots:       externalSlotsMap,
		GlobalSlots:         globalSlotsMap,
		GlobalValues:        globalValuesMap,
		Tags:                append([]string{}, serialized.Tags...),
		Meta:                meta,
		IsGlobal:            serialized.IsGlobal,
		IsPrivate:           serialized.IsPrivate,
		FastScanSafe:        serialized.FastScanSafe,
		ConditionMonotonic:  serialized.ConditionMonotonic,
		RequiresStringMatch: serialized.RequiresStringMatch,
		ModuleFunctions:     moduleFunctions,
		ModuleNames:         moduleNames,
		HeaderConstraints:   slices.Clone(serialized.HeaderConstraints),
		fixedOffsets:        fixedOffsetsMap,
		assertions:          slices.Clone(serialized.Assertions),
		assertionProgram:    slices.Clone(serialized.AssertionProgram),
		mandatoryAssertions: slices.Clone(serialized.MandatoryAssertions),
		requiredStrings:     slices.Clone(serialized.RequiredStrings),
		forbiddenStrings:    slices.Clone(serialized.ForbiddenStrings),
	}
	for _, rawID := range slices.Sorted(maps.Keys(rawModuleNames)) {
		name := rawModuleNames[rawID]
		if builtinFunction(rawID) < firstModuleFunctionID {
			return nil, fmt.Errorf("%w: module function %q has reserved function ID %d", ErrCorruptProgram, name, rawID)
		}
		signature, exists := rawModuleSignatures[rawID]
		if !exists {
			return nil, fmt.Errorf("%w: module function %q has no serialized signature", ErrCorruptProgram, name)
		}
		if err := validateSerializedModuleFunction(name, signature); err != nil {
			return nil, err
		}
		binding, exists := bindings[name]
		if !exists {
			return nil, fmt.Errorf("module function %q is not registered", name)
		}
		if !moduleFunctionCompatible(binding.function, signature) {
			return nil, fmt.Errorf("module function %q has an incompatible signature", name)
		}
		id := builtinFunction(rawID)
		rule.ModuleFunctions[id] = cloneModuleFunction(binding.function)
		rule.ModuleNames[id] = name
	}
	return rule, nil
}

func decodeByteMap(entries []serializedByteEntry, legacy map[string][]byte) (map[string][]byte, error) {
	return decodeConvertedMap(entries, legacy, convertedMapSpec[string, []byte, []byte, serializedByteEntry]{
		allocateEmpty: true,
		unpack:        func(e serializedByteEntry) (string, []byte) { return e.Key, e.Value },
		convert:       func(_ string, b []byte) ([]byte, error) { return slices.Clone(b), nil },
	})
}

func decodeIntMap(entries []serializedIntEntry, legacy map[string]int) (map[string]int, error) {
	return decodeScalarEntryMap(entries, legacy, func(e serializedIntEntry) (string, int) { return e.Key, e.Value })
}

func deserializeHexPatterns(entries []serializedHexPatternEntry, legacy map[string]serializedHexPattern) (map[string]*HexPattern, error) {
	if len(entries) > 0 {
		out := make(map[string]*HexPattern, len(entries))
		seen := make(map[string]struct{}, len(entries))
		for _, entry := range entries {
			if _, dup := seen[entry.Key]; dup {
				return nil, fmt.Errorf("%w: duplicate serialized map key %v", ErrCorruptProgram, entry.Key)
			}
			seen[entry.Key] = struct{}{}
			if !entry.Value.Present {
				continue
			}
			out[entry.Key] = buildHexPatternFromSerialized(entry.Value)
		}
		return out, nil
	}
	out := make(map[string]*HexPattern, len(legacy))
	for identifier, pattern := range legacy {
		if !pattern.Present {
			continue
		}
		out[identifier] = buildHexPatternFromSerialized(pattern)
	}
	return out, nil
}

func buildHexPatternFromSerialized(pattern serializedHexPattern) *HexPattern {
	return &HexPattern{
		Tokens: cloneHexTokens(pattern.Tokens), XorKeys: slices.Clone(pattern.XorKeys),
		XorRange: slices.Clone(pattern.XorRange), cacheKey: pattern.CacheKey, cacheIndex: -1,
	}
}

func deserializeGlobalValues(entries []serializedGlobalValueEntry, legacy map[string]serializedGlobalValue) (map[string]compiledGlobalValue, error) {
	return decodeConvertedMap(entries, legacy, convertedMapSpec[string, serializedGlobalValue, compiledGlobalValue, serializedGlobalValueEntry]{
		allocateEmpty: true,
		unpack:        func(e serializedGlobalValueEntry) (string, serializedGlobalValue) { return e.Key, e.Value },
		convert: func(_ string, value serializedGlobalValue) (compiledGlobalValue, error) {
			return compiledGlobalValue{
				valueType: value.Type, intVal: value.Int, doubleVal: value.Double, stringVal: value.String,
			}, nil
		},
	})
}

func serializeModuleFunction(function ModuleFunction) serializedModuleFunction {
	signatures := make([][]ModuleValueType, len(function.Signatures))
	returns := make([]ModuleValueType, len(function.Signatures))
	for index, signature := range function.Signatures {
		signatures[index] = slices.Clone(signature.Arguments)
		returns[index] = signature.resultType(function.ReturnType)
	}
	return serializedModuleFunction{Signatures: signatures, ReturnTypes: returns, ReturnType: function.ReturnType}
}

func validateSerializedModuleFunction(name string, signature serializedModuleFunction) error {
	if signature.ReturnType == ModuleUndefined || signature.ReturnType > ModuleRegex || len(signature.Signatures) == 0 {
		return fmt.Errorf("%w: module function %q has invalid serialized signature", ErrCorruptProgram, name)
	}
	for _, args := range signature.Signatures {
		for _, arg := range args {
			if arg == ModuleUndefined || arg > ModuleRegex {
				return fmt.Errorf("%w: module function %q has invalid serialized argument type %d", ErrCorruptProgram, name, arg)
			}
		}
	}
	for _, ret := range signature.ReturnTypes {
		if ret > ModuleRegex {
			return fmt.Errorf("%w: module function %q has invalid serialized return type %d", ErrCorruptProgram, name, ret)
		}
	}
	return nil
}

func serializeModuleRegexes(regexes []*compiledModuleRegex) []serializedModuleRegex {
	if len(regexes) == 0 {
		return nil
	}
	out := make([]serializedModuleRegex, len(regexes))
	for index, entry := range regexes {
		if entry == nil {
			continue
		}
		out[index] = serializedModuleRegex{
			Code:  slices.Clone(entry.code),
			Flags: entry.flags,
		}
	}
	return out
}

func deserializeModuleRegexes(serialized []serializedModuleRegex) ([]*compiledModuleRegex, error) {
	if len(serialized) == 0 {
		return nil, nil
	}
	out := make([]*compiledModuleRegex, len(serialized))
	for index, item := range serialized {
		entry := &compiledModuleRegex{
			code:  slices.Clone(item.Code),
			flags: item.Flags,
		}
		if err := validateCompiledModuleRegex(entry); err != nil {
			return nil, fmt.Errorf("module regex %d: %w", index, err)
		}
		out[index] = entry
	}
	return out, nil
}

func moduleFunctionCompatible(function ModuleFunction, serialized serializedModuleFunction) bool {
	if function.ReturnType != serialized.ReturnType {
		return false
	}
	for index, required := range serialized.Signatures {
		resultType := serialized.ReturnType
		if index < len(serialized.ReturnTypes) && serialized.ReturnTypes[index] != ModuleUndefined {
			resultType = serialized.ReturnTypes[index]
		}
		found := false
		for _, candidate := range function.Signatures {
			if slices.Equal(candidate.Arguments, required) && candidate.resultType(function.ReturnType) == resultType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func moduleBindingsForLoad(modules []Module) (map[string]compiledModuleFunction, error) {
	registered := defaultModules()
	for _, module := range modules {
		if module.Name == "" {
			return nil, errors.New("custom module has an empty name")
		}
		registered[module.Name] = module
	}
	bindings, err := compileModuleFunctions(registered)
	if err != nil {
		return nil, fmt.Errorf("configuring modules for compiled program: %w", err)
	}
	return bindings, nil
}

func deserializeAutomaton(infos []acStringInfo) (*acAutomaton, error) {
	if len(infos) == 0 {
		return nil, nil
	}
	automaton := newacAutomaton()
	automaton.ReserveStrings(len(infos))
	for _, info := range infos {
		if err := automaton.AddStringWithFlags(
			info.Identifier, info.Data, info.IsHex, info.IsRegex, info.Flags,
		); err != nil {
			return nil, fmt.Errorf("rebuilding rule automaton: %w", err)
		}
	}
	if err := automaton.Compile(); err != nil {
		return nil, fmt.Errorf("compiling rebuilt rule automaton: %w", err)
	}
	return automaton, nil
}

func serializeRegexPattern(pattern RegexPattern) serializedRegexPattern {
	serialized := serializedRegexPattern{
		BoundedAlternation:   cloneBoundedAlternation(pattern.boundedAlternation),
		Verification:         cloneVerificationPlan(pattern.verification),
		Code:                 slices.Clone(pattern.Code),
		CaptureCode:          slices.Clone(pattern.CaptureCode),
		CaptureGroups:        slices.Clone(pattern.CaptureGroups),
		Flags:                pattern.Flags,
		Prefix:               slices.Clone(pattern.prefix),
		WidePrefix:           slices.Clone(pattern.widePrefix),
		Atom:                 slices.Clone(pattern.atom),
		WideAtom:             slices.Clone(pattern.wideAtom),
		AtomMinOffset:        pattern.atomMinOffset,
		AtomMaxOffset:        pattern.atomMaxOffset,
		AtomMaxSuffix:        pattern.atomMaxSuffix,
		StreamPriorityBound:  pattern.streamPriorityBound,
		MaxLength:            pattern.maxLength,
		AtomASCIINoCase:      pattern.atomASCIINoCase,
		AlternativeAtoms:     serializeRegexAtoms(pattern.alternativeAtoms),
		WideAlternativeAtoms: serializeRegexAtoms(pattern.wideAlternativeAtoms),
		ByteSet:              pattern.byteSet.Values(),
		ByteSetMinOffset:     pattern.byteSetMinOffset,
		ByteSetMaxOffset:     pattern.byteSetMaxOffset,
		ByteSetCount:         pattern.byteSetCount,
		ByteSetLower:         pattern.byteSetLower,
		ByteSetUpper:         pattern.byteSetUpper,
		ByteSetContiguous:    pattern.byteSetContiguous,
		ByteSetValues:        slices.Clone(pattern.byteSetValues),
		FixedByteSets:        make([][]byte, len(pattern.fixedByteSets)),
		Anchored:             pattern.anchored,
		CacheKey:             pattern.cacheKey,
		FirstByteSet:         pattern.firstByteSet.Values(),
		HasFirstByteSet:      pattern.hasFirstByteSet,
		PrecedingByteSet:     pattern.precedingByteSet.Values(),
		HasPrecedingByteSet:  pattern.hasPrecedingByteSet,
		ExactPrefixSuffix:    slices.Clone(pattern.exactPrefixSuffix),
		WideExactPrefix:      slices.Clone(pattern.wideExactPrefix),
		HasPrefixRepeat:      pattern.hasPrefixRepeat,
		PrefixRepeatClass:    pattern.prefixRepeatClass.Values(),
		PrefixRepeatMin:      pattern.prefixRepeatMin,
		PrefixRepeatMax:      pattern.prefixRepeatMax,
	}
	for index, set := range pattern.fixedByteSets {
		serialized.FixedByteSets[index] = set.Values()
	}
	if pattern.leadingGap != nil {
		serialized.LeadingGap = &serializedLeadingGap{
			LeadingSet: pattern.leadingGap.leadingSet.Values(),
			GapSet:     pattern.leadingGap.gapSet.Values(),
			GapMin:     pattern.leadingGap.gapMin,
			GapMax:     pattern.leadingGap.gapMax,
			Atoms:      serializeRegexAtoms(pattern.leadingGap.atoms),
		}
	}
	return serialized
}

func deserializeRegexPattern(serialized serializedRegexPattern) RegexPattern {
	pattern := RegexPattern{
		boundedAlternation:   cloneBoundedAlternation(serialized.BoundedAlternation),
		verification:         cloneVerificationPlan(serialized.Verification),
		Code:                 slices.Clone(serialized.Code),
		CaptureCode:          slices.Clone(serialized.CaptureCode),
		CaptureGroups:        slices.Clone(serialized.CaptureGroups),
		Flags:                serialized.Flags,
		prefix:               slices.Clone(serialized.Prefix),
		widePrefix:           slices.Clone(serialized.WidePrefix),
		atom:                 slices.Clone(serialized.Atom),
		wideAtom:             slices.Clone(serialized.WideAtom),
		atomMinOffset:        serialized.AtomMinOffset,
		atomMaxOffset:        serialized.AtomMaxOffset,
		atomMaxSuffix:        serialized.AtomMaxSuffix,
		streamPriorityBound:  serialized.StreamPriorityBound,
		maxLength:            serialized.MaxLength,
		atomASCIINoCase:      serialized.AtomASCIINoCase,
		alternativeAtoms:     deserializeRegexAtoms(serialized.AlternativeAtoms),
		wideAlternativeAtoms: deserializeRegexAtoms(serialized.WideAlternativeAtoms),
		byteSet:              regex.NewByteSet(serialized.ByteSet),
		byteSetMinOffset:     serialized.ByteSetMinOffset,
		byteSetMaxOffset:     serialized.ByteSetMaxOffset,
		byteSetCount:         serialized.ByteSetCount,
		byteSetLower:         serialized.ByteSetLower,
		byteSetUpper:         serialized.ByteSetUpper,
		byteSetContiguous:    serialized.ByteSetContiguous,
		byteSetValues:        slices.Clone(serialized.ByteSetValues),
		fixedByteSets:        make([]regex.ByteSet, len(serialized.FixedByteSets)),
		anchored:             serialized.Anchored,
		cacheKey:             serialized.CacheKey,
		cacheIndex:           -1,
		firstByteSet:         regex.NewByteSet(serialized.FirstByteSet),
		hasFirstByteSet:      serialized.HasFirstByteSet,
		precedingByteSet:     regex.NewByteSet(serialized.PrecedingByteSet),
		hasPrecedingByteSet:  serialized.HasPrecedingByteSet,
		exactPrefixSuffix:    slices.Clone(serialized.ExactPrefixSuffix),
		wideExactPrefix:      slices.Clone(serialized.WideExactPrefix),
		hasPrefixRepeat:      serialized.HasPrefixRepeat,
		prefixRepeatClass:    regex.NewByteSet(serialized.PrefixRepeatClass),
		prefixRepeatMin:      serialized.PrefixRepeatMin,
		prefixRepeatMax:      serialized.PrefixRepeatMax,
	}
	for index, values := range serialized.FixedByteSets {
		pattern.fixedByteSets[index] = regex.NewByteSet(values)
	}
	if len(pattern.CaptureCode) == 0 {
		pattern.boundedClass = compileBoundedClass(pattern.Code, pattern.Flags)
	}
	if serialized.LeadingGap != nil {
		pattern.leadingGap = &regexLeadingGapPlan{
			leadingSet: regex.NewByteSet(serialized.LeadingGap.LeadingSet),
			gapSet:     regex.NewByteSet(serialized.LeadingGap.GapSet),
			gapMin:     serialized.LeadingGap.GapMin,
			gapMax:     serialized.LeadingGap.GapMax,
			atoms:      deserializeRegexAtoms(serialized.LeadingGap.Atoms),
		}
	}
	return pattern
}

func serializeRegexAtoms(atoms []regexPrefilterAtom) []serializedRegexAtom {
	serialized := make([]serializedRegexAtom, len(atoms))
	for index, atom := range atoms {
		serialized[index] = serializedRegexAtom{
			Data: slices.Clone(atom.data), MinOffset: atom.minOffset, MaxOffset: atom.maxOffset,
			MaxSuffix: atom.maxSuffix, Score: atom.score, ASCIINoCase: atom.asciiNoCase,
		}
	}
	return serialized
}

func deserializeRegexAtoms(atoms []serializedRegexAtom) []regexPrefilterAtom {
	result := make([]regexPrefilterAtom, len(atoms))
	for index, atom := range atoms {
		result[index] = regexPrefilterAtom{
			data: slices.Clone(atom.Data), minOffset: atom.MinOffset, maxOffset: atom.MaxOffset,
			maxSuffix: atom.MaxSuffix, score: atom.Score, asciiNoCase: atom.ASCIINoCase,
		}
	}
	return result
}

func serializeStringModifierEntries(
	all map[string][]ast.StringModifier,
) ([]serializedStringModifierEntry, error) {
	return sortedMapEntriesErr(all, func(identifier string, modifiers []ast.StringModifier) (serializedStringModifierEntry, error) {
		encoded := make([]serializedStringModifier, len(modifiers))
		for index, modifier := range modifiers {
			serialized := serializedStringModifier{Type: modifier.Type}
			switch value := modifier.Value.(type) {
			case nil:
				serialized.ValueKind = serializedModifierNone
			case string:
				serialized.ValueKind = serializedModifierString
				serialized.String = value
			case ast.XorRange:
				serialized.ValueKind = serializedModifierXorRange
				serialized.XorMinimum = value.Min
				serialized.XorMaximum = value.Max
			case []ast.CaptureBinding:
				serialized.ValueKind = serializedModifierCapture
				serialized.Captures = serializeCaptureBindingSlice(value)
			default:
				return serializedStringModifierEntry{}, fmt.Errorf("unsupported value type %T for string modifier", modifier.Value)
			}
			encoded[index] = serialized
		}
		return serializedStringModifierEntry{Key: identifier, Value: encoded}, nil
	})
}

func deserializeStringModifiers(
	entries []serializedStringModifierEntry,
	legacy map[string][]serializedStringModifier,
) (map[string][]ast.StringModifier, error) {
	return decodeConvertedMap(entries, legacy, convertedMapSpec[string, []serializedStringModifier, []ast.StringModifier, serializedStringModifierEntry]{
		allocateEmpty: true,
		unpack:        func(e serializedStringModifierEntry) (string, []serializedStringModifier) { return e.Key, e.Value },
		convert: func(_ string, modifiers []serializedStringModifier) ([]ast.StringModifier, error) {
			decoded := make([]ast.StringModifier, len(modifiers))
			for index, serialized := range modifiers {
				modifier := ast.StringModifier{Type: serialized.Type}
				switch serialized.ValueKind {
				case serializedModifierNone:
				case serializedModifierString:
					modifier.Value = serialized.String
				case serializedModifierXorRange:
					modifier.Value = ast.XorRange{Min: serialized.XorMinimum, Max: serialized.XorMaximum}
				case serializedModifierCapture:
					modifier.Value = deserializeCaptureBindingSlice(serialized.Captures)
				default:
					return nil, fmt.Errorf("unknown serialized string modifier value kind %d", serialized.ValueKind)
				}
				decoded[index] = modifier
			}
			return decoded, nil
		},
	})
}

func serializeCaptureBindingEntries(all map[string][]ast.CaptureBinding) []serializedCaptureBindingEntry {
	return sortedMapEntries(all, func(pattern string, bindings []ast.CaptureBinding) serializedCaptureBindingEntry {
		return serializedCaptureBindingEntry{Key: pattern, Value: serializeCaptureBindingSlice(bindings)}
	})
}

func deserializeCaptureBindings(
	entries []serializedCaptureBindingEntry,
	legacy map[string][]serializedCaptureBinding,
) (map[string][]ast.CaptureBinding, error) {
	return decodeConvertedMap(entries, legacy, convertedMapSpec[string, []serializedCaptureBinding, []ast.CaptureBinding, serializedCaptureBindingEntry]{
		allocateEmpty: true,
		unpack:        func(e serializedCaptureBindingEntry) (string, []serializedCaptureBinding) { return e.Key, e.Value },
		convert: func(_ string, bindings []serializedCaptureBinding) ([]ast.CaptureBinding, error) {
			return deserializeCaptureBindingSlice(bindings), nil
		},
	})
}

func serializeCaptureBindingSlice(bindings []ast.CaptureBinding) []serializedCaptureBinding {
	result := make([]serializedCaptureBinding, len(bindings))
	for index, binding := range bindings {
		result[index] = serializedCaptureBinding{Name: binding.Name, Group: binding.Group}
	}
	return result
}

func deserializeCaptureBindingSlice(bindings []serializedCaptureBinding) []ast.CaptureBinding {
	result := make([]ast.CaptureBinding, len(bindings))
	for index, binding := range bindings {
		result[index] = ast.CaptureBinding{Name: binding.Name, Group: binding.Group}
	}
	return result
}

func serializeEvidencePlans(plans []EvidencePlan) []serializedEvidencePlan {
	result := make([]serializedEvidencePlan, len(plans))
	for index, plan := range plans {
		result[index] = serializedEvidencePlan{
			Name: plan.Name, Fields: slices.Clone(plan.Fields), Anchor: plan.Anchor, Within: plan.Within,
		}
	}
	return result
}

func deserializeEvidencePlans(plans []serializedEvidencePlan) []EvidencePlan {
	result := make([]EvidencePlan, len(plans))
	for index, plan := range plans {
		result[index] = EvidencePlan{
			Name: plan.Name, Fields: slices.Clone(plan.Fields), Anchor: plan.Anchor, Within: plan.Within,
		}
	}
	return result
}

func serializeScalarEntries(values map[string]any) ([]serializedScalarEntry, error) {
	return sortedMapEntriesErr(values, func(name string, raw any) (serializedScalarEntry, error) {
		switch value := raw.(type) {
		case string:
			return serializedScalarEntry{Key: name, Value: serializedScalar{Kind: serializedScalarString, String: value}}, nil
		case int64:
			return serializedScalarEntry{Key: name, Value: serializedScalar{Kind: serializedScalarInt, Int: value}}, nil
		case bool:
			return serializedScalarEntry{Key: name, Value: serializedScalar{Kind: serializedScalarBool, Bool: value}}, nil
		default:
			return serializedScalarEntry{}, fmt.Errorf("unsupported scalar value type %T for %q", raw, name)
		}
	})
}

func deserializeScalars(entries []serializedScalarEntry, legacy map[string]serializedScalar) (map[string]any, error) {
	return decodeConvertedMap(entries, legacy, convertedMapSpec[string, serializedScalar, any, serializedScalarEntry]{
		allocateEmpty: true,
		unpack:        func(e serializedScalarEntry) (string, serializedScalar) { return e.Key, e.Value },
		convert: func(name string, value serializedScalar) (any, error) {
			switch value.Kind {
			case serializedScalarString:
				return value.String, nil
			case serializedScalarInt:
				return value.Int, nil
			case serializedScalarBool:
				return value.Bool, nil
			default:
				return nil, fmt.Errorf("unknown serialized scalar kind %d for %q", value.Kind, name)
			}
		},
	})
}

func serializeIntegerStatEntries(stats map[string]any) []serializedIntEntry {
	if len(stats) == 0 {
		return nil
	}
	var out []serializedIntEntry
	for name, raw := range stats {
		if value, ok := raw.(int); ok {
			if out == nil {
				out = make([]serializedIntEntry, 0, len(stats))
			}
			out = append(out, serializedIntEntry{Key: name, Value: value})
		}
	}
	if len(out) > 1 {
		slices.SortFunc(out, compareKeyedEntries[string, serializedIntEntry])
	}
	return out
}

func deserializeIntegerStats(entries []serializedIntEntry, legacy map[string]int) (map[string]any, error) {
	return decodeConvertedMap(entries, legacy, convertedMapSpec[string, int, any, serializedIntEntry]{
		allocateEmpty: true,
		unpack:        func(e serializedIntEntry) (string, int) { return e.Key, e.Value },
		convert:       func(_ string, value int) (any, error) { return value, nil },
	})
}

func cloneByteMap(values map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(values))
	for name, value := range values {
		result[name] = slices.Clone(value)
	}
	return result
}

func cloneStringSlices(values [][]string) [][]string {
	result := make([][]string, len(values))
	for index, value := range values {
		result[index] = slices.Clone(value)
	}
	return result
}
