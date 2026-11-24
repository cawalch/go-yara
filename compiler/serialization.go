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
	output.Grow(8192 + len(cp.Rules)*2560 + len(cp.moduleSchemas)*10240)
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

	const maxCompiledProgramBytes = 256 << 20 // 256 MiB safety bound for gob decode
	limited := io.LimitReader(reader, maxCompiledProgramBytes)
	var payload serializedProgram
	if err := gob.NewDecoder(compiledProgramReader{limited}).Decode(&payload); err != nil {
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

func compareSerializedEntries[K cmp.Ordered, V any](a, b serializedEntry[K, V]) int {
	return cmp.Compare(a.Key, b.Key)
}

func sortedMapEntries[K cmp.Ordered, V, S any](values map[K]V, build func(K, V) S) []serializedEntry[K, S] {
	if len(values) == 0 {
		return nil
	}
	out := make([]serializedEntry[K, S], 0, len(values))
	for key, val := range values {
		out = append(out, serializedEntry[K, S]{Key: key, Value: build(key, val)})
	}
	if len(out) > 1 {
		slices.SortFunc(out, compareSerializedEntries[K, S])
	}
	return out
}

func sortedMapEntriesIdentity[K cmp.Ordered, V any](values map[K]V) []serializedEntry[K, V] {
	return sortedMapEntries(values, func(_ K, val V) V { return val })
}

func sortedMapEntriesErr[K cmp.Ordered, V, S any](values map[K]V, build func(K, V) (S, error)) ([]serializedEntry[K, S], error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]serializedEntry[K, S], 0, len(values))
	for key, val := range values {
		encoded, err := build(key, val)
		if err != nil {
			return nil, err
		}
		out = append(out, serializedEntry[K, S]{Key: key, Value: encoded})
	}
	if len(out) > 1 {
		slices.SortFunc(out, compareSerializedEntries[K, S])
	}
	return out, nil
}

type entryMapSpec[K comparable, S, V, E any] struct {
	allocateEmpty bool
	unpack        func(K, E) (V, error)
	fromLegacy    func(K, S) (V, error)
}

func decodeEntryMap[K cmp.Ordered, S, V, E any](
	entries []serializedEntry[K, E],
	legacy map[K]S,
	spec entryMapSpec[K, S, V, E],
) (map[K]V, error) {
	if len(entries) > 0 {
		out := make(map[K]V, len(entries))
		for _, entry := range entries {
			value, err := spec.unpack(entry.Key, entry.Value)
			if err != nil {
				return nil, err
			}
			if _, dup := out[entry.Key]; dup {
				return nil, fmt.Errorf("%w: duplicate serialized map key %v", ErrCorruptProgram, entry.Key)
			}
			out[entry.Key] = value
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

func decodeScalarEntryMap[K cmp.Ordered, V any](
	entries []serializedEntry[K, V],
	legacy map[K]V,
) (map[K]V, error) {
	return decodeEntryMap(entries, legacy, entryMapSpec[K, V, V, V]{
		unpack:     func(_ K, v V) (V, error) { return v, nil },
		fromLegacy: func(_ K, v V) (V, error) { return v, nil },
	})
}

func decodeConvertedMap[K cmp.Ordered, S, V any](
	entries []serializedEntry[K, S],
	legacy map[K]S,
	convert func(K, S) (V, error),
) (map[K]V, error) {
	return decodeEntryMap(entries, legacy, entryMapSpec[K, S, V, S]{
		allocateEmpty: true,
		unpack:        convert,
		fromLegacy:    convert,
	})
}

func serializeModuleSchema(schema *ModuleSchema, depth int) (*serializedModuleSchema, error) {
	if schema == nil {
		return nil, nil
	}
	if depth > 32 {
		return nil, errors.New("module schema is recursive or exceeds 32 levels")
	}
	fields, err := sortedMapEntriesErr(schema.Fields, func(_ string, field ModuleField) (serializedModuleField, error) {
		return serializeModuleField(field, depth+1)
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
	fields, err := decodeConvertedMap(serialized.Fields, nil, func(_ string, field serializedModuleField) (ModuleField, error) {
		return deserializeModuleField(field, depth+1)
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
	schemaEntries, err := sortedMapEntriesErr(cp.moduleSchemas, func(name string, schema *ModuleSchema) (*serializedModuleSchema, error) {
		encoded, err := serializeModuleSchema(schema, 0)
		if err != nil {
			return nil, fmt.Errorf("serializing module schema %q: %w", name, err)
		}
		return encoded, nil
	})
	if err != nil {
		return serializedProgram{}, err
	}

	dependencyEntries := sortedMapEntries(cp.DependencyGraph(), func(_ string, deps []string) []string {
		cloned := slices.Clone(deps)
		slices.Sort(cloned)
		return cloned
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
	payload.Dependencies = entriesToMap(payload.DependencyEntries, false)
	payload.ModuleSchemaEntries = nil
	payload.DependencyEntries = nil
	for index := range payload.Rules {
		ruleToLegacyMaps(&payload.Rules[index])
	}
	return payload, nil
}

func entriesToMap[K cmp.Ordered, V any](entries []serializedEntry[K, V], allocateEmpty bool) map[K]V {
	if len(entries) == 0 && !allocateEmpty {
		return nil
	}
	out := make(map[K]V, len(entries))
	for _, entry := range entries {
		out[entry.Key] = entry.Value
	}
	return out
}

func ruleToLegacyMaps(rule *serializedRule) {
	rule.Strings = entriesToMap(rule.StringEntries, true)
	rule.StringKinds = entriesToMap(rule.StringKindEntries, false)
	rule.StringModifiers = entriesToMap(rule.StringModifierEntries, true)
	rule.CaptureBindings = entriesToMap(rule.CaptureBindingEntries, true)
	rule.TextPatterns = entriesToMap(rule.TextPatternEntries, true)
	rule.RegexPatterns = entriesToMap(rule.RegexPatternEntries, true)
	rule.HexPatterns = entriesToMap(rule.HexPatternEntries, true)
	rule.Stats = entriesToMap(rule.StatEntries, true)
	rule.ExternalSlots = entriesToMap(rule.ExternalSlotEntries, false)
	rule.GlobalSlots = entriesToMap(rule.GlobalSlotEntries, false)
	rule.GlobalValues = entriesToMap(rule.GlobalValueEntries, true)
	rule.Meta = entriesToMap(rule.MetaEntries, true)
	rule.FixedOffsets = entriesToMap(rule.FixedOffsetEntries, false)
	rule.ModuleNames = entriesToMap(rule.ModuleNameEntries, false)
	rule.ModuleSignatures = entriesToMap(rule.ModuleSignatureEntries, false)
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
		ModuleAccessNames:     rule.moduleAccessNames,
		ModuleIterations:      rule.moduleIterations,
		Name:                  rule.Name,
		Index:                 rule.Index,
		Bytecode:              rule.Bytecode,
		StringCount:           rule.StringCount,
		StringEntries:         sortedMapEntriesIdentity(rule.Strings),
		StringSets:            rule.StringSets,
		TextStringSets:        rule.TextStringSets,
		AnonymousStrings:      rule.AnonymousStrings,
		StringLiterals:        rule.StringLiterals,
		ModuleRegexes:         serializeModuleRegexes(rule.moduleRegexes),
		StringKindEntries:     sortedMapEntriesIdentity(rule.StringKinds),
		StringModifierEntries: modifierEntries,
		CaptureBindingEntries: serializeCaptureBindingEntries(rule.CaptureBindings),
		EvidencePlans:         serializeEvidencePlans(rule.EvidencePlans),
		TextPatternEntries:    sortedMapEntriesIdentity(rule.TextPatterns),
		RegexPatternEntries: sortedMapEntries(rule.RegexPatterns, func(_ string, pat RegexPattern) serializedRegexPattern {
			return serializeRegexPattern(pat)
		}),
		HexPatternEntries:   sortedMapEntries(rule.HexPatterns, serializeHexPatternEntry),
		StatEntries:         serializeIntegerStatEntries(rule.Stats),
		ExternalSlotEntries: sortedMapEntriesIdentity(rule.ExternalSlots),
		GlobalSlotEntries:   sortedMapEntriesIdentity(rule.GlobalSlots),
		GlobalValueEntries:  sortedMapEntries(rule.GlobalValues, serializeGlobalValueEntry),
		Tags:                rule.Tags,
		MetaEntries:         metaEntries,
		IsGlobal:            rule.IsGlobal,
		IsPrivate:           rule.IsPrivate,
		IsDead:              rule.IsDead,
		DeadStrings:         slices.Sorted(maps.Keys(rule.DeadStrings)),
		FastScanSafe:        rule.FastScanSafe,
		ConditionMonotonic:  rule.ConditionMonotonic,
		RequiresStringMatch: rule.RequiresStringMatch,
		HeaderConstraints:   rule.HeaderConstraints,
		FixedOffsetEntries:  sortedMapEntriesIdentity(rule.fixedOffsets),
		Assertions:          rule.assertions,
		AssertionProgram:    rule.assertionProgram,
		MandatoryAssertions: rule.mandatoryAssertions,
		RequiredStrings:     rule.requiredStrings,
		ForbiddenStrings:    rule.forbiddenStrings,
	}
	if rule.automaton != nil {
		serialized.AutomatonStrings = rule.automaton.strings
	}
	serialized.ModuleNameEntries, serialized.ModuleSignatureEntries = serializeRuleModules(rule.ModuleNames, rule.ModuleFunctions)
	return serialized, nil
}

func serializeRuleModules(
	moduleNames map[builtinFunction]string,
	moduleFunctions map[builtinFunction]ModuleFunction,
) ([]serializedEntry[uint8, string], []serializedEntry[uint8, serializedModuleFunction]) {
	if len(moduleNames) == 0 {
		return nil, nil
	}
	nameEntries := make([]serializedEntry[uint8, string], 0, len(moduleNames))
	var sigEntries []serializedEntry[uint8, serializedModuleFunction]
	if len(moduleFunctions) > 0 {
		sigEntries = make([]serializedEntry[uint8, serializedModuleFunction], 0, len(moduleFunctions))
	}
	for id, name := range moduleNames {
		rawID := uint8(id)
		nameEntries = append(nameEntries, serializedEntry[uint8, string]{Key: rawID, Value: name})
		if function, exists := moduleFunctions[id]; exists {
			sigEntries = append(sigEntries, serializedEntry[uint8, serializedModuleFunction]{
				Key:   rawID,
				Value: serializeModuleFunction(function),
			})
		}
	}
	if len(nameEntries) > 1 {
		slices.SortFunc(nameEntries, compareSerializedEntries[uint8, string])
	}
	if len(sigEntries) > 1 {
		slices.SortFunc(sigEntries, compareSerializedEntries[uint8, serializedModuleFunction])
	}
	return nameEntries, sigEntries
}

func serializeHexPatternEntry(_ string, pattern *HexPattern) serializedHexPattern {
	if pattern == nil {
		return serializedHexPattern{}
	}
	return serializedHexPattern{
		Present:  true,
		Tokens:   pattern.Tokens,
		XorKeys:  pattern.XorKeys,
		XorRange: pattern.XorRange,
		CacheKey: pattern.cacheKey,
	}
}

func serializeGlobalValueEntry(_ string, value compiledGlobalValue) serializedGlobalValue {
	return serializedGlobalValue{
		Type: value.valueType, Int: value.intVal, Double: value.doubleVal, String: value.stringVal,
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
		entryMapSpec[string, *ModuleSchema, *ModuleSchema, *serializedModuleSchema]{
			allocateEmpty: true,
			unpack: func(_ string, entry *serializedModuleSchema) (*ModuleSchema, error) {
				return deserializeModuleSchema(entry, 0)
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
		switch {
		case name == "pe" && reflect.DeepEqual(schema, peSchema):
			schemas[name] = peSchema
		case name == "pcap" && reflect.DeepEqual(schema, pcapSchema):
			schemas[name] = pcapSchema
		default:
			schemas[name] = cloneModuleSchema(schema)
		}
	}
	var dependenciesMap map[string][]string
	if len(payload.DependencyEntries) > 0 || payload.Dependencies != nil {
		dependenciesMap, err = decodeConvertedMap(
			payload.DependencyEntries,
			payload.Dependencies,
			func(_ string, deps []string) ([]string, error) { return slices.Clone(deps), nil },
		)
	}
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
	stringKindsMap, err := decodeScalarEntryMap(serialized.StringKindEntries, serialized.StringKinds)
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
		func(_ string, p serializedRegexPattern) (RegexPattern, error) { return deserializeRegexPattern(p), nil },
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
	externalSlotsMap, err := decodeScalarEntryMap(serialized.ExternalSlotEntries, serialized.ExternalSlots)
	if err != nil {
		return nil, err
	}
	globalSlotsMap, err := decodeScalarEntryMap(serialized.GlobalSlotEntries, serialized.GlobalSlots)
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
	fixedOffsetsMap, err := decodeScalarEntryMap(serialized.FixedOffsetEntries, legacyFixedOffsets)
	if err != nil {
		return nil, err
	}

	rawModuleNames, err := decodeScalarEntryMap(serialized.ModuleNameEntries, serialized.ModuleNames)
	if err != nil {
		return nil, err
	}
	rawModuleSignatures, err := decodeScalarEntryMap(serialized.ModuleSignatureEntries, serialized.ModuleSignatures)
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
		moduleAccessNames:   serialized.ModuleAccessNames,
		moduleIterations:    serialized.ModuleIterations,
		Name:                serialized.Name,
		Index:               serialized.Index,
		Bytecode:            serialized.Bytecode,
		StringCount:         serialized.StringCount,
		Strings:             stringsMap,
		automaton:           automaton,
		StringSets:          serialized.StringSets,
		TextStringSets:      serialized.TextStringSets,
		AnonymousStrings:    serialized.AnonymousStrings,
		StringLiterals:      serialized.StringLiterals,
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
		Tags:                serialized.Tags,
		Meta:                meta,
		IsGlobal:            serialized.IsGlobal,
		IsPrivate:           serialized.IsPrivate,
		IsDead:              serialized.IsDead,
		FastScanSafe:        serialized.FastScanSafe,
		ConditionMonotonic:  serialized.ConditionMonotonic,
		RequiresStringMatch: serialized.RequiresStringMatch,
		ModuleFunctions:     moduleFunctions,
		ModuleNames:         moduleNames,
		HeaderConstraints:   serialized.HeaderConstraints,
		fixedOffsets:        fixedOffsetsMap,
		assertions:          serialized.Assertions,
		assertionProgram:    serialized.AssertionProgram,
		mandatoryAssertions: serialized.MandatoryAssertions,
		requiredStrings:     serialized.RequiredStrings,
		forbiddenStrings:    serialized.ForbiddenStrings,
	}
	if len(serialized.DeadStrings) > 0 {
		rule.DeadStrings = make(map[string]bool, len(serialized.DeadStrings))
		for _, id := range serialized.DeadStrings {
			rule.DeadStrings[id] = true
		}
	}
	rule.resolveAssertionStringSlots()
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

func decodeByteMap(entries []serializedEntry[string, []byte], legacy map[string][]byte) (map[string][]byte, error) {
	return decodeConvertedMap(entries, legacy, func(_ string, b []byte) ([]byte, error) { return b, nil })
}

func deserializeHexPatterns(entries []serializedEntry[string, serializedHexPattern], legacy map[string]serializedHexPattern) (map[string]*HexPattern, error) {
	if len(entries) > 0 {
		return deserializeHexPatternEntries(entries)
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

func deserializeHexPatternEntries(entries []serializedEntry[string, serializedHexPattern]) (map[string]*HexPattern, error) {
	out := make(map[string]*HexPattern, len(entries))
	var seen map[string]struct{}
	for i, entry := range entries {
		var err error
		seen, err = checkUniqueSerializedKey(entries, i, seen)
		if err != nil {
			return nil, err
		}
		if !entry.Value.Present {
			continue
		}
		out[entry.Key] = buildHexPatternFromSerialized(entry.Value)
	}
	return out, nil
}

func checkUniqueSerializedKey[V any](entries []serializedEntry[string, V], i int, seen map[string]struct{}) (map[string]struct{}, error) {
	key := entries[i].Key
	if seen != nil {
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("%w: duplicate serialized map key %v", ErrCorruptProgram, key)
		}
		seen[key] = struct{}{}
		return seen, nil
	}
	if i == 0 || key > entries[i-1].Key {
		return nil, nil
	}
	if key == entries[i-1].Key {
		return nil, fmt.Errorf("%w: duplicate serialized map key %v", ErrCorruptProgram, key)
	}
	seen = make(map[string]struct{}, len(entries))
	for _, prev := range entries[:i] {
		seen[prev.Key] = struct{}{}
	}
	seen[key] = struct{}{}
	return seen, nil
}

func buildHexPatternFromSerialized(pattern serializedHexPattern) *HexPattern {
	return &HexPattern{
		Tokens: pattern.Tokens, XorKeys: pattern.XorKeys,
		XorRange: pattern.XorRange, cacheKey: pattern.CacheKey, cacheIndex: -1,
	}
}

func deserializeGlobalValues(entries []serializedEntry[string, serializedGlobalValue], legacy map[string]serializedGlobalValue) (map[string]compiledGlobalValue, error) {
	return decodeConvertedMap(entries, legacy, func(_ string, value serializedGlobalValue) (compiledGlobalValue, error) {
		return compiledGlobalValue{
			valueType: value.Type, intVal: value.Int, doubleVal: value.Double, stringVal: value.String,
		}, nil
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
			Code:  entry.code,
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
			code:  item.Code,
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

// deserializeAutomaton rebuilds a rule's automaton from its serialized
// pattern metadata. Construction stays deferred: the trie, failure links, and
// flat tables are materialized lazily on the first local per-rule search, so
// unmarshaling a program no longer pays for per-rule transition tables that
// normal shared-automaton scans never read.
func deserializeAutomaton(infos []acStringInfo) (*acAutomaton, error) {
	if len(infos) == 0 {
		return nil, nil
	}
	_ = mustACIndex(len(infos) - 1)
	stateHint := 1
	for i := range infos {
		infos[i].Length = len(infos[i].Data)
		stateHint += infos[i].Length
	}
	automaton := &acAutomaton{
		outputs:     make([]int32, 0, max(16, len(infos))),
		strings:     infos,
		StringCount: len(infos),
		deferred:    true,
		stateHint:   stateHint,
	}
	return automaton, nil
}

func serializeRegexPattern(pattern RegexPattern) serializedRegexPattern {
	serialized := serializedRegexPattern{
		BoundedAlternation:   pattern.boundedAlternation,
		Verification:         pattern.verification,
		Code:                 pattern.Code,
		CaptureCode:          pattern.CaptureCode,
		CaptureGroups:        pattern.CaptureGroups,
		Flags:                pattern.Flags,
		Prefix:               pattern.prefix,
		WidePrefix:           pattern.widePrefix,
		Atom:                 pattern.atom,
		WideAtom:             pattern.wideAtom,
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
		ByteSetValues:        pattern.byteSetValues,
		FixedByteSets:        make([][]byte, len(pattern.fixedByteSets)),
		Anchored:             pattern.anchored,
		CacheKey:             pattern.cacheKey,
		FirstByteSet:         pattern.firstByteSet.Values(),
		HasFirstByteSet:      pattern.hasFirstByteSet,
		PrecedingByteSet:     pattern.precedingByteSet.Values(),
		HasPrecedingByteSet:  pattern.hasPrecedingByteSet,
		ExactPrefixSuffix:    pattern.exactPrefixSuffix,
		WideExactPrefix:      pattern.wideExactPrefix,
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
		boundedAlternation:   serialized.BoundedAlternation,
		verification:         serialized.Verification,
		Code:                 serialized.Code,
		CaptureCode:          serialized.CaptureCode,
		CaptureGroups:        serialized.CaptureGroups,
		Flags:                serialized.Flags,
		prefix:               serialized.Prefix,
		widePrefix:           serialized.WidePrefix,
		atom:                 serialized.Atom,
		wideAtom:             serialized.WideAtom,
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
		byteSetValues:        serialized.ByteSetValues,
		fixedByteSets:        make([]regex.ByteSet, len(serialized.FixedByteSets)),
		anchored:             serialized.Anchored,
		cacheKey:             serialized.CacheKey,
		cacheIndex:           -1,
		firstByteSet:         regex.NewByteSet(serialized.FirstByteSet),
		hasFirstByteSet:      serialized.HasFirstByteSet,
		precedingByteSet:     regex.NewByteSet(serialized.PrecedingByteSet),
		hasPrecedingByteSet:  serialized.HasPrecedingByteSet,
		exactPrefixSuffix:    serialized.ExactPrefixSuffix,
		wideExactPrefix:      serialized.WideExactPrefix,
		hasPrefixRepeat:      serialized.HasPrefixRepeat,
		prefixRepeatClass:    regex.NewByteSet(serialized.PrefixRepeatClass),
		prefixRepeatMin:      serialized.PrefixRepeatMin,
		prefixRepeatMax:      serialized.PrefixRepeatMax,
	}
	if pattern.boundedAlternation != nil {
		pattern.boundedAlternation.prepareOrder()
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
			Data: atom.data, MinOffset: atom.minOffset, MaxOffset: atom.maxOffset,
			MaxSuffix: atom.maxSuffix, Score: atom.score, ASCIINoCase: atom.asciiNoCase,
		}
	}
	return serialized
}

func deserializeRegexAtoms(atoms []serializedRegexAtom) []regexPrefilterAtom {
	result := make([]regexPrefilterAtom, len(atoms))
	for index, atom := range atoms {
		result[index] = regexPrefilterAtom{
			data: atom.Data, minOffset: atom.MinOffset, maxOffset: atom.MaxOffset,
			maxSuffix: atom.MaxSuffix, score: atom.Score, asciiNoCase: atom.ASCIINoCase,
		}
	}
	return result
}

func serializeStringModifierEntries(
	all map[string][]ast.StringModifier,
) ([]serializedEntry[string, []serializedStringModifier], error) {
	return sortedMapEntriesErr(all, func(_ string, modifiers []ast.StringModifier) ([]serializedStringModifier, error) {
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
				return nil, fmt.Errorf("unsupported value type %T for string modifier", modifier.Value)
			}
			encoded[index] = serialized
		}
		return encoded, nil
	})
}

func deserializeStringModifiers(
	entries []serializedEntry[string, []serializedStringModifier],
	legacy map[string][]serializedStringModifier,
) (map[string][]ast.StringModifier, error) {
	return decodeConvertedMap(entries, legacy, func(_ string, modifiers []serializedStringModifier) ([]ast.StringModifier, error) {
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
	})
}

func serializeCaptureBindingEntries(all map[string][]ast.CaptureBinding) []serializedEntry[string, []serializedCaptureBinding] {
	return sortedMapEntries(all, func(_ string, bindings []ast.CaptureBinding) []serializedCaptureBinding {
		return serializeCaptureBindingSlice(bindings)
	})
}

func deserializeCaptureBindings(
	entries []serializedEntry[string, []serializedCaptureBinding],
	legacy map[string][]serializedCaptureBinding,
) (map[string][]ast.CaptureBinding, error) {
	return decodeConvertedMap(entries, legacy, func(_ string, bindings []serializedCaptureBinding) ([]ast.CaptureBinding, error) {
		return deserializeCaptureBindingSlice(bindings), nil
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
		result[index] = serializedEvidencePlan(plan)
	}
	return result
}

func deserializeEvidencePlans(plans []serializedEvidencePlan) []EvidencePlan {
	result := make([]EvidencePlan, len(plans))
	for index, plan := range plans {
		result[index] = EvidencePlan(plan)
	}
	return result
}

func serializeScalarEntries(values map[string]any) ([]serializedEntry[string, serializedScalar], error) {
	return sortedMapEntriesErr(values, func(name string, raw any) (serializedScalar, error) {
		switch value := raw.(type) {
		case string:
			return serializedScalar{Kind: serializedScalarString, String: value}, nil
		case int64:
			return serializedScalar{Kind: serializedScalarInt, Int: value}, nil
		case bool:
			return serializedScalar{Kind: serializedScalarBool, Bool: value}, nil
		default:
			return serializedScalar{}, fmt.Errorf("unsupported scalar value type %T for %q", raw, name)
		}
	})
}

func deserializeScalars(entries []serializedEntry[string, serializedScalar], legacy map[string]serializedScalar) (map[string]any, error) {
	return decodeConvertedMap(entries, legacy, func(name string, value serializedScalar) (any, error) {
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
	})
}

func serializeIntegerStatEntries(stats map[string]any) []serializedEntry[string, int] {
	if len(stats) == 0 {
		return nil
	}
	var out []serializedEntry[string, int]
	for name, raw := range stats {
		if value, ok := raw.(int); ok {
			if out == nil {
				out = make([]serializedEntry[string, int], 0, len(stats))
			}
			out = append(out, serializedEntry[string, int]{Key: name, Value: value})
		}
	}
	if len(out) > 1 {
		slices.SortFunc(out, compareSerializedEntries[string, int])
	}
	return out
}

func deserializeIntegerStats(entries []serializedEntry[string, int], legacy map[string]int) (map[string]any, error) {
	return decodeConvertedMap(entries, legacy, func(_ string, value int) (any, error) { return value, nil })
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
