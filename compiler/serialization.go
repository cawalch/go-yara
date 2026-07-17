package compiler

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"maps"
	"slices"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
)

const (
	compiledProgramMagic   = "GOYARA\x00"
	compiledProgramVersion = uint16(1)
)

type serializedProgram struct {
	Rules        []serializedRule
	Dependencies map[string][]string
}

type serializedRule struct {
	Name              string
	Index             int
	Bytecode          []byte
	StringCount       int
	Strings           map[string][]byte
	AutomatonStrings  []ACStringInfo
	StringSets        [][]string
	TextStringSets    [][]string
	AnonymousStrings  []string
	StringLiterals    []string
	StringKinds       map[string]StringKind
	StringModifiers   map[string][]serializedStringModifier
	TextPatterns      map[string][]byte
	RegexPatterns     map[string]serializedRegexPattern
	HexPatterns       map[string]serializedHexPattern
	Stats             map[string]int
	ExternalSlots     map[string]int
	GlobalSlots       map[string]int
	GlobalValues      map[string]serializedGlobalValue
	Tags              []string
	Meta              map[string]serializedScalar
	IsGlobal          bool
	IsPrivate         bool
	FastScanSafe      bool
	ModuleNames       map[uint8]string
	ModuleSignatures  map[uint8]serializedModuleFunction
	HeaderConstraints []HeaderConstraint
}

type serializedModuleFunction struct {
	Signatures [][]ModuleValueType
	ReturnType ModuleValueType
}

type serializedStringModifier struct {
	Type       ast.StringModifierType
	ValueKind  uint8
	String     string
	XorMinimum int64
	XorMaximum int64
}

const (
	serializedModifierNone uint8 = iota
	serializedModifierString
	serializedModifierXorRange
)

type serializedRegexPattern struct {
	Code                 []byte
	Flags                regex.Flags
	Prefix               []byte
	WidePrefix           []byte
	Atom                 []byte
	WideAtom             []byte
	AtomMinOffset        int
	AtomMaxOffset        int
	AlternativeAtoms     []serializedRegexAtom
	WideAlternativeAtoms []serializedRegexAtom
	LeadingGap           *serializedLeadingGap
	ByteSet              []byte
	ByteSetMinOffset     int
	ByteSetMaxOffset     int
	ByteSetCount         int
	ByteSetLower         byte
	ByteSetUpper         byte
	ByteSetContiguous    bool
	ByteSetValues        []byte
	FixedByteSets        [][]byte
	Anchored             bool
	CacheKey             string
}

type serializedRegexAtom struct {
	Data      []byte
	MinOffset int
	MaxOffset int
	Score     int
}

type serializedLeadingGap struct {
	LeadingSet []byte
	GapSet     []byte
	GapMin     int
	GapMax     int
	Atoms      []serializedRegexAtom
}

type serializedHexPattern struct {
	Present  bool
	Tokens   []HexPatternToken
	XorKeys  []byte
	XorRange []ast.XorRange
	CacheKey string
}

type serializedGlobalValue struct {
	Type   ValueType
	Int    int64
	Double float64
	String string
}

type serializedScalar struct {
	Kind   uint8
	String string
	Int    int64
	Bool   bool
}

const (
	serializedScalarString uint8 = iota + 1
	serializedScalarInt
	serializedScalarBool
)

// MarshalBinary serializes a compiled program using the current versioned
// go-yara format. Runtime external-variable values are deliberately omitted.
func (cp *CompiledProgram) MarshalBinary() ([]byte, error) {
	if cp == nil {
		return nil, fmt.Errorf("cannot serialize a nil compiled program")
	}
	if err := cp.Validate(); err != nil {
		return nil, fmt.Errorf("serializing invalid compiled program: %w", err)
	}

	payload, err := serializeProgram(cp)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
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
		return nil, fmt.Errorf("reading compiled program header: %w", err)
	}
	if string(magic) != compiledProgramMagic {
		return nil, fmt.Errorf("invalid compiled program magic")
	}
	var version uint16
	if err := binary.Read(reader, binary.BigEndian, &version); err != nil {
		return nil, fmt.Errorf("reading compiled program version: %w", err)
	}
	if version != compiledProgramVersion {
		return nil, fmt.Errorf("unsupported compiled program version %d", version)
	}

	var payload serializedProgram
	if err := gob.NewDecoder(reader).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decoding compiled program: %w", err)
	}
	return deserializeProgram(payload, modules)
}

func serializeProgram(cp *CompiledProgram) (serializedProgram, error) {
	payload := serializedProgram{
		Rules:        make([]serializedRule, len(cp.Rules)),
		Dependencies: cp.DependencyGraph(),
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

func serializeRule(rule *CompiledRule) (serializedRule, error) {
	modifiers, err := serializeStringModifiers(rule.StringModifiers)
	if err != nil {
		return serializedRule{}, err
	}
	meta, err := serializeScalars(rule.Meta)
	if err != nil {
		return serializedRule{}, fmt.Errorf("serializing metadata: %w", err)
	}

	serialized := serializedRule{
		Name:              rule.Name,
		Index:             rule.Index,
		Bytecode:          slices.Clone(rule.Bytecode),
		StringCount:       rule.StringCount,
		Strings:           cloneByteMap(rule.Strings),
		StringSets:        cloneStringSlices(rule.StringSets),
		TextStringSets:    cloneStringSlices(rule.TextStringSets),
		AnonymousStrings:  slices.Clone(rule.AnonymousStrings),
		StringLiterals:    slices.Clone(rule.StringLiterals),
		StringKinds:       maps.Clone(rule.StringKinds),
		StringModifiers:   modifiers,
		TextPatterns:      cloneByteMap(rule.TextPatterns),
		RegexPatterns:     make(map[string]serializedRegexPattern, len(rule.RegexPatterns)),
		HexPatterns:       make(map[string]serializedHexPattern, len(rule.HexPatterns)),
		Stats:             serializeIntegerStats(rule.Stats),
		ExternalSlots:     maps.Clone(rule.ExternalSlots),
		GlobalSlots:       maps.Clone(rule.GlobalSlots),
		GlobalValues:      make(map[string]serializedGlobalValue, len(rule.GlobalValues)),
		Tags:              slices.Clone(rule.Tags),
		Meta:              meta,
		IsGlobal:          rule.IsGlobal,
		IsPrivate:         rule.IsPrivate,
		FastScanSafe:      rule.FastScanSafe,
		ModuleNames:       make(map[uint8]string, len(rule.ModuleNames)),
		ModuleSignatures:  make(map[uint8]serializedModuleFunction, len(rule.ModuleFunctions)),
		HeaderConstraints: slices.Clone(rule.HeaderConstraints),
	}
	if rule.Automaton != nil {
		serialized.AutomatonStrings = cloneACStringInfo(rule.Automaton.GetStrings())
	}
	for identifier, pattern := range rule.RegexPatterns {
		serialized.RegexPatterns[identifier] = serializeRegexPattern(pattern)
	}
	for identifier, pattern := range rule.HexPatterns {
		if pattern == nil {
			serialized.HexPatterns[identifier] = serializedHexPattern{}
			continue
		}
		serialized.HexPatterns[identifier] = serializedHexPattern{
			Present:  true,
			Tokens:   cloneHexTokens(pattern.Tokens),
			XorKeys:  slices.Clone(pattern.XorKeys),
			XorRange: slices.Clone(pattern.XorRange),
			CacheKey: pattern.cacheKey,
		}
	}
	for name, value := range rule.GlobalValues {
		serialized.GlobalValues[name] = serializedGlobalValue{
			Type: value.valueType, Int: value.intVal, Double: value.doubleVal, String: value.stringVal,
		}
	}
	for id, name := range rule.ModuleNames {
		serialized.ModuleNames[uint8(id)] = name
		if function, exists := rule.ModuleFunctions[id]; exists {
			serialized.ModuleSignatures[uint8(id)] = serializeModuleFunction(function)
		}
	}
	return serialized, nil
}

func deserializeProgram(payload serializedProgram, modules []Module) (*CompiledProgram, error) {
	bindings, err := moduleBindingsForLoad(modules)
	if err != nil {
		return nil, err
	}
	rules := make([]*CompiledRule, len(payload.Rules))
	ruleNames := make(map[string]struct{}, len(payload.Rules))
	for index, serialized := range payload.Rules {
		rule, err := deserializeRule(serialized, bindings)
		if err != nil {
			return nil, fmt.Errorf("loading rule %q: %w", serialized.Name, err)
		}
		if rule.Name == "" {
			return nil, fmt.Errorf("loading rule %d: empty rule name", index)
		}
		if _, duplicate := ruleNames[rule.Name]; duplicate {
			return nil, fmt.Errorf("loading rule %q: duplicate rule name", rule.Name)
		}
		if rule.Index != index {
			return nil, fmt.Errorf("loading rule %q: index %d does not match position %d", rule.Name, rule.Index, index)
		}
		ruleNames[rule.Name] = struct{}{}
		rules[index] = rule
	}

	program := NewCompiledProgram(rules)
	program.dependencies = cloneDependencyGraph(payload.Dependencies)
	program.nonTextCacheSize = assignNonTextCacheIndices(rules)
	program.fixedRegexScan = buildFixedRegexDispatch(rules)
	sharedAutomaton, sharedLookup, err := buildSharedPatternAutomaton(rules)
	if err != nil {
		return nil, fmt.Errorf("rebuilding shared automaton: %w", err)
	}
	program.SharedAutomaton = sharedAutomaton
	program.SharedLookup = sharedLookup
	program.Stats = map[string]any{
		"rule_count":          len(rules),
		"total_bytecode_size": program.GetTotalBytecodeSize(),
	}
	if err := program.Validate(); err != nil {
		return nil, fmt.Errorf("validating loaded compiled program: %w", err)
	}
	return program, nil
}

func deserializeRule(serialized serializedRule, bindings map[string]compiledModuleFunction) (*CompiledRule, error) {
	automaton, err := deserializeAutomaton(serialized.AutomatonStrings)
	if err != nil {
		return nil, err
	}
	modifiers, err := deserializeStringModifiers(serialized.StringModifiers)
	if err != nil {
		return nil, err
	}
	meta, err := deserializeScalars(serialized.Meta)
	if err != nil {
		return nil, fmt.Errorf("loading metadata: %w", err)
	}

	rule := &CompiledRule{
		Name:              serialized.Name,
		Index:             serialized.Index,
		Bytecode:          slices.Clone(serialized.Bytecode),
		StringCount:       serialized.StringCount,
		Strings:           cloneByteMap(serialized.Strings),
		Automaton:         automaton,
		StringSets:        cloneStringSlices(serialized.StringSets),
		TextStringSets:    cloneStringSlices(serialized.TextStringSets),
		AnonymousStrings:  slices.Clone(serialized.AnonymousStrings),
		StringLiterals:    slices.Clone(serialized.StringLiterals),
		StringKinds:       maps.Clone(serialized.StringKinds),
		StringModifiers:   modifiers,
		TextPatterns:      cloneByteMap(serialized.TextPatterns),
		RegexPatterns:     make(map[string]RegexPattern, len(serialized.RegexPatterns)),
		HexPatterns:       make(map[string]*HexPattern, len(serialized.HexPatterns)),
		Stats:             deserializeIntegerStats(serialized.Stats),
		ExternalSlots:     maps.Clone(serialized.ExternalSlots),
		GlobalSlots:       maps.Clone(serialized.GlobalSlots),
		GlobalValues:      make(map[string]compiledGlobalValue, len(serialized.GlobalValues)),
		Tags:              append([]string{}, serialized.Tags...),
		Meta:              meta,
		IsGlobal:          serialized.IsGlobal,
		IsPrivate:         serialized.IsPrivate,
		FastScanSafe:      serialized.FastScanSafe,
		ModuleFunctions:   make(map[builtinFunction]ModuleFunction, len(serialized.ModuleNames)),
		ModuleNames:       make(map[builtinFunction]string, len(serialized.ModuleNames)),
		HeaderConstraints: slices.Clone(serialized.HeaderConstraints),
	}
	for identifier, pattern := range serialized.RegexPatterns {
		rule.RegexPatterns[identifier] = deserializeRegexPattern(pattern)
	}
	for identifier, pattern := range serialized.HexPatterns {
		if !pattern.Present {
			continue
		}
		rule.HexPatterns[identifier] = &HexPattern{
			Tokens: cloneHexTokens(pattern.Tokens), XorKeys: slices.Clone(pattern.XorKeys),
			XorRange: slices.Clone(pattern.XorRange), cacheKey: pattern.CacheKey, cacheIndex: -1,
		}
	}
	for name, value := range serialized.GlobalValues {
		rule.GlobalValues[name] = compiledGlobalValue{
			valueType: value.Type, intVal: value.Int, doubleVal: value.Double, stringVal: value.String,
		}
	}
	for rawID, name := range serialized.ModuleNames {
		if builtinFunction(rawID) < firstModuleFunctionID {
			return nil, fmt.Errorf("module function %q has reserved function ID %d", name, rawID)
		}
		binding, exists := bindings[name]
		if !exists {
			return nil, fmt.Errorf("module function %q is not registered", name)
		}
		signature, exists := serialized.ModuleSignatures[rawID]
		if !exists {
			return nil, fmt.Errorf("module function %q has no serialized signature", name)
		}
		if !moduleFunctionCompatible(binding.function, signature) {
			return nil, fmt.Errorf("module function %q has an incompatible signature", name)
		}
		id := builtinFunction(rawID)
		rule.ModuleFunctions[id] = binding.function
		rule.ModuleNames[id] = name
	}
	rule.BuildStringIndex()
	return rule, nil
}

func serializeModuleFunction(function ModuleFunction) serializedModuleFunction {
	signatures := make([][]ModuleValueType, len(function.Signatures))
	for index, signature := range function.Signatures {
		signatures[index] = slices.Clone(signature.Arguments)
	}
	return serializedModuleFunction{Signatures: signatures, ReturnType: function.ReturnType}
}

func moduleFunctionCompatible(function ModuleFunction, serialized serializedModuleFunction) bool {
	if function.ReturnType != serialized.ReturnType {
		return false
	}
	for _, required := range serialized.Signatures {
		found := false
		for _, candidate := range function.Signatures {
			if slices.Equal(candidate.Arguments, required) {
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
			return nil, fmt.Errorf("custom module has an empty name")
		}
		registered[module.Name] = module
	}
	bindings, _, _, err := compileModuleFunctions(registered)
	if err != nil {
		return nil, fmt.Errorf("configuring modules for compiled program: %w", err)
	}
	return bindings, nil
}

func deserializeAutomaton(infos []ACStringInfo) (*ACAutomaton, error) {
	if len(infos) == 0 {
		return nil, nil
	}
	automaton := NewACAutomaton()
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
		Code:                 slices.Clone(pattern.Code),
		Flags:                pattern.Flags,
		Prefix:               slices.Clone(pattern.prefix),
		WidePrefix:           slices.Clone(pattern.widePrefix),
		Atom:                 slices.Clone(pattern.atom),
		WideAtom:             slices.Clone(pattern.wideAtom),
		AtomMinOffset:        pattern.atomMinOffset,
		AtomMaxOffset:        pattern.atomMaxOffset,
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
		Code:                 slices.Clone(serialized.Code),
		Flags:                serialized.Flags,
		prefix:               slices.Clone(serialized.Prefix),
		widePrefix:           slices.Clone(serialized.WidePrefix),
		atom:                 slices.Clone(serialized.Atom),
		wideAtom:             slices.Clone(serialized.WideAtom),
		atomMinOffset:        serialized.AtomMinOffset,
		atomMaxOffset:        serialized.AtomMaxOffset,
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
	}
	for index, values := range serialized.FixedByteSets {
		pattern.fixedByteSets[index] = regex.NewByteSet(values)
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
			Data: slices.Clone(atom.data), MinOffset: atom.minOffset, MaxOffset: atom.maxOffset, Score: atom.score,
		}
	}
	return serialized
}

func deserializeRegexAtoms(atoms []serializedRegexAtom) []regexPrefilterAtom {
	result := make([]regexPrefilterAtom, len(atoms))
	for index, atom := range atoms {
		result[index] = regexPrefilterAtom{
			data: slices.Clone(atom.Data), minOffset: atom.MinOffset, maxOffset: atom.MaxOffset, score: atom.Score,
		}
	}
	return result
}

func serializeStringModifiers(
	all map[string][]ast.StringModifier,
) (map[string][]serializedStringModifier, error) {
	result := make(map[string][]serializedStringModifier, len(all))
	for identifier, modifiers := range all {
		result[identifier] = make([]serializedStringModifier, len(modifiers))
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
			default:
				return nil, fmt.Errorf("unsupported value type %T for string modifier", modifier.Value)
			}
			result[identifier][index] = serialized
		}
	}
	return result, nil
}

func deserializeStringModifiers(
	all map[string][]serializedStringModifier,
) (map[string][]ast.StringModifier, error) {
	result := make(map[string][]ast.StringModifier, len(all))
	for identifier, modifiers := range all {
		result[identifier] = make([]ast.StringModifier, len(modifiers))
		for index, serialized := range modifiers {
			modifier := ast.StringModifier{Type: serialized.Type}
			switch serialized.ValueKind {
			case serializedModifierNone:
			case serializedModifierString:
				modifier.Value = serialized.String
			case serializedModifierXorRange:
				modifier.Value = ast.XorRange{Min: serialized.XorMinimum, Max: serialized.XorMaximum}
			default:
				return nil, fmt.Errorf("unknown serialized string modifier value kind %d", serialized.ValueKind)
			}
			result[identifier][index] = modifier
		}
	}
	return result, nil
}

func serializeScalars(values map[string]any) (map[string]serializedScalar, error) {
	result := make(map[string]serializedScalar, len(values))
	for name, raw := range values {
		switch value := raw.(type) {
		case string:
			result[name] = serializedScalar{Kind: serializedScalarString, String: value}
		case int64:
			result[name] = serializedScalar{Kind: serializedScalarInt, Int: value}
		case bool:
			result[name] = serializedScalar{Kind: serializedScalarBool, Bool: value}
		default:
			return nil, fmt.Errorf("unsupported scalar value type %T for %q", raw, name)
		}
	}
	return result, nil
}

func deserializeScalars(values map[string]serializedScalar) (map[string]any, error) {
	result := make(map[string]any, len(values))
	for name, value := range values {
		switch value.Kind {
		case serializedScalarString:
			result[name] = value.String
		case serializedScalarInt:
			result[name] = value.Int
		case serializedScalarBool:
			result[name] = value.Bool
		default:
			return nil, fmt.Errorf("unknown serialized scalar kind %d for %q", value.Kind, name)
		}
	}
	return result, nil
}

func serializeIntegerStats(stats map[string]any) map[string]int {
	result := make(map[string]int)
	for name, raw := range stats {
		if value, ok := raw.(int); ok {
			result[name] = value
		}
	}
	return result
}

func deserializeIntegerStats(stats map[string]int) map[string]any {
	result := make(map[string]any, len(stats))
	for name, value := range stats {
		result[name] = value
	}
	return result
}

func cloneACStringInfo(infos []ACStringInfo) []ACStringInfo {
	result := make([]ACStringInfo, len(infos))
	for index, info := range infos {
		result[index] = info
		result[index].Data = slices.Clone(info.Data)
	}
	return result
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

func cloneDependencyGraph(graph map[string][]string) map[string][]string {
	result := make(map[string][]string, len(graph))
	for name, dependencies := range graph {
		result[name] = append([]string{}, dependencies...)
		slices.Sort(result[name])
	}
	return result
}
