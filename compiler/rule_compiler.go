package compiler

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
	"github.com/cawalch/go-yara/token"
)

// RuleCompiler handles compilation of complete YARA rules
type RuleCompiler struct {
	emitter           *Emitter
	stringCompiler    *StringCompiler
	conditionCompiler *ConditionCompiler
	automaton         *ACAutomaton
	currentRule       *ast.Rule
	ruleIndex         int
	allPatterns       map[string][]byte
	textPatterns      map[string][]byte
	regexPatterns     map[string]RegexPattern
	hexPatterns       map[string]*HexPattern
	stringKinds       map[string]StringKind
	stringModifiers   map[string][]ast.StringModifier
	externalNames     []string
	globalNames       []string
	globalValues      map[string]compiledGlobalValue
}

// NewRuleCompiler creates a new rule compiler
func NewRuleCompiler() *RuleCompiler {
	emitter := NewEmitter()
	automaton := NewACAutomaton()

	return &RuleCompiler{
		emitter:           emitter,
		stringCompiler:    NewStringCompiler(emitter),
		conditionCompiler: NewConditionCompiler(emitter, make(map[string]int)),
		automaton:         automaton,
		ruleIndex:         0,
		allPatterns:       make(map[string][]byte),
		textPatterns:      make(map[string][]byte),
		regexPatterns:     make(map[string]RegexPattern),
		hexPatterns:       make(map[string]*HexPattern),
		stringKinds:       make(map[string]StringKind),
		stringModifiers:   make(map[string][]ast.StringModifier),
		externalNames:     make([]string, 0),
		globalNames:       make([]string, 0),
		globalValues:      make(map[string]compiledGlobalValue),
	}
}

// CompileRule compiles a complete YARA rule to bytecode
func (rc *RuleCompiler) CompileRule(rule *ast.Rule) (*CompiledRule, error) {
	rc.currentRule = rule

	// Reset components for new rule
	rc.emitter.Reset()
	rc.automaton = NewACAutomaton()
	rc.conditionCompiler.ResetForRule()
	rc.stringCompiler.Reset()
	rc.allPatterns = make(map[string][]byte)
	rc.textPatterns = make(map[string][]byte)
	rc.regexPatterns = make(map[string]RegexPattern)
	rc.hexPatterns = make(map[string]*HexPattern)
	rc.stringKinds = make(map[string]StringKind)
	rc.stringModifiers = make(map[string][]ast.StringModifier)

	anonymousStrings := rc.assignAnonymousStringIdentifiers(rule)

	// Compile strings first
	if err := rc.compileStrings(rule); err != nil {
		return nil, fmt.Errorf("compiling strings: %w", err)
	}
	externalSlots, err := rc.allocateExternalSlots(rc.stringCompiler.GetStringOffsets())
	if err != nil {
		return nil, err
	}
	globalSlots, err := rc.allocateGlobalSlots(rc.stringCompiler.GetStringOffsets(), externalSlots)
	if err != nil {
		return nil, err
	}

	// Compile the automaton if we have text strings
	if len(rc.textPatterns) > 0 {
		if err := rc.automaton.Compile(); err != nil {
			return nil, fmt.Errorf("compiling automaton: %w", err)
		}
	}

	// Compile condition
	rc.conditionCompiler.SetExternalVariables(externalSlots)
	rc.conditionCompiler.SetGlobalVariables(globalSlots)
	rc.conditionCompiler.SetAnonymousStrings(anonymousStrings)
	if err := rc.compileCondition(rule); err != nil {
		return nil, fmt.Errorf("compiling condition: %w", err)
	}

	// Finalize bytecode
	bytecode, err := rc.emitter.GetBytecode()
	if err != nil {
		return nil, fmt.Errorf("generating bytecode: %w", err)
	}

	// Create compiled rule
	compiledRule := &CompiledRule{
		Name:             rule.Name,
		Index:            rc.ruleIndex,
		Bytecode:         bytecode,
		StringCount:      len(rule.Strings),
		Strings:          rc.copyAllPatterns(),
		Automaton:        rc.automaton,
		StringSets:       rc.conditionCompiler.GetStringSets(),
		TextStringSets:   rc.conditionCompiler.GetTextStringSets(),
		AnonymousStrings: anonymousStrings,
		StringLiterals:   rc.emitter.GetStringLiterals(),
		StringKinds:      rc.copyStringKinds(),
		StringModifiers:  rc.copyStringModifiers(),
		TextPatterns:     rc.copyTextPatterns(),
		RegexPatterns:    rc.copyRegexPatterns(),
		HexPatterns:      rc.copyHexPatterns(),
		Stats:            rc.snapshotCompilationStats(rule),
		ExternalSlots:    maps.Clone(externalSlots),
		GlobalSlots:      maps.Clone(globalSlots),
		GlobalValues:     rc.copyGlobalValuesForSlots(globalSlots),
		Tags:             rule.Tags,
		Meta:             rc.compileMeta(rule.Meta),
		IsGlobal:         rc.hasModifier(rule.Modifiers, ast.ModifierGlobal),
		IsPrivate:        rc.hasModifier(rule.Modifiers, ast.ModifierPrivate),
	}

	rc.ruleIndex++
	return compiledRule, nil
}

// hasModifier checks if the rule has a specific modifier
func (rc *RuleCompiler) hasModifier(modifiers []ast.Modifier, m ast.Modifier) bool {
	for _, mod := range modifiers {
		if mod == m {
			return true
		}
	}
	return false
}

// compileMeta converts AST metadata entries into a flat map[string]any
func (rc *RuleCompiler) compileMeta(metas []*ast.Meta) map[string]any {
	result := make(map[string]any, len(metas))
	for _, m := range metas {
		switch v := m.Value.(type) {
		case ast.MetaString:
			result[m.Key] = string(v)
		case ast.MetaInt:
			result[m.Key] = int64(v)
		case ast.MetaBool:
			result[m.Key] = bool(v)
		}
	}
	return result
}

// validateRuleStrings validates all strings in a rule
func (rc *RuleCompiler) validateRuleStrings(rule *ast.Rule) error {
	for _, str := range rule.Strings {
		if err := rc.stringCompiler.ValidateStringModifiers(str.Modifiers); err != nil {
			return fmt.Errorf("validating string %s: %w", str.Identifier, err)
		}
	}
	return nil
}

func (rc *RuleCompiler) assignAnonymousStringIdentifiers(rule *ast.Rule) []string {
	if rule == nil || len(rule.Strings) == 0 {
		return nil
	}
	used := make(map[string]struct{}, len(rule.Strings))
	for _, str := range rule.Strings {
		used[str.Identifier] = struct{}{}
	}

	anonymous := make([]string, 0)
	nextID := 1
	for _, str := range rule.Strings {
		if str.Identifier != "$" {
			continue
		}
		for {
			candidate := fmt.Sprintf("$__anon%d", nextID)
			nextID++
			if _, exists := used[candidate]; exists {
				continue
			}
			str.Identifier = candidate
			used[candidate] = struct{}{}
			anonymous = append(anonymous, candidate)
			break
		}
	}

	return anonymous
}

// calculateTextStringLength calculates the length of a text string with modifiers
func (rc *RuleCompiler) calculateTextStringLength(text string, modifiers []ast.StringModifier) int {
	l := len(text)
	// Wide strings double the byte length
	for _, m := range modifiers {
		if m.Type == ast.StringModifierWide {
			l *= 2
			break
		}
	}
	return l
}

// estimatePatternStates estimates the number of states needed for a pattern
func (rc *RuleCompiler) estimatePatternLength(str *ast.String) int {
	switch p := str.Pattern.(type) {
	case *ast.TextString:
		return rc.calculateTextStringLength(p.Value, str.Modifiers)
	case *ast.HexString:
		// Approximate: two hex digits per byte; ignore comments/whitespace
		return len(p.Value) / 2
	case *ast.RegexPattern:
		// Fallback to pattern length
		return len(p.Value)
	default:
		return 0
	}
}

// reserveCompilationResources reserves buffers and automaton capacity
func (rc *RuleCompiler) reserveCompilationResources(rule *ast.Rule) {
	// Pre-size buffers to reduce allocations
	rc.emitter.ReserveInstructions(2*len(rule.Strings) + 32)
	rc.automaton.ReserveStrings(len(rule.Strings))

	// Rough upper-bound estimate of states: 1 (root) + sum of pattern byte lengths
	expectedStates := 1
	for _, str := range rule.Strings {
		expectedStates += rc.estimatePatternLength(str)
	}
	rc.automaton.ReserveStates(expectedStates)
}

// compileRuleStrings compiles all strings in a rule and builds the automaton
func (rc *RuleCompiler) compileStrings(rule *ast.Rule) error {
	// First pass: validate and prepare strings
	if err := rc.validateRuleStrings(rule); err != nil {
		return err
	}

	// Reserve resources for compilation
	rc.reserveCompilationResources(rule)

	// Second pass: compile strings and build automaton
	for _, str := range rule.Strings {
		if err := rc.compileSingleString(str); err != nil {
			return fmt.Errorf("compiling string %s: %w", str.Identifier, err)
		}
	}

	return nil
}

// compileSingleString compiles a single string and adds it to the automaton
func (rc *RuleCompiler) compileSingleString(str *ast.String) error {
	rc.ensurePatternMaps()
	result, err := rc.compileStringPattern(str)
	if err != nil {
		return err
	}

	rc.recordStringOffset(str.Identifier)
	rc.recordPatternData(str.Identifier, result.patternData)
	switch result.kind {
	case StringKindText:
		if len(result.patternData) == 0 && len(result.altPatterns) == 0 {
			return fmt.Errorf("empty text pattern for %s", str.Identifier)
		}
		if err := rc.automaton.AddStringWithFlags(str.Identifier, result.patternData, false, false, result.patternFlags); err != nil {
			return err
		}
		for idx, alt := range result.altPatterns {
			flags := regex.Flags(0)
			if idx < len(result.altPatternFlags) {
				flags = result.altPatternFlags[idx]
			}
			if err := rc.automaton.AddStringWithFlags(str.Identifier, alt, false, false, flags); err != nil {
				return err
			}
		}
		rc.textPatterns[str.Identifier] = result.patternData
	case StringKindRegex:
		prefix, anchored := regex.LiteralPrefix(result.patternData)
		pattern := RegexPattern{
			Code:             result.patternData,
			Flags:            result.flags,
			prefix:           prefix,
			widePrefix:       widenRegexPrefix(prefix),
			atomMaxOffset:    -1,
			byteSetMaxOffset: -1,
			anchored:         anchored,
			cacheKey:         result.cacheKey,
			cacheIndex:       -1,
		}
		if atom, ok := selectMandatoryRegexAtom(result.regexAtoms); ok {
			pattern.atom = append([]byte(nil), atom.data...)
			pattern.wideAtom = widenRegexPrefix(atom.data)
			pattern.atomMinOffset = atom.minOffset
			pattern.atomMaxOffset = atom.maxOffset
		}
		if len(pattern.prefix) < minPrefilterAtomLength && len(pattern.atom) == 0 {
			if atoms, ok := selectAlternativeRegexAtoms(result.regexAlternatives); ok {
				pattern.alternativeAtoms = cloneRegexPrefilterAtoms(atoms)
				pattern.wideAlternativeAtoms = widenRegexPrefilterAtoms(atoms)
			}
		}
		if atom, ok := selectMandatoryRegexByteSetAtom(result.regexByteSetAtoms, result.flags); ok {
			pattern.byteSet = atom.set
			pattern.byteSetMinOffset = atom.minOffset
			pattern.byteSetMaxOffset = atom.maxOffset
			pattern.byteSetCount = atom.count
			pattern.byteSetLower, pattern.byteSetUpper, pattern.byteSetContiguous = atom.set.ContiguousRange()
		}
		pattern.fixedByteSets = slices.Clone(result.regexFixedByteSets)
		rc.regexPatterns[str.Identifier] = pattern
	case StringKindHex:
		rc.hexPatterns[str.Identifier] = result.hexPattern
	default:
		return fmt.Errorf("unsupported string kind for %s", str.Identifier)
	}
	rc.recordStringModifiers(str.Identifier, str.Modifiers)
	rc.stringKinds[str.Identifier] = result.kind
	return nil
}

type stringCompilationResult struct {
	patternData        []byte
	kind               StringKind
	flags              regex.Flags
	hexPattern         *HexPattern
	altPatterns        [][]byte
	patternFlags       regex.Flags
	altPatternFlags    []regex.Flags
	cacheKey           string
	regexAtoms         []regex.LiteralAtom
	regexAlternatives  [][]regex.LiteralAtom
	regexByteSetAtoms  []regex.ByteSetAtom
	regexFixedByteSets []regex.ByteSet
}

func (rc *RuleCompiler) compileStringPattern(str *ast.String) (*stringCompilationResult, error) {
	switch p := str.Pattern.(type) {
	case *ast.TextString:
		return rc.compileTextString(p.Value, str.Modifiers)
	case *ast.HexString:
		return rc.compileHexString(p.Value, str.Modifiers)
	case *ast.RegexPattern:
		return rc.compileRegexPattern(p, str.Modifiers)
	default:
		return nil, errors.New("unsupported pattern type")
	}
}

func (rc *RuleCompiler) compileTextString(value string, modifiers []ast.StringModifier) (*stringCompilationResult, error) {
	patterns, err := rc.stringCompiler.EncodeTextPatterns(value, modifiers)
	if err != nil {
		return nil, err
	}
	if len(patterns) == 0 {
		return nil, fmt.Errorf("empty text pattern")
	}

	optimized := make([]TextPattern, 0, len(patterns))
	for _, p := range patterns {
		useModifiers := modifiers
		if (p.Flags & regex.FlagsWide) == 0 {
			useModifiers = stripWideModifier(modifiers)
		}
		optimized = append(optimized, TextPattern{
			Data:  rc.stringCompiler.OptimizePattern(p.Data, useModifiers),
			Flags: p.Flags,
		})
	}
	patternData := optimized[0].Data
	patternFlags := optimized[0].Flags
	altPatterns := make([][]byte, 0, len(optimized)-1)
	altFlags := make([]regex.Flags, 0, len(optimized)-1)
	for _, p := range optimized[1:] {
		altPatterns = append(altPatterns, p.Data)
		altFlags = append(altFlags, p.Flags)
	}
	return &stringCompilationResult{
		patternData:     patternData,
		kind:            StringKindText,
		altPatterns:     altPatterns,
		patternFlags:    patternFlags,
		altPatternFlags: altFlags,
	}, nil
}

func stripWideModifier(modifiers []ast.StringModifier) []ast.StringModifier {
	out := make([]ast.StringModifier, 0, len(modifiers))
	for _, m := range modifiers {
		if m.Type == ast.StringModifierWide {
			continue
		}
		out = append(out, m)
	}
	return out
}

func (rc *RuleCompiler) compileHexString(value string, modifiers []ast.StringModifier) (*stringCompilationResult, error) {
	if rc.stringCompiler.hasModifier(modifiers, ast.StringModifierBase64) ||
		rc.stringCompiler.hasModifier(modifiers, ast.StringModifierBase64Wide) {
		return nil, fmt.Errorf("base64 modifiers are only supported for text strings")
	}
	hexPattern, err := rc.stringCompiler.parseHexPattern(value)
	if err != nil {
		return nil, err
	}
	if keys, ok := rc.stringCompiler.xorKeys(modifiers); ok {
		hexPattern.XorKeys = keys
	}
	hexPattern.cacheKey = patternCacheKey("hex", value, modifiers)
	hexPattern.cacheIndex = -1
	legacy := rc.stringCompiler.parseHexString(value)
	legacy = rc.stringCompiler.encodeHexString(legacy, modifiers)
	return &stringCompilationResult{
		patternData: legacy,
		kind:        StringKindHex,
		hexPattern:  hexPattern,
	}, nil
}

func (rc *RuleCompiler) compileRegexPattern(pattern *ast.RegexPattern, modifiers []ast.StringModifier) (*stringCompilationResult, error) {
	if rc.stringCompiler.hasModifier(modifiers, ast.StringModifierBase64) ||
		rc.stringCompiler.hasModifier(modifiers, ast.StringModifierBase64Wide) {
		return nil, fmt.Errorf("base64 modifiers are only supported for text strings")
	}
	code, parsed, err := rc.stringCompiler.compileRegexWithAST(pattern.Value, modifiers)
	if err != nil {
		return nil, fmt.Errorf("compile regex pattern: %w", err)
	}

	flags := rc.deriveRegexFlags(pattern.Value, modifiers)
	fixedByteSets, _ := regex.FixedByteSets(parsed, flags)
	return &stringCompilationResult{
		patternData:        code, // VM bytecode
		kind:               StringKindRegex,
		flags:              flags,
		cacheKey:           patternCacheKey("regex", pattern.Value, modifiers),
		regexAtoms:         regex.MandatoryLiteralAtoms(parsed),
		regexAlternatives:  regex.AlternativeMandatoryLiteralAtoms(parsed),
		regexByteSetAtoms:  regex.MandatoryByteSetAtoms(parsed),
		regexFixedByteSets: fixedByteSets,
	}, nil
}

func patternCacheKey(kind, value string, modifiers []ast.StringModifier) string {
	var key strings.Builder
	key.Grow(len(kind) + len(value) + len(modifiers)*8 + 2)
	key.WriteString(kind)
	key.WriteByte(0)
	key.WriteString(value)
	for _, modifier := range modifiers {
		key.WriteByte(0)
		fmt.Fprintf(&key, "%d=%v", modifier.Type, modifier.Value)
	}
	return key.String()
}

func (rc *RuleCompiler) deriveRegexFlags(patternValue string, modifiers []ast.StringModifier) regex.Flags {
	var flags regex.Flags

	// Flags from string modifiers
	for _, m := range modifiers {
		switch m.Type {
		case ast.StringModifierWide:
			flags |= regex.FlagsWide
		case ast.StringModifierNocase:
			flags |= regex.FlagsNoCase
		}
	}

	// Derive inline regex flags from literal suffix (e.g., /.../is)
	flags |= rc.parseInlineRegexFlags(patternValue)

	return flags
}

func (rc *RuleCompiler) parseInlineRegexFlags(patternValue string) regex.Flags {
	var flags regex.Flags

	if len(patternValue) < 2 || patternValue[0] != '/' {
		return flags
	}

	endIdx := len(patternValue) - 1
	for endIdx > 0 && patternValue[endIdx] != '/' {
		endIdx--
	}

	if endIdx > 0 && endIdx < len(patternValue)-1 {
		for i := endIdx + 1; i < len(patternValue); i++ {
			switch patternValue[i] {
			case 'i', 'I':
				flags |= regex.FlagsNoCase
			case 's', 'S':
				flags |= regex.FlagsDotAll
			}
		}
	}

	return flags
}

func (rc *RuleCompiler) recordStringOffset(identifier string) {
	offset := rc.automaton.StringCount
	rc.stringCompiler.stringOffsets[identifier] = offset
}

func (rc *RuleCompiler) recordStringModifiers(identifier string, modifiers []ast.StringModifier) {
	if rc.stringModifiers == nil {
		rc.stringModifiers = make(map[string][]ast.StringModifier)
	}
	if len(modifiers) == 0 {
		return
	}
	cp := make([]ast.StringModifier, len(modifiers))
	copy(cp, modifiers)
	rc.stringModifiers[identifier] = cp
}

func (rc *RuleCompiler) recordPatternData(identifier string, data []byte) {
	if rc.allPatterns == nil {
		rc.allPatterns = make(map[string][]byte)
	}
	if data == nil {
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	rc.allPatterns[identifier] = cp
}

func (rc *RuleCompiler) ensurePatternMaps() {
	if rc.allPatterns == nil {
		rc.allPatterns = make(map[string][]byte)
	}
	if rc.textPatterns == nil {
		rc.textPatterns = make(map[string][]byte)
	}
	if rc.regexPatterns == nil {
		rc.regexPatterns = make(map[string]RegexPattern)
	}
	if rc.hexPatterns == nil {
		rc.hexPatterns = make(map[string]*HexPattern)
	}
	if rc.stringKinds == nil {
		rc.stringKinds = make(map[string]StringKind)
	}
	if rc.stringModifiers == nil {
		rc.stringModifiers = make(map[string][]ast.StringModifier)
	}
}

// compileCondition compiles the rule condition
func (rc *RuleCompiler) compileCondition(rule *ast.Rule) error {
	// Set up string offsets for condition compiler
	stringOffsets := rc.stringCompiler.GetStringOffsets()
	rc.conditionCompiler.SetStringOffsets(stringOffsets)

	// Compile the condition expression using CompileBooleanExpression.
	// Short-circuit evaluation is disabled until the short-circuit code path properly
	// manages stack state (see compileShortCircuitBinary for details).
	if err := rc.conditionCompiler.CompileBooleanExpression(rule.Condition, false); err != nil {
		return fmt.Errorf("compiling condition: %w", err)
	}

	// Emit final halt instruction (use a default position)
	rc.emitter.EmitHalt(0, 0)

	// Resolve any pending jumps
	if err := rc.conditionCompiler.resolveJumps(); err != nil {
		return fmt.Errorf("resolving jumps: %w", err)
	}

	return nil
}

// CompileProgram compiles a complete YARA program (multiple rules)
func (rc *RuleCompiler) CompileProgram(program *ast.Program) ([]*CompiledRule, error) {
	compiledRules := make([]*CompiledRule, 0, len(program.Rules))
	rc.externalNames = rc.externalNames[:0]
	rc.globalNames = rc.globalNames[:0]
	rc.globalValues = make(map[string]compiledGlobalValue, len(program.GlobalVariables))
	rc.conditionCompiler.SetExternalVariables(make(map[string]int))
	rc.conditionCompiler.SetGlobalVariables(make(map[string]int))

	// First, register all global and external variables with the condition compiler.
	for _, globalVar := range program.GlobalVariables {
		if err := rc.registerGlobalVariable(globalVar); err != nil {
			return nil, err
		}
	}
	for _, extVar := range program.ExternalVariables {
		rc.registerExternalVariable(extVar)
	}

	// Build rule index map for resolving rule references
	ruleIndexMap := make(map[string]int)
	for i, rule := range program.Rules {
		ruleIndexMap[rule.Name] = i
	}

	// Set the rule index map in the condition compiler
	rc.conditionCompiler.SetRuleIndexMap(ruleIndexMap)

	for _, rule := range program.Rules {
		compiledRule, err := rc.CompileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("compiling rule %s: %w", rule.Name, err)
		}
		compiledRules = append(compiledRules, compiledRule)
	}

	return compiledRules, nil
}

// registerExternalVariable registers an external variable with the condition compiler
func (rc *RuleCompiler) registerExternalVariable(extVar *ast.ExternalVariable) {
	for _, name := range rc.externalNames {
		if name == extVar.Name {
			return
		}
	}
	rc.externalNames = append(rc.externalNames, extVar.Name)
}

func (rc *RuleCompiler) allocateExternalSlots(stringOffsets map[string]int) (map[string]int, error) {
	externalSlots := make(map[string]int, len(rc.externalNames))
	if len(rc.externalNames) == 0 {
		return externalSlots, nil
	}

	highestStringSlot := -1
	for _, slot := range stringOffsets {
		if slot > highestStringSlot {
			highestStringSlot = slot
		}
	}

	slot := interpreterMemorySlotCount - 1
	for _, name := range rc.externalNames {
		if slot <= highestStringSlot {
			return nil, fmt.Errorf("too many strings and external variables share interpreter memory")
		}
		externalSlots[name] = slot
		slot--
	}
	return externalSlots, nil
}

func (rc *RuleCompiler) registerGlobalVariable(globalVar *ast.GlobalVariable) error {
	for _, name := range rc.globalNames {
		if name == globalVar.Name {
			return fmt.Errorf("global variable %q already defined", globalVar.Name)
		}
	}
	value, err := compileGlobalValue(globalVar.Value)
	if err != nil {
		return fmt.Errorf("global variable %s: %w", globalVar.Name, err)
	}
	rc.globalNames = append(rc.globalNames, globalVar.Name)
	rc.globalValues[globalVar.Name] = value
	return nil
}

func (rc *RuleCompiler) allocateGlobalSlots(stringOffsets, externalSlots map[string]int) (map[string]int, error) {
	globalSlots := make(map[string]int, len(rc.globalNames))
	if len(rc.globalNames) == 0 {
		return globalSlots, nil
	}

	occupied := make(map[int]bool, len(externalSlots))
	for _, slot := range externalSlots {
		occupied[slot] = true
	}

	slot := highestMemorySlot(stringOffsets) + 1
	for _, name := range rc.globalNames {
		for slot < interpreterMemorySlotCount && occupied[slot] {
			slot++
		}
		if slot >= interpreterMemorySlotCount {
			return nil, fmt.Errorf("too many strings, external variables, and global variables share interpreter memory")
		}
		globalSlots[name] = slot
		occupied[slot] = true
		slot++
	}
	return globalSlots, nil
}

func highestMemorySlot(slots map[string]int) int {
	highest := -1
	for _, slot := range slots {
		if slot > highest {
			highest = slot
		}
	}
	return highest
}

func (rc *RuleCompiler) copyGlobalValuesForSlots(globalSlots map[string]int) map[string]compiledGlobalValue {
	values := make(map[string]compiledGlobalValue, len(globalSlots))
	for name := range globalSlots {
		values[name] = rc.globalValues[name]
	}
	return values
}

type compiledGlobalValue struct {
	valueType ValueType
	intVal    int64
	doubleVal float64
	stringVal string
}

func compileGlobalValue(expr ast.Expression) (compiledGlobalValue, error) {
	lit, ok := expr.(*ast.Literal)
	if !ok {
		return compiledGlobalValue{}, fmt.Errorf("initializer must be a literal")
	}

	switch lit.Type {
	case token.IntegerLit, token.HexIntegerLit, token.OctalIntegerLit, token.SizeLit:
		value, err := globalLiteralInt(lit)
		if err != nil {
			return compiledGlobalValue{}, err
		}
		return compiledGlobalValue{valueType: ValueTypeInt, intVal: value}, nil
	case token.FloatLit:
		value, err := globalLiteralFloat(lit)
		if err != nil {
			return compiledGlobalValue{}, err
		}
		return compiledGlobalValue{valueType: ValueTypeDouble, doubleVal: value}, nil
	case token.StringLit:
		value, ok := lit.Value.(string)
		if !ok {
			return compiledGlobalValue{}, fmt.Errorf("string literal has invalid value type %T", lit.Value)
		}
		return compiledGlobalValue{valueType: ValueTypeString, stringVal: value}, nil
	case token.TRUE, token.FALSE:
		value, err := globalLiteralBool(lit)
		if err != nil {
			return compiledGlobalValue{}, err
		}
		if value {
			return compiledGlobalValue{valueType: ValueTypeInt, intVal: 1}, nil
		}
		return compiledGlobalValue{valueType: ValueTypeInt, intVal: 0}, nil
	default:
		return compiledGlobalValue{}, fmt.Errorf("unsupported initializer literal type %s", lit.Type)
	}
}

func globalLiteralInt(lit *ast.Literal) (int64, error) {
	switch value := lit.Value.(type) {
	case int:
		return int64(value), nil
	case int8:
		return int64(value), nil
	case int16:
		return int64(value), nil
	case int32:
		return int64(value), nil
	case int64:
		return value, nil
	case string:
		if lit.Type == token.SizeLit {
			return parseSizeLiteral(value)
		}
		return strconv.ParseInt(value, 0, 64)
	default:
		return 0, fmt.Errorf("integer literal has invalid value type %T", lit.Value)
	}
}

func globalLiteralFloat(lit *ast.Literal) (float64, error) {
	switch value := lit.Value.(type) {
	case float32:
		return float64(value), nil
	case float64:
		return value, nil
	case string:
		return strconv.ParseFloat(value, 64)
	default:
		return 0, fmt.Errorf("float literal has invalid value type %T", lit.Value)
	}
}

func globalLiteralBool(lit *ast.Literal) (bool, error) {
	switch value := lit.Value.(type) {
	case bool:
		return value, nil
	case string:
		return strconv.ParseBool(value)
	default:
		return false, fmt.Errorf("boolean literal has invalid value type %T", lit.Value)
	}
}

// snapshotCompilationStats returns an owned snapshot of rule compilation stats.
func (rc *RuleCompiler) snapshotCompilationStats(rule *ast.Rule) map[string]any {
	stats := make(map[string]any)

	stats["instruction_count"] = rc.emitter.GetInstructionCount()
	stats["bytecode_size"] = rc.emitter.GetSize()
	stats["string_count"] = len(rule.Strings)
	stats["automaton_states"] = rc.automaton.GetStateCount()
	stats["variables"] = len(rc.conditionCompiler.GetVariableMap())

	// Add emitter stats
	emitterStats := rc.emitter.GetStats()
	for k, v := range emitterStats {
		stats["emitter_"+k] = v
	}

	// Add string compiler stats
	stringInfo := rc.stringCompiler.GetStringInfo()
	stats["string_info"] = stringInfo

	return stats
}

func cloneStats(stats map[string]any) map[string]any {
	if stats == nil {
		return nil
	}

	out := make(map[string]any, len(stats))
	for k, v := range stats {
		out[k] = cloneStatsValue(v)
	}
	return out
}

func cloneStatsValue(value any) any {
	switch v := value.(type) {
	case map[string]int:
		return maps.Clone(v)
	case []StringInfo:
		return cloneStringInfo(v)
	default:
		return v
	}
}

func cloneStringInfo(info []StringInfo) []StringInfo {
	out := make([]StringInfo, len(info))
	for i, item := range info {
		out[i] = item
		if item.Pattern != nil {
			out[i].Pattern = slices.Clone(item.Pattern)
		}
		if item.Modifiers != nil {
			out[i].Modifiers = slices.Clone(item.Modifiers)
		}
	}
	return out
}

func (rc *RuleCompiler) copyTextPatterns() map[string][]byte {
	out := make(map[string][]byte, len(rc.textPatterns))
	for k, v := range rc.textPatterns {
		cp := make([]byte, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

func (rc *RuleCompiler) copyAllPatterns() map[string][]byte {
	out := make(map[string][]byte, len(rc.allPatterns))
	for k, v := range rc.allPatterns {
		cp := make([]byte, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

func (rc *RuleCompiler) copyRegexPatterns() map[string]RegexPattern {
	out := make(map[string]RegexPattern, len(rc.regexPatterns))
	for k, v := range rc.regexPatterns {
		cp := make([]byte, len(v.Code))
		copy(cp, v.Code)
		out[k] = RegexPattern{
			Code:                 cp,
			Flags:                v.Flags,
			prefix:               slices.Clone(v.prefix),
			widePrefix:           slices.Clone(v.widePrefix),
			atom:                 slices.Clone(v.atom),
			wideAtom:             slices.Clone(v.wideAtom),
			atomMinOffset:        v.atomMinOffset,
			atomMaxOffset:        v.atomMaxOffset,
			alternativeAtoms:     cloneRegexPrefilterAtoms(v.alternativeAtoms),
			wideAlternativeAtoms: cloneRegexPrefilterAtoms(v.wideAlternativeAtoms),
			byteSet:              v.byteSet,
			byteSetMinOffset:     v.byteSetMinOffset,
			byteSetMaxOffset:     v.byteSetMaxOffset,
			byteSetCount:         v.byteSetCount,
			byteSetLower:         v.byteSetLower,
			byteSetUpper:         v.byteSetUpper,
			byteSetContiguous:    v.byteSetContiguous,
			fixedByteSets:        slices.Clone(v.fixedByteSets),
			anchored:             v.anchored,
			cacheKey:             v.cacheKey,
			cacheIndex:           v.cacheIndex,
		}
	}
	return out
}

func (rc *RuleCompiler) copyHexPatterns() map[string]*HexPattern {
	out := make(map[string]*HexPattern, len(rc.hexPatterns))
	for k, v := range rc.hexPatterns {
		if v == nil {
			continue
		}
		out[k] = v.Clone()
	}
	return out
}

func (rc *RuleCompiler) copyStringKinds() map[string]StringKind {
	return maps.Clone(rc.stringKinds)
}

func (rc *RuleCompiler) copyStringModifiers() map[string][]ast.StringModifier {
	out := make(map[string][]ast.StringModifier, len(rc.stringModifiers))
	for k, mods := range rc.stringModifiers {
		if len(mods) == 0 {
			continue
		}
		cp := make([]ast.StringModifier, len(mods))
		copy(cp, mods)
		out[k] = cp
	}
	return out
}

// CompiledRule represents a compiled YARA rule
type CompiledRule struct {
	Name             string            // Rule name
	Index            int               // Rule index in program
	Bytecode         []byte            // Compiled bytecode
	StringCount      int               // Number of strings
	Strings          map[string][]byte // String identifier to pattern data mapping
	Automaton        *ACAutomaton      // Aho-Corasick automaton for pattern matching
	StringSets       [][]string        // String sets for "of" expressions
	TextStringSets   [][]string        // Text string sets for text-string-set iteration
	AnonymousStrings []string          // Anonymous string identifiers for "$" expressions
	StringLiterals   []string          // String literal pool for OpPushStr
	StringKinds      map[string]StringKind
	StringModifiers  map[string][]ast.StringModifier
	TextPatterns     map[string][]byte
	RegexPatterns    map[string]RegexPattern
	HexPatterns      map[string]*HexPattern
	Stats            map[string]any // Compilation statistics (computed at compile time)
	ExternalSlots    map[string]int // external variable name -> interpreter memory slot
	GlobalSlots      map[string]int // global variable name -> interpreter memory slot
	GlobalValues     map[string]compiledGlobalValue

	// Integer string ID optimization (built during compilation)
	StringIDToIndex map[string]int   // string identifier ("$a") -> integer index
	IndexToStringID []string         // integer index -> string identifier (reverse lookup)
	StringNameToRef map[string]int64 // string identifier -> pre-computed StringRef for interpreter

	// Rule metadata (from AST)
	Tags      []string       // Rule tags (e.g., {"malware", "trojan"})
	Meta      map[string]any // Meta key-value pairs
	IsGlobal  bool           // Rule is marked as global
	IsPrivate bool           // Rule is marked as private
}

// GetName returns the rule name
func (cr *CompiledRule) GetName() string {
	return cr.Name
}

// GetBytecode returns the compiled bytecode
func (cr *CompiledRule) GetBytecode() []byte {
	return cr.Bytecode
}

// GetStrings returns the string pattern data
func (cr *CompiledRule) GetStrings() map[string][]byte {
	return cr.Strings
}

// GetStringCount returns the number of strings in this rule
func (cr *CompiledRule) GetStringCount() int {
	return cr.StringCount
}

// StringIdentifiers returns all string identifiers defined in the rule.
func (cr *CompiledRule) StringIdentifiers() []string {
	seen := make(map[string]struct{})
	for id := range cr.StringKinds {
		seen[id] = struct{}{}
	}
	for id := range cr.TextPatterns {
		seen[id] = struct{}{}
	}
	for id := range cr.RegexPatterns {
		seen[id] = struct{}{}
	}
	for id := range cr.HexPatterns {
		seen[id] = struct{}{}
	}
	for id := range cr.Strings {
		seen[id] = struct{}{}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// BuildStringIndex builds the integer string ID lookup tables.
// Must be called after all string patterns are added to the rule.
func (cr *CompiledRule) BuildStringIndex() {
	ids := cr.StringIdentifiers()
	cr.IndexToStringID = ids
	cr.StringIDToIndex = make(map[string]int, len(ids))
	for i, id := range ids {
		cr.StringIDToIndex[id] = i
	}

	// Pre-compute StringRef values for each string identifier.
	// StringLiterals are stored as negative refs: -1 = StringLiterals[0], -2 = StringLiterals[1], etc.
	// String identifiers that appear in StringLiterals get a fast O(1) lookup path.
	cr.StringNameToRef = make(map[string]int64, len(ids))
	literalMap := make(map[string]int64, len(cr.StringLiterals))
	for idx, lit := range cr.StringLiterals {
		literalMap[lit] = int64(-1 - idx)
	}
	for _, id := range ids {
		if ref, ok := literalMap[id]; ok {
			cr.StringNameToRef[id] = ref
		}
	}
}

// ResolveStringIndex returns the integer index for a string identifier.
func (cr *CompiledRule) ResolveStringIndex(id string) int {
	if idx, ok := cr.StringIDToIndex[id]; ok {
		return idx
	}
	return -1
}

// IsPrivateString reports whether a string identifier is marked as private.
func (cr *CompiledRule) IsPrivateString(identifier string) bool {
	return hasStringModifier(cr.StringModifiers[identifier], ast.StringModifierPrivate)
}

func hasStringModifier(modifiers []ast.StringModifier, modifierType ast.StringModifierType) bool {
	for _, mod := range modifiers {
		if mod.Type == modifierType {
			return true
		}
	}
	return false
}

// GetStats returns compilation statistics (computed at compile time).
func (cr *CompiledRule) GetStats() map[string]any {
	return cloneStats(cr.Stats)
}

// GetAutomaton returns the Aho-Corasick automaton
func (cr *CompiledRule) GetAutomaton() *ACAutomaton {
	return cr.Automaton
}

// Validate validates the compiled rule
func (cr *CompiledRule) Validate() error {
	if len(cr.Bytecode) == 0 {
		return errors.New("empty bytecode")
	}

	if len(cr.TextPatterns) > 0 && cr.Automaton == nil {
		return errors.New("strings present but no automaton")
	}

	if cr.Automaton != nil {
		if err := cr.Automaton.Validate(); err != nil {
			return fmt.Errorf("invalid automaton: %w", err)
		}
	}

	return nil
}

// GetMemoryUsage returns a deterministic heuristic byte estimate for the rule.
// It includes bytecode, automaton estimate, and coarse stats-map overhead.
// The value is useful for relative sizing and diagnostics; it is not an exact
// measurement of Go heap usage.
func (cr *CompiledRule) GetMemoryUsage() int {
	usage := len(cr.Bytecode)

	if cr.Automaton != nil {
		usage += cr.Automaton.EstimateMemoryUsage()
	}

	// Add stats map overhead (rough estimate)
	usage += len(cr.Stats) * 100

	return usage
}

// PrintDebug prints debug information about the compiled rule
func (cr *CompiledRule) PrintDebug() {
	fmt.Printf("Compiled Rule: %s\n", cr.Name)
	fmt.Printf("  Index: %d\n", cr.Index)
	fmt.Printf("  Bytecode Size: %d bytes\n", len(cr.Bytecode))
	fmt.Printf("  String Count: %d\n", cr.StringCount)
	fmt.Printf("  Memory Usage: ~%d bytes\n", cr.GetMemoryUsage())

	if cr.Automaton != nil {
		fmt.Printf("  Automaton States: %d\n", cr.Automaton.GetStateCount())
	}

	fmt.Printf("  Instructions: %d\n", cr.Stats["instruction_count"])

	// Print bytecode if not too large
	if len(cr.Bytecode) <= 64 {
		fmt.Printf("  Bytecode: %X\n", cr.Bytecode)
	} else {
		fmt.Printf("  Bytecode: %X... (truncated)\n", cr.Bytecode[:32])
	}
}

// CompiledProgram represents a complete compiled YARA program
// SharedAutomatonEntry maps a shared automaton entry to its exact verifier.
type SharedAutomatonEntry struct {
	RuleIndex  int // index into CompiledProgram.Rules
	StringIdx  int // index into CompiledRule.IndexToStringID
	Kind       StringKind
	AtomOffset int
	// AtomMaxOffset is the maximum number of bytes before a regex atom. It
	// equals AtomOffset for fixed-offset regex and hex atoms.
	AtomMaxOffset int
	IsWide        bool
	CacheIndex    int
}

type CompiledProgram struct {
	Rules           []*CompiledRule
	SharedAutomaton *ACAutomaton
	Stats           map[string]any
	externalValues  map[string]externalValue

	// Lookup table: shared automaton entry -> exact text/regex/hex verifier.
	// Built once at compile time, used by extractGlobalMatches for O(1) routing.
	SharedLookup []SharedAutomatonEntry

	// Number of compile-time integer slots used to cache regex/hex matches.
	nonTextCacheSize int
	fixedRegexScan   *fixedRegexDispatch

	// Streaming support
	streamingProcessor *StreamingProcessor
	enableStreaming    bool
}

// NewCompiledProgram creates a new compiled program
func NewCompiledProgram(rules []*CompiledRule) *CompiledProgram {
	return &CompiledProgram{
		Rules:           rules,
		Stats:           make(map[string]any),
		enableStreaming: false, // Disabled by default for backward compatibility
	}
}

// SetExternalVariables replaces runtime values for declared external variables.
func (cp *CompiledProgram) SetExternalVariables(vars map[string]any) error {
	values, err := normalizeExternalVariables(cp, vars)
	if err != nil {
		return err
	}
	cp.externalValues = values
	return nil
}

// SetSharedAutomaton attaches the global multi-rule search tree to the compiled program
func (cp *CompiledProgram) SetSharedAutomaton(automaton *ACAutomaton) {
	cp.SharedAutomaton = automaton
}

// GetRuleCount returns the number of compiled rules
func (cp *CompiledProgram) GetRuleCount() int {
	return len(cp.Rules)
}

// GetStringCount returns the total number of strings across all rules
func (cp *CompiledProgram) GetStringCount() int {
	total := 0
	for _, rule := range cp.Rules {
		total += rule.GetStringCount()
	}
	return total
}

// GetTotalBytecodeSize returns the total size of all bytecode
func (cp *CompiledProgram) GetTotalBytecodeSize() int {
	total := 0
	for _, rule := range cp.Rules {
		total += len(rule.Bytecode)
	}
	return total
}

// GetTotalMemoryUsage returns the sum of each rule's heuristic memory estimate.
// It is intended for relative sizing and diagnostics, not exact Go heap
// accounting for the compiled program.
func (cp *CompiledProgram) GetTotalMemoryUsage() int {
	total := 0
	for _, rule := range cp.Rules {
		total += rule.GetMemoryUsage()
	}
	return total
}

// Validate validates all compiled rules
func (cp *CompiledProgram) Validate() error {
	for i, rule := range cp.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("validating rule %d (%s): %w", i, rule.Name, err)
		}
	}
	return nil
}

// GetRuleByName finds a rule by name
func (cp *CompiledProgram) GetRuleByName(name string) (*CompiledRule, bool) {
	for _, rule := range cp.Rules {
		if rule.Name == name {
			return rule, true
		}
	}
	return nil, false
}

// PrintDebug prints debug information about the compiled program
func (cp *CompiledProgram) PrintDebug() {
	fmt.Printf("Compiled Program Debug Information:\n")
	fmt.Printf("  Rule Count: %d\n", len(cp.Rules))
	fmt.Printf("  Total Bytecode Size: %d bytes\n", cp.GetTotalBytecodeSize())
	fmt.Printf("  Total Memory Usage: ~%d bytes\n", cp.GetTotalMemoryUsage())

	fmt.Printf("\nRules:\n")
	for i, rule := range cp.Rules {
		fmt.Printf("  [%d] %s: %d bytes, %d strings\n",
			i, rule.Name, len(rule.Bytecode), rule.StringCount)
	}
}

// Optimize optimizes the compiled program for better performance
func (cp *CompiledProgram) Optimize() error {
	// This would perform various optimizations:
	// - Merge similar automata
	// - Eliminate redundant bytecode
	// - Optimize memory layout

	// For now, just validate
	return cp.Validate()
}

// GetExecutionPlan creates an execution plan for the compiled program
func (cp *CompiledProgram) GetExecutionPlan() *ExecutionPlan {
	plan := &ExecutionPlan{
		RuleCount:         len(cp.Rules),
		TotalInstructions: 0,
		MemoryLayout:      make([]MemoryRegion, 0),
	}

	// Calculate total instructions
	for _, rule := range cp.Rules {
		if stats, ok := rule.Stats["instruction_count"].(int); ok {
			plan.TotalInstructions += stats
		}
	}

	// Plan memory layout
	offset := 0
	for _, rule := range cp.Rules {
		size := len(rule.Bytecode)
		plan.MemoryLayout = append(plan.MemoryLayout, MemoryRegion{
			RuleIndex: rule.Index,
			Offset:    offset,
			Size:      size,
		})
		offset += size
	}

	return plan
}

// ExecutionPlan represents the execution plan for a compiled program
type ExecutionPlan struct {
	RuleCount         int
	TotalInstructions int
	MemoryLayout      []MemoryRegion
}

// MemoryRegion represents a memory region in the execution plan
type MemoryRegion struct {
	RuleIndex int
	Offset    int
	Size      int
}

// GetRuleOffset returns the bytecode offset for a rule
func (ep *ExecutionPlan) GetRuleOffset(ruleIndex int) (int, bool) {
	for _, region := range ep.MemoryLayout {
		if region.RuleIndex == ruleIndex {
			return region.Offset, true
		}
	}
	return 0, false
}

// GetTotalSize returns the total size of the execution plan
func (ep *ExecutionPlan) GetTotalSize() int {
	if len(ep.MemoryLayout) == 0 {
		return 0
	}
	lastRegion := ep.MemoryLayout[len(ep.MemoryLayout)-1]
	return lastRegion.Offset + lastRegion.Size
}

// Streaming methods for CompiledProgram.
//
// Streaming reports chunked string-pattern matches only. It does not evaluate
// rule condition bytecode. Use Scan, ScanReader, or ScanFile for full rule
// evaluation.

// EnableStreaming enables or disables pattern-only streaming for large files.
func (cp *CompiledProgram) EnableStreaming(enable bool) {
	cp.enableStreaming = enable
	if enable && cp.streamingProcessor == nil {
		cp.streamingProcessor = NewStreamingProcessor(cp)
	}
}

// IsStreamingEnabled returns true if streaming is enabled
func (cp *CompiledProgram) IsStreamingEnabled() bool {
	return cp.enableStreaming
}

// SetStreamingChunkSize sets the chunk size for streaming processing
func (cp *CompiledProgram) SetStreamingChunkSize(chunkSize int) {
	if cp.streamingProcessor != nil {
		cp.streamingProcessor.SetChunkSize(chunkSize)
	}
}

// SetStreamingConcurrency sets the maximum concurrency for streaming processing
func (cp *CompiledProgram) SetStreamingConcurrency(maxConcurrency int) {
	if cp.streamingProcessor != nil {
		cp.streamingProcessor.SetMaxConcurrency(maxConcurrency)
	}
}

// EnableStreamingEarlyTermination enables or disables early termination in streaming
func (cp *CompiledProgram) EnableStreamingEarlyTermination(enable bool) {
	if cp.streamingProcessor != nil {
		cp.streamingProcessor.EnableEarlyTermination(enable)
	}
}

// ProcessFileStreaming returns pattern matches from a file using chunked streaming.
func (cp *CompiledProgram) ProcessFileStreaming(ctx context.Context, filename string) ([]StreamingMatch, error) {
	if !cp.enableStreaming {
		return nil, errors.New("streaming is not enabled")
	}

	if cp.streamingProcessor == nil {
		cp.streamingProcessor = NewStreamingProcessor(cp)
	}

	return cp.streamingProcessor.ProcessFile(ctx, filename)
}

// ProcessBytesStreaming returns pattern matches from byte data using chunked streaming.
func (cp *CompiledProgram) ProcessBytesStreaming(ctx context.Context, data []byte) ([]StreamingMatch, error) {
	if !cp.enableStreaming {
		return nil, errors.New("streaming is not enabled")
	}

	if cp.streamingProcessor == nil {
		cp.streamingProcessor = NewStreamingProcessor(cp)
	}

	return cp.streamingProcessor.ProcessBytes(ctx, data)
}

// GetStreamingProgress returns progress information for streaming operations
func (cp *CompiledProgram) GetStreamingProgress() (processed, total int64, percent float64, matches int) {
	if cp.streamingProcessor != nil {
		return cp.streamingProcessor.GetProgress()
	}
	return 0, 0, 0, 0
}
