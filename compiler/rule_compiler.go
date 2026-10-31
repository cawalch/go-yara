package compiler

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/semantic"
	"github.com/cawalch/go-yara/token"
)

// ruleCompiler handles compilation of complete YARA rules
type ruleCompiler struct {
	emitter           *emitter
	stringCompiler    *stringCompiler
	conditionCompiler *conditionCompiler
	automaton         *acAutomaton
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
	moduleBindings    map[string]compiledModuleFunction
	moduleFunctions   map[builtinFunction]ModuleFunction
	moduleNames       map[builtinFunction]string
}

// newRuleCompiler creates a new rule compiler
func newRuleCompiler() *ruleCompiler {
	compiler, err := newRuleCompilerWithModules(nil)
	if err != nil {
		panic(err)
	}
	return compiler
}

// newRuleCompilerWithModules creates a rule compiler with pluggable module
// functions available to dotted calls.
func newRuleCompilerWithModules(modules map[string]Module) (*ruleCompiler, error) {
	emitter := newEmitter()
	automaton := newacAutomaton()
	bindings, functions, names, err := compileModuleFunctions(modules)
	if err != nil {
		return nil, err
	}
	conditionCompiler := newConditionCompiler(emitter, make(map[string]int))
	conditionCompiler.setModuleFunctions(bindings)
	conditionCompiler.moduleSchemas = registeredModuleSchemas(modules)
	conditionCompiler.moduleTypes = semanticModuleSchemas(modules)

	return &ruleCompiler{
		emitter:           emitter,
		stringCompiler:    newStringCompiler(),
		conditionCompiler: conditionCompiler,
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
		moduleBindings:    bindings,
		moduleFunctions:   functions,
		moduleNames:       names,
	}, nil
}

// CompileRule compiles a complete YARA rule to bytecode
func (rc *ruleCompiler) CompileRule(rule *ast.Rule) (*CompiledRule, error) {
	rc.currentRule = rule
	if err := validateCaptureAndEvidenceDeclarations(rule); err != nil {
		return nil, err
	}

	textStringCount := 0
	expectedStates := 1
	for _, str := range rule.Strings {
		if p, ok := str.Pattern.(*ast.TextString); ok {
			textStringCount++
			expectedStates += rc.calculateTextStringLength(p.Value, str.Modifiers)
		}
	}

	// Reset components for new rule
	rc.emitter.Reset()
	rc.automaton = newacAutomatonWithCapacity(expectedStates, textStringCount, expectedStates)
	rc.conditionCompiler.ResetForRule()
	rc.stringCompiler.Reset()
	rc.allPatterns = make(map[string][]byte, len(rule.Strings))
	rc.textPatterns = make(map[string][]byte, textStringCount)
	rc.regexPatterns = make(map[string]RegexPattern)
	rc.hexPatterns = make(map[string]*HexPattern)
	rc.stringKinds = make(map[string]StringKind, len(rule.Strings))
	rc.stringModifiers = make(map[string][]ast.StringModifier, len(rule.Strings))

	anonymousStrings := rc.assignAnonymousStringIdentifiers(rule)

	fixedTextOffsets := deriveFixedTextOffsets(rule)

	// Constant-fold condition and detect dead strings before compiling patterns
	rule.Condition = FoldConstants(rule.Condition)
	isDeadRule := isConditionStaticallyFalse(rule.Condition)
	deadStrings := detectDeadStrings(rule, anonymousStrings, isDeadRule)
	for id := range fixedTextOffsets {
		if deadStrings[id] {
			delete(fixedTextOffsets, id)
		}
	}

	// Compile strings first
	if err := rc.compileStrings(rule, deadStrings); err != nil {
		return nil, fmt.Errorf("compiling strings: %w", err)
	}
	externalSlots, err := rc.allocateExternalSlots(rc.stringCompiler.stringOffsets)
	if err != nil {
		return nil, err
	}
	globalSlots, err := rc.allocateGlobalSlots(rc.stringCompiler.stringOffsets, externalSlots)
	if err != nil {
		return nil, err
	}

	// Compile the automaton if we have text strings
	var ruleAutomaton *acAutomaton
	if len(rc.textPatterns) > 0 {
		if err := rc.automaton.Compile(); err != nil {
			return nil, fmt.Errorf("compiling automaton: %w", err)
		}
		ruleAutomaton = rc.automaton
	}

	// Compile condition
	rc.conditionCompiler.setExternalVariables(externalSlots)
	rc.conditionCompiler.setGlobalVariables(globalSlots)
	rc.conditionCompiler.globalValues = rc.globalValues
	rc.conditionCompiler.SetAnonymousStrings(anonymousStrings)
	if err := rc.compileCondition(rule); err != nil {
		return nil, fmt.Errorf("compiling condition: %w", err)
	}

	// Finalize bytecode
	bytecode, err := rc.emitter.GetBytecode()
	if err != nil {
		return nil, fmt.Errorf("generating bytecode: %w", err)
	}

	requiredStrings, forbiddenStrings := deriveStringPresenceBounds(rule.Condition, rule.Strings)

	// Create compiled rule
	compiledRule := &CompiledRule{
		Name:                rule.Name,
		Index:               rc.ruleIndex,
		Bytecode:            bytecode,
		StringCount:         len(rule.Strings),
		Strings:             rc.allPatterns,
		automaton:           ruleAutomaton,
		StringSets:          rc.conditionCompiler.GetStringSets(),
		TextStringSets:      rc.conditionCompiler.GetTextStringSets(),
		AnonymousStrings:    anonymousStrings,
		StringLiterals:      rc.emitter.GetStringLiterals(),
		StringKinds:         rc.stringKinds,
		StringModifiers:     rc.stringModifiers,
		CaptureBindings:     captureBindingsByPattern(rule),
		EvidencePlans:       compileEvidencePlans(rule.Evidence),
		TextPatterns:        rc.textPatterns,
		RegexPatterns:       rc.regexPatterns,
		HexPatterns:         rc.hexPatterns,
		Stats:               rc.snapshotCompilationStats(rule),
		ExternalSlots:       externalSlots,
		GlobalSlots:         globalSlots,
		GlobalValues:        rc.copyGlobalValuesForSlots(globalSlots),
		Tags:                rule.Tags,
		Meta:                rc.compileMeta(rule.Meta),
		IsGlobal:            rc.hasModifier(rule.Modifiers, ast.ModifierGlobal),
		IsPrivate:           rc.hasModifier(rule.Modifiers, ast.ModifierPrivate),
		IsDead:              isDeadRule,
		DeadStrings:         deadStrings,
		FastScanSafe:        !conditionObservesMatchOccurrences(rule.Condition) && !ruleDeclaresEvidence(rule),
		ConditionMonotonic:  !conditionObservesMatchOccurrences(rule.Condition) && !ruleDeclaresEvidence(rule) && conditionIsMonotonicInStrings(rule.Condition),
		RequiresStringMatch: len(rule.Strings) > 0 && conditionRequiresStringMatch(rule.Condition),
		ModuleFunctions:     rc.moduleFunctions,
		ModuleNames:         rc.moduleNames,
		HeaderConstraints:   deriveHeaderConstraints(rule.Condition),
		fixedTextOffsets:    fixedTextOffsets,
		assertions:          slices.Clone(rc.conditionCompiler.assertions),
		assertionProgram:    slices.Clone(rc.conditionCompiler.assertionProgram),
		moduleSchemas:       rc.conditionCompiler.moduleSchemas,
		moduleAccessNames:   slices.Clone(rc.conditionCompiler.moduleAccessNames),
		moduleIterations:    slices.Clone(rc.conditionCompiler.moduleIterations),
		mandatoryAssertions: mandatoryAssertionIndices(rule.Condition, rc.conditionCompiler.assertions),
		requiredStrings:     requiredStrings,
		forbiddenStrings:    forbiddenStrings,
		booleanPatterns:     booleanRoutingPatterns(rule),
	}

	rc.ruleIndex++
	return compiledRule, nil
}

func conditionObservesMatchOccurrences(expr ast.Expression) bool {
	switch e := expr.(type) {
	case nil, *ast.Literal, *ast.Identifier:
		return false
	case *ast.StringCount, *ast.StringOffset, *ast.StringLength, *ast.LengthOf:
		return true
	case *ast.BinaryOp:
		// MATCHES can inspect the content of every occurrence of a string.
		// Keeping only the first occurrence can discard a later qualifying match.
		if e.Op == token.AT || e.Op == token.IN || e.Op == token.MATCHES {
			return true
		}
		return conditionObservesMatchOccurrences(e.Left) || conditionObservesMatchOccurrences(e.Right)
	case *ast.UnaryOp:
		return conditionObservesMatchOccurrences(e.Right)
	case *ast.FunctionCall:
		for _, arg := range e.Args {
			if conditionObservesMatchOccurrences(arg) {
				return true
			}
		}
		return false
	case *ast.ForLoop:
		if e.InRange != nil || e.AtOffset != nil {
			return true
		}
		return conditionObservesMatchOccurrences(e.Range) || conditionObservesMatchOccurrences(e.Condition)
	case *ast.OfExpression:
		if e.InRange != nil || e.AtOffset != nil {
			return true
		}
		return conditionObservesMatchOccurrences(e.Count) || conditionObservesMatchOccurrences(e.Strings)
	case *ast.PercentExpression:
		return conditionObservesMatchOccurrences(e.Value)
	case *ast.StringTuple:
		for _, element := range e.Elements {
			if conditionObservesMatchOccurrences(element) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

func conditionIsMonotonicInStrings(expr ast.Expression) bool {
	switch e := expr.(type) {
	case nil, *ast.Literal:
		return true
	case *ast.Identifier:
		return true
	case *ast.BinaryOp:
		if e.Op == token.AND || e.Op == token.OR {
			return conditionIsMonotonicInStrings(e.Left) && conditionIsMonotonicInStrings(e.Right)
		}
		return !containsStringReference(e.Left) && !containsStringReference(e.Right)
	case *ast.UnaryOp:
		if e.Op == token.NOT {
			return !containsStringReference(e.Right)
		}
		return conditionIsMonotonicInStrings(e.Right)
	case *ast.OfExpression:
		if e.InRange != nil || e.AtOffset != nil {
			return false
		}
		if lit, ok := e.Count.(*ast.Literal); ok {
			if s, ok := lit.Value.(string); ok && strings.EqualFold(s, "none") {
				return false
			}
		}
		return true
	case *ast.StringTuple:
		for _, el := range e.Elements {
			if !conditionIsMonotonicInStrings(el) {
				return false
			}
		}
		return true
	default:
		return !containsStringReference(expr)
	}
}

func containsStringReference(expr ast.Expression) bool {
	switch e := expr.(type) {
	case nil, *ast.Literal:
		return false
	case *ast.Identifier:
		return strings.HasPrefix(e.Name, "$") || e.Name == "them"
	case *ast.StringCount, *ast.StringOffset, *ast.StringLength, *ast.LengthOf:
		return true
	case *ast.BinaryOp:
		return containsStringReference(e.Left) || containsStringReference(e.Right)
	case *ast.UnaryOp:
		return containsStringReference(e.Right)
	case *ast.MemberAccess:
		return containsStringReference(e.Object)
	case *ast.IndexAccess:
		return containsStringReference(e.Object) || containsStringReference(e.Index)
	case *ast.FunctionCall:
		for _, arg := range e.Args {
			if containsStringReference(arg) {
				return true
			}
		}
		return false
	case *ast.ForLoop:
		return containsStringReference(e.Range) || containsStringReference(e.Condition) || containsStringReference(e.InRange) || containsStringReference(e.AtOffset)
	case *ast.OfExpression:
		return true
	case *ast.PercentExpression:
		return containsStringReference(e.Value)
	case *ast.StringTuple:
		for _, el := range e.Elements {
			if containsStringReference(el) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// hasModifier checks if the rule has a specific modifier
func (rc *ruleCompiler) hasModifier(modifiers []ast.Modifier, m ast.Modifier) bool {
	for _, mod := range modifiers {
		if mod == m {
			return true
		}
	}
	return false
}

// compileMeta converts AST metadata entries into a flat map[string]any
func (rc *ruleCompiler) compileMeta(metas []*ast.Meta) map[string]any {
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
func (rc *ruleCompiler) validateRuleStrings(rule *ast.Rule) error {
	for _, str := range rule.Strings {
		if err := rc.stringCompiler.ValidateStringModifiers(str.Modifiers); err != nil {
			return fmt.Errorf("validating string %s: %w", str.Identifier, err)
		}
	}
	return nil
}

func (rc *ruleCompiler) assignAnonymousStringIdentifiers(rule *ast.Rule) []string {
	if rule == nil || len(rule.Strings) == 0 {
		return nil
	}
	hasAnonymous := false
	for _, str := range rule.Strings {
		if str != nil && str.Identifier == "$" {
			hasAnonymous = true
			break
		}
	}
	if !hasAnonymous {
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
func (rc *ruleCompiler) calculateTextStringLength(text string, modifiers []ast.StringModifier) int {
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

// reserveCompilationResources reserves buffers and automaton capacity
func (rc *ruleCompiler) reserveCompilationResources(rule *ast.Rule) {
	// Pre-size buffers to reduce allocations
	rc.emitter.ReserveInstructions(2*len(rule.Strings) + 32)
	rc.automaton.ReserveStrings(len(rule.Strings))

	expectedStates := 1
	for _, str := range rule.Strings {
		if p, ok := str.Pattern.(*ast.TextString); ok {
			expectedStates += rc.calculateTextStringLength(p.Value, str.Modifiers)
		}
	}
	rc.automaton.ReserveStates(expectedStates)
}

// compileCondition compiles the rule condition
func (rc *ruleCompiler) compileCondition(rule *ast.Rule) error {
	// Set up string offsets for condition compiler
	stringOffsets := rc.stringCompiler.stringOffsets
	rc.conditionCompiler.setStringOffsets(stringOffsets)

	// Compile the condition expression using CompileBooleanExpression.
	// Short-circuit evaluation is disabled until the short-circuit code path properly
	// manages stack state (see compileShortCircuitBinary for details).
	if !rc.conditionCompiler.compileAssertionProgram(rule.Condition) {
		if err := rc.conditionCompiler.CompileBooleanExpression(rule.Condition, false); err != nil {
			return fmt.Errorf("compiling condition: %w", err)
		}
	}

	// Emit final halt instruction (use a default position)
	rc.emitter.EmitHalt(0, 0)

	// Resolve any pending jumps
	if err := rc.conditionCompiler.resolveJumps(); err != nil {
		return fmt.Errorf("resolving jumps: %w", err)
	}

	return nil
}

// RuleCompileError identifies a code-generation failure for one rule. It lets
// resilient compilation omit that rule and its dependents without hiding
// program-level code-generation failures.
type RuleCompileError struct {
	Rule string
	Err  error
}

func (e *RuleCompileError) Error() string {
	return fmt.Sprintf("compiling rule %s: %v", e.Rule, e.Err)
}

// Unwrap returns the underlying code-generation error.
func (e *RuleCompileError) Unwrap() error {
	return e.Err
}

// CompileProgram compiles a complete YARA program (multiple rules)
func (rc *ruleCompiler) CompileProgram(program *ast.Program) ([]*CompiledRule, error) {
	compiledRules := make([]*CompiledRule, 0, len(program.Rules))
	rc.externalNames = rc.externalNames[:0]
	rc.globalNames = rc.globalNames[:0]
	rc.globalValues = make(map[string]compiledGlobalValue, len(program.GlobalVariables))
	rc.conditionCompiler.setExternalVariables(make(map[string]int))
	rc.conditionCompiler.setGlobalVariables(make(map[string]int))

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
	rc.conditionCompiler.setRuleIndexMap(ruleIndexMap)

	dependencies := semantic.RuleDependencies(program)
	for _, rule := range program.Rules {
		compiledRule, err := rc.CompileRule(rule)
		if err != nil {
			return nil, &RuleCompileError{Rule: rule.Name, Err: err}
		}
		compiledRule.dependencies = slices.Clone(dependencies[rule.Name])
		compiledRules = append(compiledRules, compiledRule)
	}

	return compiledRules, nil
}

// registerExternalVariable registers an external variable with the condition compiler
func (rc *ruleCompiler) registerExternalVariable(extVar *ast.ExternalVariable) {
	for _, name := range rc.externalNames {
		if name == extVar.Name {
			return
		}
	}
	rc.externalNames = append(rc.externalNames, extVar.Name)
}

func (rc *ruleCompiler) allocateExternalSlots(stringOffsets map[string]int) (map[string]int, error) {
	if len(rc.externalNames) == 0 {
		return nil, nil
	}
	externalSlots := make(map[string]int, len(rc.externalNames))

	highestStringSlot := -1
	for _, slot := range stringOffsets {
		if slot > highestStringSlot {
			highestStringSlot = slot
		}
	}

	slot := interpreterMemorySlotCount - 1
	for _, name := range rc.externalNames {
		if slot <= highestStringSlot {
			return nil, errors.New("too many strings and external variables share interpreter memory")
		}
		externalSlots[name] = slot
		slot--
	}
	return externalSlots, nil
}

func (rc *ruleCompiler) registerGlobalVariable(globalVar *ast.GlobalVariable) error {
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

func (rc *ruleCompiler) allocateGlobalSlots(stringOffsets, externalSlots map[string]int) (map[string]int, error) {
	if len(rc.globalNames) == 0 {
		return nil, nil
	}
	globalSlots := make(map[string]int, len(rc.globalNames))

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
			return nil, errors.New("too many strings, external variables, and global variables share interpreter memory")
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

func (rc *ruleCompiler) copyGlobalValuesForSlots(globalSlots map[string]int) map[string]compiledGlobalValue {
	if len(globalSlots) == 0 {
		return nil
	}
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
		return compiledGlobalValue{}, errors.New("initializer must be a literal")
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
		return parseIntLiteral(value)
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
func (rc *ruleCompiler) snapshotCompilationStats(rule *ast.Rule) map[string]any {
	stats := make(map[string]any, 12)

	stats["instruction_count"] = rc.emitter.GetInstructionCount()
	stats["bytecode_size"] = rc.emitter.GetSize()
	stats["string_count"] = len(rule.Strings)
	stats["automaton_states"] = rc.automaton.GetStateCount()
	stats["variables"] = len(rc.conditionCompiler.variableMap)

	// Add emitter stats
	emitterStats := rc.emitter.GetStats()
	for k, v := range emitterStats {
		stats["emitter_"+k] = v
	}

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
	default:
		return v
	}
}
