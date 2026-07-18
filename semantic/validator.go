package semantic

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cawalch/go-yara/ast"
	regexengine "github.com/cawalch/go-yara/regex"
	"github.com/cawalch/go-yara/token"
)

// Error represents a semantic analysis error
type Error struct {
	Message  string
	Position token.Position
	Rule     string
}

func (e *Error) Error() string {
	return fmt.Sprintf("semantic error at %d:%d: %s",
		e.Position.Line, e.Position.Column, e.Message)
}

// Validator performs semantic analysis on YARA rules
type Validator struct {
	symbolTable     *SymbolTable
	errors          []error
	loopVariables   map[string]string // loop variable name -> "string" or "integer"
	stringLoopDepth int
	currentRule     string
	moduleFunctions ModuleFunctions
	importedModules map[string]bool
}

// Ensure Validator implements the focused visitor interfaces it needs
var _ ast.RuleVisitor = (*Validator)(nil)
var _ ast.ExpressionVisitor = (*Validator)(nil)
var _ ast.ControlFlowVisitor = (*Validator)(nil)

// NewValidator creates a new semantic validator
func NewValidator() *Validator {
	return NewValidatorWithModules(nil)
}

// NewValidatorWithModules creates a validator that accepts the supplied
// module function signatures.
func NewValidatorWithModules(moduleFunctions ModuleFunctions) *Validator {
	return &Validator{
		symbolTable:     NewSymbolTable(),
		errors:          make([]error, 0),
		loopVariables:   make(map[string]string),
		moduleFunctions: moduleFunctions,
		importedModules: make(map[string]bool),
	}
}

// ValidateProgram performs semantic analysis on a complete program
func (v *Validator) ValidateProgram(program *ast.Program) []error {
	v.errors = v.errors[:0] // Clear previous errors
	v.symbolTable.Reset()
	v.currentRule = ""
	clear(v.importedModules)

	// First: validate module imports and remember the namespaces available to
	// dotted calls in rule conditions.
	for _, importStmt := range program.Imports {
		if !v.moduleFunctions.hasModule(importStmt.Module) {
			v.addError(v.unsupportedModuleError(importStmt.Module, importStmt.Pos))
			continue
		}
		v.importedModules[importStmt.Module] = true
	}

	// Second: collect global variables and external variables
	for _, globalVar := range program.GlobalVariables {
		v.collectGlobalVariable(globalVar)
	}
	for _, extVar := range program.ExternalVariables {
		v.collectExternalVariable(extVar)
	}

	// Third pass: collect all rule and string definitions
	for _, rule := range program.Rules {
		v.collectSymbols(rule)
	}

	// Fourth pass: reject circular rule dependencies before code generation.
	v.validateRuleDependencyCycles(program)

	// Fifth pass: validate all rules
	for _, rule := range program.Rules {
		v.validateRule(rule)
	}

	return v.errors
}

// collectSymbols collects all symbols from a rule
func (v *Validator) collectSymbols(rule *ast.Rule) {
	// Define the rule itself in the global scope (rules should be globally accessible)
	if err := v.symbolTable.DefineRule(rule.Name, rule.Pos, rule); err != nil {
		v.addError(&Error{
			Message:  err.Error(),
			Position: rule.Pos,
			Rule:     rule.Name,
		})
	}
}

func (v *Validator) validateRuleDependencyCycles(program *ast.Program) {
	ruleNames := make(map[string]token.Position, len(program.Rules))
	for _, rule := range program.Rules {
		ruleNames[rule.Name] = rule.Pos
	}

	deps := make(map[string]map[string]token.Position, len(program.Rules))
	for _, rule := range program.Rules {
		refs := make(map[string]token.Position)
		collector := ruleReferenceCollector{
			ruleNames: ruleNames,
			refs:      refs,
		}
		collector.collect(rule.Condition, nil)
		deps[rule.Name] = refs
	}

	state := make(map[string]int, len(program.Rules))
	reported := make(map[string]bool)
	var path []string
	var visit func(string)
	visit = func(ruleName string) {
		state[ruleName] = 1
		path = append(path, ruleName)
		defer func() {
			path = path[:len(path)-1]
			state[ruleName] = 2
		}()

		for dep, pos := range deps[ruleName] {
			switch state[dep] {
			case 0:
				visit(dep)
			case 1:
				cycle := appendCyclePath(path, dep)
				key := strings.Join(cycle, " -> ")
				if reported[key] {
					continue
				}
				reported[key] = true
				v.addError(&Error{
					Message:  "circular rule dependency: " + key,
					Position: pos,
					Rule:     ruleName,
				})
			}
		}
	}

	for _, rule := range program.Rules {
		if state[rule.Name] == 0 {
			visit(rule.Name)
		}
	}
}

func appendCyclePath(path []string, dep string) []string {
	for i, name := range path {
		if name == dep {
			cycle := make([]string, 0, len(path)-i+1)
			cycle = append(cycle, path[i:]...)
			cycle = append(cycle, dep)
			return cycle
		}
	}
	return append(append([]string{}, path...), dep)
}

type ruleReferenceCollector struct {
	ruleNames map[string]token.Position
	refs      map[string]token.Position
}

// RuleDependencies returns direct rule references for each rule in program.
// additionalRuleNames can be used to recognize references to rules that were
// removed from the AST, such as rules skipped during error recovery.
func RuleDependencies(program *ast.Program, additionalRuleNames ...string) map[string][]string {
	ruleNames := make(map[string]token.Position, len(program.Rules)+len(additionalRuleNames))
	for _, rule := range program.Rules {
		ruleNames[rule.Name] = rule.Pos
	}
	for _, name := range additionalRuleNames {
		if _, exists := ruleNames[name]; !exists {
			ruleNames[name] = token.Position{}
		}
	}

	dependencies := make(map[string][]string, len(program.Rules))
	for _, rule := range program.Rules {
		refs := make(map[string]token.Position)
		collector := ruleReferenceCollector{
			ruleNames: ruleNames,
			refs:      refs,
		}
		collector.collect(rule.Condition, nil)

		dependencies[rule.Name] = make([]string, 0, len(refs))
		for name := range refs {
			dependencies[rule.Name] = append(dependencies[rule.Name], name)
		}
		sort.Strings(dependencies[rule.Name])
	}
	return dependencies
}

func (c ruleReferenceCollector) collect(expr ast.Expression, scoped map[string]bool) {
	switch e := expr.(type) {
	case nil, *ast.Literal:
		return
	case *ast.Identifier:
		if scoped[e.Name] {
			return
		}
		if _, ok := c.ruleNames[e.Name]; ok {
			c.refs[e.Name] = e.Position()
		}
	case *ast.BinaryOp:
		c.collect(e.Left, scoped)
		c.collect(e.Right, scoped)
	case *ast.UnaryOp:
		c.collect(e.Right, scoped)
	case *ast.FunctionCall:
		for _, arg := range e.Args {
			c.collect(arg, scoped)
		}
	case *ast.ForLoop:
		c.collect(e.Range, scoped)
		innerScoped := cloneBoolMap(scoped)
		for _, variable := range e.Variables {
			innerScoped[variable] = true
		}
		c.collect(e.Condition, innerScoped)
		c.collect(e.InRange, innerScoped)
		c.collect(e.AtOffset, innerScoped)
	case *ast.OfExpression:
		c.collect(e.Count, scoped)
		c.collect(e.InRange, scoped)
		c.collect(e.AtOffset, scoped)
	case *ast.StringLength:
		c.collect(e.Index, scoped)
	case *ast.StringOffset:
		c.collect(e.Index, scoped)
	case *ast.StringCount:
		c.collect(e.Index, scoped)
	case *ast.LengthOf:
		return
	case *ast.PercentExpression:
		c.collect(e.Value, scoped)
	case *ast.StringTuple:
		return
	}
}

func cloneBoolMap(src map[string]bool) map[string]bool {
	dst := make(map[string]bool, len(src)+1)
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

// collectGlobalVariable collects a global variable symbol.
func (v *Validator) collectGlobalVariable(globalVar *ast.GlobalVariable) {
	typeInfo := &TypeInfo{DataType: TypeUnknown}
	if globalVar.Value != nil {
		var errs []error
		typeInfo, errs = v.validateExpression(globalVar.Value)
		v.addErrors(errs)
	}
	if typeInfo == nil || typeInfo.DataType == TypeUnknown {
		v.addError(&Error{
			Message:  "global variable " + globalVar.Name + " must have a literal integer, string, or boolean value",
			Position: globalVar.Pos,
		})
		return
	}

	def := globalVariableDefinition{
		name:     globalVar.Name,
		pos:      globalVar.Pos,
		global:   globalVar,
		typeInfo: typeInfo,
	}
	if err := v.symbolTable.defineGlobalVariable(def); err != nil {
		v.addError(&Error{
			Message:  err.Error(),
			Position: globalVar.Pos,
		})
	}
}

// collectExternalVariable collects an external variable symbol
func (v *Validator) collectExternalVariable(extVar *ast.ExternalVariable) {
	if err := v.symbolTable.DefineVariable(extVar.Name, extVar.Pos, SymbolExternal); err != nil {
		v.addError(&Error{
			Message:  err.Error(),
			Position: extVar.Pos,
		})
	}
}

// validateRule performs semantic validation on a single rule
func (v *Validator) validateRule(rule *ast.Rule) {
	previousRule := v.currentRule
	v.currentRule = rule.Name
	defer func() {
		v.currentRule = previousRule
	}()

	// Enter rule scope for validation
	v.symbolTable.EnterScope("rule_" + rule.Name)

	// Re-define strings in the new scope for validation
	for _, str := range rule.Strings {
		if err := v.symbolTable.DefineString(str.Identifier, str.Pos, str); err != nil {
			v.addError(&Error{
				Message:  err.Error(),
				Position: str.Pos,
			})
		}
	}

	// Validate meta section
	v.validateMeta(rule.Meta)

	// Validate strings section
	v.validateStrings(rule.Strings)
	v.validateEvidence(rule)

	// Validate condition
	v.validateCondition(rule.Condition)

	// Exit rule scope
	v.symbolTable.ExitScope()
}

const maxCaptureBindings = 32

func (v *Validator) validateEvidence(rule *ast.Rule) {
	captureNames := make(map[string]struct{})
	for _, str := range rule.Strings {
		captureModifiers := 0
		private := false
		var bindings []ast.CaptureBinding
		for _, modifier := range str.Modifiers {
			switch modifier.Type {
			case ast.StringModifierPrivate:
				private = true
			case ast.StringModifierCapture:
				captureModifiers++
				bindings, _ = modifier.Value.([]ast.CaptureBinding)
			}
		}
		if captureModifiers == 0 {
			continue
		}
		if captureModifiers > 1 {
			v.addEvidenceError(str.Pos, fmt.Sprintf("string %s has more than one capture modifier", str.Identifier))
		}
		if str.Identifier == "" || str.Identifier == "$" {
			v.addEvidenceError(str.Pos, fmt.Sprintf("anonymous string %s cannot declare captures", str.Identifier))
		}
		if private {
			v.addEvidenceError(str.Pos, fmt.Sprintf("string %s cannot combine private and capture modifiers", str.Identifier))
		}
		if len(bindings) == 0 {
			v.addEvidenceError(str.Pos, fmt.Sprintf("string %s has an empty capture modifier", str.Identifier))
			continue
		}
		if len(bindings) > maxCaptureBindings {
			v.addEvidenceError(str.Pos, fmt.Sprintf(
				"string %s declares %d capture bindings; maximum is %d",
				str.Identifier, len(bindings), maxCaptureBindings,
			))
		}
		groupCount, isRegex := semanticRegexGroupCount(str.Pattern)
		seen := make(map[string]struct{}, len(bindings))
		for _, binding := range bindings {
			if _, duplicate := seen[binding.Name]; duplicate {
				v.addEvidenceError(str.Pos, fmt.Sprintf("string %s declares capture name %q more than once", str.Identifier, binding.Name))
				continue
			}
			seen[binding.Name] = struct{}{}
			captureNames[binding.Name] = struct{}{}
			switch {
			case binding.Group < 0:
				v.addEvidenceError(str.Pos, fmt.Sprintf("string %s capture %q has invalid group %d", str.Identifier, binding.Name, binding.Group))
			case binding.Group > 0 && !isRegex:
				v.addEvidenceError(str.Pos, fmt.Sprintf(
					"string %s capture %q references group %d on a non-regex pattern",
					str.Identifier, binding.Name, binding.Group,
				))
			case binding.Group > groupCount:
				v.addEvidenceError(str.Pos, fmt.Sprintf("capture group %d is out of range for string %s", binding.Group, str.Identifier))
			}
		}
	}

	declarationNames := make(map[string]struct{}, len(rule.Evidence))
	for _, declaration := range rule.Evidence {
		if declaration == nil {
			continue
		}
		if declaration.Name == "" {
			v.addEvidenceError(declaration.Pos, "evidence declaration has an empty name")
		}
		if _, duplicate := declarationNames[declaration.Name]; duplicate {
			v.addEvidenceError(declaration.Pos, fmt.Sprintf("evidence declaration %q is duplicated", declaration.Name))
		}
		declarationNames[declaration.Name] = struct{}{}
		if len(declaration.Fields) == 0 {
			v.addEvidenceError(declaration.Pos, fmt.Sprintf("evidence declaration %q has no fields", declaration.Name))
		}
		if declaration.Within < 0 {
			v.addEvidenceError(declaration.Pos, fmt.Sprintf("evidence declaration %q has a negative window", declaration.Name))
		}
		if declaration.Anchor == "" {
			v.addEvidenceError(declaration.Pos, fmt.Sprintf("evidence declaration %q has an empty anchor", declaration.Name))
		}
		seenFields := make(map[string]struct{}, len(declaration.Fields))
		anchorIncluded := false
		for _, field := range declaration.Fields {
			if _, duplicate := seenFields[field]; duplicate {
				v.addEvidenceError(declaration.Pos, fmt.Sprintf("evidence declaration %q repeats field %q", declaration.Name, field))
			}
			seenFields[field] = struct{}{}
			anchorIncluded = anchorIncluded || field == declaration.Anchor
			if _, declared := captureNames[field]; !declared {
				v.addEvidenceError(declaration.Pos, fmt.Sprintf(
					"evidence declaration %q references undeclared capture %q", declaration.Name, field,
				))
			}
		}
		if !anchorIncluded {
			v.addEvidenceError(declaration.Pos, fmt.Sprintf(
				"evidence declaration %q anchor %q is not in its field list", declaration.Name, declaration.Anchor,
			))
		}
	}
}

func (v *Validator) addEvidenceError(position token.Position, message string) {
	v.addError(&Error{Message: message, Position: position})
}

func semanticRegexGroupCount(pattern ast.Pattern) (int, bool) {
	regexPattern, ok := pattern.(*ast.RegexPattern)
	if !ok {
		return 0, false
	}
	literal := regexPattern.Value
	if len(literal) >= 2 && literal[0] == '/' {
		end := len(literal) - 1
		for end > 0 && literal[end] != '/' {
			end--
		}
		if end > 0 {
			literal = literal[1:end]
		}
	}
	parsed, err := regexengine.NewParser(regexengine.ParserFlagEnableStrictEscapeSequences).Parse(literal)
	if err != nil {
		return int(^uint(0) >> 1), true
	}
	return parsed.GroupCount, true
}

// validateMeta validates the meta section
func (v *Validator) validateMeta(meta []*ast.Meta) {
	for _, m := range meta {
		// Check for duplicate meta keys (already handled by parser, but double-check)
		if existing, exists := v.symbolTable.LookupInCurrentScope(m.Key); exists {
			if existing.Type == SymbolVariable {
				v.addError(&Error{
					Message:  "duplicate meta key: " + m.Key,
					Position: m.Pos,
				})
			}
		}

		// Define meta as variable for potential use in conditions
		if err := v.symbolTable.DefineVariable(m.Key, m.Pos, SymbolVariable); err != nil {
			v.addError(&Error{
				Message:  err.Error(),
				Position: m.Pos,
			})
		}
	}
}

// validateStrings validates the strings section
func (v *Validator) validateStrings(stringsSlice []*ast.String) {
	for _, str := range stringsSlice {
		// Mark string as used when referenced in condition
		// This will be checked later during condition validation
		v.symbolTable.MarkUsed(str.Identifier)
	}
}

// validateCondition validates the condition expression
func (v *Validator) validateCondition(condition ast.Expression) {
	if condition != nil {
		conditionType, errs := v.validateExpression(condition)
		v.addErrors(errs)

		// Condition should evaluate to boolean or numeric (integers/floats are truthy/falsy)
		if conditionType != nil && conditionType.DataType != TypeUnknown && conditionType.DataType != TypeBoolean && !conditionType.IsNumeric() {
			v.addError(&Error{
				Message:  "condition must evaluate to boolean or numeric",
				Position: condition.Position(),
			})
		}
	}
}

// validateExpression validates an expression and returns its type
func (v *Validator) validateExpression(expr ast.Expression) (*TypeInfo, []error) {
	switch {
	case v.isSimpleExpression(expr):
		return v.validateSimpleExpression(expr)
	case v.isOperationExpression(expr):
		return v.validateOperationExpression(expr)
	case v.isSpecialExpression(expr):
		return v.validateSpecialExpression(expr)
	default:
		return v.validateUnknownExpression()
	}
}

// isSimpleExpression checks if expression is a simple type (literal, identifier)
func (v *Validator) isSimpleExpression(expr ast.Expression) bool {
	switch expr.(type) {
	case *ast.Literal, *ast.Identifier:
		return true
	default:
		return false
	}
}

// isOperationExpression checks if expression is an operation (binary, unary)
func (v *Validator) isOperationExpression(expr ast.Expression) bool {
	switch expr.(type) {
	case *ast.BinaryOp, *ast.UnaryOp:
		return true
	default:
		return false
	}
}

// isSpecialExpression checks if expression is a special type (function call, for loop, etc.)
func (v *Validator) isSpecialExpression(expr ast.Expression) bool {
	switch expr.(type) {
	case *ast.OfExpression, *ast.FunctionCall, *ast.ForLoop, *ast.PercentExpression:
		return true
	case *ast.StringLength, *ast.StringOffset, *ast.StringCount, *ast.LengthOf:
		return true
	default:
		return false
	}
}

// validateSimpleExpression validates simple expressions (literals, identifiers)
func (v *Validator) validateSimpleExpression(expr ast.Expression) (*TypeInfo, []error) {
	switch e := expr.(type) {
	case *ast.Literal:
		return v.validateLiteralExpression(e)
	case *ast.Identifier:
		return v.validateIdentifierExpression(e)
	default:
		return v.validateUnknownExpression()
	}
}

// validateOperationExpression validates operation expressions (binary, unary)
func (v *Validator) validateOperationExpression(expr ast.Expression) (*TypeInfo, []error) {
	switch e := expr.(type) {
	case *ast.BinaryOp:
		return v.validateBinaryOpExpression(e)
	case *ast.UnaryOp:
		return v.validateUnaryOpExpression(e)
	default:
		return v.validateUnknownExpression()
	}
}

// validateSpecialExpression validates special expressions (function calls, for loops, etc.)
func (v *Validator) validateSpecialExpression(expr ast.Expression) (*TypeInfo, []error) {
	switch e := expr.(type) {
	case *ast.OfExpression:
		return v.validateOfExpression(e)
	case *ast.FunctionCall:
		return v.validateFunctionCallExpression(e)
	case *ast.ForLoop:
		return v.validateForLoopExpression(e)
	case *ast.StringLength:
		return v.validateStringLengthExpression(e)
	case *ast.StringOffset:
		return v.validateStringOffsetExpression(e)
	case *ast.StringCount:
		return v.validateStringCountExpression(e)
	case *ast.LengthOf:
		return v.validateLengthOfExpression(e)
	case *ast.PercentExpression:
		return v.validatePercentExpression(e)
	default:
		return v.validateUnknownExpression()
	}
}

// validateUnknownExpression handles unknown expression types
func (v *Validator) validateUnknownExpression() (*TypeInfo, []error) {
	// Unrecognized expression nodes carry an unknown type.
	return &TypeInfo{DataType: TypeUnknown}, nil
}

// validateLiteralExpression validates literal expressions
func (v *Validator) validateLiteralExpression(lit *ast.Literal) (*TypeInfo, []error) {
	return InferTypeFromLiteral(lit.Type, lit.Value), nil
}

// validateIdentifierExpression validates identifier expressions
func (v *Validator) validateIdentifierExpression(ident *ast.Identifier) (*TypeInfo, []error) {
	var errors []error

	// Check for special keywords first
	switch ident.Name {
	case "filesize", "entrypoint", "flags":
		return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}, nil
	case "them":
		return &TypeInfo{DataType: TypeBoolean}, nil
	case "$":
		return v.validateQuantifierSymbol(ident)
	case "all", "any", "none":
		// Quantifier keywords - these are used in "all of them" expressions
		// They will be handled by the BinaryOp case with OF operator
		return &TypeInfo{DataType: TypeUnknown}, nil
	// Data type functions
	case "uint8", "uint16", "uint32", "uint8be", "uint16be", "uint32be":
		return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}, nil
	case "int8", "int16", "int32", "int8be", "int16be", "int32be":
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}, nil
	}

	// Look up the identifier in symbol table
	if symbol, exists := v.symbolTable.Lookup(ident.Name); exists {
		symbol.Used = true
		info := v.getTypeFromSymbol(symbol)
		// If symbol is a loop variable, use the loopVariables map for type info
		if info.DataType == TypeUnknown || symbol.Type == SymbolVariable {
			if typ, ok := v.loopVariables[ident.Name]; ok {
				switch typ {
				case "string":
					return &TypeInfo{DataType: TypeString}, nil
				case "integer":
					return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}, nil
				}
			}
		}
		return info, nil
	}

	// Try alternative lookups for special cases
	return v.tryAlternativeIdentifierLookups(ident, errors)
}

// validateQuantifierSymbol handles the special $ symbol in quantifiers
func (v *Validator) validateQuantifierSymbol(ident *ast.Identifier) (*TypeInfo, []error) {
	if v.stringLoopDepth == 0 {
		return &TypeInfo{DataType: TypeUnknown}, []error{&Error{
			Message:  "anonymous string placeholder cannot be used directly; use a string-set expression such as them",
			Position: ident.Position(),
		}}
	}
	// "$" refers to the current string in a for-loop body (for any of them : ($)).
	// In that context it evaluates to boolean (whether the string matched), so
	// it must be typed as SymbolString, not SymbolVariable.
	if symbol, exists := v.symbolTable.LookupInCurrentScope("$"); exists {
		return v.getTypeFromSymbol(symbol), nil
	}
	if err := v.symbolTable.DefineVariable("$", ident.Position(), SymbolString); err != nil {
		return &TypeInfo{DataType: TypeUnknown}, []error{&Error{
			Message:  err.Error(),
			Position: ident.Position(),
		}}
	}
	if symbol, exists := v.symbolTable.Lookup("$"); exists {
		return v.getTypeFromSymbol(symbol), nil
	}
	return &TypeInfo{DataType: TypeBoolean}, nil
}

// tryAlternativeIdentifierLookups attempts to find identifier in alternative contexts
func (v *Validator) tryAlternativeIdentifierLookups(ident *ast.Identifier, errors []error) (*TypeInfo, []error) {
	// Check if this is a wildcard string set identifier (e.g., $a*, $str*)
	// These are valid in quantifier expressions like "any of ($a*)" or "#a in (1..3) of ($a*)"
	// The compiler handles expansion at compile time; we just need to allow the identifier.
	if strings.HasPrefix(ident.Name, "$") && strings.HasSuffix(ident.Name, "*") {
		return &TypeInfo{DataType: TypeBoolean}, nil
	}

	// Check if this might be a string reference without the $ prefix
	// This happens when using #, @, or ! operators in conditions
	if stringSymbol, hasStringSymbol := v.symbolTable.Lookup("$" + ident.Name); hasStringSymbol {
		stringSymbol.Used = true
		return v.getTypeFromSymbol(stringSymbol), nil
	}

	// Bare dotted identifiers are structured module/member references. The
	// current module registry exposes typed function calls, not object fields,
	// so fail explicitly instead of guessing a placeholder type.
	if moduleName, ok := moduleNameFromDottedName(ident.Name); ok {
		errors = append(errors, v.unsupportedModuleError(moduleName, ident.Position()))
		return &TypeInfo{DataType: TypeUnknown}, errors
	}

	// Check if this might be a rule reference from an included file
	// Rules are globally accessible, so check the global scope
	if globalSymbol, hasGlobalSymbol := v.symbolTable.LookupInGlobalScope(ident.Name); hasGlobalSymbol {
		globalSymbol.Used = true
		return v.getTypeFromSymbol(globalSymbol), nil
	}

	errors = append(errors, &Error{
		Message:  "undefined identifier: " + ident.Name,
		Position: ident.Position(),
	})
	return &TypeInfo{DataType: TypeUnknown}, errors
}

// validateBinaryOpExpression validates binary operation expressions
func (v *Validator) validateBinaryOpExpression(binOp *ast.BinaryOp) (*TypeInfo, []error) {
	var errors []error

	// Special handling for module access (dot notation)
	if binOp.Op == token.DOT {
		if moduleName, handled := moduleNameFromMemberAccess(binOp); handled {
			errors = append(errors, v.unsupportedModuleError(moduleName, binOp.Position()))
			return &TypeInfo{DataType: TypeUnknown}, errors
		}
	}

	leftType, leftErrs := v.validateExpression(binOp.Left)
	rightType, rightErrs := v.validateExpression(binOp.Right)

	errors = append(errors, leftErrs...)
	errors = append(errors, rightErrs...)

	if leftType != nil && rightType != nil {
		resultType, err := InferTypeFromBinaryOp(leftType, binOp.Op, rightType)
		if err != nil {
			errors = append(errors, &Error{
				Message:  err.Error(),
				Position: binOp.Position(),
			})
			return &TypeInfo{DataType: TypeUnknown}, errors
		}
		return resultType, errors
	}

	return &TypeInfo{DataType: TypeUnknown}, errors
}

// validateUnaryOpExpression validates unary operation expressions
func (v *Validator) validateUnaryOpExpression(unaryOp *ast.UnaryOp) (*TypeInfo, []error) {
	var errors []error

	// Special handling for string operators before validating the operand
	// This is needed because we need to check if the operand is a string identifier
	if unaryOp.Op == token.NOT || unaryOp.Op == token.HASH || unaryOp.Op == token.AT {
		if resultType, handled := v.handleStringOperators(unaryOp, errors); handled {
			return resultType, errors
		}
	}

	operandType, operandErrs := v.validateExpression(unaryOp.Right)
	errors = append(errors, operandErrs...)

	if operandType != nil {
		resultType, err := InferTypeFromUnaryOp(unaryOp.Op, operandType)
		if err != nil {
			errors = append(errors, &Error{
				Message:  err.Error(),
				Position: unaryOp.Position(),
			})
			return &TypeInfo{DataType: TypeUnknown}, errors
		}
		return resultType, errors
	}

	return &TypeInfo{DataType: TypeUnknown}, errors
}

// handleStringOperators handles string-specific unary operators
func (v *Validator) handleStringOperators(unaryOp *ast.UnaryOp, _ []error) (*TypeInfo, bool) {
	if ident, ok := unaryOp.Right.(*ast.Identifier); ok {
		// Check if this is a string reference (with or without $ prefix)
		var stringName string
		if strings.HasPrefix(ident.Name, "$") {
			stringName = ident.Name
		} else {
			// Try with $ prefix for string references in conditions
			stringName = "$" + ident.Name
		}

		if symbol, exists := v.symbolTable.Lookup(stringName); exists && symbol.Type == SymbolString {
			// All string operators (#, @, !) return integer
			return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}, true
		}
	}
	return nil, false
}

// validateOfExpression validates of expressions
func (v *Validator) validateOfExpression(ofExpr *ast.OfExpression) (*TypeInfo, []error) {
	var errors []error

	// Validate the count expression
	_, countErrs := v.validateExpression(ofExpr.Count)
	errors = append(errors, countErrs...)

	// Validate the strings expression
	_, stringsErrs := v.validateExpression(ofExpr.Strings)
	errors = append(errors, stringsErrs...)
	if containsAnonymousPlaceholder(ofExpr.Strings) {
		errors = append(errors, &Error{
			Message:  "anonymous string placeholder cannot be used in explicit string lists; use them",
			Position: ofExpr.Strings.Position(),
		})
	}

	// Of expressions always return boolean
	return &TypeInfo{DataType: TypeBoolean}, errors
}

// validateFunctionCallExpression validates function call expressions
func (v *Validator) validateFunctionCallExpression(funcCall *ast.FunctionCall) (*TypeInfo, []error) {
	var errors []error

	if moduleName, ok := moduleNameFromDottedName(funcCall.Function); ok {
		moduleFunction, exists := v.moduleFunctions[funcCall.Function]
		if !exists {
			errors = append(errors, v.unsupportedModuleError(moduleName, funcCall.Pos))
			return &TypeInfo{DataType: TypeUnknown}, errors
		}
		if !v.importedModules[moduleName] {
			errors = append(errors, &Error{
				Message:  fmt.Sprintf("module %q must be imported before calling %s", moduleName, funcCall.Function),
				Position: funcCall.Pos,
			})
			return &TypeInfo{DataType: moduleFunction.ReturnType}, errors
		}
		return v.validateModuleFunctionCall(funcCall, moduleFunction)
	}

	// Check if this is a valid YARA function call
	validFunctions := map[string]struct {
		minArgs  int
		maxArgs  int
		dataType DataType
		retType  *IntegerType
	}{
		"UINT8":    {1, 1, TypeInteger, Uint8Type},
		"UINT16":   {1, 1, TypeInteger, Uint16Type},
		"UINT32":   {1, 1, TypeInteger, Uint32Type},
		"UINT8BE":  {1, 1, TypeInteger, Uint8Type},
		"UINT16BE": {1, 1, TypeInteger, Uint16Type},
		"UINT32BE": {1, 1, TypeInteger, Uint32Type},
		"INT8":     {1, 1, TypeInteger, Int8Type},
		"INT16":    {1, 1, TypeInteger, Int16Type},
		"INT32":    {1, 1, TypeInteger, Int32Type},
		"INT8BE":   {1, 1, TypeInteger, Int8Type},
		"INT16BE":  {1, 1, TypeInteger, Int16Type},
		"INT32BE":  {1, 1, TypeInteger, Int32Type},
		"INT64BE":  {1, 1, TypeInteger, Int64BEType},
		// Lowercase function names (from parser mapping)
		"uint8":    {1, 1, TypeInteger, Uint8Type},
		"uint16":   {1, 1, TypeInteger, Uint16Type},
		"uint32":   {1, 1, TypeInteger, Uint32Type},
		"uint64":   {1, 1, TypeInteger, Uint64Type},
		"uint8be":  {1, 1, TypeInteger, Uint8BEType},
		"uint16be": {1, 1, TypeInteger, Uint16BEType},
		"uint32be": {1, 1, TypeInteger, Uint32BEType},
		"uint64be": {1, 1, TypeInteger, Uint64BEType},
		"int8":     {1, 1, TypeInteger, Int8Type},
		"int16":    {1, 1, TypeInteger, Int16Type},
		"int32":    {1, 1, TypeInteger, Int32Type},
		"int64":    {1, 1, TypeInteger, Int64Type},
		"int8be":   {1, 1, TypeInteger, Int8BEType},
		"int16be":  {1, 1, TypeInteger, Int16BEType},
		"int32be":  {1, 1, TypeInteger, Int32BEType},
		"int64be":  {1, 1, TypeInteger, Int64BEType},
		// Text/hash functions
		"concat":   {2, 255, TypeString, nil},
		"tostring": {1, 1, TypeString, nil},
		"int":      {1, 1, TypeInteger, Int64Type},
		"md5":      {1, 2, TypeString, nil},
		"sha1":     {1, 2, TypeString, nil},
		"sha256":   {1, 2, TypeString, nil},
	}

	// Reject keywords that should not be function calls
	if funcCall.Function == "FILESIZE" || funcCall.Function == "ENTRYPOINT" {
		errors = append(errors, &Error{
			Message:  fmt.Sprintf("'%s' is a keyword, not a function - use without parentheses", funcCall.Function),
			Position: funcCall.Pos,
		})
		return &TypeInfo{DataType: TypeUnknown}, errors
	}

	// Check if function is valid
	funcInfo, isValid := validFunctions[funcCall.Function]
	if !isValid {
		errors = append(errors, &Error{
			Message:  fmt.Sprintf("unknown function: %s", funcCall.Function),
			Position: funcCall.Pos,
		})
		return &TypeInfo{DataType: TypeUnknown}, errors
	}

	// Validate argument count
	argCount := len(funcCall.Args)
	if argCount < funcInfo.minArgs || argCount > funcInfo.maxArgs {
		errors = append(errors, &Error{
			Message:  fmt.Sprintf("function '%s' expects %d to %d arguments, got %d", funcCall.Function, funcInfo.minArgs, funcInfo.maxArgs, argCount),
			Position: funcCall.Pos,
		})
	}

	// Validate function arguments
	argTypes := make([]*TypeInfo, len(funcCall.Args))
	for i, arg := range funcCall.Args {
		argType, argErrs := v.validateExpression(arg)
		argTypes[i] = argType
		errors = append(errors, argErrs...)
	}
	errors = append(errors, v.validateFunctionArgumentTypes(funcCall, argTypes)...)

	// Return appropriate type based on function
	return &TypeInfo{DataType: funcInfo.dataType, IntegerType: funcInfo.retType}, errors
}

func (v *Validator) validateModuleFunctionCall(
	funcCall *ast.FunctionCall,
	function ModuleFunction,
) (*TypeInfo, []error) {
	errors := make([]error, 0)
	argTypes := make([]*TypeInfo, len(funcCall.Args))
	for index, arg := range funcCall.Args {
		argType, argErrors := v.validateExpression(arg)
		argTypes[index] = argType
		errors = append(errors, argErrors...)
	}

	matchedArity := false
	for _, signature := range function.Signatures {
		if len(signature) != len(argTypes) {
			continue
		}
		matchedArity = true
		matches := true
		for index, expected := range signature {
			actual := argTypes[index]
			if actual != nil && actual.DataType != TypeUnknown && actual.DataType != expected {
				matches = false
				break
			}
		}
		if matches {
			return &TypeInfo{DataType: function.ReturnType}, errors
		}
	}

	message := fmt.Sprintf("module function %q does not accept the supplied argument types", funcCall.Function)
	if !matchedArity {
		message = fmt.Sprintf("module function %q does not accept %d arguments", funcCall.Function, len(argTypes))
	}
	errors = append(errors, &Error{Message: message, Position: funcCall.Pos})
	return &TypeInfo{DataType: function.ReturnType}, errors
}

func (v *Validator) validateFunctionArgumentTypes(funcCall *ast.FunctionCall, argTypes []*TypeInfo) []error {
	var errors []error
	switch {
	case isIntegerReadFunction(funcCall.Function):
		if len(argTypes) == 1 && !isIntegerCompatible(argTypes[0]) {
			errors = append(errors, &Error{
				Message:  fmt.Sprintf("function '%s' argument 1 must be integer", funcCall.Function),
				Position: funcCall.Args[0].Position(),
			})
		}
	case isHashFunction(funcCall.Function):
		errors = append(errors, validateHashFunctionArguments(funcCall, argTypes)...)
	}
	return errors
}

func validateHashFunctionArguments(funcCall *ast.FunctionCall, argTypes []*TypeInfo) []error {
	switch len(argTypes) {
	case 1:
		if !isStringCompatible(argTypes[0]) {
			return []error{&Error{
				Message:  fmt.Sprintf("function '%s' argument 1 must be string", funcCall.Function),
				Position: funcCall.Args[0].Position(),
			}}
		}
	case 2:
		var errors []error
		if !isIntegerCompatible(argTypes[0]) {
			errors = append(errors, &Error{
				Message:  fmt.Sprintf("function '%s' argument 1 must be integer", funcCall.Function),
				Position: funcCall.Args[0].Position(),
			})
		}
		if !isIntegerCompatible(argTypes[1]) {
			errors = append(errors, &Error{
				Message:  fmt.Sprintf("function '%s' argument 2 must be integer", funcCall.Function),
				Position: funcCall.Args[1].Position(),
			})
		}
		return errors
	}
	return nil
}

func isIntegerReadFunction(name string) bool {
	switch strings.ToLower(name) {
	case "uint8", "uint16", "uint32", "uint64",
		"uint8be", "uint16be", "uint32be", "uint64be",
		"int8", "int16", "int32", "int64",
		"int8be", "int16be", "int32be", "int64be":
		return true
	default:
		return false
	}
}

func isHashFunction(name string) bool {
	switch name {
	case "md5", "sha1", "sha256":
		return true
	default:
		return false
	}
}

func isIntegerCompatible(typeInfo *TypeInfo) bool {
	return typeInfo == nil || typeInfo.DataType == TypeUnknown || typeInfo.DataType == TypeInteger
}

func isStringCompatible(typeInfo *TypeInfo) bool {
	return typeInfo == nil || typeInfo.DataType == TypeUnknown || typeInfo.DataType == TypeString
}

func containsAnonymousPlaceholder(expr ast.Expression) bool {
	switch e := expr.(type) {
	case nil:
		return false
	case *ast.Identifier:
		return e.Name == "$"
	case *ast.StringTuple:
		for _, element := range e.Elements {
			if containsAnonymousPlaceholder(element) {
				return true
			}
		}
	case *ast.BinaryOp:
		return containsAnonymousPlaceholder(e.Left) || containsAnonymousPlaceholder(e.Right)
	case *ast.UnaryOp:
		return containsAnonymousPlaceholder(e.Right)
	case *ast.FunctionCall:
		for _, arg := range e.Args {
			if containsAnonymousPlaceholder(arg) {
				return true
			}
		}
	case *ast.ForLoop:
		return containsAnonymousPlaceholder(e.Range) ||
			containsAnonymousPlaceholder(e.Condition) ||
			containsAnonymousPlaceholder(e.InRange) ||
			containsAnonymousPlaceholder(e.AtOffset)
	case *ast.OfExpression:
		return containsAnonymousPlaceholder(e.Count) ||
			containsAnonymousPlaceholder(e.Strings) ||
			containsAnonymousPlaceholder(e.InRange) ||
			containsAnonymousPlaceholder(e.AtOffset)
	case *ast.StringLength:
		return containsAnonymousPlaceholder(e.String) || containsAnonymousPlaceholder(e.Index)
	case *ast.StringOffset:
		return containsAnonymousPlaceholder(e.String) || containsAnonymousPlaceholder(e.Index)
	case *ast.StringCount:
		return containsAnonymousPlaceholder(e.String) || containsAnonymousPlaceholder(e.Index)
	case *ast.LengthOf:
		return containsAnonymousPlaceholder(e.Target)
	case *ast.PercentExpression:
		return containsAnonymousPlaceholder(e.Value)
	}
	return false
}

func isAnonymousPlaceholder(expr ast.Expression) bool {
	ident, ok := expr.(*ast.Identifier)
	return ok && ident.Name == "$"
}

func isStringSetExpression(expr ast.Expression) bool {
	switch e := expr.(type) {
	case nil:
		return false
	case *ast.Identifier:
		return e.Name == "them" || (strings.HasPrefix(e.Name, "$") && e.Name != "$")
	case *ast.StringTuple:
		for _, element := range e.Elements {
			if !isStringSetExpression(element) {
				return false
			}
		}
		return true
	case *ast.BinaryOp:
		return e.Op == token.COMMA && isStringSetExpression(e.Left) && isStringSetExpression(e.Right)
	default:
		return false
	}
}

// validateForLoopExpression validates for loop expressions
func (v *Validator) validateForLoopExpression(forLoop *ast.ForLoop) (*TypeInfo, []error) {
	var errors []error

	// Determine loop variable type from range expression
	loopVarType := ""
	switch r := forLoop.Range.(type) {
	case *ast.StringTuple:
		loopVarType = "string"
	case *ast.Literal:
		if r.Type == token.StringLit {
			loopVarType = "string"
		}
	case *ast.BinaryOp:
		// Integer range (min..max)
		if r.Op == token.DOT {
			loopVarType = "integer"
		}
	case *ast.Identifier:
		// String set iteration: for any s in ($*), for any s in (them)
		loopVarType = "string"
	}
	if loopVarType == "" && isStringSetExpression(forLoop.Range) {
		loopVarType = "string"
	}
	if containsAnonymousPlaceholder(forLoop.Range) {
		errors = append(errors, &Error{
			Message:  "anonymous string placeholder cannot be used in explicit string lists; use them",
			Position: forLoop.Range.Position(),
		})
	}

	// Create a scope for the loop variables so it is visible in the condition.
	v.symbolTable.EnterScope("for_loop")
	for _, variable := range forLoop.Variables {
		if variable != "" {
			if variable == "$" {
				errors = append(errors, &Error{
					Message:  "for-loop variable cannot be anonymous string placeholder $",
					Position: forLoop.Pos,
				})
				continue
			}
			if err := v.symbolTable.DefineVariable(variable, forLoop.Pos, SymbolVariable); err != nil {
				errors = append(errors, &Error{
					Message:  err.Error(),
					Position: forLoop.Pos,
				})
			}
			if loopVarType != "" {
				v.loopVariables[variable] = loopVarType
			}
		}
	}

	// Validate the range expression
	_, rangeErrs := v.validateExpression(forLoop.Range)
	errors = append(errors, rangeErrs...)

	// Validate the condition expression
	if loopVarType == "string" {
		v.stringLoopDepth++
	}
	_, conditionErrs := v.validateExpression(forLoop.Condition)
	if loopVarType == "string" {
		v.stringLoopDepth--
	}
	errors = append(errors, conditionErrs...)

	// Clean up loop variables
	for _, variable := range forLoop.Variables {
		delete(v.loopVariables, variable)
	}

	v.symbolTable.ExitScope()

	// For loops always return boolean
	return &TypeInfo{DataType: TypeBoolean}, errors
}

// getTypeFromSymbol returns the type information for a symbol
func (v *Validator) getTypeFromSymbol(symbol *Symbol) *TypeInfo {
	switch symbol.Type {
	case SymbolRule:
		return &TypeInfo{DataType: TypeBoolean}
	case SymbolString:
		// String identifiers in conditions evaluate to boolean (whether the string is found)
		return &TypeInfo{DataType: TypeBoolean}
	case SymbolVariable:
		// Variables without explicit type metadata default to int64.
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
	case SymbolExternal:
		// Runtime external variables are dynamically typed by the caller.
		return &TypeInfo{DataType: TypeUnknown}
	case SymbolGlobal:
		if symbol.TypeInfo != nil {
			return symbol.TypeInfo
		}
		return &TypeInfo{DataType: TypeUnknown}
	default:
		return &TypeInfo{DataType: TypeUnknown}
	}
}

// addError adds a semantic error
func (v *Validator) addError(err error) {
	if semanticErr, ok := err.(*Error); ok && semanticErr.Rule == "" {
		semanticErr.Rule = v.currentRule
	}
	v.errors = append(v.errors, err)
}

func (v *Validator) addErrors(errs []error) {
	for _, err := range errs {
		v.addError(err)
	}
}

// GetErrors returns all semantic errors
func (v *Validator) GetErrors() []error {
	return v.errors
}

// HasErrors returns true if there are semantic errors
func (v *Validator) HasErrors() bool {
	return len(v.errors) > 0
}

// GetSymbolTable returns the symbol table
func (v *Validator) GetSymbolTable() *SymbolTable {
	return v.symbolTable
}

// ============================================================================
// Visitor Pattern Implementation - Focused Interface Methods
// ============================================================================

// RuleVisitor implementations

// VisitGlobalVariable visits a global variable - not used directly in validator
func (v *Validator) VisitGlobalVariable(node *ast.GlobalVariable) any {
	return nil
}

// VisitImport visits an import statement - not used directly in validator but needed for AST visitor
func (v *Validator) VisitImport(node *ast.Import) any {
	return nil
}

// VisitInclude visits an include statement - not used directly in validator but needed for AST visitor
func (v *Validator) VisitInclude(node *ast.Include) any {
	return nil
}

// VisitExternalVariable visits a global variable - not used directly in validator but needed for AST visitor
func (v *Validator) VisitExternalVariable(node *ast.ExternalVariable) any {
	return nil
}

// Ensure Validator implements ast.Visitor completely
var _ ast.Visitor = (*Validator)(nil)

// VisitProgram visits and validates a program node
func (v *Validator) VisitProgram(program *ast.Program) any {
	return v.ValidateProgram(program)
}

// VisitRule visits and validates a rule node
func (v *Validator) VisitRule(rule *ast.Rule) any {
	v.validateRule(rule)
	return nil
}

// VisitMeta visits and validates a meta node
func (v *Validator) VisitMeta(_ *ast.Meta) any {
	// Meta validation is handled in validateMeta
	return nil
}

// VisitTextString visits and validates a text string node
func (v *Validator) VisitTextString(_ *ast.TextString) any {
	return nil
}

// VisitHexString visits and validates a hex string node
func (v *Validator) VisitHexString(_ *ast.HexString) any {
	return nil
}

// VisitRegexPattern visits and validates a regex pattern node
func (v *Validator) VisitRegexPattern(_ *ast.RegexPattern) any {
	return nil
}

// VisitString visits and validates a string node
func (v *Validator) VisitString(_ *ast.String) any {
	// String validation is handled in validateStrings
	return nil
}

// VisitCondition visits and validates a condition node
func (v *Validator) VisitCondition(condition *ast.Condition) any {
	if condition.Expression != nil {
		v.validateCondition(condition.Expression)
	}
	return nil
}

// ExpressionVisitor implementations

// VisitBinaryOp visits and validates a binary operation node
func (v *Validator) VisitBinaryOp(_ *ast.BinaryOp) any {
	// Binary operation validation is handled in validateExpression
	return nil
}

// VisitUnaryOp visits and validates a unary operation node
func (v *Validator) VisitUnaryOp(_ *ast.UnaryOp) any {
	// Unary operation validation is handled in validateExpression
	return nil
}

// VisitIdentifier visits and validates an identifier node
func (v *Validator) VisitIdentifier(_ *ast.Identifier) any {
	// Identifier validation is handled in validateExpression
	return nil
}

// VisitLiteral visits and validates a literal node
func (v *Validator) VisitLiteral(_ *ast.Literal) any {
	// Literal validation is handled in validateExpression
	return nil
}

// VisitFunctionCall visits and validates a function call node
func (v *Validator) VisitFunctionCall(_ *ast.FunctionCall) any {
	// FunctionCall validation is handled in validateExpression
	return nil
}

// VisitStringTuple visits a string tuple node
func (v *Validator) VisitStringTuple(node *ast.StringTuple) any {
	for _, expr := range node.Elements {
		expr.Accept(v)
	}
	return nil
}

// ControlFlowVisitor implementations

// VisitForLoop visits and validates a for loop node
func (v *Validator) VisitForLoop(_ *ast.ForLoop) any {
	// ForLoop validation is handled in validateExpression
	return nil
}

// VisitOfExpression visits and validates an of expression node
func (v *Validator) VisitOfExpression(_ *ast.OfExpression) any {
	// OfExpression validation is handled in validateExpression
	return nil
}

// VisitPercentExpression visits and validates a percent expression node
func (v *Validator) VisitPercentExpression(_ *ast.PercentExpression) any {
	// PercentExpression validation is handled in compileOfExpression
	return nil
}

// validatePercentExpression validates a percent expression ("N %")
func (v *Validator) validatePercentExpression(expr *ast.PercentExpression) (*TypeInfo, []error) {
	// The inner value should be an integer (1-100)
	valType, errs := v.validateExpression(expr.Value)
	if valType.DataType != TypeInteger {
		errs = append(errs, fmt.Errorf("percentage must be an integer, got %v", valType.DataType))
	}
	// PercentExpression itself is an integer (used as count in OfExpression)
	return &TypeInfo{DataType: TypeInteger}, errs
}

// VisitStringLength visits and validates a string length node
func (v *Validator) VisitStringLength(_ *ast.StringLength) any {
	// StringLength validation is handled in validateExpression
	return nil
}

// VisitStringOffset visits and validates a string offset node
func (v *Validator) VisitStringOffset(_ *ast.StringOffset) any {
	// StringOffset validation is handled in validateExpression
	return nil
}

// VisitStringCount visits and validates a string count node
func (v *Validator) VisitStringCount(_ *ast.StringCount) any {
	// StringCount validation is handled in validateExpression
	return nil
}

// VisitLengthOf visits and validates a length of node
func (v *Validator) VisitLengthOf(_ *ast.LengthOf) any {
	// LengthOf validation is handled in validateExpression
	return nil
}

// validateStringLengthExpression validates string length expressions (!a or !a[i])
func (v *Validator) validateStringLengthExpression(stringLength *ast.StringLength) (*TypeInfo, []error) {
	return v.validateStringIndexExpression(stringLength.String, stringLength.Index, "length")
}

// validateStringOffsetExpression validates string offset expressions (@a or @a[i])
func (v *Validator) validateStringOffsetExpression(stringOffset *ast.StringOffset) (*TypeInfo, []error) {
	return v.validateStringIndexExpression(stringOffset.String, stringOffset.Index, "offset")
}

// validateStringCountExpression validates string count expressions (#a or #a[i])
func (v *Validator) validateStringCountExpression(stringCount *ast.StringCount) (*TypeInfo, []error) {
	return v.validateStringIndexExpression(stringCount.String, stringCount.Index, "count")
}

// validateStringIndexExpression is the shared body for the string length / offset /
// count validators. The three AST node types (StringLength, StringOffset,
// StringCount) carry the same String and Index fields with the same semantics,
// so their validation differs only in the operator name used in the index-type
// error message. Returns TypeInteger, matching the YARA semantics of !a / @a / #a.
func (v *Validator) validateStringIndexExpression(str ast.Expression, index ast.Expression, opName string) (*TypeInfo, []error) {
	var errors []error

	if isAnonymousPlaceholder(str) && v.stringLoopDepth == 0 {
		errors = append(errors, &Error{
			Message:  "anonymous string placeholder cannot be used with string " + opName + " outside a string loop",
			Position: str.Position(),
		})
	} else if err := v.validateStringIdentifier(str); err != nil {
		errors = append(errors, err)
	}

	if index != nil {
		indexType, indexErrs := v.validateExpression(index)
		errors = append(errors, indexErrs...)

		if indexType != nil && indexType.DataType != TypeInteger {
			errors = append(errors, &Error{
				Message:  "string " + opName + " index must be integer",
				Position: index.Position(),
			})
		}
	}

	return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}, errors
}

// validateLengthOfExpression validates "length of" expressions
func (v *Validator) validateLengthOfExpression(lengthOf *ast.LengthOf) (*TypeInfo, []error) {
	var errors []error

	// Validate the target expression
	targetType, targetErrs := v.validateExpression(lengthOf.Target)
	errors = append(errors, targetErrs...)

	// The target should be a string identifier, quantified string, or special identifier (them/all)
	// String identifiers in conditions evaluate to boolean (found/not found), which is valid for length of
	if targetType != nil && targetType.DataType != TypeBoolean && targetType.DataType != TypeString && targetType.DataType != TypeUnknown {
		errors = append(errors, &Error{
			Message:  "length of target must be a string identifier",
			Position: lengthOf.Target.Position(),
		})
	}

	// Length of expressions return integers
	return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}, errors
}

// validateStringIdentifier validates that an expression can be a string identifier
func (v *Validator) validateStringIdentifier(expr ast.Expression) error {
	ident, ok := expr.(*ast.Identifier)
	if !ok {
		return &Error{
			Message:  "string operations require string identifier",
			Position: expr.Position(),
		}
	}

	// Check if this identifier could be a string reference
	var stringName string
	if strings.HasPrefix(ident.Name, "$") {
		stringName = ident.Name
	} else {
		// Try with $ prefix for string references in conditions
		stringName = "$" + ident.Name
	}

	if symbol, exists := v.symbolTable.Lookup(stringName); exists && symbol.Type == SymbolString {
		symbol.Used = true
	}

	// We accept the syntax even if string doesn't exist yet
	// This matches the lenient behavior of YARA validation
	return nil
}

func (v *Validator) unsupportedModuleError(moduleName string, pos token.Position) *Error {
	return &Error{
		Message:  "unsupported module: " + moduleName,
		Position: pos,
	}
}

func moduleNameFromDottedName(name string) (string, bool) {
	moduleName, _, found := strings.Cut(name, ".")
	if !found || moduleName == "" {
		return "", false
	}
	return moduleName, true
}

func moduleNameFromMemberAccess(expr ast.Expression) (string, bool) {
	binOp, ok := expr.(*ast.BinaryOp)
	if !ok || binOp.Op != token.DOT {
		return "", false
	}
	if _, ok := binOp.Right.(*ast.Identifier); !ok {
		return "", false
	}
	return leftmostIdentifierName(binOp.Left)
}

func leftmostIdentifierName(expr ast.Expression) (string, bool) {
	switch e := expr.(type) {
	case *ast.Identifier:
		if e.Name == "" {
			return "", false
		}
		if moduleName, ok := moduleNameFromDottedName(e.Name); ok {
			return moduleName, true
		}
		return e.Name, true
	case *ast.BinaryOp:
		if e.Op != token.DOT {
			return "", false
		}
		return leftmostIdentifierName(e.Left)
	default:
		return "", false
	}
}
