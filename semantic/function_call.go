package semantic

import (
	"fmt"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func (v *Validator) validateFunctionCallExpression(funcCall *ast.FunctionCall) (*TypeInfo, []error) {
	if moduleName, ok := moduleNameFromDottedName(funcCall.Function); ok {
		return v.validateDottedFunctionCall(funcCall, moduleName)
	}

	var errors []error

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
			Code:     ErrCodeInvalidFunction,
			Message:  fmt.Sprintf("'%s' is a keyword, not a function - use without parentheses", funcCall.Function),
			Position: funcCall.Pos,
			Rule:     v.currentRule,
		})
		return &TypeInfo{DataType: TypeUnknown}, errors
	}

	// Check if function is valid
	funcInfo, isValid := validFunctions[funcCall.Function]
	if !isValid {
		err := &Error{
			Code:     ErrCodeInvalidFunction,
			Message:  "unknown function: " + funcCall.Function,
			Position: funcCall.Pos,
			Rule:     v.currentRule,
		}
		var fnNames []string
		for name := range validFunctions {
			fnNames = append(fnNames, name)
		}
		if sugg, ok := findSimilarIdentifier(funcCall.Function, fnNames); ok {
			err.Suggestion = sugg
		}
		errors = append(errors, err)
		return &TypeInfo{DataType: TypeUnknown}, errors
	}

	// Validate argument count
	argCount := len(funcCall.Args)
	if argCount < funcInfo.minArgs || argCount > funcInfo.maxArgs {
		errors = append(errors, &Error{
			Code:     ErrCodeInvalidArgumentCount,
			Message:  fmt.Sprintf("function '%s' expects %d to %d arguments, got %d", funcCall.Function, funcInfo.minArgs, funcInfo.maxArgs, argCount),
			Position: funcCall.Pos,
			Rule:     v.currentRule,
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

func (v *Validator) validateDottedFunctionCall(funcCall *ast.FunctionCall, moduleName string) (*TypeInfo, []error) {
	moduleFunction, exists := v.moduleFunctions[funcCall.Function]
	if !exists {
		if v.moduleFunctions.hasModule(moduleName) {
			return &TypeInfo{DataType: TypeUnknown}, []error{v.unknownModuleFunctionError(funcCall, moduleName)}
		}
		return &TypeInfo{DataType: TypeUnknown}, []error{v.unsupportedModuleError(moduleName, funcCall.Pos)}
	}
	if !v.importedModules[moduleName] {
		err := &Error{
			Code:     ErrCodeUnsupportedModule,
			Message:  fmt.Sprintf("module %q must be imported before calling %s", moduleName, funcCall.Function),
			Position: funcCall.Pos,
			Rule:     v.currentRule,
		}
		return &TypeInfo{DataType: moduleFunction.ReturnType}, []error{err}
	}
	return v.validateModuleFunctionCall(funcCall, moduleFunction)
}

func (v *Validator) unknownModuleFunctionError(funcCall *ast.FunctionCall, moduleName string) *Error {
	var fnCandidates []string
	for fn := range v.moduleFunctions {
		if strings.HasPrefix(fn, moduleName+".") {
			fnCandidates = append(fnCandidates, fn)
		}
	}
	err := &Error{
		Code:     ErrCodeInvalidFunction,
		Message:  fmt.Sprintf("unknown function %q in module %q (unsupported module: %s)", funcCall.Function, moduleName, moduleName),
		Position: funcCall.Pos,
		Rule:     v.currentRule,
	}
	if sugg, ok := findSimilarIdentifier(funcCall.Function, fnCandidates); ok {
		err.Suggestion = fmt.Sprintf("%q", sugg)
	}
	return err
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
	matchedReturn := TypeUnknown
	for signatureIndex, signature := range function.Signatures {
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
			result := function.ReturnType
			if signatureIndex < len(function.ReturnTypes) && function.ReturnTypes[signatureIndex] != TypeUnknown {
				result = function.ReturnTypes[signatureIndex]
			}
			if matchedReturn != TypeUnknown && matchedReturn != result {
				// Preserve the declared result contract for untyped external arguments.
				return &TypeInfo{DataType: function.ReturnType}, errors
			}
			matchedReturn = result
		}
	}
	if matchedReturn != TypeUnknown {
		return &TypeInfo{DataType: matchedReturn}, errors
	}

	message := fmt.Sprintf("module function %q does not accept the supplied argument types", funcCall.Function)
	code := ErrCodeInvalidArgumentType
	if !matchedArity {
		message = fmt.Sprintf("module function %q does not accept %d arguments", funcCall.Function, len(argTypes))
		code = ErrCodeInvalidArgumentCount
	}
	errors = append(errors, &Error{
		Code:     code,
		Message:  message,
		Position: funcCall.Pos,
		Rule:     v.currentRule,
	})
	return &TypeInfo{DataType: function.ReturnType}, errors
}

func (v *Validator) validateFunctionArgumentTypes(funcCall *ast.FunctionCall, argTypes []*TypeInfo) []error {
	var errors []error
	switch {
	case isIntegerReadFunction(funcCall.Function):
		if len(argTypes) == 1 && !isIntegerCompatible(argTypes[0]) {
			errors = append(errors, &Error{
				Code:     ErrCodeInvalidArgumentType,
				Message:  fmt.Sprintf("function '%s' argument 1 must be integer", funcCall.Function),
				Position: funcCall.Args[0].Position(),
				Rule:     v.currentRule,
			})
		}
	case isHashFunction(funcCall.Function):
		errors = append(errors, v.validateHashFunctionArguments(funcCall, argTypes)...)
	}
	return errors
}

func (v *Validator) validateHashFunctionArguments(funcCall *ast.FunctionCall, argTypes []*TypeInfo) []error {
	switch len(argTypes) {
	case 1:
		if !isStringCompatible(argTypes[0]) {
			return []error{&Error{
				Code:     ErrCodeInvalidArgumentType,
				Message:  fmt.Sprintf("function '%s' argument 1 must be string", funcCall.Function),
				Position: funcCall.Args[0].Position(),
				Rule:     v.currentRule,
			}}
		}
	case 2:
		var errors []error
		if !isIntegerCompatible(argTypes[0]) {
			errors = append(errors, &Error{
				Code:     ErrCodeInvalidArgumentType,
				Message:  fmt.Sprintf("function '%s' argument 1 must be integer", funcCall.Function),
				Position: funcCall.Args[0].Position(),
				Rule:     v.currentRule,
			})
		}
		if !isIntegerCompatible(argTypes[1]) {
			errors = append(errors, &Error{
				Code:     ErrCodeInvalidArgumentType,
				Message:  fmt.Sprintf("function '%s' argument 2 must be integer", funcCall.Function),
				Position: funcCall.Args[1].Position(),
				Rule:     v.currentRule,
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

func (v *Validator) availableModuleNames() []string {
	if len(v.moduleFunctions) == 0 {
		return nil
	}
	var available []string
	seen := make(map[string]struct{})
	for fn := range v.moduleFunctions {
		mod, _, found := strings.Cut(fn, ".")
		if !found || mod == "" {
			continue
		}
		if _, ok := seen[mod]; !ok {
			seen[mod] = struct{}{}
			available = append(available, mod)
		}
	}
	return available
}

func (v *Validator) unsupportedModuleError(moduleName string, pos token.Position) *Error {
	err := &Error{
		Code:     ErrCodeUnsupportedModule,
		Message:  "unsupported module: " + moduleName,
		Position: pos,
		Rule:     v.currentRule,
	}
	if sugg, ok := findSimilarIdentifier(moduleName, v.availableModuleNames()); ok {
		err.Suggestion = fmt.Sprintf("%q", sugg)
	}
	return err
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
