package compiler

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"

	"github.com/cawalch/go-yara/semantic"
)

// ModuleValueType is the public type system used by pluggable module calls.
type ModuleValueType uint8

const (
	// ModuleUndefined indicates an uninitialized or undefined module value.
	ModuleUndefined ModuleValueType = iota
	// ModuleInteger indicates a 64-bit signed integer value.
	ModuleInteger
	// ModuleFloat indicates a 64-bit floating point value.
	ModuleFloat
	// ModuleString indicates a string value.
	ModuleString
	// ModuleBoolean indicates a boolean value.
	ModuleBoolean
	// ModuleStruct is a schema-backed structure.
	ModuleStruct
	// ModuleArray is an indexed collection.
	ModuleArray
	// ModuleDictionary is a string-keyed collection.
	ModuleDictionary
)

// ModuleValue is a value passed to or returned from a module function.
type ModuleValue struct {
	Type    ModuleValueType
	Integer int64
	Float   float64
	String  string
	Boolean bool
	object  *moduleObject
}

// IntegerValue constructs an integer module value.
func IntegerValue(value int64) ModuleValue {
	return ModuleValue{Type: ModuleInteger, Integer: value}
}

// FloatValue constructs a floating-point module value.
func FloatValue(value float64) ModuleValue {
	return ModuleValue{Type: ModuleFloat, Float: value}
}

// StringValue constructs a string module value.
func StringValue(value string) ModuleValue {
	return ModuleValue{Type: ModuleString, String: value}
}

// BooleanValue constructs a boolean module value.
func BooleanValue(value bool) ModuleValue {
	return ModuleValue{Type: ModuleBoolean, Boolean: value}
}

// ModuleContext is the immutable scan context visible to module functions.
type ModuleContext struct {
	Data     []byte
	Blocks   []MemoryBlock
	RuleName string
}

// ModuleSignature describes one accepted argument list for a module function.
type ModuleSignature struct {
	// ReturnType may specialize an integer function to a float result for numeric overloads.
	// ModuleUndefined inherits ModuleFunction.ReturnType.
	ReturnType ModuleValueType
	Arguments  []ModuleValueType
}

// ModuleFunction is a typed function exposed by a module.
type ModuleFunction struct {
	Signatures []ModuleSignature
	ReturnType ModuleValueType
	// Cacheable opts into bounded per-scan memoization of calls with up to three
	// numeric arguments. Evaluate must depend only on Data, Blocks and arguments,
	// never RuleName, time, external state, or side effects. Custom functions are
	// not cached by default. This hint is not persisted for custom modules.
	Cacheable bool
	// Evaluate implements a custom function. Only unmodified built-in PE
	// function registrations may leave it nil to select scan-owned evaluation.
	// Evaluate may return ModuleUndefined for any declared return type. An
	// undefined argument propagates without invoking the callback.
	Evaluate func(ModuleContext, []ModuleValue) (ModuleValue, error)
}

// Module is a collection of functions available under a dotted namespace.
// Rules must import Name before calling one of its functions.
type Module struct {
	Schema    *ModuleSchema
	Name      string
	Functions map[string]ModuleFunction
}

// builtinModules is initialized once. Module values and their function tables
// are immutable by convention: copies returned by defaultModules share them,
// while public option accessors still clone before returning.
var builtinModules = buildBuiltinModules()

func buildBuiltinModules() map[string]Module {
	modules := make(map[string]Module, 5)
	for _, module := range []Module{hashModule(), mathModule(), stringModule(), timeModule(), peModule()} {
		modules[module.Name] = module
	}
	return modules
}

func defaultModules() map[string]Module {
	modules := make(map[string]Module, len(builtinModules))
	for name, module := range builtinModules {
		modules[name] = module
	}
	return modules
}

// isBuiltinModuleRegistry reports whether modules is the unmodified built-in
// registry. Copies made by defaultModules keep the same function-table and
// schema identities; public copies are cloned and therefore fail this check.
func isBuiltinModuleRegistry(modules map[string]Module) bool {
	if len(modules) != len(builtinModules) {
		return false
	}
	for name, builtin := range builtinModules {
		module, ok := modules[name]
		if !ok || module.Name != builtin.Name || module.Schema != builtin.Schema ||
			reflect.ValueOf(module.Functions).Pointer() != reflect.ValueOf(builtin.Functions).Pointer() {
			return false
		}
	}
	return true
}

func cloneModules(modules map[string]Module) map[string]Module {
	if modules == nil {
		return nil
	}
	cloned := make(map[string]Module, len(modules))
	for name, module := range modules {
		cloned[name] = cloneModule(module)
	}
	return cloned
}

func cloneModule(module Module) Module {
	module.Schema = cloneModuleSchema(module.Schema)
	functions := make(map[string]ModuleFunction, len(module.Functions))
	for functionName, function := range module.Functions {
		functions[functionName] = cloneModuleFunction(function)
	}
	module.Functions = functions
	return module
}

func cloneModuleFunction(function ModuleFunction) ModuleFunction {
	signatures := make([]ModuleSignature, len(function.Signatures))
	for index, signature := range function.Signatures {
		signatures[index] = signature
		signatures[index].Arguments = slices.Clone(signature.Arguments)
	}
	function.Signatures = signatures
	return function
}

func moduleFunctionCount(registered map[string]Module) int {
	count := 0
	for _, module := range registered {
		count += len(module.Functions)
	}
	return count
}

func semanticModuleFunctions(registered map[string]Module) semantic.ModuleFunctions {
	if isBuiltinModuleRegistry(registered) {
		return builtinSemanticModuleFunctions
	}
	return buildSemanticModuleFunctions(registered)
}

var builtinSemanticModuleFunctions = buildSemanticModuleFunctions(builtinModules)

func buildSemanticModuleFunctions(registered map[string]Module) semantic.ModuleFunctions {
	functions := make(semantic.ModuleFunctions, moduleFunctionCount(registered))
	for moduleName, module := range registered {
		for functionName, function := range module.Functions {
			signatures := make([][]semantic.DataType, len(function.Signatures))
			returns := make([]semantic.DataType, len(function.Signatures))
			for signatureIndex, signature := range function.Signatures {
				returns[signatureIndex] = moduleSemanticType(signature.resultType(function.ReturnType))
				signatures[signatureIndex] = make([]semantic.DataType, len(signature.Arguments))
				for argumentIndex, argument := range signature.Arguments {
					signatures[signatureIndex][argumentIndex] = moduleSemanticType(argument)
				}
			}
			functions[moduleName+"."+functionName] = semantic.ModuleFunction{
				Signatures:  signatures,
				ReturnTypes: returns,
				ReturnType:  moduleSemanticType(function.ReturnType),
			}
		}
	}
	return functions
}

const firstModuleFunctionID builtinFunction = 128

type compiledModuleFunction struct {
	id       builtinFunction
	name     string
	function ModuleFunction
}

func compileModuleFunctions(registered map[string]Module) (map[string]compiledModuleFunction, error) {
	if len(registered) == 0 {
		return nil, nil
	}
	if isBuiltinModuleRegistry(registered) {
		return builtinModuleBindings, nil
	}
	return buildModuleBindings(registered)
}

var builtinModuleBindings = mustBuildModuleBindings(builtinModules)

func mustBuildModuleBindings(registered map[string]Module) map[string]compiledModuleFunction {
	bindings, err := buildModuleBindings(registered)
	if err != nil {
		panic("invalid built-in module registry: " + err.Error())
	}
	return bindings
}

// buildModuleBindings validates every registered function, including functions
// that no rule uses, then assigns stable IDs from the sorted qualified names.
// Per-rule metadata only retains the subset referenced by its condition.
func buildModuleBindings(registered map[string]Module) (map[string]compiledModuleFunction, error) {
	qualifiedNames := make([]string, 0, moduleFunctionCount(registered))
	for moduleName, module := range registered {
		if module.Name == "" || module.Name != moduleName || strings.Contains(module.Name, ".") {
			return nil, fmt.Errorf("invalid module name %q", module.Name)
		}
		if err := validateModuleSchema(module.Schema); err != nil {
			return nil, fmt.Errorf("module %s: %w", moduleName, err)
		}
		for functionName, function := range module.Functions {
			if functionName == "" || strings.Contains(functionName, ".") {
				return nil, fmt.Errorf("invalid function name %q in module %q", functionName, moduleName)
			}
			if (function.Evaluate == nil && !isNativePEFunction(module, functionName, function)) || len(function.Signatures) == 0 || (function.ReturnType < ModuleInteger || function.ReturnType > ModuleBoolean) {
				return nil, fmt.Errorf("invalid module function %s.%s", moduleName, functionName)
			}
			for _, signature := range function.Signatures {
				if typ := signature.resultType(function.ReturnType); typ < ModuleInteger || typ > ModuleBoolean {
					return nil, fmt.Errorf("invalid overload result in module function %s.%s", moduleName, functionName)
				}
				if err := signature.validateResult(function.ReturnType); err != nil {
					return nil, fmt.Errorf("module function %s.%s: %w", moduleName, functionName, err)
				}
				for _, argument := range signature.Arguments {
					if argument < ModuleInteger || argument > ModuleBoolean {
						return nil, fmt.Errorf("invalid argument type in module function %s.%s", moduleName, functionName)
					}
				}
			}
			qualifiedNames = append(qualifiedNames, moduleName+"."+functionName)
		}
	}
	slices.Sort(qualifiedNames)
	if len(qualifiedNames) > int(^builtinFunction(0)-firstModuleFunctionID)+1 {
		return nil, fmt.Errorf("too many module functions: %d", len(qualifiedNames))
	}

	bindings := make(map[string]compiledModuleFunction, len(qualifiedNames))
	for index, qualifiedName := range qualifiedNames {
		moduleName, functionName, _ := strings.Cut(qualifiedName, ".")
		function := registered[moduleName].Functions[functionName]
		id := firstModuleFunctionID + builtinFunction(index) // #nosec G115 -- checkednarrow:ignore qualifiedNames length is bounded above
		bindings[qualifiedName] = compiledModuleFunction{id: id, name: qualifiedName, function: function}
	}
	return bindings, nil
}

func moduleSemanticType(valueType ModuleValueType) semantic.DataType {
	switch valueType {
	case ModuleInteger:
		return semantic.TypeInteger
	case ModuleFloat:
		return semantic.TypeFloat
	case ModuleString:
		return semantic.TypeString
	case ModuleBoolean:
		return semantic.TypeBoolean
	case ModuleStruct:
		return semantic.TypeStruct
	case ModuleArray:
		return semantic.TypeArray
	case ModuleDictionary:
		return semantic.TypeDictionary
	default:
		return semantic.TypeUnknown
	}
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, value := range data {
		counts[value]++
	}
	entropy := 0.0
	for _, count := range counts {
		if count == 0 {
			continue
		}
		probability := float64(count) / float64(len(data))
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}

func (signature ModuleSignature) resultType(fallback ModuleValueType) ModuleValueType {
	if signature.ReturnType != ModuleUndefined {
		return signature.ReturnType
	}
	return fallback
}

func (signature ModuleSignature) validateResult(fallback ModuleValueType) error {
	if signature.ReturnType == ModuleUndefined || signature.ReturnType == fallback {
		return nil
	}
	if fallback != ModuleInteger || signature.ReturnType != ModuleFloat {
		return errors.New("only integer-to-float result overloads are supported")
	}
	hasFloat := false
	for _, argument := range signature.Arguments {
		if argument != ModuleInteger && argument != ModuleFloat {
			return errors.New("float result overload requires numeric arguments")
		}
		hasFloat = hasFloat || argument == ModuleFloat
	}
	if !hasFloat {
		return errors.New("float result overload requires a float argument")
	}
	return nil
}
