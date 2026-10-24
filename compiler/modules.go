package compiler

import (
	"fmt"
	"math"
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
	Arguments []ModuleValueType
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

func defaultModules() map[string]Module {
	modules := map[string]Module{}
	for _, module := range []Module{hashModule(), mathModule(), stringModule(), timeModule()} {
		modules[module.Name] = module
	}
	return modules
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
		signatures := make([]ModuleSignature, len(function.Signatures))
		for index, signature := range function.Signatures {
			signatures[index] = signature
			signatures[index].Arguments = slices.Clone(signature.Arguments)
		}
		function.Signatures = signatures
		functions[functionName] = function
	}
	module.Functions = functions
	return module
}

func semanticModuleFunctions(registered map[string]Module) semantic.ModuleFunctions {
	functions := make(semantic.ModuleFunctions)
	for moduleName, module := range registered {
		for functionName, function := range module.Functions {
			signatures := make([][]semantic.DataType, len(function.Signatures))
			for signatureIndex, signature := range function.Signatures {
				signatures[signatureIndex] = make([]semantic.DataType, len(signature.Arguments))
				for argumentIndex, argument := range signature.Arguments {
					signatures[signatureIndex][argumentIndex] = moduleSemanticType(argument)
				}
			}
			functions[moduleName+"."+functionName] = semantic.ModuleFunction{
				Signatures: signatures,
				ReturnType: moduleSemanticType(function.ReturnType),
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

func compileModuleFunctions(
	registered map[string]Module,
) (map[string]compiledModuleFunction, map[builtinFunction]ModuleFunction, map[builtinFunction]string, error) {
	qualifiedNames := make([]string, 0)
	for moduleName, module := range registered {
		if module.Name == "" || module.Name != moduleName || strings.Contains(module.Name, ".") {
			return nil, nil, nil, fmt.Errorf("invalid module name %q", module.Name)
		}
		if err := validateModuleSchema(module.Schema); err != nil {
			return nil, nil, nil, fmt.Errorf("module %s: %w", moduleName, err)
		}
		for functionName, function := range module.Functions {
			if functionName == "" || strings.Contains(functionName, ".") {
				return nil, nil, nil, fmt.Errorf("invalid function name %q in module %q", functionName, moduleName)
			}
			if function.Evaluate == nil || len(function.Signatures) == 0 || (function.ReturnType < ModuleInteger || function.ReturnType > ModuleBoolean) {
				return nil, nil, nil, fmt.Errorf("invalid module function %s.%s", moduleName, functionName)
			}
			for _, signature := range function.Signatures {
				for _, argument := range signature.Arguments {
					if argument < ModuleInteger || argument > ModuleBoolean {
						return nil, nil, nil, fmt.Errorf("invalid argument type in module function %s.%s", moduleName, functionName)
					}
				}
			}
			qualifiedNames = append(qualifiedNames, moduleName+"."+functionName)
		}
	}
	slices.Sort(qualifiedNames)
	if len(qualifiedNames) > int(^builtinFunction(0)-firstModuleFunctionID)+1 {
		return nil, nil, nil, fmt.Errorf("too many module functions: %d", len(qualifiedNames))
	}

	bindings := make(map[string]compiledModuleFunction, len(qualifiedNames))
	functions := make(map[builtinFunction]ModuleFunction, len(qualifiedNames))
	names := make(map[builtinFunction]string, len(qualifiedNames))
	for index, qualifiedName := range qualifiedNames {
		moduleName, functionName, _ := strings.Cut(qualifiedName, ".")
		function := registered[moduleName].Functions[functionName]
		id := firstModuleFunctionID + builtinFunction(index) // #nosec G115 -- checkednarrow:ignore qualifiedNames length is bounded above
		bindings[qualifiedName] = compiledModuleFunction{id: id, name: qualifiedName, function: function}
		functions[id] = function
		names[id] = qualifiedName
	}
	return bindings, functions, names, nil
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
