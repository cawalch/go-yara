package compiler

import (
	"crypto/md5"  // #nosec G501 -- YARA compatibility requires MD5.
	"crypto/sha1" // #nosec G505 -- YARA compatibility requires SHA-1.
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/cawalch/go-yara/semantic"
)

// ModuleValueType is the public type system used by pluggable module calls.
type ModuleValueType uint8

const (
	ModuleUndefined ModuleValueType = iota
	ModuleInteger
	ModuleFloat
	ModuleString
	ModuleBoolean
)

// ModuleValue is a value passed to or returned from a module function.
type ModuleValue struct {
	Type    ModuleValueType
	Integer int64
	Float   float64
	String  string
	Boolean bool
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
	Evaluate   func(ModuleContext, []ModuleValue) (ModuleValue, error)
}

// Module is a collection of functions available under a dotted namespace.
// Rules must import Name before calling one of its functions.
type Module struct {
	Name      string
	Functions map[string]ModuleFunction
}

func defaultModules() map[string]Module {
	modules := map[string]Module{}
	for _, module := range []Module{hashModule(), mathModule()} {
		modules[module.Name] = module
	}
	return modules
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
		for functionName, function := range module.Functions {
			if functionName == "" || strings.Contains(functionName, ".") {
				return nil, nil, nil, fmt.Errorf("invalid function name %q in module %q", functionName, moduleName)
			}
			if function.Evaluate == nil || len(function.Signatures) == 0 || function.ReturnType == ModuleUndefined {
				return nil, nil, nil, fmt.Errorf("invalid module function %s.%s", moduleName, functionName)
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
		id := firstModuleFunctionID + builtinFunction(index) // #nosec G115 -- bounded above.
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
	default:
		return semantic.TypeUnknown
	}
}

func hashModule() Module {
	hashSignatures := []ModuleSignature{
		{Arguments: []ModuleValueType{ModuleString}},
		{Arguments: []ModuleValueType{ModuleInteger, ModuleInteger}},
	}
	return Module{
		Name: "hash",
		Functions: map[string]ModuleFunction{
			"md5": {
				Signatures: hashSignatures,
				ReturnType: ModuleString,
				Evaluate: func(ctx ModuleContext, args []ModuleValue) (ModuleValue, error) {
					data, err := moduleDataRange(ctx, args)
					if err != nil {
						return ModuleValue{}, err
					}
					sum := md5.Sum(data) // #nosec G401 -- YARA compatibility requires MD5.
					return StringValue(hex.EncodeToString(sum[:])), nil
				},
			},
			"sha1": {
				Signatures: hashSignatures,
				ReturnType: ModuleString,
				Evaluate: func(ctx ModuleContext, args []ModuleValue) (ModuleValue, error) {
					data, err := moduleDataRange(ctx, args)
					if err != nil {
						return ModuleValue{}, err
					}
					sum := sha1.Sum(data) // #nosec G401 -- YARA compatibility requires SHA-1.
					return StringValue(hex.EncodeToString(sum[:])), nil
				},
			},
			"sha256": {
				Signatures: hashSignatures,
				ReturnType: ModuleString,
				Evaluate: func(ctx ModuleContext, args []ModuleValue) (ModuleValue, error) {
					data, err := moduleDataRange(ctx, args)
					if err != nil {
						return ModuleValue{}, err
					}
					sum := sha256.Sum256(data)
					return StringValue(hex.EncodeToString(sum[:])), nil
				},
			},
		},
	}
}

func mathModule() Module {
	rangeSignature := []ModuleSignature{{Arguments: []ModuleValueType{ModuleInteger, ModuleInteger}}}
	return Module{
		Name: "math",
		Functions: map[string]ModuleFunction{
			"entropy": {
				Signatures: rangeSignature,
				ReturnType: ModuleFloat,
				Evaluate: func(ctx ModuleContext, args []ModuleValue) (ModuleValue, error) {
					data, err := moduleDataRange(ctx, args)
					if err != nil {
						return ModuleValue{}, err
					}
					return FloatValue(shannonEntropy(data)), nil
				},
			},
			"mean": {
				Signatures: rangeSignature,
				ReturnType: ModuleFloat,
				Evaluate: func(ctx ModuleContext, args []ModuleValue) (ModuleValue, error) {
					data, err := moduleDataRange(ctx, args)
					if err != nil {
						return ModuleValue{}, err
					}
					if len(data) == 0 {
						return FloatValue(0), nil
					}
					total := uint64(0)
					for _, value := range data {
						total += uint64(value)
					}
					return FloatValue(float64(total) / float64(len(data))), nil
				},
			},
			"deviation": {
				Signatures: rangeSignature,
				ReturnType: ModuleFloat,
				Evaluate: func(ctx ModuleContext, args []ModuleValue) (ModuleValue, error) {
					data, err := moduleDataRange(ctx, args)
					if err != nil {
						return ModuleValue{}, err
					}
					if len(data) == 0 {
						return FloatValue(0), nil
					}
					mean := 0.0
					for _, value := range data {
						mean += float64(value)
					}
					mean /= float64(len(data))
					variance := 0.0
					for _, value := range data {
						delta := float64(value) - mean
						variance += delta * delta
					}
					return FloatValue(math.Sqrt(variance / float64(len(data)))), nil
				},
			},
		},
	}
}

func moduleDataRange(ctx ModuleContext, args []ModuleValue) ([]byte, error) {
	switch len(args) {
	case 1:
		if args[0].Type != ModuleString {
			return nil, fmt.Errorf("expected string or (offset, size)")
		}
		return []byte(args[0].String), nil
	case 2:
		if args[0].Type != ModuleInteger || args[1].Type != ModuleInteger {
			return nil, fmt.Errorf("expected integer offset and size")
		}
		offset, size := args[0].Integer, args[1].Integer
		if offset < 0 || size < 0 {
			return nil, fmt.Errorf("data range out of bounds")
		}
		if ctx.Data != nil {
			if offset > int64(len(ctx.Data)) || size > int64(len(ctx.Data))-offset {
				return nil, fmt.Errorf("data range out of bounds")
			}
			return ctx.Data[offset : offset+size], nil
		}
		for _, block := range ctx.Blocks {
			if offset < block.Base {
				continue
			}
			relative := offset - block.Base
			if relative <= int64(len(block.Data)) && size <= int64(len(block.Data))-relative {
				return block.Data[relative : relative+size], nil
			}
		}
		return nil, fmt.Errorf("data range out of bounds")
	default:
		return nil, fmt.Errorf("expected string or (offset, size)")
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
