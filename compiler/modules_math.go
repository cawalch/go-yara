package compiler

import (
	"math"
	"strconv"
)

func mathModule() Module {
	functions := map[string]ModuleFunction{
		"entropy": dataModuleFunction(ModuleFloat, func(data []byte) ModuleValue { return FloatValue(shannonEntropy(data)) }),
		"mean": statisticalModuleFunction(func(data []byte, signed bool) ModuleValue {
			sum := 0.0
			for _, b := range data {
				sum += statisticalByte(b, signed)
			}
			return FloatValue(sum / float64(len(data)))
		}),
		"serial_correlation": statisticalModuleFunction(moduleSerialCorrelation),
		"monte_carlo_pi":     statisticalModuleFunction(moduleMonteCarloPi),
	}
	integers := func(n int) []ModuleValueType {
		args := make([]ModuleValueType, n)
		for j := range args {
			args[j] = ModuleInteger
		}
		return args
	}
	add := func(name string, function ModuleFunction) { functions[name] = function }
	for _, name := range []string{"min", "max", "abs", "to_number", "to_string", "in_range"} {
		function := ModuleFunction{ReturnType: ModuleInteger}
		switch name {
		case "min", "max":
			function.Signatures = []ModuleSignature{
				{Arguments: integers(2)},
				{Arguments: []ModuleValueType{ModuleFloat, ModuleFloat}, ReturnType: ModuleFloat},
				{Arguments: []ModuleValueType{ModuleInteger, ModuleFloat}, ReturnType: ModuleFloat},
				{Arguments: []ModuleValueType{ModuleFloat, ModuleInteger}, ReturnType: ModuleFloat},
			}
		case "abs":
			function.Signatures = []ModuleSignature{{Arguments: integers(1)}}
		case "to_number":
			function.Signatures = []ModuleSignature{{Arguments: []ModuleValueType{ModuleBoolean}}}
		case "to_string":
			function.Signatures = []ModuleSignature{{Arguments: integers(1)}, {Arguments: integers(2)}}
			function.ReturnType = ModuleString
		case "in_range":
			function.Signatures = []ModuleSignature{{Arguments: []ModuleValueType{ModuleFloat, ModuleFloat, ModuleFloat}}}
		}
		function.Evaluate = func(_ ModuleContext, args []ModuleValue) (ModuleValue, error) {
			return moduleMathScalar(name, args), nil
		}
		add(name, function)
	}
	for _, name := range []string{"count", "percentage", "mode"} {
		function := ModuleFunction{ReturnType: ModuleInteger, Cacheable: true}
		if name == "mode" {
			function.Signatures = []ModuleSignature{{}, {Arguments: integers(2)}}
		} else {
			function.Signatures = []ModuleSignature{{Arguments: integers(1)}, {Arguments: integers(3)}}
		}
		if name == "percentage" {
			function.ReturnType = ModuleFloat
		}
		function.Evaluate = func(ctx ModuleContext, args []ModuleValue) (ModuleValue, error) {
			return moduleDistribution(ctx, name, args), nil
		}
		add(name, function)
	}
	// Retain the original two-integer standard-deviation extension for source
	// and serialized-program compatibility; add YARA's mean-absolute-deviation
	// overloads with an explicit mean.
	add("deviation", ModuleFunction{
		Signatures: []ModuleSignature{{Arguments: integers(2)}, {Arguments: []ModuleValueType{ModuleInteger, ModuleInteger, ModuleFloat}}, {Arguments: []ModuleValueType{ModuleString, ModuleFloat}}},
		ReturnType: ModuleFloat, Cacheable: true, Evaluate: moduleDeviation,
	})
	return Module{Name: "math", Functions: functions}
}

func moduleNumber(value ModuleValue) float64 {
	if value.Type == ModuleInteger {
		return float64(value.Integer)
	}
	return value.Float
}

func moduleMathScalar(name string, args []ModuleValue) ModuleValue {
	value := args[0].Integer
	switch name {
	case "min", "max":
		if args[0].Type == ModuleFloat || args[1].Type == ModuleFloat {
			a, b := moduleNumber(args[0]), moduleNumber(args[1])
			if name == "min" {
				return FloatValue(math.Min(a, b))
			}
			return FloatValue(math.Max(a, b))
		}
		other := args[1].Integer
		// YARA compares unsigned values but returns the selected signed bit pattern.
		if (name == "min" && uint64(other) < uint64(value)) || (name == "max" && uint64(other) > uint64(value)) {
			value = other
		}
	case "abs":
		if value < 0 {
			value = -value
		}
	case "to_number":
		if args[0].Boolean {
			value = 1
		} else {
			value = 0
		}
	case "in_range":
		test, lower, upper := moduleNumber(args[0]), moduleNumber(args[1]), moduleNumber(args[2])
		value = 0
		if lower <= test && test <= upper {
			value = 1
		}
	case "to_string":
		base := int64(10)
		if len(args) == 2 {
			base = args[1].Integer
		}
		switch base {
		case 10:
			return StringValue(strconv.FormatInt(value, 10))
		case 8, 16:
			return StringValue(strconv.FormatUint(uint64(value), int(base)))
		default:
			return ModuleValue{}
		}
	}
	return IntegerValue(value)
}

func moduleDistribution(ctx ModuleContext, name string, args []ModuleValue) ModuleValue {
	var data []byte
	var ok bool
	rangeArgs := args
	if name != "mode" {
		if args[0].Integer < 0 || args[0].Integer > 255 {
			return ModuleValue{}
		}
		rangeArgs = args[1:]
	}
	if len(rangeArgs) == 0 {
		data, ok = moduleWholeData(ctx)
	} else {
		data, ok = moduleDataRange(ctx, rangeArgs)
	}
	if !ok {
		return ModuleValue{}
	}
	var counts [256]int64
	for _, b := range data {
		counts[b]++
	}
	if name == "mode" {
		mode := 0
		for b, count := range counts {
			if count > counts[mode] {
				mode = b
			}
		}
		return IntegerValue(int64(mode))
	}
	count := counts[args[0].Integer]
	if name == "percentage" {
		return FloatValue(float64(float32(count) / float32(len(data))))
	}
	return IntegerValue(count)
}

func moduleWholeData(ctx ModuleContext) ([]byte, bool) {
	if ctx.Data != nil {
		return ctx.Data, len(ctx.Data) > 0
	}
	var length int64
	for _, block := range ctx.Blocks {
		if block.Base != length || int64(len(block.Data)) > math.MaxInt64-length {
			return nil, false
		}
		length += int64(len(block.Data))
	}
	if length == 0 {
		return nil, false
	}
	return moduleDataRange(ctx, []ModuleValue{IntegerValue(0), IntegerValue(length)})
}

func moduleDeviation(ctx ModuleContext, args []ModuleValue) (ModuleValue, error) {
	legacy := len(args) == 2 && args[0].Type == ModuleInteger
	rangeArgs := args
	if !legacy {
		rangeArgs = args[:len(args)-1]
	}
	data, ok := moduleDataRange(ctx, rangeArgs)
	if !ok {
		return ModuleValue{}, nil
	}
	mean := moduleNumber(args[len(args)-1])
	if legacy {
		if len(data) == 0 {
			return FloatValue(0), nil
		}
		mean = 0
		for _, b := range data {
			mean += float64(b)
		}
		mean /= float64(len(data))
	}
	sum := 0.0
	for _, b := range data {
		delta := statisticalByte(b, args[0].Type == ModuleString) - mean
		if legacy {
			sum += delta * delta
		} else {
			sum += math.Abs(delta)
		}
	}
	result := sum / float64(len(data))
	if legacy {
		result = math.Sqrt(result)
	}
	return FloatValue(result), nil
}

func moduleSerialCorrelation(data []byte, signed bool) ModuleValue {
	var sum, squares, products float64
	for index, b := range data {
		value := statisticalByte(b, signed)
		sum += value
		squares += value * value
		products += value * statisticalByte(data[(index+1)%len(data)], signed)
	}
	n := float64(len(data))
	denominator := n*squares - sum*sum
	if denominator == 0 {
		return FloatValue(-100000)
	}
	return FloatValue((n*products - sum*sum) / denominator)
}

func moduleMonteCarloPi(data []byte, signed bool) ModuleValue {
	count, inside := len(data)/6, 0
	if count == 0 {
		return ModuleValue{}
	}
	for index := 0; index < count*6; index += 6 {
		var x, y float64
		for j := 0; j < 3; j++ {
			x = x*256 + monteCarloByte(data[index+j], signed)
			y = y*256 + monteCarloByte(data[index+j+3], signed)
		}
		const radius = 16777215.0
		if x*x+y*y <= radius*radius {
			inside++
		}
	}
	estimate := 4 * float64(inside) / float64(count)
	return FloatValue(math.Abs((estimate - math.Pi) / math.Pi))
}

// libyara string statistics depend on C char signedness. Use the signed-char
// convention consistently across Go targets; range statistics use unsigned bytes.
func statisticalByte(b byte, signed bool) float64 {
	if signed && b >= 128 {
		return float64(int(b) - 256)
	}
	return float64(b)
}

func monteCarloByte(b byte, signed bool) float64 {
	if signed && b >= 128 {
		return float64(uint64(1)<<32) + float64(int(b)-256)
	}
	return float64(b)
}

func statisticalModuleFunction(eval func([]byte, bool) ModuleValue) ModuleFunction {
	function := ModuleFunction{Signatures: stringAndRangeSignatures(), ReturnType: ModuleFloat, Cacheable: true}
	function.Evaluate = func(ctx ModuleContext, args []ModuleValue) (ModuleValue, error) {
		data, ok := moduleDataRange(ctx, args)
		if !ok {
			return ModuleValue{}, nil
		}
		return eval(data, len(args) == 1), nil
	}
	return function
}
