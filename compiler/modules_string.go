package compiler

import (
	"strconv"
	"strings"
	"time"
)

func stringModule() Module {
	return Module{Name: "string", Functions: map[string]ModuleFunction{
		"length": {Signatures: []ModuleSignature{{Arguments: []ModuleValueType{ModuleString}}}, ReturnType: ModuleInteger,
			Evaluate: func(_ ModuleContext, args []ModuleValue) (ModuleValue, error) {
				return IntegerValue(int64(len(args[0].String))), nil
			}},
		"to_int": {Signatures: []ModuleSignature{{Arguments: []ModuleValueType{ModuleString}}, {Arguments: []ModuleValueType{ModuleString, ModuleInteger}}}, ReturnType: ModuleInteger,
			Evaluate: func(_ ModuleContext, args []ModuleValue) (ModuleValue, error) {
				base := int64(0)
				if len(args) == 2 {
					base = args[1].Integer
				}
				if base != 0 && (base < 2 || base > 36) {
					return ModuleValue{}, nil
				}
				// strtoll accepts leading C whitespace and stops at a NUL, but requires
				// all other input to be consumed. Go's binary and underscore extensions
				// are deliberately excluded.
				str, _, _ := strings.Cut(args[0].String, "\x00")
				str = strings.TrimLeft(str, " \t\n\r\v\f")
				sign := ""
				if strings.HasPrefix(str, "+") || strings.HasPrefix(str, "-") {
					sign, str = str[:1], str[1:]
				}
				if base == 0 {
					base = 10
					if strings.HasPrefix(str, "0") {
						base = 8
					}
					if strings.HasPrefix(str, "0x") || strings.HasPrefix(str, "0X") {
						base = 16
						str = str[2:]
					}
				} else if base == 16 && (strings.HasPrefix(str, "0x") || strings.HasPrefix(str, "0X")) {
					str = str[2:]
				}
				if strings.HasPrefix(str, "+") || strings.HasPrefix(str, "-") {
					return ModuleValue{}, nil
				}
				value, err := strconv.ParseInt(sign+str, int(base), 64)
				if err != nil {
					return ModuleValue{}, nil
				}
				return IntegerValue(value), nil
			}},
	}}
}

func timeModule() Module {
	return Module{Name: "time", Functions: map[string]ModuleFunction{
		"now": {Signatures: []ModuleSignature{{}}, ReturnType: ModuleInteger,
			Evaluate: func(_ ModuleContext, _ []ModuleValue) (ModuleValue, error) {
				return IntegerValue(time.Now().Unix()), nil
			}},
	}}
}
