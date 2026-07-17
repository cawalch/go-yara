package semantic

import "strings"

// ModuleFunction describes the type signatures accepted by one dotted module
// function. Each inner slice in Signatures is one accepted argument list.
type ModuleFunction struct {
	Signatures [][]DataType
	ReturnType DataType
}

// ModuleFunctions maps fully qualified names (for example, "hash.md5") to
// their semantic signatures.
type ModuleFunctions map[string]ModuleFunction

func (functions ModuleFunctions) hasModule(name string) bool {
	prefix := name + "."
	for functionName := range functions {
		if strings.HasPrefix(functionName, prefix) {
			return true
		}
	}
	return false
}
