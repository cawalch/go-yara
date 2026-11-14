package compiler

import (
	"strings"

	pe "github.com/cawalch/go-pe"
)

func (i *Interpreter) peImports(args []ModuleValue) ModuleValue {
	// Guard the indexes even if a caller modifies a compiled function table.
	if len(args) < 1 || len(args) > 2 || args[0].Type != ModuleString ||
		(len(args) == 2 && args[1].Type != ModuleString && args[1].Type != ModuleInteger) {
		return ModuleValue{}
	}
	// A serialized custom module must not fall back to native parsing when
	// loaded without its callback, even if the function signatures match.
	if i.currentCompiledRule == nil || !i.currentCompiledRule.nativePE {
		return ModuleValue{}
	}
	// Normalize each query once, not once per imported function. The argument
	// values belong to this call; their strings remain immutable.
	args[0].String, _, _ = strings.Cut(args[0].String, "\x00")
	if len(args) == 2 && args[1].Type == ModuleString {
		args[1].String, _, _ = strings.Cut(args[1].String, "\x00")
	}
	if data, supplied := i.moduleData["pe"]; supplied {
		return peHostImports(data, args)
	}
	image := loadPE(i.matchContext)
	if image.file == nil {
		return ModuleValue{}
	}
	imports := image.loadImports()
	if !imports.valid {
		return ModuleValue{}
	}
	var count int64
	for _, library := range imports.libraries {
		if !peNameEqual(library.DLL, args[0].String) {
			continue
		}
		if len(args) == 1 {
			count += int64(len(library.Symbols))
			continue
		}
		kind := peMatchOrdinalDLL(library.DLL)
		for _, symbol := range library.Symbols {
			if peImportSymbolMatches(kind, symbol, args[1]) {
				return IntegerValue(1)
			}
		}
	}
	return IntegerValue(count)
}

func peImportSymbolMatches(kind peOrdinalDLLKind, symbol pe.ImportSymbol, query ModuleValue) bool {
	if query.Type == ModuleInteger {
		return symbol.ByOrdinal && int64(symbol.Ordinal) == query.Integer
	}
	if !symbol.ByOrdinal {
		return peNameEqual(symbol.Name, query.String)
	}
	return peOrdinalNameMatches(kind, symbol.Ordinal, query.String)
}

// Host snapshots take precedence over file parsing, including absent fields.
// They are already schema-checked and own their values.
func peHostImports(data ModuleValue, args []ModuleValue) ModuleValue {
	if data.object == nil {
		return ModuleValue{}
	}
	details := data.object.fields["import_details"]
	if details.object == nil {
		return ModuleValue{}
	}
	var count int64
	for _, library := range details.object.elements {
		if library.object == nil {
			continue
		}
		name := library.object.fields["library_name"]
		functions := library.object.fields["functions"]
		name.String, _, _ = strings.Cut(name.String, "\x00")
		if name.Type != ModuleString || !peNameEqual(name.String, args[0].String) || functions.object == nil {
			continue
		}
		kind := peMatchOrdinalDLL(name.String)
		for _, symbol := range functions.object.elements {
			if symbol.object == nil {
				continue
			}
			if len(args) == 1 {
				count++
				continue
			}
			if peHostImportSymbolMatches(kind, symbol, args[1]) {
				return IntegerValue(1)
			}
		}
	}
	return IntegerValue(count)
}

func peHostImportSymbolMatches(kind peOrdinalDLLKind, symbol, query ModuleValue) bool {
	if query.Type == ModuleInteger {
		ordinal := symbol.object.fields["ordinal"]
		return ordinal.Type == ModuleInteger && ordinal.Integer == query.Integer
	}
	fnName := symbol.object.fields["name"]
	if fnName.Type == ModuleString {
		fnName.String, _, _ = strings.Cut(fnName.String, "\x00")
		return peNameEqual(fnName.String, query.String)
	}
	ordinal := symbol.object.fields["ordinal"]
	if ordinal.Type != ModuleInteger || ordinal.Integer < 0 || ordinal.Integer > 65535 {
		return false
	}
	return peOrdinalNameMatches(kind, uint16(ordinal.Integer), query.String) //checkednarrow:ignore range checked above
}

// Compare bytes with ASCII case folding, as libyara does in the C locale.
// Import callers trim NUL suffixes; export comparisons preserve the full length.
// Unicode folding would incorrectly match names such as the Kelvin sign to K.
func peNameEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
