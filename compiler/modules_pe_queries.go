package compiler

import "strings"

func (i *Interpreter) peImports(args []ModuleValue) ModuleValue {
	// A caller can copy a built-in registration and change its signatures.
	if len(args) != 2 || args[0].Type != ModuleString || (args[1].Type != ModuleString && args[1].Type != ModuleInteger) {
		return ModuleValue{}
	}
	// Normalize each query once, not once per imported function. The argument
	// values belong to this call; their strings remain immutable.
	args[0].String, _, _ = strings.Cut(args[0].String, "\x00")
	if args[1].Type == ModuleString {
		args[1].String, _, _ = strings.Cut(args[1].String, "\x00")
	}
	if data, supplied := i.moduleData["pe"]; supplied {
		return peHostImports(data, args)
	}
	image := cachedPE(i.matchContext)
	if image.file == nil {
		return ModuleValue{}
	}
	imports := image.loadImports()
	if !imports.valid {
		return ModuleValue{}
	}
	for _, library := range imports.libraries {
		if !peImportNameEqual(library.DLL, args[0].String) {
			continue
		}
		for _, symbol := range library.Symbols {
			if args[1].Type == ModuleInteger {
				if symbol.ByOrdinal && int64(symbol.Ordinal) == args[1].Integer {
					return IntegerValue(1)
				}
			} else if !symbol.ByOrdinal && peImportNameEqual(symbol.Name, args[1].String) {
				return IntegerValue(1)
			}
		}
	}
	return IntegerValue(0)
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
	for _, library := range details.object.elements {
		if library.object == nil {
			continue
		}
		name := library.object.fields["library_name"]
		functions := library.object.fields["functions"]
		if name.Type != ModuleString || !peImportNameEqual(name.String, args[0].String) || functions.object == nil {
			continue
		}
		for _, symbol := range functions.object.elements {
			if symbol.object == nil {
				continue
			}
			if args[1].Type == ModuleInteger {
				ordinal := symbol.object.fields["ordinal"]
				if ordinal.Type == ModuleInteger && ordinal.Integer == args[1].Integer {
					return IntegerValue(1)
				}
			} else {
				name := symbol.object.fields["name"]
				if name.Type == ModuleString && peImportNameEqual(name.String, args[1].String) {
					return IntegerValue(1)
				}
			}
		}
	}
	return IntegerValue(0)
}

// Match libyara's strcasecmp in the C locale. Query b is already NUL-trimmed.
// Unicode folding would incorrectly match names such as the Kelvin sign to K.
func peImportNameEqual(a, b string) bool {
	a, _, _ = strings.Cut(a, "\x00")
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
