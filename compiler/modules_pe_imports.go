package compiler

import (
	"maps"
	"strings"

	pe "github.com/cawalch/go-pe"
)

func newPEImportsSchema() *ModuleSchema {
	fields := maps.Clone(peHeaderSchema.Fields)
	fields["number_of_imports"] = ModuleField{Kind: ModuleInteger}
	fields["number_of_imported_functions"] = ModuleField{Kind: ModuleInteger}
	fields["import_details"] = ModuleField{Kind: ModuleArray, Element: &ModuleField{Kind: ModuleStruct,
		Struct: &ModuleSchema{Fields: map[string]ModuleField{
			"library_name":        {Kind: ModuleString},
			"number_of_functions": {Kind: ModuleInteger},
			"functions": {Kind: ModuleArray, Element: &ModuleField{Kind: ModuleStruct,
				Struct: &ModuleSchema{Fields: map[string]ModuleField{
					"name": {Kind: ModuleString}, "ordinal": {Kind: ModuleInteger},
				}},
			}},
		}},
	}}
	return &ModuleSchema{Fields: fields}
}

// Import errors leave header fields intact and all import fields undefined.
// A non-nil cache records both success and failure, so rules never retry parsing.
type peImportData struct {
	libraries []pe.ImportLibrary
	functions int
	details   ModuleValue
	valid     bool
}

func (image *peImage) importField(name string) ModuleValue {
	if image.imports == nil {
		image.imports = &peImportData{}
		libraries, err := image.file.Imports(peScanData(image.context))
		image.context = nil // Parsed records own their names.
		if err == nil {
			image.imports.libraries, image.imports.functions = peFilterImports(libraries)
			image.imports.valid = true
		}
	}
	imports := image.imports
	if !imports.valid {
		return ModuleValue{}
	}
	switch name {
	case "number_of_imports":
		return IntegerValue(int64(len(imports.libraries)))
	case "number_of_imported_functions":
		return IntegerValue(int64(imports.functions))
	default: // import_details
		if imports.details.Type == ModuleUndefined {
			libraries := make([]ModuleValue, len(imports.libraries))
			for i := range libraries {
				libraries[i] = peImportLibraryFields(&imports.libraries[i])
			}
			imports.details = peArray(libraries)
		}
		return imports.details
	}
}

// Apply libyara 4.5.8's name filters and 16,384-function limit here, not in
// go-pe. Empty libraries are omitted; duplicate descriptors remain separate.
func peFilterImports(libraries []pe.ImportLibrary) ([]pe.ImportLibrary, int) {
	kept, total := 0, 0
	for _, library := range libraries {
		if total == 16384 {
			break
		}
		if len(library.DLL) >= 256 || strings.ContainsAny(library.DLL, `"*<>?|`) {
			continue
		}
		if strings.IndexFunc(library.DLL, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0 {
			continue
		}
		symbols := library.Symbols[:0]
		for _, symbol := range library.Symbols[:min(len(library.Symbols), 16384)] {
			if total == 16384 {
				break
			}
			if !symbol.ByOrdinal {
				symbol.Name = symbol.Name[:min(len(symbol.Name), 512)]
				if strings.IndexFunc(symbol.Name, func(r rune) bool {
					if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
						return false
					}
					return !strings.ContainsRune("._?@$()<>", r)
				}) >= 0 {
					continue
				}
			}
			symbols = append(symbols, symbol)
			total++
		}
		clear(library.Symbols[len(symbols):])
		library.Symbols = symbols
		if len(symbols) != 0 {
			libraries[kept] = library
			kept++
		}
	}
	clear(libraries[kept:])
	return libraries[:kept], total
}

func peImportLibraryFields(library *pe.ImportLibrary) ModuleValue {
	var functions ModuleValue
	return peLazyStruct(func(name string) ModuleValue {
		switch name {
		case "library_name":
			return StringValue(library.DLL)
		case "number_of_functions":
			return IntegerValue(int64(len(library.Symbols)))
		case "functions":
			if functions.Type == ModuleUndefined {
				values := make([]ModuleValue, len(library.Symbols))
				for i := range values {
					symbol := &library.Symbols[i]
					values[i] = peLazyStruct(func(name string) ModuleValue {
						if name == "name" && !symbol.ByOrdinal {
							return StringValue(symbol.Name)
						}
						if name == "ordinal" && symbol.ByOrdinal {
							return IntegerValue(int64(symbol.Ordinal))
						}
						return ModuleValue{}
					})
				}
				functions = peArray(values)
			}
			return functions
		}
		return ModuleValue{}
	})
}
