package compiler

import (
	pe "github.com/cawalch/go-pe"
)

func addPEImportsSchemaFields(schema *ModuleSchema) {
	fields := schema.Fields
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
}

// Import errors leave header fields intact and all import fields undefined.
// A non-nil cache records both success and failure, so rules never retry parsing.
type peImportData struct {
	libraries      []pe.ImportLibrary
	functions      int
	details        ModuleValue
	dllCounts      map[string]int64
	scannedSymbols int
	index          *peImportIndex
	valid          bool
}

type peImportIndex struct {
	fnHits  map[peImportFnKey]struct{}
	ordHits map[peImportOrdKey]struct{}
}

type peImportFnKey struct {
	dllLower string
	fnLower  string
}

type peImportOrdKey struct {
	dllLower string
	ordinal  int64
}

func (image *peImage) loadImports() *peImportData {
	if image.imports == nil {
		done := peCancelDone(image.context)
		if scanCanceled(done) {
			return &peImportData{}
		}
		libraries, err := image.file.Imports(peScanData(image.context))
		if err != nil {
			image.imports = &peImportData{}
			return image.imports
		}
		filtered, functions, canceled := peFilterImportsWithCancel(libraries, done)
		if canceled {
			return &peImportData{}
		}
		image.imports = &peImportData{
			libraries: filtered,
			functions: functions,
			valid:     true,
		}
	}
	return image.imports
}

func (image *peImage) importField(name string) ModuleValue {
	imports := image.loadImports()
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

var peValidImportSymbolByte = func() [256]bool {
	var table [256]bool
	for c := byte('a'); c <= 'z'; c++ {
		table[c] = true
	}
	for c := byte('A'); c <= 'Z'; c++ {
		table[c] = true
	}
	for c := byte('0'); c <= '9'; c++ {
		table[c] = true
	}
	for _, c := range []byte("._?@$()<>") {
		table[c] = true
	}
	return table
}()

func peValidImportDLL(dll string) bool {
	if len(dll) >= 256 {
		return false
	}
	for i := 0; i < len(dll); i++ {
		b := dll[i]
		if b < 0x20 || b > 0x7e {
			return false
		}
		switch b {
		case '"', '*', '<', '>', '?', '|':
			return false
		}
	}
	return true
}

func peValidImportSymbolName(name string) bool {
	for i := 0; i < len(name); i++ {
		if !peValidImportSymbolByte[name[i]] {
			return false
		}
	}
	return true
}

// Apply libyara 4.5.8's name filters and 16,384-function limit here, not in
// go-pe. Empty libraries are omitted; duplicate descriptors remain separate.
func peFilterImportsWithCancel(libraries []pe.ImportLibrary, done <-chan struct{}) ([]pe.ImportLibrary, int, bool) {
	kept, total, iter := 0, 0, 0
	for _, library := range libraries {
		if total == 16384 {
			break
		}
		if scanCanceledAt(done, iter) {
			return nil, 0, true
		}
		iter++
		if !peValidImportDLL(library.DLL) {
			continue
		}
		symbols := library.Symbols[:0]
		for _, symbol := range library.Symbols[:min(len(library.Symbols), 16384)] {
			if scanCanceledAt(done, iter) {
				return nil, 0, true
			}
			iter++
			if total == 16384 {
				break
			}
			if !symbol.ByOrdinal {
				symbol.Name = symbol.Name[:min(len(symbol.Name), 512)]
				if !peValidImportSymbolName(symbol.Name) {
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
	return libraries[:kept], total, false
}

func peImportLibraryFields(library *pe.ImportLibrary) ModuleValue {
	var functions ModuleValue
	kind := peMatchOrdinalDLL(library.DLL)
	return peLazyStruct(func(name string) ModuleValue {
		switch name {
		case "library_name":
			return StringValue(library.DLL)
		case "number_of_functions":
			return IntegerValue(int64(len(library.Symbols)))
		case "functions":
			if functions.Type == ModuleUndefined {
				values := make([]ModuleValue, len(library.Symbols))
				views := make([]peImportFunctionView, len(values))
				for i := range views {
					view := &views[i]
					view.kind, view.symbol = kind, &library.Symbols[i]
					view.object = moduleObject{kind: ModuleStruct, getter: view}
					values[i] = ModuleValue{Type: ModuleStruct, object: &view.object}
				}
				functions = peArray(values)
			}
			return functions
		}
		return ModuleValue{}
	})
}

// Batch storage keeps each lazy field callback's state and module object
// together, instead of allocating an object and ordinal-name cell per symbol.
type peImportFunctionView struct {
	object      moduleObject
	symbol      *pe.ImportSymbol
	ordinalName string
	kind        peOrdinalDLLKind
}

func (view *peImportFunctionView) field(name string) ModuleValue {
	if name == "name" {
		if !view.symbol.ByOrdinal {
			return StringValue(view.symbol.Name)
		}
		if view.ordinalName == "" {
			view.ordinalName = peImportOrdinalName(view.kind, view.symbol.Ordinal)
		}
		return StringValue(view.ordinalName)
	}
	if name == "ordinal" && view.symbol.ByOrdinal {
		return IntegerValue(int64(view.symbol.Ordinal))
	}
	return ModuleValue{}
}
