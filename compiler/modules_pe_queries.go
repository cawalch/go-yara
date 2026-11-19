package compiler

import (
	"strings"

	pe "github.com/cawalch/go-pe"

	"github.com/cawalch/go-yara/regex"
)

func (i *Interpreter) peImports(args []ModuleValue) ModuleValue {
	// A serialized custom module must not fall back to native parsing when
	// loaded without its callback, even if the function signatures match.
	if len(args) < 1 || len(args) > 2 || i.currentCompiledRule == nil || !i.currentCompiledRule.nativePE {
		return ModuleValue{}
	}
	if args[0].Type == ModuleRegex {
		return i.peImportsRegex(args)
	}
	// Guard the indexes even if a caller modifies a compiled function table.
	if args[0].Type != ModuleString || (len(args) == 2 && args[1].Type != ModuleString && args[1].Type != ModuleInteger) {
		return ModuleValue{}
	}
	// Normalize each query once, not once per imported function. The argument
	// values belong to this call; their strings remain immutable.
	args[0].String, _, _ = strings.Cut(args[0].String, "\x00")
	if len(args) == 2 && args[1].Type == ModuleString {
		args[1].String, _, _ = strings.Cut(args[1].String, "\x00")
	}
	done := peCancelDone(i.matchContext)
	if scanCanceled(done) {
		return ModuleValue{}
	}
	if data, supplied := i.moduleData["pe"]; supplied {
		return peHostImports(data, args, done)
	}
	image := loadPE(i.matchContext)
	if image.file == nil {
		return ModuleValue{}
	}
	imports := image.loadImports()
	if !imports.valid {
		return ModuleValue{}
	}
	if len(args) == 1 {
		return peImportDLLCount(imports, args[0].String)
	}
	if imports.index == nil && imports.scannedSymbols >= 256 {
		imports.index = buildPEImportIndex(imports.libraries)
	}
	if imports.index != nil {
		return lookupPEImportIndex(imports.index, args[0].String, args[1])
	}
	seen := 0
	for _, library := range imports.libraries {
		if !peNameEqual(library.DLL, args[0].String) {
			continue
		}
		kind := peMatchOrdinalDLL(library.DLL)
		for _, symbol := range library.Symbols {
			if scanCanceledAt(done, seen) {
				return ModuleValue{}
			}
			seen++
			imports.scannedSymbols++
			if peImportSymbolMatches(kind, symbol, args[1]) {
				return IntegerValue(1)
			}
		}
	}
	return IntegerValue(0)
}

func peImportDLLCount(imports *peImportData, dll string) ModuleValue {
	if len(imports.libraries) >= 4 {
		if imports.dllCounts == nil {
			imports.dllCounts = buildPEDLLCounts(imports.libraries)
		}
		return IntegerValue(imports.dllCounts[peLowerASCII(dll)])
	}
	var count int64
	for _, library := range imports.libraries {
		if peNameEqual(library.DLL, dll) {
			count += int64(len(library.Symbols))
		}
	}
	return IntegerValue(count)
}

func lookupPEImportIndex(index *peImportIndex, dll string, query ModuleValue) ModuleValue {
	dllLower := peLowerASCII(dll)
	if query.Type == ModuleInteger {
		if _, ok := index.ordHits[peImportOrdKey{dllLower: dllLower, ordinal: query.Integer}]; ok {
			return IntegerValue(1)
		}
		return IntegerValue(0)
	}
	if _, ok := index.fnHits[peImportFnKey{dllLower: dllLower, fnLower: peLowerASCII(query.String)}]; ok {
		return IntegerValue(1)
	}
	return IntegerValue(0)
}

func buildPEDLLCounts(libraries []pe.ImportLibrary) map[string]int64 {
	counts := make(map[string]int64, len(libraries))
	for _, library := range libraries {
		counts[peLowerASCII(library.DLL)] += int64(len(library.Symbols))
	}
	return counts
}

func buildPEImportIndex(libraries []pe.ImportLibrary) *peImportIndex {
	total := 0
	for _, library := range libraries {
		total += len(library.Symbols)
	}
	fnHits := make(map[peImportFnKey]struct{}, total)
	ordHits := make(map[peImportOrdKey]struct{})
	for _, library := range libraries {
		dllLower := peLowerASCII(library.DLL)
		kind := peMatchOrdinalDLL(library.DLL)
		for _, symbol := range library.Symbols {
			if !symbol.ByOrdinal {
				fnHits[peImportFnKey{dllLower: dllLower, fnLower: peLowerASCII(symbol.Name)}] = struct{}{}
				continue
			}
			ordHits[peImportOrdKey{dllLower: dllLower, ordinal: int64(symbol.Ordinal)}] = struct{}{}
			fnHits[peImportFnKey{dllLower: dllLower, fnLower: peLowerASCII(peImportOrdinalName(kind, symbol.Ordinal))}] = struct{}{}
		}
	}
	return &peImportIndex{
		fnHits:  fnHits,
		ordHits: ordHits,
	}
}

type peImportRegexQuery struct {
	dll, fn CompiledRegex
}

// peImportsRegex matches DLL and function regexes across all exposed standard
// imports and preserves libyara's total match count return value.
func (i *Interpreter) peImportsRegex(args []ModuleValue) ModuleValue {
	if len(args) != 2 || args[0].Type != ModuleRegex || args[1].Type != ModuleRegex {
		return ModuleValue{}
	}
	dllRegex, ok := args[0].CompiledRegex()
	if !ok {
		return ModuleValue{}
	}
	fnRegex, ok := args[1].CompiledRegex()
	if !ok {
		return ModuleValue{}
	}
	done := peCancelDone(i.matchContext)
	if scanCanceled(done) {
		return ModuleValue{}
	}
	query := peImportRegexQuery{dll: dllRegex, fn: fnRegex}
	if data, supplied := i.moduleData["pe"]; supplied {
		return peHostImportsRegex(data, query, done)
	}
	image := loadPE(i.matchContext)
	if image.file == nil {
		return ModuleValue{}
	}
	imports := image.loadImports()
	if !imports.valid {
		return ModuleValue{}
	}
	var batch *regex.VMBatch
	if i.matchContext != nil {
		batch = &i.matchContext.regexBatch
	}
	var count int64
	seen := 0
	for _, library := range imports.libraries {
		if scanCanceledAt(done, seen) {
			return ModuleValue{}
		}
		seen++
		dllMatched, err := query.dll.matchStringBatch(library.DLL, batch)
		if err != nil {
			return ModuleValue{}
		}
		if !dllMatched {
			continue
		}
		kind := peMatchOrdinalDLL(library.DLL)
		for _, symbol := range library.Symbols {
			if scanCanceledAt(done, seen) {
				return ModuleValue{}
			}
			seen++
			matched, err := peImportSymbolRegexMatchesBatch(kind, symbol, query.fn, batch)
			if err != nil {
				return ModuleValue{}
			}
			if matched {
				count++
			}
		}
	}
	return IntegerValue(count)
}

//nolint:revive // argument-limit: internal batch matcher
func peImportSymbolRegexMatchesBatch(kind peOrdinalDLLKind, symbol pe.ImportSymbol, query CompiledRegex, batch *regex.VMBatch) (bool, error) {
	if !symbol.ByOrdinal {
		return query.matchStringBatch(symbol.Name, batch)
	}
	return peOrdinalRegexMatchesBatch(kind, symbol.Ordinal, query, batch)
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
func peHostImports(data ModuleValue, args []ModuleValue, done <-chan struct{}) ModuleValue {
	if data.object == nil {
		return ModuleValue{}
	}
	details := data.object.fields["import_details"]
	if details.object == nil {
		return ModuleValue{}
	}
	var count int64
	seen := 0
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
			if scanCanceledAt(done, seen) {
				return ModuleValue{}
			}
			seen++
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

func peHostImportsRegex(data ModuleValue, query peImportRegexQuery, done <-chan struct{}) ModuleValue {
	if data.object == nil {
		return ModuleValue{}
	}
	details := data.object.fields["import_details"]
	if details.object == nil {
		return ModuleValue{}
	}
	var count int64
	seen := 0
	for _, library := range details.object.elements {
		if scanCanceledAt(done, seen) {
			return ModuleValue{}
		}
		seen++
		if library.object == nil {
			continue
		}
		name := library.object.fields["library_name"]
		functions := library.object.fields["functions"]
		if name.Type != ModuleString || functions.object == nil {
			continue
		}
		name.String, _, _ = strings.Cut(name.String, "\x00")
		dllMatched, err := query.dll.MatchString(name.String)
		if err != nil {
			return ModuleValue{}
		}
		if !dllMatched {
			continue
		}
		kind := peMatchOrdinalDLL(name.String)
		for _, symbol := range functions.object.elements {
			if scanCanceledAt(done, seen) {
				return ModuleValue{}
			}
			seen++
			if symbol.object == nil {
				continue
			}
			matched, err := peHostImportSymbolRegexMatches(kind, symbol, query.fn)
			if err != nil {
				return ModuleValue{}
			}
			if matched {
				count++
			}
		}
	}
	return IntegerValue(count)
}

func peHostImportSymbolRegexMatches(kind peOrdinalDLLKind, symbol ModuleValue, query CompiledRegex) (bool, error) {
	fnName := symbol.object.fields["name"]
	if fnName.Type == ModuleString {
		fnName.String, _, _ = strings.Cut(fnName.String, "\x00")
		return query.MatchString(fnName.String)
	}
	ordinal := symbol.object.fields["ordinal"]
	if ordinal.Type != ModuleInteger || ordinal.Integer < 0 || ordinal.Integer > 65535 {
		return false, nil
	}
	return peOrdinalRegexMatches(kind, uint16(ordinal.Integer), query) //checkednarrow:ignore range checked above
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
