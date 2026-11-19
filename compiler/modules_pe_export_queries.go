package compiler

import (
	pe "github.com/cawalch/go-pe"

	"github.com/cawalch/go-yara/regex"
)

func (i *Interpreter) peExports(args []ModuleValue, wantIndex bool) ModuleValue {
	index, valid := i.peExportLookup(args)
	if !valid || (wantIndex && index < 0) {
		return ModuleValue{}
	}
	if wantIndex {
		return IntegerValue(int64(index))
	}
	if index >= 0 {
		return IntegerValue(1)
	}
	return IntegerValue(0)
}

type peExportQuery struct {
	value ModuleValue
	regex CompiledRegex
}

// A valid lookup returns -1 for no match. Invalid metadata stays distinct so
// exports can return zero for a miss while both overload families propagate
// undefined input. Index zero is a match.
func (i *Interpreter) peExportLookup(args []ModuleValue) (index int, valid bool) {
	if len(args) != 1 || i.currentCompiledRule == nil || !i.currentCompiledRule.nativePE {
		return -1, false
	}
	query := peExportQuery{value: args[0]}
	switch query.value.Type {
	case ModuleString, ModuleInteger:
	case ModuleRegex:
		var ok bool
		query.regex, ok = query.value.CompiledRegex()
		if !ok {
			return -1, false
		}
	default:
		return -1, false
	}
	done := peCancelDone(i.matchContext)
	if scanCanceled(done) {
		return -1, false
	}
	if data, supplied := i.moduleData["pe"]; supplied {
		return peHostExportLookup(data, query, done)
	}
	image := loadPE(i.matchContext)
	if image.file == nil {
		return -1, false
	}
	exports := image.loadExports()
	if !exports.valid {
		return -1, false
	}
	// libyara rejects zero and ordinals above the exposed slot count, even
	// when the directory's ordinal base puts an exported ordinal above it.
	if query.value.Type == ModuleInteger && (query.value.Integer == 0 || query.value.Integer > int64(len(exports.symbols))) {
		return -1, true
	}
	exports.queries++
	if idx, ok := lookupPEExportIndex(exports, query); ok {
		return idx, true
	}
	var batch *regex.VMBatch
	if query.value.Type == ModuleRegex && i.matchContext != nil {
		batch = &i.matchContext.regexBatch
	}
	for index := range exports.symbols {
		if scanCanceledAt(done, index) {
			return -1, false
		}
		symbol := &exports.symbols[index]
		if query.value.Type == ModuleInteger {
			if query.value.Integer == int64(symbol.Ordinal) {
				return index, true
			}
			continue
		}
		if len(symbol.Names) == 0 {
			continue
		}
		name := symbol.Names[0]
		matched, err := peExportNameMatchesBatch(query, name[:min(len(name), 512)], batch)
		if err != nil {
			return -1, false
		}
		if matched {
			return index, true
		}
	}
	return -1, true
}

// Host snapshots use their detail array, including its length, instead of
// parsing the file. Missing arrays are undefined; empty arrays don't match.
func peHostExportLookup(data ModuleValue, query peExportQuery, done <-chan struct{}) (index int, valid bool) {
	if data.object == nil {
		return -1, false
	}
	details := data.object.fields["export_details"]
	if details.object == nil {
		return -1, false
	}
	if query.value.Type == ModuleInteger && (query.value.Integer == 0 || query.value.Integer > int64(len(details.object.elements))) {
		return -1, true
	}
	for index, symbol := range details.object.elements {
		if scanCanceledAt(done, index) {
			return -1, false
		}
		if symbol.object == nil {
			continue
		}
		if query.value.Type == ModuleInteger {
			ordinal := symbol.object.fields["ordinal"]
			if ordinal.Type == ModuleInteger && ordinal.Integer == query.value.Integer {
				return index, true
			}
			continue
		}
		name := symbol.object.fields["name"]
		if name.Type != ModuleString {
			continue
		}
		matched, err := peExportNameMatches(query, name.String)
		if err != nil {
			return -1, false
		}
		if matched {
			return index, true
		}
	}
	return -1, true
}

func peExportNameMatches(query peExportQuery, candidate string) (bool, error) {
	return peExportNameMatchesBatch(query, candidate, nil)
}

func peExportNameMatchesBatch(query peExportQuery, candidate string, batch *regex.VMBatch) (bool, error) {
	if query.value.Type == ModuleRegex {
		return query.regex.matchStringBatch(candidate, batch)
	}
	return peNameEqual(candidate, query.value.String), nil
}

func buildPEExportIndex(symbols []pe.ExportSymbol) *peExportIndex {
	byName := make(map[string]int, len(symbols))
	byOrdinal := make(map[int64]int, len(symbols))
	for index := range symbols {
		symbol := &symbols[index]
		if _, exists := byOrdinal[int64(symbol.Ordinal)]; !exists {
			byOrdinal[int64(symbol.Ordinal)] = index
		}
		if len(symbol.Names) == 0 {
			continue
		}
		name := symbol.Names[0]
		name = peLowerASCII(name[:min(len(name), 512)])
		if _, exists := byName[name]; !exists {
			byName[name] = index
		}
	}
	return &peExportIndex{
		byName:    byName,
		byOrdinal: byOrdinal,
	}
}

func lookupPEExportIndex(exports *peExportData, query peExportQuery) (int, bool) {
	if query.value.Type == ModuleRegex {
		return -1, false
	}
	if exports.index == nil && exports.queries > 1 && len(exports.symbols) >= 16 {
		exports.index = buildPEExportIndex(exports.symbols)
	}
	if exports.index == nil {
		return -1, false
	}
	if query.value.Type == ModuleInteger {
		if idx, ok := exports.index.byOrdinal[query.value.Integer]; ok {
			return idx, true
		}
		return -1, true
	}
	if idx, ok := exports.index.byName[peLowerASCII(query.value.String)]; ok {
		return idx, true
	}
	return -1, true
}

func peLowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 'A' || b > 'Z' {
			continue
		}
		buf := make([]byte, len(s))
		copy(buf, s[:i])
		buf[i] = b + ('a' - 'A')
		for j := i + 1; j < len(s); j++ {
			c := s[j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			buf[j] = c
		}
		return string(buf)
	}
	return s
}
