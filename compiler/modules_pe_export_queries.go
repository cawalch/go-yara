package compiler

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
		matched, err := peExportNameMatches(query, name[:min(len(name), 512)])
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
	if query.value.Type == ModuleRegex {
		return query.regex.MatchString(candidate)
	}
	return peNameEqual(candidate, query.value.String), nil
}
