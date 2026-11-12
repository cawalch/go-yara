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

// A valid lookup returns -1 for no match. Invalid metadata stays distinct so
// exports can return zero for a miss while both overload families propagate
// undefined input. Index zero is a match.
func (i *Interpreter) peExportLookup(args []ModuleValue) (index int, valid bool) {
	if len(args) != 1 || (args[0].Type != ModuleString && args[0].Type != ModuleInteger) ||
		i.currentCompiledRule == nil || !i.currentCompiledRule.nativePE {
		return -1, false
	}
	query := args[0]
	if data, supplied := i.moduleData["pe"]; supplied {
		return peHostExportLookup(data, query)
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
	if query.Type == ModuleInteger && (query.Integer == 0 || query.Integer > int64(len(exports.symbols))) {
		return -1, true
	}
	for index := range exports.symbols {
		symbol := &exports.symbols[index]
		if query.Type == ModuleInteger {
			if query.Integer == int64(symbol.Ordinal) {
				return index, true
			}
		} else if len(symbol.Names) != 0 {
			name := symbol.Names[0]
			if peNameEqual(name[:min(len(name), 512)], query.String) {
				return index, true
			}
		}
	}
	return -1, true
}

// Host snapshots use their detail array, including its length, instead of
// parsing the file. Missing arrays are undefined; empty arrays don't match.
func peHostExportLookup(data, query ModuleValue) (index int, valid bool) {
	if data.object == nil {
		return -1, false
	}
	details := data.object.fields["export_details"]
	if details.object == nil {
		return -1, false
	}
	if query.Type == ModuleInteger && (query.Integer == 0 || query.Integer > int64(len(details.object.elements))) {
		return -1, true
	}
	for index, symbol := range details.object.elements {
		if symbol.object == nil {
			continue
		}
		if query.Type == ModuleInteger {
			ordinal := symbol.object.fields["ordinal"]
			if ordinal.Type == ModuleInteger && ordinal.Integer == query.Integer {
				return index, true
			}
		} else {
			name := symbol.object.fields["name"]
			if name.Type == ModuleString && peNameEqual(name.String, query.String) {
				return index, true
			}
		}
	}
	return -1, true
}
