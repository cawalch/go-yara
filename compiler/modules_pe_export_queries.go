package compiler

func (i *Interpreter) peExports(args []ModuleValue) ModuleValue {
	if len(args) != 1 || (args[0].Type != ModuleString && args[0].Type != ModuleInteger) ||
		i.currentCompiledRule == nil || !i.currentCompiledRule.nativePE {
		return ModuleValue{}
	}
	query := args[0]
	if data, supplied := i.moduleData["pe"]; supplied {
		return peHostExports(data, query)
	}
	image := loadPE(i.matchContext)
	if image.file == nil {
		return ModuleValue{}
	}
	exports := image.loadExports()
	if !exports.valid {
		return ModuleValue{}
	}
	// libyara rejects zero and ordinals above the exposed slot count, even
	// when the directory's ordinal base puts an exported ordinal above it.
	if query.Type == ModuleInteger && (query.Integer == 0 || query.Integer > int64(len(exports.symbols))) {
		return IntegerValue(0)
	}
	for index := range exports.symbols {
		symbol := &exports.symbols[index]
		if query.Type == ModuleInteger {
			if query.Integer == int64(symbol.Ordinal) {
				return IntegerValue(1)
			}
		} else if len(symbol.Names) != 0 {
			name := symbol.Names[0]
			if peNameEqual(name[:min(len(name), 512)], query.String) {
				return IntegerValue(1)
			}
		}
	}
	return IntegerValue(0)
}

// Host snapshots use their detail array, including its length, instead of
// parsing the file. Missing arrays are undefined; empty arrays don't match.
func peHostExports(data, query ModuleValue) ModuleValue {
	if data.object == nil {
		return ModuleValue{}
	}
	details := data.object.fields["export_details"]
	if details.object == nil {
		return ModuleValue{}
	}
	if query.Type == ModuleInteger && (query.Integer == 0 || query.Integer > int64(len(details.object.elements))) {
		return IntegerValue(0)
	}
	for _, symbol := range details.object.elements {
		if symbol.object == nil {
			continue
		}
		if query.Type == ModuleInteger {
			ordinal := symbol.object.fields["ordinal"]
			if ordinal.Type == ModuleInteger && ordinal.Integer == query.Integer {
				return IntegerValue(1)
			}
		} else {
			name := symbol.object.fields["name"]
			if name.Type == ModuleString && peNameEqual(name.String, query.String) {
				return IntegerValue(1)
			}
		}
	}
	return IntegerValue(0)
}
