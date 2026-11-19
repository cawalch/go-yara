package compiler

import pe "github.com/cawalch/go-pe"

func addPEDebugSchemaFields(schema *ModuleSchema) {
	schema.Fields["pdb_path"] = ModuleField{Kind: ModuleString}
}

// peDebugData caches one scan's parsed IMAGE_DEBUG_DIRECTORY entries without
// converting PDB path bytes to a ModuleValue unless pdb_path is accessed.
type peDebugData struct {
	entries        []pe.DebugEntry
	pdbPath        ModuleValue
	valid          bool
	pdbPathChecked bool
}

func (image *peImage) loadDebug() *peDebugData {
	if image.debug != nil {
		return image.debug
	}
	if scanCanceled(peCancelDone(image.context)) {
		return &peDebugData{}
	}
	image.debug = &peDebugData{}
	entries, err := image.file.Debug(peScanData(image.context))
	if err != nil {
		return image.debug
	}
	image.debug.entries = entries
	image.debug.valid = true
	return image.debug
}

func (image *peImage) pdbPathField() ModuleValue {
	debug := image.loadDebug()
	if !debug.valid {
		return ModuleValue{}
	}
	if !debug.pdbPathChecked {
		debug.pdbPathChecked = true
		for _, entry := range debug.entries {
			if entry.Type == pe.DebugTypeCodeView && entry.CodeView != nil {
				debug.pdbPath = StringValue(string(entry.CodeView.PDBPath))
				break
			}
		}
	}
	return debug.pdbPath
}
