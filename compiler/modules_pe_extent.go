package compiler

import (
	"math"

	pe "github.com/cawalch/go-pe"
)

// newPEExtentSchema extends peDebugSchema without mutating it so previously
// serialized programs continue matching isNativePESchema.
func newPEExtentSchema() *ModuleSchema {
	schema := cloneModuleSchema(peDebugSchema)
	schema.Fields["declared_extent"] = ModuleField{Kind: ModuleInteger}
	schema.Fields["input_truncated"] = ModuleField{Kind: ModuleInteger}
	return schema
}

// extentField reports declared image bounds and input truncation relative to the
// scan's logical file size rather than any retained streaming header prefix.
func (image *peImage) extentField(name string) ModuleValue {
	if image.file == nil {
		return ModuleValue{}
	}
	extent, ok := image.file.DeclaredExtent()
	if !ok {
		return ModuleValue{}
	}
	switch name {
	case "declared_extent":
		if extent > math.MaxInt64 {
			return ModuleValue{}
		}
		return IntegerValue(int64(extent))
	case "input_truncated":
		if image.fileSize < 0 {
			return ModuleValue{}
		}
		if extent > uint64(image.fileSize) {
			return IntegerValue(1)
		}
		return IntegerValue(0)
	}
	return ModuleValue{}
}

// peIsDotNet classifies whether the image declares a non-empty CLR/.NET runtime
// header directory (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR), returning 1, 0, or
// undefined on non-PE inputs and incomplete host snapshots.
func (i *Interpreter) peIsDotNet() ModuleValue {
	if i.currentCompiledRule == nil || !i.currentCompiledRule.nativePE {
		return ModuleValue{}
	}
	if data, supplied := i.moduleData["pe"]; supplied {
		return peHostIsDotNet(data)
	}
	image := loadPE(i.matchContext)
	if image.file == nil {
		return ModuleValue{}
	}
	opt := &image.file.OptionalHeader
	if opt.NumberOfRvaAndSizes <= pe.DataDirectoryCLRRuntime {
		return IntegerValue(0)
	}
	dir := opt.DataDirectories[pe.DataDirectoryCLRRuntime]
	if dir.VirtualAddress != 0 && dir.Size != 0 {
		return IntegerValue(1)
	}
	return IntegerValue(0)
}

func peHostIsDotNet(data ModuleValue) ModuleValue {
	if data.object == nil {
		return ModuleValue{}
	}
	dirs, ok := data.object.fields["data_directories"]
	if !ok || dirs.Type != ModuleArray || dirs.object == nil {
		return ModuleValue{}
	}
	if len(dirs.object.elements) <= pe.DataDirectoryCLRRuntime {
		return IntegerValue(0)
	}
	entry := dirs.object.elements[pe.DataDirectoryCLRRuntime]
	if entry.Type != ModuleStruct || entry.object == nil {
		return ModuleValue{}
	}
	va, okVA := entry.object.fields["virtual_address"]
	sz, okSZ := entry.object.fields["size"]
	if !okVA || !okSZ || va.Type != ModuleInteger || sz.Type != ModuleInteger {
		return ModuleValue{}
	}
	if va.Integer != 0 && sz.Integer != 0 {
		return IntegerValue(1)
	}
	return IntegerValue(0)
}
