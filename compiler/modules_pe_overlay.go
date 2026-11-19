package compiler

import (
	pe "github.com/cawalch/go-pe"
)

func addPEOverlaySchemaFields(schema *ModuleSchema) {
	schema.Fields["overlay"] = ModuleField{
		Kind: ModuleStruct,
		Struct: &ModuleSchema{Fields: map[string]ModuleField{
			"offset": {Kind: ModuleInteger},
			"size":   {Kind: ModuleInteger},
		}},
	}
}

func (image *peImage) overlayValue() ModuleValue {
	offset, size := peOverlayExtents(image.file.Sections, image.fileSize)
	return peStruct(map[string]ModuleValue{
		"offset": IntegerValue(offset),
		"size":   IntegerValue(size),
	})
}

// peOverlayExtents implements libyara's overlay calculation from the exposed
// section records and known input size without aligning offsets, consulting the
// certificate directory, or reading overlay bytes.
func peOverlayExtents(sections []pe.Section, fileSize int64) (offset, size int64) {
	if fileSize <= 0 {
		return 0, 0
	}
	var largest uint64
	for i := range sections {
		end := uint64(sections[i].PointerToRawData) + uint64(sections[i].SizeOfRawData)
		if end > largest {
			largest = end
		}
	}
	if largest == 0 || largest >= uint64(fileSize) {
		return 0, 0
	}
	offset = int64(largest) //checkednarrow:ignore bounded by nonnegative fileSize
	return offset, fileSize - offset
}
