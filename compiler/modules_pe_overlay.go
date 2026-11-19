package compiler

import (
	pe "github.com/cawalch/go-pe"
)

func addPEOverlaySchemaFields(schema *ModuleSchema) {
	schema.Fields["overlay"] = ModuleField{
		Kind: ModuleStruct,
		Struct: &ModuleSchema{Fields: map[string]ModuleField{
			"offset":           {Kind: ModuleInteger},
			"size":             {Kind: ModuleInteger},
			"data_offset":      {Kind: ModuleInteger},
			"data_size":        {Kind: ModuleInteger},
			"certificate_size": {Kind: ModuleInteger},
		}},
	}
}

type peOverlayInfo struct {
	offset          int64
	size            int64
	dataOffset      int64
	dataSize        int64
	certificateSize int64
}

func (image *peImage) overlayValue() ModuleValue {
	info := peOverlayDetails(image.file, image.fileSize)
	return peStruct(map[string]ModuleValue{
		"offset":           IntegerValue(info.offset),
		"size":             IntegerValue(info.size),
		"data_offset":      IntegerValue(info.dataOffset),
		"data_size":        IntegerValue(info.dataSize),
		"certificate_size": IntegerValue(info.certificateSize),
	})
}

func peOverlayDetails(file *pe.File, fileSize int64) peOverlayInfo {
	offset, size := peOverlayExtents(file.Sections, fileSize)
	info := peOverlayInfo{
		offset:     offset,
		size:       size,
		dataOffset: offset,
		dataSize:   size,
	}
	opt := &file.OptionalHeader
	if opt.NumberOfRvaAndSizes <= pe.DataDirectoryCertificate {
		return info
	}
	secDir := opt.DataDirectories[pe.DataDirectoryCertificate]
	if secDir.VirtualAddress == 0 || secDir.Size == 0 {
		return info
	}
	info.certificateSize = int64(secDir.Size)
	if size <= 0 {
		return info
	}
	ovStart := uint64(offset)
	ovEnd := uint64(offset + size)
	certStart := uint64(secDir.VirtualAddress)
	certEnd := certStart + uint64(secDir.Size)
	overlapStart := max(certStart, ovStart)
	overlapEnd := min(certEnd, ovEnd)
	if overlapEnd <= overlapStart {
		return info
	}
	info.dataSize = size - int64(overlapEnd-overlapStart) //checkednarrow:ignore bounded by size
	if info.dataSize == 0 {
		info.dataOffset = 0
	} else if overlapStart == ovStart {
		info.dataOffset = int64(overlapEnd) //checkednarrow:ignore bounded by fileSize
	}
	return info
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
