package compiler

import "math"

func (i *Interpreter) peRVAToOffsetQuery(args []ModuleValue) ModuleValue {
	if len(args) != 1 || args[0].Type != ModuleInteger {
		return ModuleValue{}
	}
	if i.currentCompiledRule == nil || !i.currentCompiledRule.nativePE {
		return ModuleValue{}
	}
	rva := args[0].Integer
	if rva < 0 {
		return ModuleValue{}
	}
	if data, supplied := i.moduleData["pe"]; supplied {
		var fileSize int64
		if i.matchContext != nil {
			fileSize = i.matchContext.FileSize
		}
		return peHostRVAToOffset(data, uint64(rva), fileSize)
	}
	image := loadPE(i.matchContext)
	if image.file == nil {
		return ModuleValue{}
	}
	return peOffsetValue(peRVAToOffset64(image.file, uint64(rva), image.context.FileSize))
}

func peOffsetValue(offset int64) ModuleValue {
	if offset < 0 {
		return ModuleValue{}
	}
	return IntegerValue(offset)
}

// Host snapshots are authoritative. Mapping requires number_of_sections, all
// exposed section records, and both alignment fields; incomplete metadata is
// undefined rather than falling back to file parsing.
func peHostRVAToOffset(data ModuleValue, rva uint64, fileSize int64) ModuleValue {
	if data.object == nil || fileSize < 0 {
		return ModuleValue{}
	}
	count := data.object.fields["number_of_sections"]
	if count.Type != ModuleInteger || count.Integer < 0 {
		return ModuleValue{}
	}
	limit := min(count.Integer, int64(peSectionExposureLimit))
	sections := data.object.fields["sections"]
	if limit > 0 && (sections.object == nil || int64(len(sections.object.elements)) < limit) {
		return ModuleValue{}
	}
	fileAlignment, ok := peHostUint32(data.object.fields["file_alignment"])
	if !ok {
		return ModuleValue{}
	}
	sectionAlignment, ok := peHostUint32(data.object.fields["section_alignment"])
	if !ok {
		return ModuleValue{}
	}
	offset := peRVAToOffsetExtents(peRVAMapping{
		count: int(limit), //checkednarrow:ignore limit is bounded by peSectionExposureLimit
		section: func(index int) (peSectionExtent, bool) {
			return peHostSectionExtent(sections.object.elements[index])
		},
		fileAlignment: fileAlignment, sectionAlignment: sectionAlignment, fileSize: fileSize, rva: rva,
	})
	return peOffsetValue(offset)
}

func peHostSectionExtent(section ModuleValue) (peSectionExtent, bool) {
	if section.object == nil {
		return peSectionExtent{}, false
	}
	virtualAddress, ok := peHostUint32(section.object.fields["virtual_address"])
	if !ok {
		return peSectionExtent{}, false
	}
	virtualSize, ok := peHostUint32(section.object.fields["virtual_size"])
	if !ok {
		return peSectionExtent{}, false
	}
	rawDataOffset, ok := peHostUint32(section.object.fields["raw_data_offset"])
	if !ok {
		return peSectionExtent{}, false
	}
	rawDataSize, ok := peHostUint32(section.object.fields["raw_data_size"])
	if !ok {
		return peSectionExtent{}, false
	}
	return peSectionExtent{
		virtualAddress: virtualAddress,
		virtualSize:    virtualSize,
		rawDataOffset:  rawDataOffset,
		rawDataSize:    rawDataSize,
	}, true
}

func peHostUint32(value ModuleValue) (uint32, bool) {
	if value.Type != ModuleInteger || value.Integer < 0 || value.Integer > math.MaxUint32 {
		return 0, false
	}
	return uint32(value.Integer), true //checkednarrow:ignore range checked above
}
