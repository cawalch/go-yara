package compiler

const peSectionExposureLimit = 96

// peSectionIndex implements libyara's section_index overloads. File scans use
// the cached raw section records and names without constructing section
// objects. Host snapshots use the supplied number_of_sections and sections
// array and never fall back to file parsing.
func (i *Interpreter) peSectionIndex(args []ModuleValue) ModuleValue {
	if len(args) != 1 || (args[0].Type != ModuleString && args[0].Type != ModuleInteger) {
		return ModuleValue{}
	}
	if i.currentCompiledRule == nil || !i.currentCompiledRule.nativePE {
		return ModuleValue{}
	}
	if data, supplied := i.moduleData["pe"]; supplied {
		return peHostSectionIndex(data, args[0])
	}
	image := loadPE(i.matchContext)
	if image.file == nil {
		return ModuleValue{}
	}
	if args[0].Type == ModuleString {
		query := peCString(args[0].String)
		for index := range image.file.Sections {
			if peCString(image.names[index]) == query {
				return IntegerValue(int64(index))
			}
		}
		return ModuleValue{}
	}
	for index := range image.file.Sections {
		section := &image.file.Sections[index]
		if peSectionContainsOffset(args[0].Integer, int64(section.PointerToRawData), int64(section.SizeOfRawData)) {
			return IntegerValue(int64(index))
		}
	}
	return ModuleValue{}
}

func peHostSectionIndex(data ModuleValue, arg ModuleValue) ModuleValue {
	if data.object == nil {
		return ModuleValue{}
	}
	count := data.object.fields["number_of_sections"]
	if count.Type != ModuleInteger {
		return ModuleValue{}
	}
	limit := min(count.Integer, int64(peSectionExposureLimit))
	sections := data.object.fields["sections"]
	if limit <= 0 || sections.object == nil {
		return ModuleValue{}
	}
	for index := int64(0); index < limit; index++ {
		if index >= int64(len(sections.object.elements)) {
			continue
		}
		section := sections.object.elements[index]
		if section.object == nil {
			continue
		}
		if arg.Type == ModuleString {
			name := section.object.fields["name"]
			if name.Type == ModuleString && peCString(name.String) == peCString(arg.String) {
				return IntegerValue(index)
			}
			continue
		}
		offset := section.object.fields["raw_data_offset"]
		size := section.object.fields["raw_data_size"]
		if offset.Type == ModuleInteger && size.Type == ModuleInteger &&
			peSectionContainsOffset(arg.Integer, offset.Integer, size.Integer) {
			return IntegerValue(index)
		}
	}
	return ModuleValue{}
}

// peSectionContainsOffset uses subtraction to avoid overflowing offset+size for
// large host-supplied values. Empty sections and negative ranges never match.
func peSectionContainsOffset(address, offset, size int64) bool {
	if size <= 0 || offset < 0 || address < offset {
		return false
	}
	return address-offset < size
}
