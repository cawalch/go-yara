package compiler

import (
	"bytes"
	"math"
	"strings"

	pe "github.com/cawalch/go-pe"
)

// The schema is immutable. Runtime values are owned by one scan, not by go-pe
// or the compiled program. Constants are folded by the condition compiler.
var peSchema = newPESchema()

// The semantic validator only reads this type tree. Reuse it so rules that
// don't import PE don't pay to reconstruct the built-in schema.
var peSemanticType = moduleFieldType(ModuleField{Kind: ModuleStruct, Struct: peSchema})

var notPE = peStruct(map[string]ModuleValue{"is_pe": IntegerValue(0)})

func peModule() Module { return Module{Name: "pe", Schema: peSchema} }

func newPESchema() *ModuleSchema {
	fields := map[string]ModuleField{}
	for _, name := range strings.Fields(`is_pe machine number_of_sections timestamp
		pointer_to_symbol_table number_of_symbols size_of_optional_header characteristics
		entry_point entry_point_raw image_base number_of_rva_and_sizes opthdr_magic
		size_of_code size_of_initialized_data size_of_uninitialized_data base_of_code base_of_data
		section_alignment file_alignment win32_version_value size_of_image size_of_headers
		checksum subsystem dll_characteristics size_of_stack_reserve size_of_stack_commit
		size_of_heap_reserve size_of_heap_commit loader_flags`) {
		fields[name] = ModuleField{Kind: ModuleInteger}
	}
	version := &ModuleSchema{Fields: map[string]ModuleField{
		"major": {Kind: ModuleInteger}, "minor": {Kind: ModuleInteger},
	}}
	for _, name := range []string{"linker_version", "os_version", "image_version", "subsystem_version"} {
		fields[name] = ModuleField{Kind: ModuleStruct, Struct: version}
	}
	section := &ModuleSchema{Fields: map[string]ModuleField{
		"name": {Kind: ModuleString}, "full_name": {Kind: ModuleString},
	}}
	for _, name := range strings.Fields(`characteristics virtual_address virtual_size
		raw_data_offset raw_data_size pointer_to_relocations pointer_to_line_numbers
		number_of_relocations number_of_line_numbers`) {
		section.Fields[name] = ModuleField{Kind: ModuleInteger}
	}
	fields["sections"] = ModuleField{Kind: ModuleArray, Element: &ModuleField{Kind: ModuleStruct, Struct: section}}
	fields["data_directories"] = ModuleField{Kind: ModuleArray, Element: &ModuleField{Kind: ModuleStruct,
		Struct: &ModuleSchema{Fields: map[string]ModuleField{
			"virtual_address": {Kind: ModuleInteger}, "size": {Kind: ModuleInteger},
		}},
	}}
	for name, number := range peConstants {
		value := IntegerValue(number)
		fields[name] = ModuleField{Kind: ModuleInteger, Constant: &value}
	}
	return &ModuleSchema{Fields: fields}
}

func peStruct(fields map[string]ModuleValue) ModuleValue {
	return ModuleValue{Type: ModuleStruct, object: &moduleObject{kind: ModuleStruct, fields: fields}}
}

func peArray(elements []ModuleValue) ModuleValue {
	return ModuleValue{Type: ModuleArray, object: &moduleObject{kind: ModuleArray, elements: elements}}
}

func peVersion(major, minor uint16) ModuleValue {
	return peStruct(map[string]ModuleValue{"major": IntegerValue(int64(major)), "minor": IntegerValue(int64(minor))})
}

// loadPE uses file offsets even for block scans. Only the block at file offset
// zero can contain the headers; disjoint blocks are not concatenated. Reader
// scans supply their retained header and the actual file size separately.
func loadPE(ctx *MatchContext) ModuleValue {
	if ctx == nil {
		return notPE
	}
	data := ctx.Data
	if data == nil {
		for _, block := range ctx.Blocks {
			if block.Base == 0 {
				data = block.Data
				break
			}
		}
	}
	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' {
		return notPE
	}
	file, err := pe.New(data)
	if err != nil {
		return notPE
	}
	// libyara requires a complete standard optional header, even if the file
	// declares fewer directories. go-pe also supports shorter valid headers.
	optionalSize := uint64(224)
	if file.Is64Bit() {
		optionalSize = 240
	}
	if uint64(file.DOSHeader.AddressOfNewEXEHeader)+24+optionalSize > uint64(len(data)) {
		return notPE
	}
	// libyara exposes and maps at most 96 sections, while go-pe validates up
	// to 256. Keep the declared number_of_sections unchanged.
	file.Sections = file.Sections[:min(len(file.Sections), 96)]
	return peFields(file, data, ctx.FileSize)
}

func peFields(file *pe.File, data []byte, fileSize int64) ModuleValue {
	// Keep the snapshot independent of the caller's buffer. Section names in
	// YARA preserve embedded NULs, unlike go-pe's normalized Name field.
	names := make([]string, len(file.Sections))
	sectionStart := uint64(file.DOSHeader.AddressOfNewEXEHeader) + 24 + uint64(file.FileHeader.SizeOfOptionalHeader)
	for i := range names {
		start := sectionStart + uint64(i)*40
		names[i] = string(bytes.TrimRight(data[start:start+8], "\x00"))
	}
	entryPoint := peEntryPoint(file, fileSize)
	var sections, directories ModuleValue
	var versions [4]ModuleValue
	return peLazyStruct(func(name string) ModuleValue {
		coff, opt := file.FileHeader, file.OptionalHeader
		switch name {
		case "is_pe":
			return IntegerValue(1)
		case "machine":
			return IntegerValue(int64(coff.Machine))
		case "number_of_sections":
			return IntegerValue(int64(coff.NumberOfSections))
		case "timestamp":
			return IntegerValue(int64(coff.TimeDateStamp))
		case "pointer_to_symbol_table":
			return IntegerValue(int64(coff.PointerToSymbolTable))
		case "number_of_symbols":
			return IntegerValue(int64(coff.NumberOfSymbols))
		case "size_of_optional_header":
			return IntegerValue(int64(coff.SizeOfOptionalHeader))
		case "characteristics":
			return IntegerValue(int64(coff.Characteristics))
		case "entry_point":
			return IntegerValue(entryPoint)
		case "entry_point_raw":
			return IntegerValue(int64(opt.AddressOfEntryPoint))
		case "image_base":
			return peInteger(opt.ImageBase)
		case "number_of_rva_and_sizes":
			return IntegerValue(int64(opt.NumberOfRvaAndSizes))
		case "opthdr_magic":
			return IntegerValue(int64(opt.Magic))
		case "size_of_code":
			return IntegerValue(int64(opt.SizeOfCode))
		case "size_of_initialized_data":
			return IntegerValue(int64(opt.SizeOfInitializedData))
		case "size_of_uninitialized_data":
			return IntegerValue(int64(opt.SizeOfUninitializedData))
		case "base_of_code":
			return IntegerValue(int64(opt.BaseOfCode))
		case "section_alignment":
			return IntegerValue(int64(opt.SectionAlignment))
		case "file_alignment":
			return IntegerValue(int64(opt.FileAlignment))
		case "linker_version":
			if versions[0].Type == ModuleUndefined {
				versions[0] = peVersion(uint16(opt.MajorLinkerVersion), uint16(opt.MinorLinkerVersion))
			}
			return versions[0]
		case "os_version":
			if versions[1].Type == ModuleUndefined {
				versions[1] = peVersion(opt.MajorOperatingSystemVersion, opt.MinorOperatingSystemVersion)
			}
			return versions[1]
		case "image_version":
			if versions[2].Type == ModuleUndefined {
				versions[2] = peVersion(opt.MajorImageVersion, opt.MinorImageVersion)
			}
			return versions[2]
		case "subsystem_version":
			if versions[3].Type == ModuleUndefined {
				versions[3] = peVersion(opt.MajorSubsystemVersion, opt.MinorSubsystemVersion)
			}
			return versions[3]
		case "win32_version_value":
			return IntegerValue(int64(opt.Win32VersionValue))
		case "size_of_image":
			return IntegerValue(int64(opt.SizeOfImage))
		case "size_of_headers":
			return IntegerValue(int64(opt.SizeOfHeaders))
		case "checksum":
			return IntegerValue(int64(opt.CheckSum))
		case "subsystem":
			return IntegerValue(int64(opt.Subsystem))
		case "dll_characteristics":
			return IntegerValue(int64(opt.DllCharacteristics))
		case "size_of_stack_reserve":
			return peInteger(opt.SizeOfStackReserve)
		case "size_of_stack_commit":
			return peInteger(opt.SizeOfStackCommit)
		case "size_of_heap_reserve":
			return peInteger(opt.SizeOfHeapReserve)
		case "size_of_heap_commit":
			return peInteger(opt.SizeOfHeapCommit)
		case "loader_flags":
			return IntegerValue(int64(opt.LoaderFlags))
		case "base_of_data":
			if file.Is32Bit() {
				return IntegerValue(int64(opt.BaseOfData))
			}
		case "sections":
			if sections.Type == ModuleUndefined {
				values := make([]ModuleValue, len(file.Sections))
				for i, section := range file.Sections {
					values[i] = peSectionFields(section, names[i], coff.PointerToSymbolTable != 0)
				}
				sections = peArray(values)
			}
			return sections
		case "data_directories":
			if directories.Type == ModuleUndefined {
				values := make([]ModuleValue, min(opt.NumberOfRvaAndSizes, pe.NumberOfDataDirectories))
				for i := range values {
					d := opt.DataDirectories[i]
					values[i] = peStruct(map[string]ModuleValue{
						"virtual_address": IntegerValue(int64(d.VirtualAddress)), "size": IntegerValue(int64(d.Size)),
					})
				}
				directories = peArray(values)
			}
			return directories
		}
		return ModuleValue{}
	})
}

func peLazyStruct(field func(string) ModuleValue) ModuleValue {
	return ModuleValue{Type: ModuleStruct, object: &moduleObject{kind: ModuleStruct, field: field}}
}

func peSectionFields(s pe.Section, name string, hasSymbols bool) ModuleValue {
	fullName := StringValue(name)
	if hasSymbols && strings.HasPrefix(name, "/") {
		fullName = StringValue(s.Name)
		for _, b := range []byte(s.Name) {
			if b < 0x20 || b > 0x7e {
				fullName = ModuleValue{}
				break
			}
		}
	}
	return peLazyStruct(func(field string) ModuleValue {
		switch field {
		case "name":
			return StringValue(name)
		case "full_name":
			return fullName
		case "characteristics":
			return IntegerValue(int64(s.Characteristics))
		case "virtual_address":
			return IntegerValue(int64(s.VirtualAddress))
		case "virtual_size":
			return IntegerValue(int64(s.VirtualSize))
		case "raw_data_offset":
			return IntegerValue(int64(s.PointerToRawData))
		case "raw_data_size":
			return IntegerValue(int64(s.SizeOfRawData))
		case "pointer_to_relocations":
			return IntegerValue(int64(s.PointerToRelocations))
		case "pointer_to_line_numbers":
			return IntegerValue(int64(s.PointerToLinenumbers))
		case "number_of_relocations":
			return IntegerValue(int64(s.NumberOfRelocations))
		case "number_of_line_numbers":
			return IntegerValue(int64(s.NumberOfLinenumbers))
		}
		return ModuleValue{}
	})
}

// peEntryPoint implements libyara's file mapping policy. It deliberately does
// not use go-pe's RVA mapper: YARA aligns raw offsets down, chooses the highest
// covering section RVA (the last on ties), and maps bytes before the first
// section directly. An unmapped entry point is -1, not undefined.
func peEntryPoint(file *pe.File, fileSize int64) int64 {
	rva := uint64(file.OptionalHeader.AddressOfEntryPoint)
	lowest := uint64(math.MaxUint32)
	var address, offset, size uint64
	for _, s := range file.Sections {
		va := uint64(s.VirtualAddress)
		lowest = min(lowest, va)
		if rva < va || rva-va >= uint64(max(s.VirtualSize, s.SizeOfRawData)) || va < address {
			continue
		}
		address, offset, size = va, uint64(s.PointerToRawData), uint64(s.SizeOfRawData)
		if alignment := uint64(min(file.OptionalHeader.FileAlignment, 0x200)); alignment != 0 {
			offset -= offset % alignment
		}
		if file.OptionalHeader.SectionAlignment >= 0x1000 {
			offset &^= 0x1ff
		}
	}
	if rva < lowest {
		address, offset, size = 0, 0, uint64(fileSize) //checkednarrow:ignore scan sizes are nonnegative
	}
	if rva < address || rva-address >= size || offset+rva-address >= uint64(fileSize) {
		return -1
	}
	return int64(offset + rva - address) //checkednarrow:ignore bounded by nonnegative fileSize
}

// peInteger preserves unsigned header bits, including libyara's reserved
// undefined sentinel. Only PE32+ fields can hold this 64-bit value.
func peInteger(value uint64) ModuleValue {
	if value == 0xfffabadafabadaff {
		return ModuleValue{}
	}
	return IntegerValue(int64(value)) //checkednarrow:ignore intentional YARA bit interpretation
}
