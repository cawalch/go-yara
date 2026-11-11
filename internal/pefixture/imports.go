package pefixture

import "encoding/binary"

// Imports returns a synthetic image with one import library and named symbols
// in its second section. Symbols share a hint/name record to keep large-limit
// fixtures small. The descriptors start at file offset 0x400 (RVA 0x2000),
// lookup entries at 0x440, DLL name at 0x428, and hint/name after the lookup table.
func Imports(is64 bool, symbols int) []byte {
	data := New(is64)
	width, section, directory := 4, 0x1a0, 0x100
	if is64 {
		width, section, directory = 8, 0x1b0, 0x110
	}
	name := 0x440 + (symbols+1)*width
	size := (name + 1024 + 511) &^ 511
	data = append(data[:0x400], make([]byte, size-0x400)...)
	binary.LittleEndian.PutUint32(data[section+8:], uint32(size-0x400))  //checkednarrow:ignore test fixture sizes
	binary.LittleEndian.PutUint32(data[section+16:], uint32(size-0x400)) //checkednarrow:ignore test fixture sizes
	binary.LittleEndian.PutUint32(data[directory:], 0x2000)
	binary.LittleEndian.PutUint32(data[directory+4:], 40)
	binary.LittleEndian.PutUint32(data[0x400:], 0x2040)
	binary.LittleEndian.PutUint32(data[0x40c:], 0x2028)
	binary.LittleEndian.PutUint32(data[0x410:], 0x2040)
	copy(data[0x428:], "Example.DLL\x00")
	for i := range symbols {
		value := uint64(name - 0x400 + 0x2000) //checkednarrow:ignore nonnegative test offset
		if is64 {
			binary.LittleEndian.PutUint64(data[0x440+i*width:], value)
		} else {
			binary.LittleEndian.PutUint32(data[0x440+i*width:], uint32(value))
		} //checkednarrow:ignore bounded test RVA
	}
	binary.LittleEndian.PutUint16(data[name:], 42)
	copy(data[name+2:], "NamedFunction\x00")
	return data
}

// ImportOrdinal replaces a lookup entry with an ordinal import.
func ImportOrdinal(data []byte, index int, ordinal uint16) {
	if binary.LittleEndian.Uint16(data[0x98:]) == 0x20b {
		binary.LittleEndian.PutUint64(data[0x440+index*8:], 1<<63|uint64(ordinal))
	} else {
		binary.LittleEndian.PutUint32(data[0x440+index*4:], 1<<31|uint32(ordinal))
	}
}

// ImportName replaces the shared function name without moving its RVA.
func ImportName(data []byte, name string) {
	rva := binary.LittleEndian.Uint32(data[0x440:])
	offset := int(rva) - 0x2000 + 0x400 + 2
	if len(name)+1 > len(data)-offset {
		panic("import name exceeds fixture")
	}
	copy(data[offset:], name+"\x00")
}
