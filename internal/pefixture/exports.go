package pefixture

import (
	"encoding/binary"
	"fmt"
)

// Exports adds an export directory after the import metadata. Images contain
// both directories so tests can exercise independent, deferred parsing.
// The directory is at file offset 0x800 (RVA 0x2400), followed by address,
// name-pointer, and ordinal tables. Each name has a 16-byte slot; the directory
// ends with 1 KiB of spare space for forwarder and long-name tests.
func Exports(is64 bool, symbols int) []byte {
	data := Imports(is64, 3)
	pointers := 0x828 + symbols*4
	ordinals := pointers + symbols*4
	names := ordinals + symbols*2
	end := names + symbols*16 + 1024
	data = append(data[:0x800], make([]byte, ((end+511)&^511)-0x800)...)
	section, directory := 0x1a0, 0xf8
	if is64 {
		section, directory = 0x1b0, 0x108
	}
	put32 := func(offset int, value uint32) { binary.LittleEndian.PutUint32(data[offset:], value) }
	rva := func(offset int) uint32 { return uint32(offset-0x400) + 0x2000 } //checkednarrow:ignore bounded fixture offsets
	put32(section+8, uint32(len(data)-0x400))                               //checkednarrow:ignore bounded fixture size
	put32(section+16, uint32(len(data)-0x400))                              //checkednarrow:ignore bounded fixture size
	put32(directory, 0x2400)
	put32(directory+4, uint32(end-0x800)) //checkednarrow:ignore bounded fixture size
	put32(0x80c, 0x2028)                  // Reuse the import DLL name.
	put32(0x810, 7)
	put32(0x814, uint32(symbols)) //checkednarrow:ignore bounded fixture counts
	put32(0x818, uint32(symbols)) //checkednarrow:ignore bounded fixture counts
	put32(0x81c, 0x2428)
	put32(0x820, rva(pointers))
	put32(0x824, rva(ordinals))
	for i := range symbols {
		put32(0x828+i*4, 0x1020)
		put32(pointers+i*4, rva(names+i*16))
		binary.LittleEndian.PutUint16(data[ordinals+i*2:], uint16(i)) //checkednarrow:ignore fixture has at most 65536 slots
		copy(data[names+i*16:], fmt.Sprintf("Function%05d", i))
	}
	return data
}
