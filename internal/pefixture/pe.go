// Package pefixture builds synthetic PE images for tests and benchmarks.
package pefixture

import "encoding/binary"

// New returns a PE32 or PE32+ image with two sections. It contains no executable
// instructions or directory contents. Each call returns an independent buffer.
func New(is64 bool) []byte {
	data := make([]byte, 0x800)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:], 0x80)
	copy(data[0x80:], "PE\x00\x00")
	coff := data[0x84:]
	machine, optionalSize, magic := uint16(0x14c), uint16(224), uint16(0x10b)
	if is64 {
		machine, optionalSize, magic = 0x8664, 240, 0x20b
	}
	binary.LittleEndian.PutUint16(coff, machine)
	binary.LittleEndian.PutUint16(coff[2:], 2)
	binary.LittleEndian.PutUint32(coff[4:], 0xf1234567)
	binary.LittleEndian.PutUint16(coff[16:], optionalSize)
	binary.LittleEndian.PutUint16(coff[18:], 0x2022)
	opt := data[0x98:]
	binary.LittleEndian.PutUint16(opt, magic)
	opt[2], opt[3] = 14, 3
	for offset, value := range map[int]uint32{
		4: 0x200, 8: 0x400, 12: 0x100, 16: 0x1020, 20: 0x1000,
		32: 0x1000, 36: 0x200, 52: 7, 56: 0x3000, 60: 0x200, 64: 0x12345678,
	} {
		binary.LittleEndian.PutUint32(opt[offset:], value)
	}
	for offset, value := range map[int]uint16{40: 6, 42: 1, 44: 2, 46: 3, 48: 6, 50: 2, 68: 3, 70: 0x8160} {
		binary.LittleEndian.PutUint16(opt[offset:], value)
	}
	if is64 {
		binary.LittleEndian.PutUint64(opt[24:], 0x140000000)
		for offset, value := range map[int]uint64{72: 0x100000000, 80: 0x2000, 88: 0x200000000, 96: 0x3000} {
			binary.LittleEndian.PutUint64(opt[offset:], value)
		}
		binary.LittleEndian.PutUint32(opt[104:], 9)
		binary.LittleEndian.PutUint32(opt[108:], 16)
	} else {
		binary.LittleEndian.PutUint32(opt[24:], 0x2000)
		binary.LittleEndian.PutUint32(opt[28:], 0x400000)
		for offset, value := range map[int]uint32{72: 0x100000, 76: 0x2000, 80: 0x200000, 84: 0x3000, 88: 9, 92: 16} {
			binary.LittleEndian.PutUint32(opt[offset:], value)
		}
	}
	sections := data[0x98+int(optionalSize):]
	for i, name := range []string{".text", ".data"} {
		s := sections[i*40:]
		copy(s, name)
		binary.LittleEndian.PutUint32(s[8:], 0x180)
		binary.LittleEndian.PutUint32(s[12:], uint32(0x1000*(i+1))) //checkednarrow:ignore two sections
		binary.LittleEndian.PutUint32(s[16:], 0x200)
		binary.LittleEndian.PutUint32(s[20:], uint32(0x200*(i+1))) //checkednarrow:ignore two sections
		binary.LittleEndian.PutUint32(s[24:], 0x600)
		binary.LittleEndian.PutUint32(s[28:], 0x640)
		binary.LittleEndian.PutUint16(s[32:], 3)
		binary.LittleEndian.PutUint16(s[34:], 4)
		flags := uint32(0x60000020)
		if i == 1 {
			flags = 0xc0000040
		}
		binary.LittleEndian.PutUint32(s[36:], flags)
	}
	return data
}
