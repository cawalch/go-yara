package integration

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestLibyaraPERVAToOffset(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		t.Run(fmt.Sprintf("64=%t", is64), func(t *testing.T) {
			for _, tc := range []struct {
				name       string
				change     func([]byte)
				predicates []string
			}{
				{"base", func([]byte) {}, []string{
					`pe.rva_to_offset(0) == 0`,
					`pe.rva_to_offset(0x200) == 0x200`,
					`pe.rva_to_offset(0x7ff) == 0x7ff`,
					`not defined pe.rva_to_offset(0x800)`,
					`pe.rva_to_offset(0x1000) == 0x200`,
					`pe.rva_to_offset(0x11ff) == 0x3ff`,
					`not defined pe.rva_to_offset(0x1200)`,
					`pe.rva_to_offset(0x2000) == 0x400`,
					`pe.rva_to_offset(0x21ff) == 0x5ff`,
					`not defined pe.rva_to_offset(0x2200)`,
					`not defined pe.rva_to_offset(-1)`,
					`not defined pe.rva_to_offset(0xffffffff)`,
					`not defined pe.rva_to_offset(0x100000000)`,
					`pe.rva_to_offset(pe.entry_point_raw) == pe.entry_point`,
				}},
				{"gap", func(data []byte) {
					binary.LittleEndian.PutUint32(data[peFixtureSectionOffset(data, 1)+12:], 0x3000)
				}, []string{
					`pe.rva_to_offset(0x3000) == 0x400`,
					`not defined pe.rva_to_offset(0x2500)`,
				}},
				{"virtual-tail", func(data []byte) {
					binary.LittleEndian.PutUint32(data[peFixtureSectionOffset(data, 0)+8:], 0x400)
				}, []string{
					`pe.rva_to_offset(0x11ff) == 0x3ff`,
					`not defined pe.rva_to_offset(0x1200)`,
				}},
				{"overlap", func(data []byte) {
					binary.LittleEndian.PutUint32(data[peFixtureSectionOffset(data, 1)+12:], 0x1100)
				}, []string{
					`pe.rva_to_offset(0x1050) == 0x250`,
					`pe.rva_to_offset(0x1150) == 0x450`,
				}},
				{"overlap-tie", func(data []byte) {
					binary.LittleEndian.PutUint32(data[peFixtureSectionOffset(data, 1)+12:], 0x1000)
				}, []string{
					`pe.rva_to_offset(0x1050) == 0x450`,
				}},
				{"no-sections", func(data []byte) {
					binary.LittleEndian.PutUint16(data[0x86:], 0)
				}, []string{
					`pe.rva_to_offset(0) == 0`,
					`pe.rva_to_offset(0x7ff) == 0x7ff`,
					`not defined pe.rva_to_offset(0x800)`,
					`not defined pe.rva_to_offset(0xffffffff)`,
					`not defined pe.rva_to_offset(0x100000000)`,
				}},
				{"file-alignment", func(data []byte) {
					binary.LittleEndian.PutUint32(data[peFixtureSectionOffset(data, 0)+20:], 0x205)
					binary.LittleEndian.PutUint32(data[0x98+32:], 0x200)
					binary.LittleEndian.PutUint32(data[0x98+36:], 4)
				}, []string{`pe.rva_to_offset(0x1000) == 0x204`}},
				{"sector-alignment", func(data []byte) {
					binary.LittleEndian.PutUint32(data[peFixtureSectionOffset(data, 0)+20:], 0x3ff)
				}, []string{`pe.rva_to_offset(0x1000) == 0x200`}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					data := pefixture.New(is64)
					tc.change(data)
					checkPEPaths(t, peProbeSource(tc.predicates), data)
				})
			}
		})
	}
	for name, data := range map[string][]byte{"non_pe": []byte("ordinary"), "empty": nil, "mz_only": []byte("MZ")} {
		t.Run(name, func(t *testing.T) {
			checkPEPaths(t, peProbeSource([]string{`not defined pe.rva_to_offset(0)`, `not defined pe.rva_to_offset(0x1000)`}), data)
		})
	}

	t.Run("section-limit", func(t *testing.T) {
		data := make([]byte, 0x10000)
		copy(data, pefixture.New(false))
		binary.LittleEndian.PutUint16(data[0x86:], 97)
		for i := 0; i < 97; i++ {
			section := data[0x178+i*40:]
			copy(section, ".text\x00\x00\x00")
			binary.LittleEndian.PutUint32(section[8:], 0x200)
			binary.LittleEndian.PutUint32(section[12:], uint32(0x1000*(i+1))) //checkednarrow:ignore bounded by 97
			binary.LittleEndian.PutUint32(section[16:], 0x200)
			binary.LittleEndian.PutUint32(section[20:], 0x2000)
		}
		checkPEPaths(t, peProbeSource([]string{
			`pe.rva_to_offset(0x60000) == 0x2000`,
			`not defined pe.rva_to_offset(0x61000)`,
		}), data)
	})

	t.Run("4gb-cross", func(t *testing.T) {
		data := make([]byte, 0x3000)
		copy(data, pefixture.New(false))
		s0 := peFixtureSectionOffset(data, 0)
		binary.LittleEndian.PutUint32(data[s0+8:], 0x2000)
		binary.LittleEndian.PutUint32(data[s0+12:], 0xfffff000)
		binary.LittleEndian.PutUint32(data[s0+16:], 0x2000)
		binary.LittleEndian.PutUint32(data[s0+20:], 0x200)
		checkPEPaths(t, peProbeSource([]string{
			`pe.rva_to_offset(0xffffffff) == 0x11ff`,
			`pe.rva_to_offset(0x100000000) == 0x1200`,
			`not defined pe.rva_to_offset(0x100001000)`,
		}), data)
	})
}
