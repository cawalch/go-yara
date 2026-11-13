package integration

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func peFixtureSectionOffset(data []byte, index int) int {
	return 0x98 + int(binary.LittleEndian.Uint16(data[0x94:])) + index*40
}

func TestLibyaraPESectionIndex(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		t.Run(fmt.Sprintf("64=%t", is64), func(t *testing.T) {
			for _, tc := range []struct {
				name       string
				change     func([]byte)
				predicates []string
			}{
				{"base", func([]byte) {}, []string{
					`pe.section_index(".text") == 0`, `pe.section_index(".data") == 1`,
					`not defined pe.section_index(".TEXT")`, `not defined pe.section_index("")`,
					`pe.section_index(0x200) == 0`, `pe.section_index(0x3ff) == 0`,
					`pe.section_index(0x400) == 1`, `pe.section_index(0x5ff) == 1`,
					`not defined pe.section_index(0x1ff)`, `not defined pe.section_index(0x600)`,
					`not defined pe.section_index(-1)`, `not defined pe.section_index(0x7fffffff)`,
				}},
				{"duplicate", func(data []byte) {
					copy(data[peFixtureSectionOffset(data, 1):], ".text\x00\x00\x00")
				}, []string{`pe.section_index(".text") == 0`}},
				{"nul", func(data []byte) {
					offset := peFixtureSectionOffset(data, 0)
					copy(data[offset:offset+8], "a\x00bc\x00\x00\x00")
				}, []string{
					`pe.section_index("a") == 0`,
					`pe.section_index("a\x00bc") == 0`,
					`not defined pe.section_index("ab")`,
				}},
				{"overlap", func(data []byte) {
					binary.LittleEndian.PutUint32(data[peFixtureSectionOffset(data, 1)+20:], 0x300)
				}, []string{
					`pe.section_index(0x300) == 0`,
					`pe.section_index(0x400) == 1`,
				}},
				{"zero-size", func(data []byte) {
					binary.LittleEndian.PutUint32(data[peFixtureSectionOffset(data, 0)+16:], 0)
				}, []string{
					`not defined pe.section_index(0x200)`,
					`pe.section_index(0x400) == 1`,
				}},
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
			checkPEPaths(t, peProbeSource([]string{`not defined pe.section_index(".text")`, `not defined pe.section_index(0)`}), data)
		})
	}
}

func TestLibyaraPESectionIndexLimit(t *testing.T) {
	for _, count := range []uint16{0, 96, 97} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			data := make([]byte, 0x10000)
			copy(data, pefixture.New(false))
			binary.LittleEndian.PutUint16(data[0x86:], count)
			for i := 0; i < int(count); i++ {
				section := data[0x178+i*40:]
				copy(section, ".text\x00\x00\x00")
				binary.LittleEndian.PutUint32(section[16:], 0x200)
				binary.LittleEndian.PutUint32(section[20:], 0x400)
			}
			if count == 97 {
				copy(data[0x178+96*40:], ".late\x00\x00\x00")
			}
			predicates := []string{`pe.section_index(".text") == 0`, `pe.section_index(0x400) == 0`, `not defined pe.section_index(".late")`}
			if count == 0 {
				predicates = []string{`not defined pe.section_index(".text")`, `not defined pe.section_index(0x400)`, `not defined pe.section_index(".late")`}
			}
			checkPEPaths(t, peProbeSource(predicates), data)
		})
	}
}
