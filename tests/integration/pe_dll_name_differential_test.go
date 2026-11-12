package integration

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestLibyaraPEDLLName(t *testing.T) {
	libyaraOracle(t)
	source := peProbeSource([]string{
		`defined pe.dll_name`, `pe.dll_name == ""`, `pe.dll_name == "Example.DLL"`,
		`pe.dll_name == "example.dll"`, `pe.dll_name contains "DLL"`, `pe.dll_name == "\xffName"`,
		`pe.dll_name == "Example.DLL\x00suffix"`,
		`pe.dll_name startswith "Example"`, `pe.dll_name endswith "DLL"`,
		`pe.dll_name icontains "dll"`, `pe.dll_name istartswith "example"`,
		`pe.dll_name iendswith "dll"`, `pe.dll_name iequals "example.dll"`,
		`"Example.DLL" iequals pe.dll_name`, `pe.dll_name matches /DLL/`,
		fmt.Sprintf(`pe.dll_name == "%s"`, strings.Repeat("N", 512)),
		fmt.Sprintf(`pe.dll_name == "%s"`, strings.Repeat("N", 513)),
	})
	for _, is64 := range []bool{false, true} {
		for _, count := range []int{0, 3} {
			for _, tc := range []struct {
				name   string
				change func([]byte)
			}{
				{"named", func([]byte) {}},
				{"absent", func(d []byte) { binary.LittleEndian.PutUint32(d[0x80c:], 0) }},
				{"empty", func(d []byte) { d[0x428] = 0 }},
				{"raw", func(d []byte) { copy(d[0x428:], "\xffName\x00") }},
				{"long", func(d []byte) {
					off := len(d) - 600
					copy(d[off:], strings.Repeat("N", 513)+"\x00")
					binary.LittleEndian.PutUint32(d[0x80c:], uint32(off+0x1c00)) //checkednarrow:ignore bounded fixture offset
				}},
				{"last_byte", func(d []byte) { binary.LittleEndian.PutUint32(d[0x80c:], uint32(len(d)-1+0x1c00)) }}, //checkednarrow:ignore bounded fixture offset
				{"unmapped", func(d []byte) { binary.LittleEndian.PutUint32(d[0x80c:], 0xffffffff) }},
				{"headers", func(d []byte) { copy(d[0x1f0:], "Example.DLL\x00"); binary.LittleEndian.PutUint32(d[0x80c:], 0x1f0) }},
				{"offset_zero", func(d []byte) {
					section := 0x98 + int(binary.LittleEndian.Uint16(d[0x94:]))
					binary.LittleEndian.PutUint32(d[section+20:], 0)
					binary.LittleEndian.PutUint32(d[0x80c:], 0x1000)
				}},
			} {
				t.Run(fmt.Sprintf("%s/PE64=%t/count=%d", tc.name, is64, count), func(t *testing.T) {
					data := pefixture.Exports(is64, count)
					tc.change(data)
					checkPEPaths(t, source, data)
				})
			}
		}
	}
	for name, data := range map[string][]byte{"no_directory32": pefixture.New(false), "no_directory64": pefixture.New(true), "non_pe": []byte("ordinary"), "empty": nil} {
		t.Run(name, func(t *testing.T) { checkPEPaths(t, source, data) })
	}
}
