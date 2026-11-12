package integration

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func exportTable(data []byte, field int) int {
	return int(binary.LittleEndian.Uint32(data[0x800+field:])) - 0x1c00
}

func TestLibyaraPEStandardExports(t *testing.T) {
	libyaraOracle(t)
	predicates := []string{
		`pe.is_pe`, `pe.number_of_exports == 0`, `pe.number_of_exports == 3`, `defined pe.number_of_exports`,
		`pe.number_of_imports == 1`, `pe.imports("example.dll") == 3`,
		`for any e in pe.export_details : (e.name == "Function00000" and e.ordinal == 7)`,
		`for all e in pe.export_details : (e.rva == 0x1020)`,
		`defined pe.export_details[-1].ordinal`, `defined pe.export_details[3].ordinal`,
		`defined pe.exports("Function00000")`, `defined pe.exports(1)`,
		`pe.exports("Function00000") == 1`, `pe.exports("fUNCTION00000") == 1`,
		`pe.exports("Function00001") == 1`, `pe.exports("missing") == 0`,
		`pe.exports("") == 1`, `pe.exports("Function00000\x00suffix") == 0`,
		`pe.exports("\x00") == 0`, `pe.exports("odd-name") == 1`,
		`pe.exports("Kelvin") == 1`, `pe.exports("Kelvin") == 0`,
		`pe.exports("\xffname") == 1`, `pe.exports("other.Target") == 0`,
		`defined pe.exports(pe.export_details[3].name)`, `defined pe.exports(uint16(filesize))`,
		`pe.exports(pe.export_details[0].name) == 1`,
		`for any e in pe.export_details : (pe.exports(e.ordinal))`,
		`defined pe.exports_index("Function00000")`, `pe.exports_index("FUNCTION00000") == 0`,
		`pe.exports_index("Function00001") == 1`, `pe.exports_index("Function00002") == 2`,
		`defined pe.exports_index("missing")`, `defined pe.exports_index("Function00000\x00suffix")`,
		`pe.exports_index("") == 0`, `defined pe.exports_index("\x00")`,
		`pe.exports_index("Kelvin") == 0`, `defined pe.exports_index("Kelvin")`,
		`pe.exports_index("\xffname") == 0`, `pe.exports_index("odd-name") == 0`,
		`defined pe.exports_index("other.Target")`, `defined pe.exports_index(uint16(filesize))`,
		`defined pe.exports_index(pe.export_details[3].name)`,
		`pe.exports_index(pe.export_details[1].name) == 0`, `pe.exports_index(pe.export_details[1].name) == 1`,
		`pe.export_details[pe.exports_index("Function00002")].rva == 0x1020`,
		fmt.Sprintf(`pe.exports_index("%s") == 0`, strings.Repeat("N", 512)),
		fmt.Sprintf(`defined pe.exports_index("%s")`, strings.Repeat("N", 513)),
		fmt.Sprintf(`pe.exports("%s") == 1`, strings.Repeat("N", 512)),
		fmt.Sprintf(`pe.exports("%s") == 0`, strings.Repeat("N", 513)),
	}
	for _, ordinal := range []string{"-1", "0", "1", "2", "3", "7", "9", "0xfffffffe", "0x100000001", "0x7fffffffffffffff"} {
		predicates = append(predicates, fmt.Sprintf("pe.exports(%s) == 1", ordinal),
			fmt.Sprintf("defined pe.exports_index(%s)", ordinal))
		for index := range 3 {
			predicates = append(predicates, fmt.Sprintf("pe.exports_index(%s) == %d", ordinal, index))
		}
	}
	for i := range 3 {
		for _, field := range []string{"name", "ordinal", "rva", "offset", "forward_name"} {
			predicates = append(predicates, fmt.Sprintf("defined pe.export_details[%d].%s", i, field))
		}
		for _, pair := range []struct{ field, value string }{
			{"ordinal", strconv.Itoa(7 + i)}, {"rva", "0x1020"}, {"rva", "0"}, {"rva", "0xffffffff"},
			{"offset", "0x220"}, {"offset", "0"}, {"offset", "0x40"}, {"offset", "0x700"},
			{"offset", "0x200"}, {"offset", "filesize - 1"}, {"offset", "filesize"},
			{"name", fmt.Sprintf("%q", fmt.Sprintf("Function%05d", i))}, {"name", `""`},
			{"name", `"odd-name"`}, {"name", fmt.Sprintf("%q", strings.Repeat("N", 512))},
			{"forward_name", `"other.Target"`}, {"forward_name", `""`},
			{"forward_name", fmt.Sprintf("%q", strings.Repeat("F", 512))},
		} {
			predicates = append(predicates, fmt.Sprintf("pe.export_details[%d].%s == %s", i, pair.field, pair.value))
		}
	}
	source := peProbeSource(predicates)
	for _, is64 := range []bool{false, true} {
		for _, tc := range []struct {
			name   string
			change func([]byte)
		}{
			{"named", func([]byte) {}},
			{"duplicate_names", func(d []byte) { copy(d[exportTable(d, 36)+6+16:], "FUNCTION00000\x00") }},
			{"base_zero", func(d []byte) { binary.LittleEndian.PutUint32(d[0x810:], 0) }},
			{"base_one", func(d []byte) { binary.LittleEndian.PutUint32(d[0x810:], 1) }},
			{"base_high", func(d []byte) { binary.LittleEndian.PutUint32(d[0x810:], 0xfffffffc) }},
			{"unicode_query", func(d []byte) { copy(d[exportTable(d, 36)+6:], "Kelvin\x00") }},
			{"high_byte_name", func(d []byte) { copy(d[exportTable(d, 36)+6:], "\xffName\x00") }},
			{"ordinal_only", func(d []byte) { binary.LittleEndian.PutUint32(d[0x818:], 0) }},
			{"empty", func(d []byte) { clear(d[0x814:0x81c]) }},
			{"hole", func(d []byte) { clear(d[0x82c:0x830]); binary.LittleEndian.PutUint32(d[0x810:], 1) }},
			{"aliases", func(d []byte) { binary.LittleEndian.PutUint16(d[exportTable(d, 36)+2:], 0) }},
			{"empty_name", func(d []byte) { d[exportTable(d, 36)+6] = 0 }},
			{"raw_name", func(d []byte) { copy(d[exportTable(d, 36)+6:], "odd-name\x00") }},
			{"long_name", func(d []byte) {
				off := len(d) - 600
				copy(d[off:], strings.Repeat("N", 513)+"\x00")
				binary.LittleEndian.PutUint32(d[exportTable(d, 32):], uint32(off+0x1c00)) //checkednarrow:ignore fixture offset
			}},
			{"forwarder", func(d []byte) {
				off := exportTable(d, 36) + 6 + 3*16
				copy(d[off:], "other.Target\x00")
				binary.LittleEndian.PutUint32(d[0x82c:], uint32(off+0x1c00)) //checkednarrow:ignore fixture offset
			}},
			{"long_forwarder", func(d []byte) {
				off := exportTable(d, 36) + 6 + 3*16
				copy(d[off:], strings.Repeat("F", 513)+"\x00")
				binary.LittleEndian.PutUint32(d[0x82c:], uint32(off+0x1c00)) //checkednarrow:ignore fixture offset
			}},
			{"empty_forwarder", func(d []byte) {
				binary.LittleEndian.PutUint32(d[0x82c:], uint32(exportTable(d, 36)+6+3*16+0x1c00)) //checkednarrow:ignore fixture offset
			}},
			{"unmapped_target", func(d []byte) { binary.LittleEndian.PutUint32(d[0x828:], 0xffffffff) }},
			{"header_target", func(d []byte) { binary.LittleEndian.PutUint32(d[0x828:], 0x40) }},
			{"before_first_section", func(d []byte) { binary.LittleEndian.PutUint32(d[0x828:], 0x700) }},
			{"zero_rva_section", func(d []byte) {
				section := 0x98 + int(binary.LittleEndian.Uint16(d[0x94:]))
				binary.LittleEndian.PutUint32(d[section+12:], 0)
				binary.LittleEndian.PutUint32(d[0x828:], 0)
			}},
			{"last_file_byte", func(d []byte) { binary.LittleEndian.PutUint32(d[0x828:], uint32(len(d)-1+0x1c00)) }}, //checkednarrow:ignore fixture offset
			{"past_file_end", func(d []byte) { binary.LittleEndian.PutUint32(d[0x828:], uint32(len(d)+0x1c00)) }},    //checkednarrow:ignore fixture offset
			{"aligned_target_offset", func(d []byte) {
				section := 0x98 + int(binary.LittleEndian.Uint16(d[0x94:]))
				binary.LittleEndian.PutUint32(d[section+20:], 0x2ff)
			}},
			{"virtual_target", func(d []byte) {
				section := 0x98 + int(binary.LittleEndian.Uint16(d[0x94:]))
				binary.LittleEndian.PutUint32(d[section+8:], 0x400)
				binary.LittleEndian.PutUint32(d[0x828:], 0x1300)
			}},
		} {
			t.Run(fmt.Sprintf("%s/PE64=%t", tc.name, is64), func(t *testing.T) {
				data := pefixture.Exports(is64, 3)
				tc.change(data)
				checkPEPaths(t, source, data)
			})
		}
	}
	for name, data := range map[string][]byte{"absent32": pefixture.New(false), "absent64": pefixture.New(true), "non_pe": []byte("ordinary"), "empty": nil} {
		t.Run(name, func(t *testing.T) { checkPEPaths(t, source, data) })
	}
}

func TestLibyaraPEExportCompatibilityLimits(t *testing.T) {
	for _, tc := range []struct {
		name          string
		change        func([]byte)
		oracle, local string
	}{
		{"short_directory", func(d []byte) { binary.LittleEndian.PutUint32(d[0xfc:], 39) }, `pe.number_of_exports == 3`, `not defined pe.number_of_exports`},
		{"bad_name_ordinal", func(d []byte) { binary.LittleEndian.PutUint16(d[exportTable(d, 36):], 3) }, `pe.number_of_exports == 3`, `not defined pe.number_of_exports`},
		{"bad_table", func(d []byte) { binary.LittleEndian.PutUint32(d[0x81c:], 0xffffffff) }, `pe.number_of_exports == 0 and pe.exports(1) == 0 and pe.exports("Function00000") == 0 and not defined pe.exports_index(1) and not defined pe.exports_index("Function00000")`, `not defined pe.number_of_exports and not defined pe.exports(1) and not defined pe.exports("Function00000") and not defined pe.exports_index(1) and not defined pe.exports_index("Function00000")`},
		{"directory_start_forwarder", func(d []byte) { binary.LittleEndian.PutUint32(d[0x828:], 0x2400) }, `pe.export_details[0].offset == 0x800 and not defined pe.export_details[0].forward_name`, `pe.export_details[0].forward_name == "" and not defined pe.export_details[0].offset`},
		{"alias_beyond_name_window", func(d []byte) {
			binary.LittleEndian.PutUint32(d[0x814:], 2)
			ordinals := exportTable(d, 36)
			for i, index := range []uint16{1, 1, 0} {
				binary.LittleEndian.PutUint16(d[ordinals+i*2:], index)
			}
		}, `not defined pe.export_details[0].name and pe.exports("Function00002") == 0 and not defined pe.exports_index("Function00002")`, `pe.export_details[0].name == "Function00002" and pe.exports("Function00002") == 1 and pe.exports_index("Function00002") == 0`},
		{"name_beyond_address_count", func(d []byte) {
			binary.LittleEndian.PutUint32(d[0x814:], 1)
			clear(d[exportTable(d, 36) : exportTable(d, 36)+6])
			// Put the third name at an invalid RVA: go-pe validates every alias,
			// including the third, which libyara does not examine.
			binary.LittleEndian.PutUint32(d[exportTable(d, 32)+8:], 0xffffffff)
		}, `pe.export_details[0].name == "Function00000"`, `not defined pe.number_of_exports`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := pefixture.Exports(false, 3)
			tc.change(data)
			source := fmt.Sprintf(`import "pe" rule oracle {condition: pe.is_pe and %s} rule local {condition: pe.is_pe and %s}`, tc.oracle, tc.local)
			want, err := scanWithLibyara(t, libyaraOracle(t), source, data)
			if err != nil || !reflect.DeepEqual(want, map[string][]span{"oracle": nil}) {
				t.Fatalf("oracle changed: %v %v", want, err)
			}
			got, err := scanWithGoYara(source, data)
			if err != nil || !reflect.DeepEqual(got, map[string][]span{"local": nil}) {
				t.Fatalf("local changed: %v %v", got, err)
			}
		})
	}
}

func TestLibyaraPEExportQueryLimit(t *testing.T) {
	for _, count := range []int{16384, 16385} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			data := pefixture.Exports(true, count)
			binary.LittleEndian.PutUint32(data[0x810:], 1)
			checkReleaseScanPaths(t, peProbeSource([]string{
				`pe.exports("Function16383") == 1`, `pe.exports("Function16384") == 0`,
				`pe.exports(16384) == 1`, `pe.exports(16385) == 0`,
				`pe.exports_index("Function16383") == 16383`, `not defined pe.exports_index("Function16384")`,
				`pe.exports_index(16384) == 16383`, `not defined pe.exports_index(16385)`,
			}), data)
		})
	}
}
