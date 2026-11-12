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
			{"ordinal_only", func(d []byte) { binary.LittleEndian.PutUint32(d[0x818:], 0) }},
			{"empty", func(d []byte) { clear(d[0x814:0x81c]) }},
			{"hole", func(d []byte) { clear(d[0x82c:0x830]) }},
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
		{"bad_table", func(d []byte) { binary.LittleEndian.PutUint32(d[0x81c:], 0xffffffff) }, `pe.number_of_exports == 0`, `not defined pe.number_of_exports`},
		{"directory_start_forwarder", func(d []byte) { binary.LittleEndian.PutUint32(d[0x828:], 0x2400) }, `pe.export_details[0].offset == 0x800 and not defined pe.export_details[0].forward_name`, `pe.export_details[0].forward_name == "" and not defined pe.export_details[0].offset`},
		{"alias_beyond_name_window", func(d []byte) {
			binary.LittleEndian.PutUint32(d[0x814:], 2)
			ordinals := exportTable(d, 36)
			for i, index := range []uint16{1, 1, 0} {
				binary.LittleEndian.PutUint16(d[ordinals+i*2:], index)
			}
		}, `not defined pe.export_details[0].name`, `pe.export_details[0].name == "Function00002"`},
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
