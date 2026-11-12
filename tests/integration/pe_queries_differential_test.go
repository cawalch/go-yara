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

func TestLibyaraPEImportQueries(t *testing.T) {
	predicates := []string{
		`defined pe.imports("Example.DLL")`,
		`pe.imports("Example.DLL") == 0`, `pe.imports("Example.DLL") == 2`,
		`pe.imports("Example.DLL") == 3`, `pe.imports("Example.DLL") == 4`,
		`pe.imports("EXAMPLE.dll\x00suffix") == pe.imports("Example.DLL")`,
		`pe.imports("Other.DLL") == 3`,
		`pe.imports("missing.dll") == 0`, `pe.imports("") == 0`,
		`pe.imports("\x00Example.DLL") == 0`,
		`pe.imports("kernel32.dll") == 3`, `pe.imports("Kernel32.dll") == 0`,
		`pe.imports(pe.import_details[0].library_name) == pe.number_of_imported_functions`,
		`defined pe.imports(pe.sections[99].name)`,
		`defined pe.imports("Example.DLL", "NamedFunction")`,
		`pe.imports("Example.DLL", "NamedFunction") == 1`,
		`pe.imports("EXAMPLE.dll", "namedFUNCTION") == 1`,
		`pe.imports("missing.dll", "NamedFunction") == 0`,
		`pe.imports("Example.DLL", "missing") == 0`,
		`pe.imports("Example.DLL", "") == 0`,
		`pe.imports("", "NamedFunction") == 0`,
		`pe.imports("Example.DLL\x00suffix", "NamedFunction\x00suffix") == 1`,
		`pe.imports("\x00Example.DLL", "NamedFunction") == 0`,
		`pe.imports("Example.DLL", 0) == 1`, `pe.imports("example.dll", 7) == 1`,
		`pe.imports("EXAMPLE.DLL", 9) == 1`, `pe.imports("Example.DLL", 65535) == 1`,
		`pe.imports("Example.DLL", 42) == 0`, // A named import's hint isn't an ordinal.
		`pe.imports("Example.DLL", -1) == 0`, `pe.imports("Example.DLL", 65536) == 0`,
		`pe.imports("Example.DLL", 0x10007) == 0`, `pe.imports("Example.DLL", 0x7fffffffffffffff) == 0`,
		`pe.imports(pe.import_details[0].library_name, pe.import_details[0].functions[0].name) == 1`,
		`defined pe.imports(pe.sections[99].name, "NamedFunction")`,
		`defined pe.imports("Example.DLL", uint16(filesize))`,
		`pe.imports("kernel32.dll", "KELVIN") == 1`,
		`pe.imports("Kernel32.dll", "Kelvin") == 0`, `pe.imports("kernel32.dll", "Kelvin") == 0`,
		fmt.Sprintf(`pe.imports("Example.DLL", "%s") == 1`, strings.Repeat("N", 512)),
		fmt.Sprintf(`pe.imports("Example.DLL", "%s") == 1`, strings.Repeat("N", 513)),
		`for any d in pe.import_details : (for any f in d.functions : (defined f.ordinal and pe.imports(d.library_name, f.ordinal)))`,
	}
	for _, is64 := range []bool{false, true} {
		for _, tc := range []struct {
			name   string
			change func([]byte)
		}{
			{"named", func([]byte) {}},
			{"ordinal_zero", func(d []byte) { pefixture.ImportOrdinal(d, 1, 0) }},
			{"ordinal_seven", func(d []byte) { pefixture.ImportOrdinal(d, 1, 7) }},
			{"ordinal_max", func(d []byte) { pefixture.ImportOrdinal(d, 1, 65535) }},
			{"iat_fallback", func(d []byte) { binary.LittleEndian.PutUint32(d[0x400:], 0) }},
			{"filtered_name", func(d []byte) { pefixture.ImportName(d, "bad-name") }},
			{"name_limit", func(d []byte) { pefixture.ImportName(d, strings.Repeat("N", 512)) }},
			{"truncated_name", func(d []byte) { pefixture.ImportName(d, strings.Repeat("N", 513)) }},
			{"unicode_queries", func(d []byte) { copy(d[0x428:], "kernel32.dll\x00"); pefixture.ImportName(d, "Kelvin") }},
			{"different_dlls", func(d []byte) {
				copy(d[0x414:0x428], d[0x400:0x414])
				clear(d[0x428:0x43c])
				copy(d[0x1d0:], "Example.DLL\x00")
				copy(d[0x1e0:], "Other.DLL\x00")
				binary.LittleEndian.PutUint32(d[0x40c:], 0x1d0)
				binary.LittleEndian.PutUint32(d[0x420:], 0x1e0)
				directory := 0x100
				if is64 {
					directory = 0x110
				}
				binary.LittleEndian.PutUint32(d[directory+4:], 60)
			}},
			{"second_duplicate_dll", func(d []byte) {
				copy(d[0x414:0x428], d[0x400:0x414])
				clear(d[0x428:0x43c])
				copy(d[0x1f0:], "Example.DLL\x00")
				binary.LittleEndian.PutUint32(d[0x40c:], 0x1f0)
				binary.LittleEndian.PutUint32(d[0x420:], 0x1f0)
				binary.LittleEndian.PutUint32(d[0x414:], 0x1100)
				clear(d[0x300:0x310])
				if is64 {
					binary.LittleEndian.PutUint32(d[0x114:], 60)
					binary.LittleEndian.PutUint64(d[0x300:], 1<<63|9)
				} else {
					binary.LittleEndian.PutUint32(d[0x104:], 60)
					binary.LittleEndian.PutUint32(d[0x300:], 1<<31|9)
				}
			}},
		} {
			t.Run(fmt.Sprintf("64=%t/%s", is64, tc.name), func(t *testing.T) {
				data := pefixture.Imports(is64, 3)
				tc.change(data)
				checkPEPaths(t, peProbeSource(predicates), data)
			})
		}
	}
	for name, data := range map[string][]byte{"non_pe": []byte("ordinary"), "empty": nil, "no_imports": pefixture.New(false)} {
		t.Run(name, func(t *testing.T) { checkPEPaths(t, peProbeSource(predicates), data) })
	}
}

func TestLibyaraPEImportQueryCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]byte)
		query  string
		local  string
	}{
		{"malformed_count", func(d []byte) { binary.LittleEndian.PutUint32(d[0x444:], 0x7fffffff) }, `pe.imports("Example.DLL")`, `not defined`},
		{"malformed", func(d []byte) { binary.LittleEndian.PutUint32(d[0x444:], 0x7fffffff) }, `pe.imports("Example.DLL", "NamedFunction")`, `not defined`},
		{"synthetic_ordinal_name", func(d []byte) { pefixture.ImportOrdinal(d, 1, 7) }, `pe.imports("Example.DLL", "ord7")`, `not`},
		{"ordinal_alias", func(d []byte) {
			copy(d[0x428:], "ws2_32.dll\x00")
			pefixture.ImportOrdinal(d, 1, 1)
		}, `pe.imports("ws2_32.dll", "accept")`, `not`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := pefixture.Imports(false, 3)
			tc.change(data)
			source := fmt.Sprintf(`import "pe" rule oracle {condition: %s} rule local {condition: %s (%s)}`, tc.query, tc.local, tc.query)
			oracle, err := scanWithLibyara(t, libyaraOracle(t), source, data)
			if err != nil || !reflect.DeepEqual(oracle, map[string][]span{"oracle": nil}) {
				t.Fatalf("oracle: %v %v", oracle, err)
			}
			local, err := scanWithGoYara(source, data)
			if err != nil || !reflect.DeepEqual(local, map[string][]span{"local": nil}) {
				t.Fatalf("local: %v %v", local, err)
			}
		})
	}
}

func TestLibyaraPEImportQueryLimit(t *testing.T) {
	for _, count := range []int{16384, 16385} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			data := pefixture.Imports(true, count)
			pefixture.ImportOrdinal(data, count-1, 9)
			checkReleaseScanPaths(t, peProbeSource([]string{
				`pe.number_of_imported_functions == 16384`,
				`pe.imports("Example.DLL") == 16384`,
				`pe.imports("Example.DLL", "NamedFunction") == 1`,
				`pe.imports("Example.DLL", 9) == 1`,
			}), data)
		})
	}
}
