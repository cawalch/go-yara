package integration

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	gope "github.com/cawalch/go-pe"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestLibyaraPEStandardImports(t *testing.T) {
	libyaraOracle(t)
	predicates := []string{
		`pe.imports("Example.DLL") == 0`, `pe.imports("Example.DLL") == 2`,
		`pe.imports("Example.DLL") == 3`, `pe.imports("Example.DLL") == 6`,
		`pe.is_pe`, `defined pe.number_of_imports`, `defined pe.number_of_imported_functions`,
		`pe.number_of_imports == 0`, `pe.number_of_imports == 1`, `pe.number_of_imports == 2`,
		`pe.number_of_imported_functions == 0`, `pe.number_of_imported_functions == 2`, `pe.number_of_imported_functions == 3`, `pe.number_of_imported_functions == 6`,
		`pe.import_details[0].functions[1].ordinal == 9`,
		`pe.import_details[0].library_name == "Example.DLL"`, `pe.import_details[0].number_of_functions == 3`,
		`pe.import_details[0].functions[0].name == "NamedFunction"`,
		`defined pe.import_details[0].functions[0].ordinal`, `pe.import_details[0].functions[1].ordinal == 7`,
		`defined pe.import_details[0].functions[3].name`, `defined pe.import_details[2].library_name`,
		`defined pe.import_details[-1].library_name`, `defined pe.import_details[0].functions[-1].ordinal`,
		`for any d in pe.import_details : (d.library_name == "Example.DLL")`,
		`for all d in pe.import_details : (d.number_of_functions == 3)`,
		`for none d in pe.import_details : (d.number_of_functions == 0)`,
		`for any d in pe.import_details : (for any f in d.functions : (f.ordinal == 7))`,
		`for any i in (0..pe.number_of_imports-1) : (for any j in (0..pe.import_details[i].number_of_functions-1) : (pe.import_details[i].functions[j].ordinal == 7))`,
	}
	for _, is64 := range []bool{false, true} {
		for _, tc := range []struct {
			name   string
			change func([]byte)
		}{
			{"named", func([]byte) {}},
			{"ordinal", func(d []byte) { pefixture.ImportOrdinal(d, 1, 7) }},
			{"iat_fallback", func(d []byte) { binary.LittleEndian.PutUint32(d[0x400:], 0) }},
			{"bound_with_lookup", func(d []byte) {
				binary.LittleEndian.PutUint32(d[0x404:], 0xffffffff)
				binary.LittleEndian.PutUint32(d[0x410:], 0xffffffff)
			}},
			{"cross_section_name", func(d []byte) {
				copy(d[0x200:], append([]byte{42, 0}, []byte("NamedFunction\x00")...))
				for i := range 3 {
					if is64 {
						binary.LittleEndian.PutUint64(d[0x440+i*8:], 0x1000)
					} else {
						binary.LittleEndian.PutUint32(d[0x440+i*4:], 0x1000)
					}
				}
			}},
			{"duplicate_libraries", func(d []byte) {
				copy(d[0x414:0x428], d[0x400:0x414])
				clear(d[0x428:0x43c])
				copy(d[0x1e0:], "Example.DLL\x00")
				binary.LittleEndian.PutUint32(d[0x40c:], 0x1e0)
				binary.LittleEndian.PutUint32(d[0x420:], 0x1e0)
				directory := 0x100
				if is64 {
					directory = 0x110
				}
				binary.LittleEndian.PutUint32(d[directory+4:], 60)
			}},
			{"empty_library", func(d []byte) { clear(d[0x440:0x448]) }},
			{"invalid_function", func(d []byte) { pefixture.ImportName(d, "bad-name") }},
			{"filtered_between_valid_functions", func(d []byte) {
				copy(d[0x300:], "\x00\x00bad-name\x00")
				if is64 {
					binary.LittleEndian.PutUint64(d[0x448:], 0x1100)
				} else {
					binary.LittleEndian.PutUint32(d[0x444:], 0x1100)
				}
				pefixture.ImportOrdinal(d, 2, 9)
			}},
			{"decorated_function", func(d []byte) { pefixture.ImportName(d, "?Decorated@@YAHH@Z") }},
			{"dll_path", func(d []byte) { copy(d[0x428:], "a/b:c.dll\x00") }},
			{"invalid_dll", func(d []byte) { copy(d[0x428:], "bad?.dll\x00") }},
			{"non_ascii_dll", func(d []byte) { d[0x428] = 0xff }},
		} {
			t.Run(fmt.Sprintf("64=%t/%s", is64, tc.name), func(t *testing.T) {
				data := pefixture.Imports(is64, 3)
				tc.change(data)
				checkPEPaths(t, peProbeSource(predicates), data)
			})
		}
	}
	for name, data := range map[string][]byte{"non_pe": []byte("ordinary"), "empty": nil, "no_import_directory": pefixture.New(false)} {
		t.Run(name, func(t *testing.T) { checkPEPaths(t, peProbeSource(predicates), data) })
	}
}

func TestLibyaraPEImportNameAndCountLimits(t *testing.T) {
	for _, length := range []int{511, 512, 513} {
		t.Run(fmt.Sprintf("function_%d", length), func(t *testing.T) {
			data := pefixture.Imports(false, 1)
			pefixture.ImportName(data, strings.Repeat("A", length))
			checkPEPaths(t, peProbeSource([]string{`pe.number_of_imported_functions == 1`, fmt.Sprintf("pe.import_details[0].functions[0].name == %q", strings.Repeat("A", min(length, 512)))}), data)
		})
	}
	for _, length := range []int{255, 256} {
		t.Run(fmt.Sprintf("dll_%d", length), func(t *testing.T) {
			data := pefixture.Imports(false, 1)
			offset := len(data) - 300
			copy(data[offset:], strings.Repeat("a", length)+"\x00")
			binary.LittleEndian.PutUint32(data[0x40c:], uint32(offset-0x400+0x2000)) //checkednarrow:ignore bounded fixture offset
			checkPEPaths(t, peProbeSource([]string{`pe.number_of_imports == 0`, `pe.number_of_imports == 1`, `defined pe.import_details[0].library_name`}), data)
		})
	}
	for _, count := range []int{16384, 16385} {
		t.Run(fmt.Sprintf("functions_%d", count), func(t *testing.T) {
			// PE32+ makes this fixture large enough for the mmap path. Smaller
			// cancellable file scans use the documented 64 KiB reader prefix.
			checkReleaseScanPaths(t, peProbeSource([]string{`pe.number_of_imports == 1`, `pe.number_of_imported_functions == 16384`, `pe.import_details[0].number_of_functions == 16384`, `defined pe.import_details[0].functions[16383].name`, `defined pe.import_details[0].functions[16384].name`}), pefixture.Imports(true, count))
		})
	}
	t.Run("total_across_libraries", func(t *testing.T) {
		data := pefixture.Imports(true, 9000)
		copy(data[0x414:0x428], data[0x400:0x414])
		clear(data[0x428:0x43c])
		copy(data[0x1f0:], "Example.DLL\x00")
		binary.LittleEndian.PutUint32(data[0x40c:], 0x1f0)
		binary.LittleEndian.PutUint32(data[0x420:], 0x1f0)
		binary.LittleEndian.PutUint32(data[0x114:], 60)
		// Include an overlay so cancellable file scans use mmap too.
		data = append(data, make([]byte, (128<<10)-len(data))...)
		checkPEPaths(t, peProbeSource([]string{
			`pe.number_of_imports == 2`, `pe.number_of_imported_functions == 16384`,
			`pe.import_details[0].number_of_functions == 9000`,
			`pe.import_details[1].number_of_functions == 7384`,
			`defined pe.import_details[1].functions[7383].name`,
			`defined pe.import_details[1].functions[7384].name`,
		}), data)
	})
	t.Run("invalid_names_consume_descriptor_limit", func(t *testing.T) {
		data := pefixture.Imports(true, 16385)
		pefixture.ImportName(data, "bad-name")
		pefixture.ImportOrdinal(data, 16384, 7)
		checkReleaseScanPaths(t, peProbeSource([]string{
			`pe.number_of_imports == 0`, `pe.number_of_imported_functions == 0`,
			`defined pe.import_details[0].library_name`,
		}), data)
	})
}

// Deliberate strict-parser differences must remain visible, not disappear into
// a parity test that checks only successful images or aggregates predicates.
func TestLibyaraPEStrictImportCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name          string
		change        func([]byte) []byte
		oracle, local string
	}{
		{"invalid_function_rva", func(d []byte) []byte { binary.LittleEndian.PutUint32(d[0x444:], 0x7fffffff); return d }, `pe.number_of_imported_functions == 2`, `not defined pe.number_of_imports`},
		{"short_directory_size", func(d []byte) []byte { binary.LittleEndian.PutUint32(d[0x104:], 20); return d }, `pe.number_of_imported_functions == 3`, `not defined pe.number_of_imports`},
		{"bound_without_lookup", func(d []byte) []byte {
			binary.LittleEndian.PutUint32(d[0x400:], 0)
			binary.LittleEndian.PutUint32(d[0x404:], 1)
			return d
		}, `pe.number_of_imported_functions == 3`, `not defined pe.number_of_imports`},
		{"empty_function_name", func(d []byte) []byte { pefixture.ImportName(d, ""); return d }, `pe.number_of_imports == 0`, `not defined pe.number_of_imports`},
		{"unaligned_raw_offset", func(d []byte) []byte { binary.LittleEndian.PutUint32(d[0x1b4:], 0x4ff); return d }, `pe.number_of_imported_functions == 3`, `pe.number_of_imports == 0`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.change(pefixture.Imports(false, 3))
			source := fmt.Sprintf(`import "pe" rule oracle {condition: pe.is_pe and %s} rule local {condition: pe.is_pe and %s}`, tc.oracle, tc.local)
			want, err := scanWithLibyara(t, libyaraOracle(t), source, data)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(want, map[string][]span{"oracle": nil}) {
				t.Fatalf("oracle changed: %v", want)
			}
			got, err := scanWithGoYara(source, data)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, map[string][]span{"local": nil}) {
				t.Fatalf("local changed: %v", got)
			}
		})
	}
}

func TestLibyaraPEOrdinalNamesCompatibility(t *testing.T) {
	for _, tc := range []struct {
		dll, name string
		ordinal   uint16
	}{{"Example.DLL", "ord7", 7}, {"ws2_32.dll", "accept", 1}, {"Example.DLL", "ord0", 0}, {"Example.DLL", "ord65535", 65535}} {
		t.Run(tc.name, func(t *testing.T) {
			data := pefixture.Imports(false, 1)
			pefixture.ImportOrdinal(data, 0, tc.ordinal)
			copy(data[0x428:], tc.dll+"\x00")
			source := fmt.Sprintf(`import "pe" rule ordinal {condition: pe.import_details[0].functions[0].ordinal == %d}
rule oracle {condition: pe.import_details[0].functions[0].name == %q}
rule local {condition: not defined pe.import_details[0].functions[0].name}`, tc.ordinal, tc.name)
			want, err := scanWithLibyara(t, libyaraOracle(t), source, data)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(want, map[string][]span{"ordinal": nil, "oracle": nil}) {
				t.Fatalf("oracle changed: %v", want)
			}
			got, err := scanWithGoYara(source, data)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, map[string][]span{"ordinal": nil, "local": nil}) {
				t.Fatalf("local changed: %v", got)
			}
		})
	}
}

func TestLibyaraPEImportToolchainFixtures(t *testing.T) {
	root, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gcc-386-mingw-exec", "gcc-amd64-mingw-exec", "gcc-386-mingw-no-symbols-exec"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(root)), "src", "debug", "pe", "testdata", name))
			if err != nil {
				t.Fatal(err)
			}
			file, err := gope.New(data)
			if err != nil {
				t.Fatal(err)
			}
			libraries, err := file.Imports(data)
			if err != nil {
				t.Fatal(err)
			}
			// Build individual predicates from the parser's records, then check
			// each predicate and its inverse against the independent C oracle.
			predicates := []string{fmt.Sprintf("pe.number_of_imports == %d", len(libraries))}
			total := 0
			for i, library := range libraries {
				predicates = append(predicates, fmt.Sprintf("pe.import_details[%d].library_name == %q", i, library.DLL), fmt.Sprintf("pe.import_details[%d].number_of_functions == %d", i, len(library.Symbols)))
				for j, symbol := range library.Symbols {
					field, value := "name", fmt.Sprintf("%q", symbol.Name)
					if symbol.ByOrdinal {
						field, value = "ordinal", strconv.FormatUint(uint64(symbol.Ordinal), 10)
					}
					predicates = append(predicates, fmt.Sprintf("pe.import_details[%d].functions[%d].%s == %s", i, j, field, value))
				}
				total += len(library.Symbols)
			}
			predicates = append(predicates, fmt.Sprintf("pe.number_of_imported_functions == %d", total))
			checkPEPaths(t, peProbeSource(predicates), data)
		})
	}
}
