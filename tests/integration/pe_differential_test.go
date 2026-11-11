package integration

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/internal/pefixture"
)

// Keep each predicate and its inverse separate: an aggregate conjunction can
// conceal a field mismatch behind an unrelated false or undefined operand.
func peProbeSource(predicates []string) string {
	var source strings.Builder
	source.WriteString("import \"pe\"\n")
	for i, predicate := range predicates {
		fmt.Fprintf(&source, "rule p%d { condition: %s }\nrule n%d { condition: not (%s) }\n", i, predicate, i, predicate)
	}
	return source.String()
}

func TestLibyaraPEHeadersAndSections(t *testing.T) {
	libyaraOracle(t)
	predicates := []string{
		`pe.is_pe == 1`, `pe.machine == pe.MACHINE_I386`, `pe.machine == pe.MACHINE_AMD64`,
		`pe.number_of_sections == 2`, `pe.timestamp == 0xf1234567`, `pe.pointer_to_symbol_table == 0`,
		`pe.number_of_symbols == 0`, `pe.size_of_optional_header == 224`, `pe.size_of_optional_header == 240`,
		`pe.characteristics == 0x2022`, `pe.characteristics & pe.DLL != 0`,
		`pe.entry_point == 0x220`, `pe.entry_point_raw == 0x1020`, `pe.image_base == 0x400000`, `pe.image_base == 0x140000000`,
		`pe.number_of_rva_and_sizes == 16`, `pe.opthdr_magic == pe.IMAGE_NT_OPTIONAL_HDR32_MAGIC`,
		`pe.opthdr_magic == pe.IMAGE_NT_OPTIONAL_HDR64_MAGIC`, `pe.size_of_code == 0x200`,
		`pe.size_of_initialized_data == 0x400`, `pe.size_of_uninitialized_data == 0x100`,
		`pe.base_of_code == 0x1000`, `pe.base_of_data == 0x2000`, `defined pe.base_of_data`,
		`pe.section_alignment == 0x1000`, `pe.file_alignment == 0x200`,
		`pe.linker_version.major == 14`, `pe.linker_version.minor == 3`,
		`pe.os_version.major == 6`, `pe.os_version.minor == 1`,
		`pe.image_version.major == 2`, `pe.image_version.minor == 3`,
		`pe.subsystem_version.major == 6`, `pe.subsystem_version.minor == 2`,
		`pe.win32_version_value == 7`, `pe.size_of_image == 0x3000`, `pe.size_of_headers == 0x200`,
		`pe.checksum == 0x12345678`, `pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI`,
		`pe.dll_characteristics == 0x8160`, `pe.size_of_stack_reserve == 0x100000`,
		`pe.size_of_stack_reserve == 0x100000000`, `pe.size_of_stack_commit == 0x2000`,
		`pe.size_of_heap_reserve == 0x200000`, `pe.size_of_heap_reserve == 0x200000000`,
		`pe.size_of_heap_commit == 0x3000`, `pe.loader_flags == 9`,
		`pe.data_directories[0].virtual_address == 0`, `pe.data_directories[15].size == 0`,
		`defined pe.data_directories[16].size`, `defined pe.data_directories[-1].size`,
		`pe.sections[0].name == ".text"`, `pe.sections[0].full_name == ".text"`,
		`pe.sections[0].characteristics == 0x60000020`, `pe.sections[0].virtual_address == 0x1000`,
		`pe.sections[0].virtual_size == 0x180`, `pe.sections[0].raw_data_offset == 0x200`,
		`pe.sections[0].raw_data_size == 0x200`, `pe.sections[0].pointer_to_relocations == 0x600`,
		`pe.sections[0].pointer_to_line_numbers == 0x640`, `pe.sections[0].number_of_relocations == 3`,
		`pe.sections[0].number_of_line_numbers == 4`, `pe.sections[1].name == ".data"`,
		`pe.sections[1].characteristics == 0xc0000040`, `pe.sections[1].raw_data_offset == 0x400`,
		`pe.sections[1].virtual_address == 0x2000`, `defined pe.sections[2].name`, `defined pe.sections[-1].name`,
		`for any s in pe.sections : (s.name == ".text" and s.characteristics & pe.SECTION_MEM_EXECUTE != 0)`,
		`for all i in (0..pe.number_of_sections-1) : (pe.sections[i].raw_data_size == 0x200)`,
		`for all s in pe.sections : (s.virtual_size > 0)`,
		`for none s in pe.sections : (s.virtual_size == 0)`,
		`for none i in (0..pe.number_of_sections-1) : (pe.sections[i].virtual_size == 0)`,
	}
	for name, data := range map[string][]byte{"pe32": pefixture.New(false), "pe64": pefixture.New(true), "non_pe": []byte("ordinary"), "empty": nil, "mz_only": []byte("MZ")} {
		t.Run(name, func(t *testing.T) { checkPEPaths(t, peProbeSource(predicates), data) })
	}
}

// Exercise caches, compact scans, and the bounded reader as well as the
// release buffer/file paths. Fixtures here have all metadata in the prefix.
func checkPEPaths(t *testing.T, source string, data []byte) {
	t.Helper()
	checkReleaseScanPaths(t, source, data)
	want, err := scanWithLibyara(t, libyaraOracle(t), source, data)
	if err != nil {
		t.Fatal(err)
	}
	p, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	p, err = compiler.UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner(compiler.WithFastScan())
	defer s.Close()
	for _, input := range [][]byte{nil, data} {
		if _, err := s.Scan(input); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.Scan(data)
	if err != nil {
		t.Fatal(err)
	}
	assertReleaseScanResult(t, want, r)

	matches, err := s.MatchingRules(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != len(want) {
		t.Fatalf("compact scan returned %d rules, want %d", len(matches), len(want))
	}
	for _, match := range matches {
		if _, ok := want[match.Rule]; !ok {
			t.Fatalf("unexpected compact match %s", match.Rule)
		}
	}
	// Reader scans can only resolve COFF long names in the retained prefix.
	if len(data) > 64<<10 {
		return
	}
	r, err = s.ScanReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	assertReleaseScanResult(t, want, r)
}

func TestLibyaraPEEntryPoint(t *testing.T) {
	libyaraOracle(t)
	for _, tc := range []struct {
		name   string
		change func([]byte)
	}{
		{"headers", func(d []byte) { binary.LittleEndian.PutUint32(d[0xa8:], 0x40) }},
		{"before_first_section_outside_headers", func(d []byte) { binary.LittleEndian.PutUint32(d[0xa8:], 0x700) }},
		{"outside_file", func(d []byte) { binary.LittleEndian.PutUint32(d[0xa8:], 0x900) }},
		{"raw_padding", func(d []byte) { binary.LittleEndian.PutUint32(d[0xa8:], 0x11f0) }},
		{"zero_fill", func(d []byte) {
			binary.LittleEndian.PutUint32(d[0x180:], 0x400)
			binary.LittleEndian.PutUint32(d[0xa8:], 0x1300)
		}},
		{"unaligned_raw", func(d []byte) { binary.LittleEndian.PutUint32(d[0x18c:], 0x2ff) }},
		{"small_alignment", func(d []byte) {
			binary.LittleEndian.PutUint32(d[0xb8:], 4)
			binary.LittleEndian.PutUint32(d[0xbc:], 4)
			binary.LittleEndian.PutUint32(d[0x18c:], 0x2ff)
		}},
		{"page_alignment", func(d []byte) {
			binary.LittleEndian.PutUint32(d[0xbc:], 4)
			binary.LittleEndian.PutUint32(d[0x18c:], 0x2ff)
		}},
		{"zero_alignment", func(d []byte) {
			binary.LittleEndian.PutUint32(d[0xb8:], 0)
			binary.LittleEndian.PutUint32(d[0xbc:], 0)
			binary.LittleEndian.PutUint32(d[0x18c:], 0x2ff)
		}},
		{"overlap_tie", func(d []byte) { binary.LittleEndian.PutUint32(d[0x1ac:], 0x1000) }},
		{"overlap_highest", func(d []byte) { binary.LittleEndian.PutUint32(d[0x1ac:], 0x1010) }},
		{"overlap_reversed", func(d []byte) { binary.LittleEndian.PutUint32(d[0x1ac:], 0xff0) }},
		{"truncated_body", func(d []byte) { binary.LittleEndian.PutUint32(d[0x18c:], 0x1000) }},
		{"overflow_rva", func(d []byte) {
			binary.LittleEndian.PutUint32(d[0xa8:], 0xfffffff0)
			binary.LittleEndian.PutUint32(d[0x184:], 0xffffff00)
		}},
		{"no_sections", func(d []byte) { binary.LittleEndian.PutUint16(d[0x86:], 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := pefixture.New(false)
			tc.change(data)
			predicates := []string{`pe.is_pe`, `defined pe.entry_point`}
			for _, offset := range []int64{-1, 0x40, 0x220, 0x2f0, 0x31c, 0x31f, 0x410, 0x420, 0x700} {
				predicates = append(predicates, fmt.Sprintf("pe.entry_point == %d", offset))
			}
			checkPEPaths(t, peProbeSource(predicates), data)
		})
	}
}

func TestLibyaraPESectionNames(t *testing.T) {
	libyaraOracle(t)
	for _, name := range []string{"abcdefgh", "a\x00bc", "\xff\x80name", "", "/4"} {
		t.Run(fmt.Sprintf("%x", name), func(t *testing.T) {
			data := pefixture.New(false)
			clear(data[0x178:0x180])
			copy(data[0x178:], name)
			if name == "/4" {
				binary.LittleEndian.PutUint32(data[0x8c:], 0x600)
				binary.LittleEndian.PutUint32(data[0x600:], 32)
				copy(data[0x604:], ".long_section_name\x00")
			}
			checkPEPaths(t, peProbeSource([]string{`pe.is_pe`, `pe.sections[0].name == "abcdefgh"`, `pe.sections[0].name == "a\x00bc"`, `pe.sections[0].full_name == "a\x00bc"`, `pe.sections[0].name == "\xff\x80name"`, `pe.sections[0].name == ""`, `pe.sections[0].name == "/4"`, `pe.sections[0].full_name == ".long_section_name"`}), data)
		})
	}
}

// These deliberate strict-parser differences are separate from parity tests.
// A rejected image exposes is_pe=0 and leaves the other fields undefined.
func TestLibyaraPEStrictHeaderCompatibility(t *testing.T) {
	libyaraOracle(t)
	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"truncated_sections", func(d []byte) []byte { return d[:0x180] }},
		{"too_many_sections", func(d []byte) []byte { binary.LittleEndian.PutUint16(d[0x86:], 257); return d }},
		{"unknown_magic", func(d []byte) []byte { binary.LittleEndian.PutUint16(d[0x98:], 0x999); return d }},
		{"short_optional_header", func(d []byte) []byte { binary.LittleEndian.PutUint16(d[0x94:], 2); return d }},
		{"too_many_directories", func(d []byte) []byte { binary.LittleEndian.PutUint32(d[0xf4:], 17); return d }},
		{"bad_long_name", func(d []byte) []byte {
			copy(d[0x178:], "/9999999")
			binary.LittleEndian.PutUint32(d[0x8c:], 0x600)
			return d
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.change(pefixture.New(false))
			const source = `import "pe" rule recognized { condition: pe.is_pe == 1 } rule rejected { condition: pe.is_pe == 0 and not defined pe.machine and not defined pe.sections[0].name }`
			want, err := scanWithLibyara(t, libyaraOracle(t), source, data)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := want["recognized"]; !ok || len(want) != 1 {
				t.Fatalf("oracle contract changed: %v", want)
			}
			p, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), source)
			if err != nil {
				t.Fatal(err)
			}
			r, err := p.Scan(data)
			if err != nil {
				t.Fatal(err)
			}
			assertReleaseScanResult(t, map[string][]span{"rejected": nil}, r)
		})
	}
}

func TestLibyaraPEGoToolchainFixtures(t *testing.T) {
	libyaraOracle(t)
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
			checkPEPaths(t, peProbeSource([]string{`pe.is_pe == 1`, `pe.number_of_sections > 0`, `pe.machine == pe.MACHINE_I386`, `pe.machine == pe.MACHINE_AMD64`, `pe.entry_point >= 0`, `pe.entry_point < filesize`, `pe.entry_point_raw > 0`, `for any s in pe.sections : (s.name == ".text")`, `for any s in pe.sections : (s.name startswith "/" and s.full_name startswith ".debug")`}), data)
		})
	}
}

func TestLibyaraPEConstants(t *testing.T) {
	libyaraOracle(t)
	var predicates []string
	for name, field := range compiler.NewCompiler().GetOptions().Modules["pe"].Schema.Fields {
		if field.Constant != nil {
			predicates = append(predicates, fmt.Sprintf("pe.%s == %d", name, field.Constant.Integer))
		}
	}
	sort.Strings(predicates)
	checkPEPaths(t, peProbeSource(predicates), nil)
}

func TestLibyaraPEOptionalHeaderEdges(t *testing.T) {
	libyaraOracle(t)
	for _, tc := range []struct {
		name   string
		is64   bool
		change func([]byte)
	}{
		{"no_directories", false, func(d []byte) { binary.LittleEndian.PutUint32(d[0xf4:], 0) }},
		{"one_directory", false, func(d []byte) { binary.LittleEndian.PutUint32(d[0xf4:], 1) }},
		{"directory_values", false, func(d []byte) {
			binary.LittleEndian.PutUint32(d[0x170:], 0xfedcba98)
			binary.LittleEndian.PutUint32(d[0x174:], 0x76543210)
		}},
		{"undefined_sentinel", true, func(d []byte) {
			for _, offset := range []int{0xb0, 0xe0, 0xe8, 0xf0, 0xf8} {
				binary.LittleEndian.PutUint64(d[offset:], 0xfffabadafabadaff)
			}
		}},
		{"unsigned64", true, func(d []byte) {
			binary.LittleEndian.PutUint64(d[0xb0:], 0xffffffffffffffff)
			binary.LittleEndian.PutUint64(d[0xe0:], 0x8000000000000000)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := pefixture.New(tc.is64)
			tc.change(data)
			checkPEPaths(t, peProbeSource([]string{`pe.is_pe`, `pe.number_of_rva_and_sizes == 0`, `pe.number_of_rva_and_sizes == 1`, `defined pe.data_directories[0].size`, `defined pe.data_directories[1].size`, `defined pe.data_directories[15].size`, `pe.data_directories[15].virtual_address == 0xfedcba98`, `pe.data_directories[15].size == 0x76543210`, `defined pe.image_base`, `defined pe.size_of_stack_reserve`, `defined pe.size_of_stack_commit`, `defined pe.size_of_heap_reserve`, `defined pe.size_of_heap_commit`, `pe.image_base == -1`, `pe.size_of_stack_reserve == -9223372036854775807 - 1`}), data)
		})
	}
}

func TestLibyaraPETruncatedHeaders(t *testing.T) {
	libyaraOracle(t)
	for _, is64 := range []bool{false, true} {
		data := pefixture.New(is64)
		// The range ends before libyara accepts a full standard optional header.
		for _, size := range []int{0, 2, 63, 64, 127, 128, 131, 151, 152, 247, 375} {
			t.Run(fmt.Sprintf("pe64=%t/size=%d", is64, size), func(t *testing.T) {
				checkReleaseScanPaths(t, peProbeSource([]string{`pe.is_pe == 0`, `defined pe.machine`, `defined pe.sections[0].name`}), data[:size])
			})
		}
	}
}

func TestLibyaraPESectionLimit(t *testing.T) {
	libyaraOracle(t)
	for _, count := range []uint16{0, 96, 97, 256} {
		t.Run(strconv.FormatUint(uint64(count), 10), func(t *testing.T) {
			data := make([]byte, 0x10000)
			copy(data, pefixture.New(false))
			binary.LittleEndian.PutUint16(data[0x86:], count)
			for i := 0; i < int(count); i++ {
				s := data[0x178+i*40:]
				copy(s, ".text\x00\x00\x00")
				binary.LittleEndian.PutUint32(s[8:], 0x200)
				binary.LittleEndian.PutUint32(s[12:], uint32(0x1000*(i+1))) //checkednarrow:ignore count bounded by 256
				binary.LittleEndian.PutUint32(s[16:], 0x200)
				binary.LittleEndian.PutUint32(s[20:], 0x400)
			}
			binary.LittleEndian.PutUint32(data[0xa8:], 0x61020) // Section 96 is outside libyara's mapping limit.
			checkPEPaths(t, peProbeSource([]string{
				`pe.is_pe`, fmt.Sprintf("pe.number_of_sections == %d", count),
				`pe.entry_point == -1`, `defined pe.sections[95].name`, `defined pe.sections[96].name`,
				`for all s in pe.sections : (s.name == ".text")`,
				`for none s in pe.sections : (s.name != ".text")`,
			}), data)
		})
	}
}
