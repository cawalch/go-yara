package compiler

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cawalch/go-pe"

	"github.com/cawalch/go-yara/internal/pefixture"
)

type peDirPatch struct {
	index    int
	va, size uint32
}

func setPEDataDirectory(data []byte, is64 bool, patch peDirPatch) {
	dirOffset := 0x98 + 96 + patch.index*8
	if is64 {
		dirOffset = 0x98 + 112 + patch.index*8
	}
	binary.LittleEndian.PutUint32(data[dirOffset:], patch.va)
	binary.LittleEndian.PutUint32(data[dirOffset+4:], patch.size)
}

func makeLargeSectionPE(is64 bool, totalSize int, epRVA uint32) []byte {
	data := make([]byte, totalSize)
	base := pefixture.New(is64)
	copy(data, base)
	opt := data[0x98:]
	binary.LittleEndian.PutUint32(opt[16:], epRVA) // AddressOfEntryPoint
	optSize := 224
	if is64 {
		optSize = 240
	}
	text := data[0x98+optSize:]
	rawSize := uint32(totalSize - 0x400) //checkednarrow:ignore test fixture totalSize > 0x400
	binary.LittleEndian.PutUint32(text[8:], rawSize)
	binary.LittleEndian.PutUint32(text[16:], rawSize)
	binary.LittleEndian.PutUint32(text[20:], 0x400)
	return data
}

func TestPEInputTruncatedAndDeclaredExtent(t *testing.T) {
	const rules = `import "pe"
rule native_ep_outside {
	condition:
		pe.is_pe and
		not pe.input_truncated and
		not pe.is_dotnet() and
		pe.entry_point_raw != 0 and
		pe.entry_point != -1 and
		for all s in pe.sections : (
			pe.entry_point < s.raw_data_offset or
			pe.entry_point >= s.raw_data_offset + s.raw_data_size
		)
}
rule truncated_pe {
	condition:
		pe.is_pe and pe.input_truncated == 1 and filesize < pe.declared_extent
}
rule complete_pe {
	condition:
		pe.is_pe and pe.input_truncated == 0 and pe.declared_extent <= filesize
}
rule non_pe_undefined {
	condition:
		pe.is_pe == 0 and not defined pe.input_truncated and not defined pe.declared_extent
}`
	program, err := NewCompiler().CompileSource(rules)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := program.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := UnmarshalCompiledProgram(raw)
	if err != nil {
		t.Fatal(err)
	}
	scanner := roundTrip.NewScanner()
	defer scanner.Close()

	// Issue #501 pattern: 151040 B image with .text [0x400, 0x18a00) and EP at 0x13450.
	large := makeLargeSectionPE(true, 151040, 0x1000+(0x13450-0x400))
	fullRes, err := scanner.Scan(large)
	if err != nil {
		t.Fatal(err)
	}
	if !fullRes.RuleResults["complete_pe"] || fullRes.RuleResults["truncated_pe"] || fullRes.RuleResults["native_ep_outside"] {
		t.Fatalf("full Scan unexpected results: %+v", fullRes.RuleResults)
	}

	// Prefix Scan(data[:65536]) sets filesize = 65536 while declared extent is 0x18a00:
	// entry_point maps to -1, but input_truncated prevents false positives on ep_outside.
	prefixRes, err := scanner.Scan(large[:65536])
	if err != nil {
		t.Fatal(err)
	}
	if !prefixRes.RuleResults["truncated_pe"] || prefixRes.RuleResults["complete_pe"] || prefixRes.RuleResults["native_ep_outside"] {
		t.Fatalf("prefix Scan unexpected results: %+v", prefixRes.RuleResults)
	}

	// ScanReader over the complete 151040 B stream retains only a 64 KiB header window
	// while knowing the full stream length, so input_truncated must remain 0.
	readerRes, err := scanner.ScanReader(bytes.NewReader(large))
	if err != nil {
		t.Fatal(err)
	}
	if !readerRes.RuleResults["complete_pe"] || readerRes.RuleResults["truncated_pe"] || readerRes.RuleResults["native_ep_outside"] {
		t.Fatalf("ScanReader full unexpected results: %+v", readerRes.RuleResults)
	}

	// Overlay past declared extent does not mark input truncated; cutting inside cert table does.
	withCert := pefixture.New(false)
	setPEDataDirectory(withCert, false, peDirPatch{pe.DataDirectoryCertificate, 0x800, 0x200})
	certTruncated, err := scanner.Scan(withCert)
	if err != nil {
		t.Fatal(err)
	}
	if !certTruncated.RuleResults["truncated_pe"] {
		t.Fatalf("truncated certificate directory not detected: %+v", certTruncated.RuleResults)
	}

	withOverlay := append(pefixture.New(false), make([]byte, 128)...)
	overlayRes, err := scanner.Scan(withOverlay)
	if err != nil {
		t.Fatal(err)
	}
	if !overlayRes.RuleResults["complete_pe"] {
		t.Fatalf("image with overlay marked truncated: %+v", overlayRes.RuleResults)
	}

	nonPERes, err := scanner.Scan([]byte("plain non-pe bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if !nonPERes.RuleResults["non_pe_undefined"] {
		t.Fatalf("non-PE should leave truncation/extent undefined: %+v", nonPERes.RuleResults)
	}

	blocks := roundTrip.NewBlockScanner()
	if err := blocks.Scan(0, large[:65536]); err != nil {
		t.Fatal(err)
	}
	blockPrefixRes, err := blocks.Finish()
	blocks.Close()
	if err != nil || !blockPrefixRes.RuleResults["truncated_pe"] || blockPrefixRes.RuleResults["native_ep_outside"] {
		t.Fatalf("block prefix unexpected results: %+v err=%v", blockPrefixRes.RuleResults, err)
	}

	blocksSized := roundTrip.NewBlockScanner()
	if err := blocksSized.SetFileSize(int64(len(large))); err != nil {
		t.Fatal(err)
	}
	if err := blocksSized.Scan(0, large[:65536]); err != nil {
		t.Fatal(err)
	}
	blockFullRes, err := blocksSized.Finish()
	blocksSized.Close()
	if err != nil || !blockFullRes.RuleResults["complete_pe"] || blockFullRes.RuleResults["native_ep_outside"] {
		t.Fatalf("block SetFileSize unexpected results: %+v err=%v", blockFullRes.RuleResults, err)
	}
}

func TestPEIsDotNet(t *testing.T) {
	const rules = `import "pe"
rule managed {
	condition:
		pe.is_pe and pe.is_dotnet() == 1 and pe.is_dotnet()
}
rule native {
	condition:
		pe.is_pe and pe.is_dotnet() == 0 and not pe.is_dotnet()
}
rule absent {
	condition:
		not defined pe.is_dotnet()
}
rule native_ep_outside {
	condition:
		pe.is_pe and
		not pe.input_truncated and
		not pe.is_dotnet() and
		pe.entry_point_raw != 0 and
		pe.entry_point != -1 and
		for all s in pe.sections : (
			pe.entry_point < s.raw_data_offset or
			pe.entry_point >= s.raw_data_offset + s.raw_data_size
		)
}`
	program, err := NewCompiler().CompileSource(rules)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := program.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := UnmarshalCompiledProgram(raw)
	if err != nil {
		t.Fatal(err)
	}
	scanner := roundTrip.NewScanner()
	defer scanner.Close()

	for _, is64 := range []bool{false, true} {
		nativeImg := pefixture.New(is64)
		res, err := scanner.Scan(nativeImg)
		if err != nil || !res.RuleResults["native"] || res.RuleResults["managed"] || res.RuleResults["native_ep_outside"] {
			t.Fatalf("PE64=%t native unexpected: %+v err=%v", is64, res.RuleResults, err)
		}

		// Issue #502: CLR DLL sets AddressOfEntryPoint = 0 and CLR directory (index 14).
		clrImg := pefixture.New(is64)
		binary.LittleEndian.PutUint32(clrImg[0x98+16:], 0)
		setPEDataDirectory(clrImg, is64, peDirPatch{pe.DataDirectoryCLRRuntime, 0x1008, 0x48})
		for _, reader := range []bool{false, true} {
			var clrRes *ScanResult
			if reader {
				clrRes, err = scanner.ScanReader(bytes.NewReader(clrImg))
			} else {
				clrRes, err = scanner.Scan(clrImg)
			}
			if err != nil || !clrRes.RuleResults["managed"] || clrRes.RuleResults["native"] || clrRes.RuleResults["native_ep_outside"] {
				t.Fatalf("PE64=%t reader=%t CLR unexpected: %+v err=%v", is64, reader, clrRes.RuleResults, err)
			}
		}

		// Zero VA with non-zero size or fewer than 15 data directories must report is_dotnet() == 0.
		badVA := pefixture.New(is64)
		setPEDataDirectory(badVA, is64, peDirPatch{pe.DataDirectoryCLRRuntime, 0, 0x48})
		badRes, err := scanner.Scan(badVA)
		if err != nil || !badRes.RuleResults["native"] {
			t.Fatalf("PE64=%t zero CLR VA unexpected: %+v err=%v", is64, badRes.RuleResults, err)
		}

		fewDirs := pefixture.New(is64)
		setPEDataDirectory(fewDirs, is64, peDirPatch{pe.DataDirectoryCLRRuntime, 0x1008, 0x48})
		rvaCountOff := 0x98 + 92
		if is64 {
			rvaCountOff = 0x98 + 108
		}
		binary.LittleEndian.PutUint32(fewDirs[rvaCountOff:], 14)
		fewRes, err := scanner.Scan(fewDirs)
		if err != nil || !fewRes.RuleResults["native"] {
			t.Fatalf("PE64=%t fewer directories unexpected: %+v err=%v", is64, fewRes.RuleResults, err)
		}
	}

	for _, nonPE := range [][]byte{nil, []byte("plain"), pefixture.New(false)[:0x97]} {
		res, err := scanner.Scan(nonPE)
		if err != nil || !res.RuleResults["absent"] || res.RuleResults["managed"] || res.RuleResults["native"] {
			t.Fatalf("non-PE %d bytes unexpected: %+v err=%v", len(nonPE), res.RuleResults, err)
		}
	}

	// Host snapshot contract via WithModuleData.
	clrDirs := make([]map[string]any, 15)
	for idx := range clrDirs {
		clrDirs[idx] = map[string]any{"virtual_address": 0, "size": 0}
	}
	clrDirs[14] = map[string]any{"virtual_address": 0x2000, "size": 0x48}
	hostManaged := roundTrip.NewScanner(WithModuleData("pe", map[string]any{
		"is_pe":            1,
		"data_directories": clrDirs,
	}))
	defer hostManaged.Close()
	if r, err := hostManaged.Scan(pefixture.New(false)); err != nil || !r.RuleResults["managed"] {
		t.Fatalf("host managed snapshot: %+v err=%v", r.RuleResults, err)
	}

	hostShortDirs := roundTrip.NewScanner(WithModuleData("pe", map[string]any{
		"is_pe":            1,
		"data_directories": []map[string]any{{"virtual_address": 0, "size": 0}},
	}))
	defer hostShortDirs.Close()
	if r, err := hostShortDirs.Scan(pefixture.New(false)); err != nil || !r.RuleResults["native"] {
		t.Fatalf("host short directories snapshot: %+v err=%v", r.RuleResults, err)
	}

	hostIncomplete := roundTrip.NewScanner(WithModuleData("pe", map[string]any{"is_pe": 1}))
	defer hostIncomplete.Close()
	if r, err := hostIncomplete.Scan(pefixture.New(false)); err != nil || !r.RuleResults["absent"] {
		t.Fatalf("host incomplete snapshot should leave is_dotnet undefined: %+v err=%v", r.RuleResults, err)
	}
}

func TestPEDebugSchemaRemainsNativeAfterExtentExtension(t *testing.T) {
	prog, err := NewCompiler().CompileSource(`import "pe" rule r { condition: pe.is_pe == 1 and pe.is_dotnet() == 0 }`)
	if err != nil {
		t.Fatal(err)
	}
	prog.moduleSchemas["pe"] = peDebugSchema
	if err := prog.Validate(); err != nil {
		t.Fatalf("expected peDebugSchema program to validate: %v", err)
	}
	if !prog.Rules[0].nativePE {
		t.Fatal("expected peDebugSchema program to keep nativePE=true")
	}
	data, err := prog.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := UnmarshalCompiledProgram(data)
	if err != nil {
		t.Fatal(err)
	}
	res, err := roundTrip.NewScanner().Scan(pefixture.New(false))
	if err != nil || !res.RuleResults["r"] {
		t.Fatalf("expected peDebugSchema round-trip to run native pe.is_dotnet: %+v err=%v", res.RuleResults, err)
	}
}

func TestPEIsDotNetZeroDirectoryAllocs(t *testing.T) {
	data := pefixture.New(true)
	setPEDataDirectory(data, true, peDirPatch{pe.DataDirectoryCLRRuntime, 0x1008, 0x48})
	ctx := &MatchContext{Data: data, FileSize: int64(len(data)), moduleCache: &moduleCallCache{}}
	i := &Interpreter{matchContext: ctx, currentCompiledRule: &CompiledRule{nativePE: true}}
	if got := i.peIsDotNet(); got.Type != ModuleInteger || got.Integer != 1 {
		t.Fatalf("peIsDotNet() = %+v, want 1", got)
	}
	image := loadPE(ctx)
	if image.directories.Type != ModuleUndefined || image.imports != nil || image.exports != nil {
		t.Fatal("is_dotnet allocated data_directories or directory objects")
	}
	clear(data)
	ctx.Data, ctx.FileSize = nil, 0
	if got := i.peIsDotNet(); got.Type != ModuleInteger || got.Integer != 1 {
		t.Fatalf("header snapshot peIsDotNet() = %+v, want 1", got)
	}
	i.currentCompiledRule.nativePE = false
	if got := i.peIsDotNet(); got.Type != ModuleUndefined {
		t.Fatal("custom module fell back to native headers")
	}
}
