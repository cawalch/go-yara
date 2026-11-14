package compiler

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func peSecurityDirOffset(is64 bool) int {
	if is64 {
		return 0x98 + 112 + 4*8
	}
	return 0x98 + 96 + 4*8
}

func TestPEOverlay(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		for _, tc := range []struct {
			name      string
			change    func([]byte) []byte
			condition string
		}{
			{
				name:      "base",
				change:    func(d []byte) []byte { return d },
				condition: `pe.overlay.offset == 0x600 and pe.overlay.size == 0x200`,
			},
			{
				name:      "exact-eof",
				change:    func(d []byte) []byte { return d[:0x600] },
				condition: `defined pe.overlay.offset and defined pe.overlay.size and pe.overlay.offset == 0 and pe.overlay.size == 0`,
			},
			{
				name:      "one-byte-overlay",
				change:    func(d []byte) []byte { return d[:0x601] },
				condition: `pe.overlay.offset == 0x600 and pe.overlay.size == 1`,
			},
			{
				name: "past-eof",
				change: func(d []byte) []byte {
					binary.LittleEndian.PutUint32(d[peSectionOffset(d, 1)+16:], 0x600)
					return d
				},
				condition: `pe.overlay.offset == 0 and pe.overlay.size == 0`,
			},
			{
				name: "u32-overflow",
				change: func(d []byte) []byte {
					s1 := peSectionOffset(d, 1)
					binary.LittleEndian.PutUint32(d[s1+16:], 0x20000)
					binary.LittleEndian.PutUint32(d[s1+20:], 0xffff0000)
					return d
				},
				condition: `pe.overlay.offset == 0 and pe.overlay.size == 0`,
			},
			{
				name: "zero-sections",
				change: func(d []byte) []byte {
					binary.LittleEndian.PutUint16(d[0x86:], 0)
					return d
				},
				condition: `pe.overlay.offset == 0 and pe.overlay.size == 0`,
			},
			{
				name: "zero-raw-size",
				change: func(d []byte) []byte {
					s1 := peSectionOffset(d, 1)
					binary.LittleEndian.PutUint32(d[s1+16:], 0)
					binary.LittleEndian.PutUint32(d[s1+20:], 0x700)
					return d
				},
				condition: `pe.overlay.offset == 0x700 and pe.overlay.size == 0x100`,
			},
			{
				name: "all-zero-extents",
				change: func(d []byte) []byte {
					for i := range 2 {
						s := peSectionOffset(d, i)
						binary.LittleEndian.PutUint32(d[s+16:], 0)
						binary.LittleEndian.PutUint32(d[s+20:], 0)
					}
					return d
				},
				condition: `pe.overlay.offset == 0 and pe.overlay.size == 0`,
			},
			{
				name: "reversed-sections",
				change: func(d []byte) []byte {
					binary.LittleEndian.PutUint32(d[peSectionOffset(d, 0)+20:], 0x400)
					binary.LittleEndian.PutUint32(d[peSectionOffset(d, 1)+20:], 0x200)
					return d
				},
				condition: `pe.overlay.offset == 0x600 and pe.overlay.size == 0x200`,
			},
			{
				name: "unaligned-raw",
				change: func(d []byte) []byte {
					s1 := peSectionOffset(d, 1)
					binary.LittleEndian.PutUint32(d[s1+16:], 0x100)
					binary.LittleEndian.PutUint32(d[s1+20:], 0x405)
					return d
				},
				condition: `pe.overlay.offset == 0x505 and pe.overlay.size == 0x2fb`,
			},
			{
				name: "cert-exact-overlay",
				change: func(d []byte) []byte {
					dir := peSecurityDirOffset(is64)
					binary.LittleEndian.PutUint32(d[dir:], 0x600)
					binary.LittleEndian.PutUint32(d[dir+4:], 0x200)
					return d
				},
				condition: `pe.overlay.offset == 0x600 and pe.overlay.size == 0x200`,
			},
			{
				name: "section-limit",
				change: func([]byte) []byte {
					data := make([]byte, 0x10000)
					copy(data, pefixture.New(is64))
					binary.LittleEndian.PutUint16(data[0x86:], 97)
					start := peSectionOffset(data, 0)
					for i := 0; i < 97; i++ {
						s := data[start+i*40:]
						copy(s, ".text\x00\x00\x00")
						binary.LittleEndian.PutUint32(s[8:], 0x200)
						binary.LittleEndian.PutUint32(s[12:], uint32(0x1000*(i+1))) //checkednarrow:ignore bounded by 97
						binary.LittleEndian.PutUint32(s[16:], 0x200)
						rawOff := uint32(0x3e00)
						if i == 96 {
							rawOff = 0x4e00
						}
						binary.LittleEndian.PutUint32(s[20:], rawOff)
					}
					return data
				},
				condition: `pe.overlay.offset == 0x4000 and pe.overlay.size == 0xc000`,
			},
		} {
			data := tc.change(pefixture.New(is64))
			p, err := NewCompiler().CompileSource(`import "pe" rule query { condition: ` + tc.condition + ` }`)
			if err != nil {
				t.Fatalf("64=%t %s: %v", is64, tc.name, err)
			}
			if ok, err := p.Matches(data); err != nil || !ok {
				t.Fatalf("64=%t %s: %t %v", is64, tc.name, ok, err)
			}
		}
	}

	p, err := NewCompiler().CompileSource(`import "pe" rule absent { condition: not defined pe.overlay.offset and not defined pe.overlay.size }`)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{nil, []byte("MZ"), []byte("ordinary"), pefixture.New(false)[:0x99]} {
		if ok, err := p.Matches(data); err != nil || !ok {
			t.Fatalf("non-PE(%d): %t %v", len(data), ok, err)
		}
	}
}

func TestPEOverlayScanPathsAndSerialization(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule has_overlay { condition: pe.overlay.offset == 0x600 and pe.overlay.size == 0x200 }
rule absent { condition: not defined pe.overlay.offset and not defined pe.overlay.size }`)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalCompiledProgram(blob)
	if err != nil {
		t.Fatal(err)
	}
	for _, program := range []*CompiledProgram{p, restored} {
		data := pefixture.New(false)
		s := program.NewScanner(WithFastScan())
		for _, reader := range []bool{false, true} {
			var r *ScanResult
			if reader {
				r, err = s.ScanReader(bytes.NewReader(data))
			} else {
				r, err = s.Scan(data)
			}
			if err != nil || !r.RuleResults["has_overlay"] || r.RuleResults["absent"] {
				t.Fatalf("reader=%t: %v %v", reader, r, err)
			}
			r, err = s.Scan(nil)
			if err != nil || r.RuleResults["has_overlay"] || !r.RuleResults["absent"] {
				t.Fatalf("reuse nil: %v %v", r, err)
			}
		}
		s.Close()

		for _, tc := range []struct {
			base     int64
			fileSize int64
			want     string
		}{
			{0, 0, "has_overlay"},
			{4096, 0, "absent"},
		} {
			b := program.NewBlockScanner()
			if err := b.Scan(tc.base, data); err != nil {
				t.Fatal(err)
			}
			r, err := b.Finish()
			b.Close()
			if err != nil || len(r.MatchedRules) != 1 || !r.RuleResults[tc.want] {
				t.Fatalf("block base=%d: %v %v", tc.base, r, err)
			}
		}

		// Header-only block with explicit full file size computes overlay from file length.
		b := program.NewBlockScanner()
		if err := b.Scan(0, data[:0x200]); err != nil {
			t.Fatal(err)
		}
		if err := b.SetFileSize(0x800); err != nil {
			t.Fatal(err)
		}
		r, err := b.Finish()
		b.Close()
		if err != nil || !r.RuleResults["has_overlay"] {
			t.Fatalf("header block + SetFileSize: %v %v", r, err)
		}
	}

	// Section body ending beyond the 64 KiB reader retention prefix.
	large := make([]byte, 128<<10)
	copy(large, pefixture.New(false))
	binary.LittleEndian.PutUint32(large[peSectionOffset(large, 1)+20:], 0x15000)
	largeProgram, err := NewCompiler().CompileSource(`import "pe" rule large { condition: pe.overlay.offset == 0x15200 and pe.overlay.size == 0xae00 }`)
	if err != nil {
		t.Fatal(err)
	}
	s := largeProgram.NewScanner()
	defer s.Close()
	r, err := s.ScanReader(bytes.NewReader(large))
	if err != nil || !r.RuleResults["large"] {
		t.Fatalf("large reader: %v %v", r, err)
	}
}

func TestPEOverlayCache(t *testing.T) {
	base := pefixture.Exports(false, 3)
	offset := int64(len(base))
	data := make([]byte, len(base)+0x200)
	copy(data, base)
	ctx := &MatchContext{Data: data, FileSize: int64(len(data)), moduleCache: &moduleCallCache{}}
	image := loadPE(ctx)
	if image.overlay.Type != ModuleUndefined {
		t.Fatal("overlay computed before access")
	}
	ov := image.field("overlay")
	if ov.Type != ModuleStruct || ov.object.fields["offset"].Integer != offset || ov.object.fields["size"].Integer != 0x200 {
		t.Fatalf("overlay = %+v", ov)
	}
	if image.sections.Type != ModuleUndefined || image.directories.Type != ModuleUndefined || image.imports != nil || image.exports != nil {
		t.Fatal("overlay materialized unrelated PE caches")
	}
	clear(data)
	ctx.Data, ctx.FileSize = nil, 0
	if got := image.field("overlay"); got.object != ov.object || got.object.fields["offset"].Integer != offset || got.object.fields["size"].Integer != 0x200 {
		t.Fatalf("cached overlay changed after input clear: %+v", got)
	}

	// Verify scanner reuse skips overlay computation when rules never access it.
	peData := pefixture.New(false)
	pHeaders, err := NewCompiler().CompileSource(`import "pe" rule h { condition: pe.is_pe == 1 }`)
	if err != nil {
		t.Fatal(err)
	}
	sh := pHeaders.NewScanner()
	defer sh.Close()
	if _, err := sh.Scan(peData); err != nil {
		t.Fatal(err)
	}
	if sh.moduleCache.pe.overlay.Type != ModuleUndefined {
		t.Fatal("unused overlay was computed during scan")
	}
}

func TestPEOverlayHostData(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule host { condition: pe.overlay.offset == 0x600 and pe.overlay.size == 0x200 }
rule zero { condition: pe.overlay.offset == 0 and pe.overlay.size == 0 }
rule absent { condition: not defined pe.overlay.offset and not defined pe.overlay.size }`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data map[string]any
		want string
	}{
		{"nil", nil, "absent"},
		{"empty", map[string]any{}, "absent"},
		{"headers-without-overlay", map[string]any{"is_pe": 1, "number_of_sections": 1}, "absent"},
		{"zero", map[string]any{"overlay": map[string]any{"offset": 0, "size": 0}}, "zero"},
		{"mapped", map[string]any{"overlay": map[string]any{"offset": 0x600, "size": 0x200}}, "host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opt ScannerOption
			if tc.data == nil {
				opt = WithModuleData("pe", nil)
			} else {
				opt = WithModuleData("pe", tc.data)
			}
			s := p.NewScanner(opt)
			defer s.Close()
			if tc.data != nil {
				clear(tc.data)
			}
			r, err := s.Scan(pefixture.New(false))
			if err != nil || s.moduleCache.pe != nil || len(r.MatchedRules) != 1 || !r.RuleResults[tc.want] {
				t.Fatalf("want %s: %v %v", tc.want, r, err)
			}
		})
	}

	// Custom schema named pe with an overlay struct must never fall back to native parsing.
	custom := Module{
		Name: "pe",
		Schema: &ModuleSchema{Fields: map[string]ModuleField{
			"label": {Kind: ModuleString},
			"overlay": {Kind: ModuleStruct, Struct: &ModuleSchema{Fields: map[string]ModuleField{
				"offset": {Kind: ModuleInteger},
				"size":   {Kind: ModuleInteger},
			}}},
		}},
	}
	cp, err := NewCompiler(WithModule(custom)).CompileSource(`import "pe" rule r { condition: not defined pe.overlay.offset and not defined pe.overlay.size }`)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := cp.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	unbound, err := UnmarshalCompiledProgram(blob)
	if err != nil {
		t.Fatal(err)
	}
	su := unbound.NewScanner()
	defer su.Close()
	if ok, err := su.Matches(pefixture.New(false)); err != nil || !ok || su.moduleCache.pe != nil {
		t.Fatalf("custom schema fell back to native parsing: %t %v", ok, err)
	}
}

func TestPEOverlayNonPEAllocations(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe" rule query { condition: defined pe.overlay.offset or defined pe.overlay.size }`)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner(WithoutMatches(), WithoutRuleResults())
	defer s.Close()
	for _, input := range [][]byte{nil, []byte("ordinary data")} {
		if n := testing.AllocsPerRun(100, func() {
			if _, err := s.MatchingRules(input); err != nil {
				t.Fatal(err)
			}
		}); n != 0 {
			t.Fatalf("non-PE overlay(%d bytes) allocates %g times", len(input), n)
		}
	}
}

func BenchmarkPEOverlay(b *testing.B) {
	benchmarkPEHeaderQuery(b, "pe.overlay.offset == 0x600 and pe.overlay.size == 0x200")
}
