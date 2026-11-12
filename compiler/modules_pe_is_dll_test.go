package compiler

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

const peIsDLLRules = `import "pe"
rule dll {condition: pe.is_dll() == 0x2000 and pe.is_dll() != 1}
rule exe {condition: pe.is_dll() == 0}
rule absent {condition: not defined pe.is_dll()}`

func TestPEIsDLL(t *testing.T) {
	p, err := NewCompiler().CompileSource(peIsDLLRules)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		s := p.NewScanner()
		for _, is64 := range []bool{false, true} {
			for _, flags := range []uint16{0, 0x22, 0x2000, 0xffff} {
				data := pefixture.New(is64)
				binary.LittleEndian.PutUint16(data[0x96:], flags)
				want := "exe"
				if flags&0x2000 != 0 {
					want = "dll"
				}
				for _, tc := range []struct {
					data []byte
					want string
				}{
					{data, want}, {nil, "absent"}, {[]byte("MZ"), "absent"}, {data[:0x97], "absent"}, {data, want},
				} {
					for _, reader := range []bool{false, true} {
						var r *ScanResult
						if reader {
							r, err = s.ScanReader(bytes.NewReader(tc.data))
						} else {
							r, err = s.Scan(tc.data)
						}
						if err != nil || len(r.MatchedRules) != 1 || !r.RuleResults[tc.want] {
							t.Fatalf("PE64=%t flags=%#x reader=%t want=%s: %v %v", is64, flags, reader, tc.want, r, err)
						}
					}
				}
				blocks := p.NewBlockScanner()
				if err := blocks.Scan(0, data); err != nil {
					t.Fatal(err)
				}
				r, err := blocks.Finish()
				blocks.Close()
				if err != nil || len(r.MatchedRules) != 1 || !r.RuleResults[want] {
					t.Fatalf("blocks: %v %v", r, err)
				}
			}
		}
		s.Close()
		for _, tc := range []struct {
			data any
			want string
		}{
			{nil, "absent"}, {map[string]any{}, "absent"}, {map[string]any{"is_pe": 1}, "absent"},
			{map[string]any{"characteristics": 0}, "exe"},
			{map[string]any{"characteristics": 0x2000, "is_pe": 0}, "dll"},
			{map[string]any{"characteristics": int64(-1)}, "dll"},
			{map[string]any{"characteristics": int64(1) << 32}, "exe"},
		} {
			s := p.NewScanner(WithModuleData("pe", tc.data))
			r, err := s.Scan(pefixture.New(false))
			if err != nil || len(r.MatchedRules) != 1 || !r.RuleResults[tc.want] || s.moduleCache.pe != nil {
				t.Fatalf("host want=%s: %v %v", tc.want, r, err)
			}
			s.Close()
		}
		blob, err := p.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		p, err = UnmarshalCompiledProgram(blob)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestPEIsDLLHeaderCache(t *testing.T) {
	data := pefixture.Exports(true, 3)
	ctx := &MatchContext{Data: data, FileSize: int64(len(data)), moduleCache: &moduleCallCache{}}
	i := &Interpreter{matchContext: ctx, currentCompiledRule: &CompiledRule{nativePE: true}}
	if got := i.peIsDLL(nil); got.Type != ModuleInteger || got.Integer != 0x2000 {
		t.Fatalf("DLL flag: %+v", got)
	}
	image := loadPE(ctx)
	if image.imports != nil || image.exports != nil {
		t.Fatal("is_dll parsed directories")
	}
	clear(data)
	ctx.Data, ctx.FileSize = nil, 0
	if got := i.peIsDLL(nil); got.Type != ModuleInteger || got.Integer != 0x2000 {
		t.Fatalf("header snapshot: %+v", got)
	}
	if got := i.peIsDLL([]ModuleValue{IntegerValue(1)}); got.Type != ModuleUndefined {
		t.Fatal("accepted an argument")
	}
	i.currentCompiledRule.nativePE = false
	if got := i.peIsDLL(nil); got.Type != ModuleUndefined {
		t.Fatal("custom module fell back to native headers")
	}
}

func BenchmarkPEIsDLL(b *testing.B) {
	for _, rules := range []int{1, 100} {
		var source strings.Builder
		source.WriteString("import \"pe\"\n")
		for n := range rules {
			fmt.Fprintf(&source, "rule r%d {condition: pe.is_dll() == 0x2000}\n", n)
		}
		p, err := NewCompiler().CompileSource(source.String())
		if err != nil {
			b.Fatal(err)
		}
		for _, isPE := range []bool{false, true} {
			data := []byte("ordinary data")
			want := 0
			if isPE {
				data = pefixture.New(false)
				want = rules
			}
			b.Run(fmt.Sprintf("rules=%d/pe=%t", rules, isPE), func(b *testing.B) {
				s := p.NewScanner(WithoutMatches(), WithoutRuleResults())
				defer s.Close()
				b.ReportAllocs()
				for b.Loop() {
					matches, err := s.MatchingRules(data)
					if err != nil || len(matches) != want {
						b.Fatalf("matches=%d want=%d: %v", len(matches), want, err)
					}
				}
			})
		}
	}
}
