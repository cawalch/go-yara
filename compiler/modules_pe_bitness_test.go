package compiler

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

const peBitnessRules = `import "pe"
rule pe32 {condition: pe.is_32bit() == 1 and pe.is_64bit() == 0}
rule pe64 {condition: pe.is_32bit() == 0 and pe.is_64bit() == 1}
rule absent {condition: not defined pe.is_32bit() and not defined pe.is_64bit()}`

func TestPEBitness(t *testing.T) {
	p, err := NewCompiler().CompileSource(peBitnessRules)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		s := p.NewScanner()
		for _, is64 := range []bool{false, true} {
			want := "pe32"
			if is64 {
				want = "pe64"
			}
			for _, machine := range []uint16{0, 0x14c, 0x8664} {
				data := pefixture.New(is64)
				binary.LittleEndian.PutUint16(data[0x84:], machine)
				invalid := pefixture.New(is64)
				binary.LittleEndian.PutUint16(invalid[0x98:], 0x107)
				for _, tc := range []struct {
					data []byte
					want string
				}{
					{data, want}, {nil, "absent"}, {[]byte("MZ"), "absent"}, {data[:0x99], "absent"}, {invalid, "absent"}, {data, want},
				} {
					for _, reader := range []bool{false, true} {
						var r *ScanResult
						if reader {
							r, err = s.ScanReader(bytes.NewReader(tc.data))
						} else {
							r, err = s.Scan(tc.data)
						}
						if err != nil || len(r.MatchedRules) != 1 || !r.RuleResults[tc.want] {
							t.Fatalf("PE64=%t machine=%#x reader=%t want=%s: %v %v", is64, machine, reader, tc.want, r, err)
						}
					}
				}
			}
			for _, base := range []int64{0, 4096} {
				blocks := p.NewBlockScanner()
				if err := blocks.Scan(base, pefixture.New(is64)); err != nil {
					t.Fatal(err)
				}
				r, err := blocks.Finish()
				blocks.Close()
				expected := want
				if base != 0 {
					expected = "absent"
				}
				if err != nil || len(r.MatchedRules) != 1 || !r.RuleResults[expected] {
					t.Fatalf("blocks base=%d: %v %v", base, r, err)
				}
			}
		}
		for _, tc := range []struct {
			data any
			want string
		}{
			{nil, "absent"}, {map[string]any{}, "absent"}, {map[string]any{"is_pe": 1, "machine": 0x8664}, "absent"},
			{map[string]any{"opthdr_magic": ModuleValue{}}, "absent"},
			{map[string]any{"opthdr_magic": 0}, "absent"},
			{map[string]any{"opthdr_magic": 0x107}, "absent"},
			{map[string]any{"opthdr_magic": -1}, "absent"},
			{map[string]any{"opthdr_magic": int64(1)<<32 | 0x10b}, "absent"},
			{map[string]any{"opthdr_magic": 0x10b, "machine": 0x8664, "is_pe": 0}, "pe32"},
			{map[string]any{"opthdr_magic": 0x20b, "machine": 0x14c}, "pe64"},
		} {
			if err := s.SetModuleData("pe", tc.data); err != nil {
				t.Fatal(err)
			}
			if fields, ok := tc.data.(map[string]any); ok {
				clear(fields)
			}
			for _, input := range [][]byte{nil, pefixture.New(false), pefixture.New(true)} {
				r, err := s.Scan(input)
				if err != nil || len(r.MatchedRules) != 1 || !r.RuleResults[tc.want] || s.moduleCache.pe != nil {
					t.Fatalf("host want=%s: %v %v", tc.want, r, err)
				}
			}
		}
		s.Close()
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

func TestPEBitnessHeaderCache(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		data := pefixture.Exports(is64, 3)
		ctx := &MatchContext{Data: data, FileSize: int64(len(data)), moduleCache: &moduleCallCache{}}
		i := &Interpreter{matchContext: ctx, currentCompiledRule: &CompiledRule{nativePE: true}}
		for range 2 {
			for _, want64 := range []bool{false, true} {
				want := int64(0)
				if want64 == is64 {
					want = 1
				}
				if got := i.peIsBitness(want64); got.Type != ModuleInteger || got.Integer != want {
					t.Fatalf("PE64=%t query64=%t: %+v", is64, want64, got)
				}
			}
			image := loadPE(ctx)
			if image.imports != nil || image.exports != nil {
				t.Fatal("bitness parsed directories")
			}
			clear(data)
			ctx.Data, ctx.FileSize = nil, 0
		}
		i.currentCompiledRule.nativePE = false
		for _, want64 := range []bool{false, true} {
			if got := i.peIsBitness(want64); got.Type != ModuleUndefined {
				t.Fatal("custom module fell back to native headers")
			}
		}
	}
}

func BenchmarkPEBitness(b *testing.B) {
	for _, query := range []struct{ name, condition string }{
		{"is_32bit", "pe.is_32bit() == 1"}, {"is_64bit", "pe.is_64bit() == 0"},
	} {
		b.Run(query.name, func(b *testing.B) { benchmarkPEHeaderQuery(b, query.condition) })
	}
}
