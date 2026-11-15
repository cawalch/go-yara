package compiler

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func yaraHexLiteral(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b) * 4)
	for _, v := range b {
		fmt.Fprintf(&sb, "\\x%02x", v)
	}
	return sb.String()
}

func TestPERichSignatureFieldsAndQueries(t *testing.T) {
	entries := []pefixture.RichEntry{
		{ToolID: 259, Version: 29500, Count: 12},
		{ToolID: 257, Version: 29500, Count: 3},
		{ToolID: 259, Version: 29500, Count: 5},
		{ToolID: 100, Version: 12345, Count: 0xffffffff},
		{ToolID: 100, Version: 12345, Count: 2},
	}
	for _, is64 := range []bool{false, true} {
		t.Run(fmt.Sprintf("is64=%t", is64), func(t *testing.T) {
			data := pefixture.RichPE(is64, pefixture.RichOptions{
				Key:           0x4a3b2c1d,
				TailZeroWords: 2,
				Entries:       entries,
			})
			rawLen := 16 + len(entries)*8
			rawHex := yaraHexLiteral(data[0x80 : 0x80+rawLen])

			clearBuf := make([]byte, rawLen)
			for off := 0; off < rawLen; off += 4 {
				w := binary.LittleEndian.Uint32(data[0x80+off : 0x80+off+4])
				binary.LittleEndian.PutUint32(clearBuf[off:off+4], w^0x4a3b2c1d)
			}
			clearHex := yaraHexLiteral(clearBuf)

			versionBuf := make([]byte, len(entries)*4)
			for i := range entries {
				copy(versionBuf[i*4:i*4+4], clearBuf[16+i*8:16+i*8+4])
			}
			versionHex := yaraHexLiteral(versionBuf)

			source := fmt.Sprintf(`import "pe"
rule rich_match {
	condition:
		pe.is_pe == 1 and
		pe.rich_signature.offset == 128 and
		pe.rich_signature.length == %d and
		pe.rich_signature.key == 0x4a3b2c1d and
		pe.rich_signature.raw_data == "%s" and
		pe.rich_signature.clear_data == "%s" and
		pe.rich_signature.version_data == "%s" and
		pe.rich_signature.version(29500) == 20 and
		pe.rich_signature.version(29500, 259) == 17 and
		pe.rich_signature.version(29500, 257) == 3 and
		pe.rich_signature.version(12345, 100) == 0x100000001 and
		pe.rich_signature.toolid(259) == 17 and
		pe.rich_signature.toolid(259, 29500) == 17 and
		pe.rich_signature.toolid(257, 29500) == 3 and
		pe.rich_signature.toolid(100) == 0x100000001 and
		pe.rich_signature.version(999) == 0 and
		pe.rich_signature.toolid(999, 29500) == 0 and
		pe.rich_signature.version(-1) == 0 and
		pe.rich_signature.version(0x10000) == 0 and
		pe.rich_signature.version(29500, -1) == 0 and
		pe.rich_signature.toolid(-1) == 0 and
		pe.rich_signature.toolid(0x10000) == 0 and
		pe.rich_signature.toolid(259, 0x10000) == 0
}
rule rich_absent {
	condition:
		not defined pe.rich_signature.offset and
		not defined pe.rich_signature.length and
		not defined pe.rich_signature.key and
		not defined pe.rich_signature.raw_data and
		not defined pe.rich_signature.clear_data and
		not defined pe.rich_signature.version_data and
		not defined pe.rich_signature.version(29500) and
		not defined pe.rich_signature.version(29500, 259) and
		not defined pe.rich_signature.toolid(259) and
		not defined pe.rich_signature.toolid(259, 29500)
}`, rawLen, rawHex, clearHex, versionHex)

			p, err := NewCompiler().CompileSource(source)
			if err != nil {
				t.Fatal(err)
			}
			s := p.NewScanner()
			defer s.Close()

			if r, err := s.Scan(data); err != nil || !r.RuleResults["rich_match"] || r.RuleResults["rich_absent"] {
				t.Fatalf("Scan(RichPE): results=%+v err=%v", r.RuleResults, err)
			}
			if r, err := s.ScanReader(bytes.NewReader(data)); err != nil || !r.RuleResults["rich_match"] || r.RuleResults["rich_absent"] {
				t.Fatalf("ScanReader(RichPE): results=%+v err=%v", r.RuleResults, err)
			}

			for _, base := range []int64{0, 4096} {
				bs := p.NewBlockScanner()
				if err := bs.Scan(base, data); err != nil {
					t.Fatal(err)
				}
				r, err := bs.Finish()
				bs.Close()
				wantRich := base == 0
				if err != nil || r.RuleResults["rich_match"] != wantRich || r.RuleResults["rich_absent"] != !wantRich {
					t.Fatalf("BlockScanner(base=%d): results=%+v err=%v", base, r.RuleResults, err)
				}
			}

			// Scanner reuse across no-Rich PE, non-PE, and Rich PE.
			for _, tc := range []struct {
				name string
				in   []byte
				rich bool
			}{
				{"NoRichPE", pefixture.New(is64), false},
				{"NonPE", []byte("not a pe image"), false},
				{"RichAgain", data, true},
			} {
				r, err := s.Scan(tc.in)
				if err != nil || r.RuleResults["rich_match"] != tc.rich || r.RuleResults["rich_absent"] != !tc.rich {
					t.Fatalf("reuse %s: results=%+v err=%v", tc.name, r.RuleResults, err)
				}
			}
		})
	}

	t.Run("ZeroEntriesRichHeader", func(t *testing.T) {
		data := pefixture.RichPE(false, pefixture.RichOptions{Key: 0x01020304})
		p, err := NewCompiler().CompileSource(`import "pe"
rule zero_entries {
	condition:
		pe.rich_signature.offset == 128 and
		pe.rich_signature.length == 16 and
		pe.rich_signature.key == 0x01020304 and
		pe.rich_signature.version_data == "" and
		defined pe.rich_signature.version_data and
		pe.rich_signature.version(0) == 0 and
		pe.rich_signature.toolid(0) == 0
}`)
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := p.Matches(data); err != nil || !ok {
			t.Fatalf("Matches = (%t, %v)", ok, err)
		}
	})
}

func TestPERichSignatureCacheAndLaziness(t *testing.T) {
	data := pefixture.RichPE(true, pefixture.RichOptions{
		Key:     0x55667788,
		Entries: []pefixture.RichEntry{{ToolID: 259, Version: 29500, Count: 4}},
	})

	t.Run("UnrelatedRuleSkipsRichLoad", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe" rule r { condition: pe.is_pe == 1 and pe.machine == pe.MACHINE_AMD64 }`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()
		if ok, err := s.Matches(data); err != nil || !ok {
			t.Fatalf("Matches = (%t, %v)", ok, err)
		}
		if s.moduleCache.pe.rich != nil {
			t.Fatal("unrelated PE rule populated rich cache")
		}
	})

	t.Run("QueryOnlyAvoidsStructAndStringWrappers", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe" rule r { condition: pe.rich_signature.version(29500, 259) == 4 and pe.rich_signature.toolid(259) == 4 }`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()
		if ok, err := s.Matches(data); err != nil || !ok {
			t.Fatalf("Matches = (%t, %v)", ok, err)
		}
		rich := s.moduleCache.pe.rich
		if rich == nil || !rich.valid {
			t.Fatalf("expected valid rich cache, got %+v", rich)
		}
		if rich.structVal.Type != ModuleUndefined || rich.rawData.Type != ModuleUndefined || rich.clearData.Type != ModuleUndefined || rich.versionData.Type != ModuleUndefined {
			t.Fatal("query-only rule allocated lazy struct or string wrappers")
		}
	})

	t.Run("NumericFieldAvoidsByteStringWrappers", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe" rule r { condition: pe.rich_signature.key == 0x55667788 and pe.rich_signature.offset == 128 }`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()
		if ok, err := s.Matches(data); err != nil || !ok {
			t.Fatalf("Matches = (%t, %v)", ok, err)
		}
		rich := s.moduleCache.pe.rich
		if rich == nil || rich.rawData.Type != ModuleUndefined || rich.clearData.Type != ModuleUndefined || rich.versionData.Type != ModuleUndefined {
			t.Fatal("numeric rich field access allocated string wrappers")
		}
	})

	t.Run("MultiRuleCacheSharingAcrossEvaluations", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe"
rule query_first { condition: pe.rich_signature.version(29500) == 4 }
rule field_second { condition: pe.rich_signature.key == 0x55667788 }
rule toolid_third { condition: pe.rich_signature.toolid(259, 29500) == 4 }`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()

		buf := append([]byte(nil), data...)
		r, err := s.Scan(buf)
		if err != nil || len(r.MatchedRules) != 3 {
			t.Fatalf("Scan = (%v, %v)", r.RuleResults, err)
		}
		cached := s.moduleCache.pe.rich
		if cached == nil || !cached.valid {
			t.Fatal("expected cached rich header")
		}
		// Overwrite the input Rich marker in place to verify cached struct & queries
		// do not re-parse input bytes during the same scan snapshot.
		copy(buf[0x80:0x84], "XXXX")
		for _, rule := range p.Rules {
			if !s.isRuleConditionSatisfied(rule) || s.moduleCache.pe.rich != cached {
				t.Fatalf("rule %s did not reuse cached rich snapshot", rule.Name)
			}
		}
	})
}

func TestPERichSignatureStrictMalformed(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule strict_reject {
	condition:
		pe.is_pe == 1 and
		not defined pe.rich_signature.offset and
		not defined pe.rich_signature.key and
		not defined pe.rich_signature.version(29500) and
		not defined pe.rich_signature.toolid(259)
}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{
			name: "ZeroKey",
			data: pefixture.RichPE(true, pefixture.RichOptions{
				ZeroKey: true,
				Entries: []pefixture.RichEntry{{ToolID: 259, Version: 29500, Count: 1}},
			}),
		},
		{
			name: "NonzeroHeaderPadding",
			data: pefixture.RichPE(true, pefixture.RichOptions{
				Key:           0x12345678,
				HeaderPadding: [3]uint32{0, 1, 0},
				Entries:       []pefixture.RichEntry{{ToolID: 259, Version: 29500, Count: 1}},
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if ok, err := p.Matches(tc.data); err != nil || !ok {
				t.Fatalf("Matches(%s) = (%t, %v)", tc.name, ok, err)
			}
		})
	}
}

func TestPERichSignatureHostSnapshotSerializationLegacyAndOverride(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule host_rich {
	condition:
		pe.rich_signature.offset == 128 and
		pe.rich_signature.length == 32 and
		pe.rich_signature.key == 123456 and
		pe.rich_signature.raw_data == "raw" and
		pe.rich_signature.version_data == "vdata" and
		pe.rich_signature.version(29500) == 7 and
		pe.rich_signature.version(29500, 259) == 7 and
		pe.rich_signature.toolid(259) == 10 and
		pe.rich_signature.toolid(259, 29500) == 7 and
		pe.rich_signature.version(-1) == 0 and
		pe.rich_signature.toolid(0x10000) == 0
}
rule host_absent {
	condition:
		not defined pe.rich_signature.key and
		not defined pe.rich_signature.version(29500) and
		not defined pe.rich_signature.toolid(259)
}`)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := UnmarshalCompiledProgram(blob)
	if err != nil {
		t.Fatal(err)
	}

	clearBuf := make([]byte, 32)
	copy(clearBuf[0:4], "DanS")
	binary.LittleEndian.PutUint16(clearBuf[16:18], 29500)
	binary.LittleEndian.PutUint16(clearBuf[18:20], 259)
	binary.LittleEndian.PutUint32(clearBuf[20:24], 7)
	binary.LittleEndian.PutUint16(clearBuf[24:26], 30000)
	binary.LittleEndian.PutUint16(clearBuf[26:28], 259)
	binary.LittleEndian.PutUint32(clearBuf[28:32], 3)

	hostPE := pefixture.RichPE(true, pefixture.RichOptions{
		Key:     0x99887766,
		Entries: []pefixture.RichEntry{{ToolID: 1, Version: 2, Count: 99}},
	})
	hs := roundTrip.NewScanner(WithModuleData("pe", map[string]any{
		"rich_signature": map[string]any{
			"offset":       128,
			"length":       32,
			"key":          123456,
			"raw_data":     "raw",
			"clear_data":   string(clearBuf),
			"version_data": "vdata",
		},
	}))
	defer hs.Close()
	r, err := hs.Scan(hostPE)
	if err != nil || !r.RuleResults["host_rich"] || r.RuleResults["host_absent"] || hs.moduleCache.pe != nil {
		t.Fatalf("host snapshot: results=%+v err=%v cache=%v", r.RuleResults, err, hs.moduleCache.pe)
	}

	for _, partialData := range []map[string]any{
		{"machine": 0x8664},
		{"rich_signature": map[string]any{"offset": 128}},
		{"rich_signature": map[string]any{"clear_data": "short"}},
		{"rich_signature": map[string]any{"clear_data": string(clearBuf[:20])}},
	} {
		partial := roundTrip.NewScanner(WithModuleData("pe", partialData))
		r, err := partial.Scan(hostPE)
		partial.Close()
		if err != nil || r.RuleResults["host_rich"] || !r.RuleResults["host_absent"] || partial.moduleCache.pe != nil {
			t.Fatalf("partial host snapshot (%v): results=%+v err=%v", partialData, r.RuleResults, err)
		}
	}

	t.Run("LegacyVersionInfoSchemaPreservesNativePE", func(t *testing.T) {
		prevProg, err := NewCompiler().CompileSource(`import "pe" rule legacy { condition: pe.is_pe == 1 }`)
		if err != nil {
			t.Fatal(err)
		}
		prevProg.moduleSchemas["pe"] = peVersionInfoSchema
		prevBlob, err := prevProg.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		restored, err := UnmarshalCompiledProgram(prevBlob)
		if err != nil {
			t.Fatal(err)
		}
		if !restored.Rules[0].nativePE {
			t.Fatal("expected peVersionInfoSchema program to keep nativePE=true")
		}
		if ok, err := restored.Matches(hostPE); err != nil || !ok {
			t.Fatalf("legacy schema scan = (%t, %v)", ok, err)
		}
	})

	t.Run("CustomCallbackOverride", func(t *testing.T) {
		customPE := NewCompiler().GetOptions().Modules["pe"]
		vFn := customPE.Functions["rich_signature.version"]
		vFn.Evaluate = func(_ ModuleContext, args []ModuleValue) (ModuleValue, error) {
			return IntegerValue(args[0].Integer + 42), nil
		}
		tFn := customPE.Functions["rich_signature.toolid"]
		tFn.Evaluate = func(_ ModuleContext, args []ModuleValue) (ModuleValue, error) {
			return IntegerValue(args[0].Integer + 99), nil
		}
		customPE.Functions["rich_signature.version"] = vFn
		customPE.Functions["rich_signature.toolid"] = tFn

		cp, err := NewCompiler(WithModule(customPE)).CompileSource(`import "pe"
rule custom { condition: pe.rich_signature.version(10) == 52 and pe.rich_signature.toolid(1) == 100 }`)
		if err != nil {
			t.Fatal(err)
		}
		cs := cp.NewScanner()
		defer cs.Close()
		r, err := cs.Scan(hostPE)
		if err != nil || !r.RuleResults["custom"] || cs.moduleCache.pe != nil {
			t.Fatalf("custom callback override: results=%+v err=%v cache=%v", r.RuleResults, err, cs.moduleCache.pe)
		}
	})
}

func TestPERichSignatureCancel(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe" rule r { condition: pe.rich_signature.version(29500) > 0 }`)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner()
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	data := pefixture.RichPE(true, pefixture.RichOptions{
		Entries: []pefixture.RichEntry{{ToolID: 259, Version: 29500, Count: 1}},
	})
	if _, err := s.ScanWithContext(ctx, data); err == nil {
		t.Fatal("expected canceled scan error")
	}
}

func TestValidModuleFunctionName(t *testing.T) {
	schema := &ModuleSchema{
		Fields: map[string]ModuleField{
			"scalar": {Kind: ModuleInteger},
			"rich_signature": {
				Kind: ModuleStruct,
				Struct: &ModuleSchema{Fields: map[string]ModuleField{
					"key": {Kind: ModuleInteger},
				}},
			},
		},
	}
	for _, valid := range []string{"top_level", "rich_signature.version", "rich_signature.toolid"} {
		if !validModuleFunctionName(schema, valid) {
			t.Errorf("validModuleFunctionName(%q) = false, want true", valid)
		}
	}
	for _, invalid := range []string{"", "rich_signature.key", "scalar.method", "missing.method", ".leading", "rich_signature."} {
		if validModuleFunctionName(schema, invalid) {
			t.Errorf("validModuleFunctionName(%q) = true, want false", invalid)
		}
	}
	if validModuleFunctionName(nil, "rich_signature.version") {
		t.Error("expected nil schema to reject dotted module method")
	}
}

func BenchmarkPERichSignature(b *testing.B) {
	b.Run("Compile", func(b *testing.B) {
		const src = `import "pe"
rule r {
	condition:
		pe.rich_signature.key != 0 and
		pe.rich_signature.version(29500, 259) > 0 and
		pe.rich_signature.toolid(259) > 0
}`
		b.ReportAllocs()
		for b.Loop() {
			if _, err := NewCompiler().CompileSource(src); err != nil {
				b.Fatal(err)
			}
		}
	})

	entries := make([]pefixture.RichEntry, 24)
	for i := range entries {
		entries[i] = pefixture.RichEntry{
			ToolID:  uint16(200 + (i % 8)), //checkednarrow:ignore small benchmark table
			Version: uint16(29000 + i),     //checkednarrow:ignore small benchmark table
			Count:   uint32(i + 1),         //checkednarrow:ignore small benchmark table
		}
	}
	entries[0] = pefixture.RichEntry{ToolID: 259, Version: 29500, Count: 5}
	entries[12] = pefixture.RichEntry{ToolID: 259, Version: 29500, Count: 7}
	data := pefixture.RichPE(true, pefixture.RichOptions{Entries: entries})

	for _, tc := range []struct {
		name string
		src  string
		in   []byte
		want bool
	}{
		{"Fields", `import "pe" rule r { condition: pe.rich_signature.offset == 128 and pe.rich_signature.key != 0 }`, data, true},
		{"VersionQuery", `import "pe" rule r { condition: pe.rich_signature.version(29500, 259) == 12 }`, data, true},
		{"ToolIDQuery", `import "pe" rule r { condition: pe.rich_signature.toolid(259) > 0 }`, data, true},
		{"NonPERule", `rule r { strings: $a = "payload" condition: $a }`, []byte("unrelated payload bytes"), true},
	} {
		p, err := NewCompiler().CompileSource(tc.src)
		if err != nil {
			b.Fatal(err)
		}
		s := p.NewScanner()
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				ok, err := s.Matches(tc.in)
				if err != nil || ok != tc.want {
					b.Fatalf("Matches = (%t, %v)", ok, err)
				}
			}
		})
		s.Close()
	}
}
