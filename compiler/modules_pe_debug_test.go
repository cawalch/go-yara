package compiler

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestPEDebugPDBPath(t *testing.T) {
	const (
		debugTypeCodeView = 2
		debugTypeMisc     = 4
		debugTypeRepro    = 16
	)
	for _, is64 := range []bool{false, true} {
		t.Run(fmt.Sprintf("is64=%t", is64), func(t *testing.T) {
			rsds := pefixture.DebugPE(is64, pefixture.DebugEntrySpec{
				Type:    debugTypeCodeView,
				Payload: pefixture.RSDSPayload([]byte("C:\\build\\app.pdb\x00")),
			})
			nb10 := pefixture.DebugPE(is64, pefixture.DebugEntrySpec{
				Type:    debugTypeCodeView,
				Payload: pefixture.NB10Payload([]byte("legacy.pdb\x00")),
			})
			rvaOnly := pefixture.DebugPE(is64, pefixture.DebugEntrySpec{
				Type:    debugTypeCodeView,
				RVAOnly: true,
				Payload: pefixture.RSDSPayload([]byte("rva_only.pdb\x00")),
			})
			overlayPtrOnly := pefixture.DebugPE(is64, pefixture.DebugEntrySpec{
				Type:      debugTypeCodeView,
				InOverlay: true,
				Payload:   pefixture.RSDSPayload([]byte("overlay.pdb\x00")),
			})
			multiFirst := pefixture.DebugPE(is64,
				pefixture.DebugEntrySpec{Type: debugTypeMisc, Payload: []byte("misc")},
				pefixture.DebugEntrySpec{Type: debugTypeCodeView, Payload: append([]byte("XXXX"), make([]byte, 20)...)},
				pefixture.DebugEntrySpec{Type: debugTypeCodeView, Payload: pefixture.NB10Payload([]byte("first.pdb\x00"))},
				pefixture.DebugEntrySpec{Type: debugTypeCodeView, Payload: pefixture.RSDSPayload([]byte("second.pdb\x00"))},
			)
			emptyFirstWins := pefixture.DebugPE(is64,
				pefixture.DebugEntrySpec{Type: debugTypeCodeView, Payload: pefixture.RSDSPayload([]byte{0})},
				pefixture.DebugEntrySpec{Type: debugTypeCodeView, Payload: pefixture.RSDSPayload([]byte("later.pdb\x00"))},
			)
			noTrailingRSDS := pefixture.DebugPE(is64, pefixture.DebugEntrySpec{
				Type:    debugTypeCodeView,
				Payload: pefixture.RSDSPayload(nil),
			})
			noTrailingNB10 := pefixture.DebugPE(is64, pefixture.DebugEntrySpec{
				Type:    debugTypeCodeView,
				Payload: pefixture.NB10Payload(nil),
			})
			embeddedNUL := pefixture.DebugPE(is64, pefixture.DebugEntrySpec{
				Type:    debugTypeCodeView,
				Payload: pefixture.RSDSPayload([]byte("head\x00tail.pdb\x00")),
			})
			nonASCII := pefixture.DebugPE(is64, pefixture.DebugEntrySpec{
				Type:    debugTypeCodeView,
				Payload: pefixture.RSDSPayload([]byte{'C', ':', '\\', 0xff, 0xfe, '.', 'p', 'd', 'b', 0}),
			})
			onlyNonCV := pefixture.DebugPE(is64,
				pefixture.DebugEntrySpec{Type: debugTypeMisc, Payload: []byte("misc")},
				pefixture.DebugEntrySpec{Type: debugTypeRepro},
			)
			onlyUnknownCV := pefixture.DebugPE(is64, pefixture.DebugEntrySpec{
				Type:    debugTypeCodeView,
				Payload: append([]byte("ZZZZ"), make([]byte, 20)...),
			})

			p, err := NewCompiler().CompileSource(`import "pe"
rule def { condition: defined pe.pdb_path }
rule rsds { condition: pe.pdb_path == "C:\\build\\app.pdb" }
rule nb10 { condition: pe.pdb_path == "legacy.pdb" }
rule rva { condition: pe.pdb_path == "rva_only.pdb" }
rule overlay { condition: pe.pdb_path == "overlay.pdb" }
rule first { condition: pe.pdb_path == "first.pdb" }
rule empty { condition: defined pe.pdb_path and pe.pdb_path == "" }
rule emb { condition: pe.pdb_path == "head" }
rule rawbytes { condition: pe.pdb_path == "C:\\\xff\xfe.pdb" }`)
			if err != nil {
				t.Fatal(err)
			}
			s := p.NewScanner()
			defer s.Close()

			for _, tc := range []struct {
				name     string
				data     []byte
				wantRule string
			}{
				{"RSDS", rsds, "rsds"},
				{"NB10", nb10, "nb10"},
				{"RVAOnly", rvaOnly, "rva"},
				{"OverlayPtrOnly", overlayPtrOnly, "overlay"},
				{"MultiFirstValidWins", multiFirst, "first"},
				{"EmptyFirstWins", emptyFirstWins, "empty"},
				{"NoTrailingRSDS", noTrailingRSDS, "empty"},
				{"NoTrailingNB10", noTrailingNB10, "empty"},
				{"EmbeddedNUL", embeddedNUL, "emb"},
				{"NonASCII", nonASCII, "rawbytes"},
				{"OnlyNonCV", onlyNonCV, ""},
				{"OnlyUnknownCV", onlyUnknownCV, ""},
				{"NoDebugDir", pefixture.New(is64), ""},
				{"NonPE", []byte("not a PE image"), ""},
				{"EmptyInput", nil, ""},
			} {
				r, err := s.Scan(tc.data)
				if err != nil {
					t.Fatalf("%s Scan: %v", tc.name, err)
				}
				if tc.wantRule == "" {
					if r.RuleResults["def"] {
						t.Fatalf("%s: expected undefined pdb_path, got %+v", tc.name, r.RuleResults)
					}
					continue
				}
				if !r.RuleResults["def"] || !r.RuleResults[tc.wantRule] {
					t.Fatalf("%s: expected rule %s true, got %+v", tc.name, tc.wantRule, r.RuleResults)
				}
			}

			// Verify ScanReader and BlockScanner behavior on RSDS.
			r, err := s.ScanReader(bytes.NewReader(rsds))
			if err != nil || !r.RuleResults["rsds"] {
				t.Fatalf("ScanReader(rsds): results=%+v err=%v", r.RuleResults, err)
			}
			for _, base := range []int64{0, 4096} {
				bs := p.NewBlockScanner()
				if err := bs.Scan(base, rsds); err != nil {
					t.Fatal(err)
				}
				br, err := bs.Finish()
				bs.Close()
				if err != nil || br.RuleResults["rsds"] != (base == 0) {
					t.Fatalf("BlockScanner(base=%d): results=%+v err=%v", base, br.RuleResults, err)
				}
			}
		})
	}
}

func TestPEDebugCacheStrictAndReaderBounds(t *testing.T) {
	const debugTypeCodeView = 2
	valid := pefixture.DebugPE(true, pefixture.DebugEntrySpec{
		Type:    debugTypeCodeView,
		Payload: pefixture.RSDSPayload([]byte("cached.pdb\x00")),
	})

	t.Run("UnrelatedRuleSkipsDebugLoad", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe" rule r { condition: pe.is_pe == 1 and pe.machine == pe.MACHINE_AMD64 }`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()
		if ok, err := s.Matches(valid); err != nil || !ok {
			t.Fatalf("Matches = (%t, %v)", ok, err)
		}
		if s.moduleCache.pe.debug != nil {
			t.Fatal("unrelated PE rule populated debug cache")
		}
	})

	t.Run("MultiRuleCacheSharingAndAbsentMemoization", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe"
rule a { condition: pe.pdb_path == "cached.pdb" }
rule b { condition: defined pe.pdb_path and pe.pdb_path contains "cached" }
rule c { condition: not defined pe.pdb_path }`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()

		buf := append([]byte(nil), valid...)
		r, err := s.Scan(buf)
		if err != nil || !r.RuleResults["a"] || !r.RuleResults["b"] || r.RuleResults["c"] {
			t.Fatalf("Scan = (%+v, %v)", r.RuleResults, err)
		}
		cached := s.moduleCache.pe.debug
		if cached == nil || !cached.valid || !cached.pdbPathChecked {
			t.Fatalf("unexpected debug cache state: %+v", cached)
		}
		// Corrupt payload in place and ensure re-evaluating rules in the same scan
		// still reads the cached snapshot.
		idx := bytes.Index(buf, []byte("cached.pdb"))
		copy(buf[idx:], "xxxxxx.pdb")
		for _, rule := range p.Rules[:2] {
			if !s.isRuleConditionSatisfied(rule) || s.moduleCache.pe.debug != cached {
				t.Fatalf("rule %s did not reuse debug cache", rule.Name)
			}
		}

		// No-CodeView PE caches pdbPathChecked=true with undefined pdbPath.
		rNoCV, err := s.Scan(pefixture.New(true))
		if err != nil || !rNoCV.RuleResults["c"] {
			t.Fatalf("no-debug scan = (%+v, %v)", rNoCV.RuleResults, err)
		}
		if s.moduleCache.pe.debug == nil || !s.moduleCache.pe.debug.valid || !s.moduleCache.pe.debug.pdbPathChecked || s.moduleCache.pe.debug.pdbPath.Type != ModuleUndefined {
			t.Fatalf("unexpected absent debug cache state: %+v", s.moduleCache.pe.debug)
		}
	})

	t.Run("StrictMalformedAndOutOfPrefixReader", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe" rule undef { condition: pe.is_pe == 1 and not defined pe.pdb_path }`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()

		unterminated := pefixture.DebugPE(true, pefixture.DebugEntrySpec{
			Type:    debugTypeCodeView,
			Payload: pefixture.RSDSPayload([]byte("no_nul_terminator")),
		})
		shortRSDS := pefixture.DebugPE(true, pefixture.DebugEntrySpec{
			Type:    debugTypeCodeView,
			Payload: []byte("RSDS\x01\x02\x03\x04"),
		})
		conflictingPtr := pefixture.DebugPE(true, pefixture.DebugEntrySpec{
			Type:           debugTypeCodeView,
			ConflictOffset: 0x100,
			Payload:        pefixture.RSDSPayload([]byte("bad_ptr.pdb\x00")),
		})
		truncatedSize := pefixture.DebugPE(true, pefixture.DebugEntrySpec{
			Type:          debugTypeCodeView,
			HasCustomSize: true,
			CustomSize:    0x8000,
			Payload:       pefixture.RSDSPayload([]byte("trunc.pdb\x00")),
		})
		for _, tc := range []struct {
			name string
			data []byte
		}{
			{"UnterminatedPath", unterminated},
			{"ShortRSDS", shortRSDS},
			{"ConflictingRawPtrAndRVA", conflictingPtr},
			{"TruncatedPayloadSize", truncatedSize},
		} {
			if r, err := s.Scan(tc.data); err != nil || !r.RuleResults["undef"] {
				t.Fatalf("%s: results=%+v err=%v", tc.name, r.RuleResults, err)
			}
		}

		// Out-of-prefix payload past 64 KiB ScanReader retained prefix.
		outOfPrefix := pefixture.DebugPE(true, pefixture.DebugEntrySpec{
			Type:        debugTypeCodeView,
			OutOfPrefix: 70000,
			Payload:     pefixture.RSDSPayload([]byte("far.pdb\x00")),
		})
		if r, err := s.Scan(outOfPrefix); err != nil || r.RuleResults["undef"] {
			t.Fatalf("full Scan outOfPrefix expected defined pdb_path, got %+v err=%v", r.RuleResults, err)
		}
		if r, err := s.ScanReader(bytes.NewReader(outOfPrefix)); err != nil || !r.RuleResults["undef"] {
			t.Fatalf("ScanReader outOfPrefix expected undefined pdb_path, got %+v err=%v", r.RuleResults, err)
		}
	})
}

func TestPEDebugHostSnapshotSerializationLegacyAndCancel(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule match { condition: pe.pdb_path == "host.pdb" }
rule empty { condition: defined pe.pdb_path and pe.pdb_path == "" }
rule absent { condition: not defined pe.pdb_path }`)
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

	peWithPDB := pefixture.DebugPE(true, pefixture.DebugEntrySpec{
		Type:    2,
		Payload: pefixture.RSDSPayload([]byte("file.pdb\x00")),
	})

	hs := roundTrip.NewScanner(WithModuleData("pe", map[string]any{"pdb_path": "host.pdb"}))
	defer hs.Close()
	r, err := hs.Scan(peWithPDB)
	if err != nil || !r.RuleResults["match"] || r.RuleResults["absent"] || hs.moduleCache.pe != nil {
		t.Fatalf("host snapshot: results=%+v err=%v cache=%v", r.RuleResults, err, hs.moduleCache.pe)
	}

	hsEmpty := roundTrip.NewScanner(WithModuleData("pe", map[string]any{"pdb_path": ""}))
	defer hsEmpty.Close()
	r, err = hsEmpty.Scan(peWithPDB)
	if err != nil || !r.RuleResults["empty"] || r.RuleResults["absent"] || hsEmpty.moduleCache.pe != nil {
		t.Fatalf("host empty pdb_path: results=%+v err=%v", r.RuleResults, err)
	}

	partial := roundTrip.NewScanner(WithModuleData("pe", map[string]any{"machine": 0x8664}))
	defer partial.Close()
	r, err = partial.Scan(peWithPDB)
	if err != nil || r.RuleResults["match"] || !r.RuleResults["absent"] || partial.moduleCache.pe != nil {
		t.Fatalf("partial host snapshot: results=%+v err=%v", r.RuleResults, err)
	}

	t.Run("LegacyRichSchemaPreservesNativePE", func(t *testing.T) {
		prevProg, err := NewCompiler().CompileSource(`import "pe" rule legacy { condition: pe.is_pe == 1 }`)
		if err != nil {
			t.Fatal(err)
		}
		prevProg.moduleSchemas["pe"] = peRichSignatureSchema
		prevBlob, err := prevProg.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		restored, err := UnmarshalCompiledProgram(prevBlob)
		if err != nil {
			t.Fatal(err)
		}
		if !restored.Rules[0].nativePE {
			t.Fatal("expected peRichSignatureSchema program to keep nativePE=true")
		}
		if ok, err := restored.Matches(peWithPDB); err != nil || !ok {
			t.Fatalf("legacy schema scan = (%t, %v)", ok, err)
		}
	})

	t.Run("Cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		cs := roundTrip.NewScanner()
		defer cs.Close()
		if len(peWithPDB) == 0 || binary.LittleEndian.Uint16(peWithPDB[:2]) != 0x5a4d {
			t.Fatal("invalid fixture")
		}
		if _, err := cs.ScanWithContext(ctx, peWithPDB); err == nil {
			t.Fatal("expected canceled scan error")
		}
	})
}

func BenchmarkPEDebugPDBPath(b *testing.B) {
	b.Run("Compile", func(b *testing.B) {
		const src = `import "pe" rule r { condition: pe.is_pe == 1 and pe.pdb_path contains ".pdb" }`
		b.ReportAllocs()
		for b.Loop() {
			if _, err := NewCompiler().CompileSource(src); err != nil {
				b.Fatal(err)
			}
		}
	})

	data := pefixture.DebugPE(true, pefixture.DebugEntrySpec{
		Type:    2,
		Payload: pefixture.RSDSPayload([]byte("C:\\projects\\app\\Release\\app.pdb\x00")),
	})
	for _, tc := range []struct {
		name string
		src  string
		in   []byte
		want bool
	}{
		{"PDBPath", `import "pe" rule r { condition: pe.pdb_path == "C:\\projects\\app\\Release\\app.pdb" }`, data, true},
		{"HeaderOnly", `import "pe" rule r { condition: pe.is_pe == 1 }`, data, true},
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
