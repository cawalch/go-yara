package compiler

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestPEVersionInfoFieldsAndSemantics(t *testing.T) {
	longKey := strings.Repeat("K", 70)
	longVal := strings.Repeat("V", 270)
	multi := pefixture.VersionInfoPE(true,
		pefixture.VersionInfoSpec{
			IncludeVarFileInfo: true,
			Translations:       []uint32{0x04b00409},
			StringTables: []pefixture.VersionStringTableSpec{
				{
					Key: "040904b0",
					Entries: []pefixture.VersionStringEntry{
						{Key: "CompanyName", Value: "First Corp"},
						{Key: "EmptyOmitted", OmitValue: true},
						{Key: "EmptyTerminated", Value: ""},
						{Key: "", Value: "BlankKey"},
					},
				},
				{
					Key: "040c04b0",
					Entries: []pefixture.VersionStringEntry{
						{Key: "ProductName", Value: "Café€"},
						{Key: "LegalCopyright", Value: "© 2026"},
						{Key: "Emoji", Value: "🚀!"},
						{Key: "StopLowZero", Value: "\u0100Ignored"},
					},
				},
			},
		},
		pefixture.VersionInfoSpec{
			StringTables: []pefixture.VersionStringTableSpec{
				{
					Key: "040904b0",
					Entries: []pefixture.VersionStringEntry{
						{Key: "CompanyName", Value: "Second Corp"},
						{Key: longKey, Value: longVal},
					},
				},
			},
		},
	)

	const source = `import "pe"

rule multi {
	condition:
		pe.is_pe == 1 and
		pe.number_of_version_infos == 10 and
		pe.version_info["CompanyName"] == "Second Corp" and
		pe.version_info["EmptyOmitted"] == "" and
		pe.version_info["EmptyTerminated"] == "" and
		pe.version_info[""] == "BlankKey" and
		pe.version_info["ProductName"] == "Caf\xe9\xac" and
		pe.version_info["LegalCopyright"] == "\xa9 2026" and
		pe.version_info["Emoji"] == "=\x80!" and
		pe.version_info["StopLowZero"] == "" and
		not defined pe.version_info["Translation"] and
		not defined pe.version_info["Missing"] and
		pe.version_info_list[0].key == "CompanyName" and
		pe.version_info_list[0].value == "First Corp" and
		pe.version_info_list[1].key == "EmptyOmitted" and
		pe.version_info_list[1].value == "" and
		pe.version_info_list[2].key == "EmptyTerminated" and
		pe.version_info_list[2].value == "" and
		pe.version_info_list[3].key == "" and
		pe.version_info_list[3].value == "BlankKey" and
		pe.version_info_list[8].key == "CompanyName" and
		pe.version_info_list[8].value == "Second Corp" and
		not defined pe.version_info_list[10].key and
		for any entry in pe.version_info_list : (entry.key == "CompanyName" and entry.value == "First Corp") and
		for any k, v in pe.version_info : (k == "CompanyName" and v == "Second Corp") and
		not for any k, v in pe.version_info : (k == "CompanyName" and v == "First Corp") and
		for all entry in pe.version_info_list : (defined pe.version_info[entry.key])
}

rule truncated_caps {
	strings:
		$k63 = "KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK" wide
	condition:
		$k63 and
		for any entry in pe.version_info_list : (
			entry.key == "KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK" and
			pe.version_info[entry.key] == entry.value and
			for any i in (0..pe.number_of_version_infos - 1) : (
				pe.version_info_list[i].key == entry.key
			)
		) and
		not defined pe.version_info["KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK"]
}

rule empty_pe {
	condition:
		pe.is_pe == 1 and
		pe.number_of_version_infos == 0 and
		not defined pe.version_info["CompanyName"] and
		not defined pe.version_info_list[0].key and
		not for any entry in pe.version_info_list : (true) and
		not for any k, v in pe.version_info : (true)
}

rule non_pe {
	condition:
		pe.is_pe == 0 and
		not defined pe.number_of_version_infos and
		not defined pe.version_info["CompanyName"] and
		not defined pe.version_info_list[0].key
}
`
	p, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner()
	defer s.Close()

	r, err := s.Scan(multi)
	if err != nil {
		t.Fatal(err)
	}
	if !r.RuleResults["multi"] || !r.RuleResults["truncated_caps"] || r.RuleResults["empty_pe"] || r.RuleResults["non_pe"] {
		t.Fatalf("unexpected multi scan results: %+v", r.RuleResults)
	}

	// Verify exact 63/255 truncation lengths directly through cached entry inspection.
	wantKey := strings.Repeat("K", 63)
	wantVal := strings.Repeat("V", 255)
	if got := s.moduleCache.pe.versionInfo.entries[9]; got.key != wantKey || got.value != wantVal {
		t.Fatalf("capped entry = (%q (%d), %q (%d))", got.key, len(got.key), got.value, len(got.value))
	}

	// Scanner reuse across no-rsrc PE, PE with non-version resources, and non-PE.
	for _, tc := range []struct {
		name string
		data []byte
		rule string
	}{
		{"NoRsrc", pefixture.New(false), "empty_pe"},
		{"NonVersionRsrc", pefixture.Resources(true, 2), "empty_pe"},
		{"NonPE", []byte("not a PE"), "non_pe"},
	} {
		res, err := s.Scan(tc.data)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !res.RuleResults[tc.rule] {
			t.Fatalf("%s: expected rule %s true, got %+v", tc.name, tc.rule, res.RuleResults)
		}
	}

	// Scan again with PE having version info after non-PE reuse.
	r2, err := s.Scan(multi)
	if err != nil || !r2.RuleResults["multi"] {
		t.Fatalf("reuse after non-PE: (%v, %v)", r2.RuleResults, err)
	}
}

func TestPEVersionInfoLazinessAndCacheSharing(t *testing.T) {
	data := pefixture.VersionInfoPE(true, pefixture.VersionInfoSpec{
		StringTables: []pefixture.VersionStringTableSpec{{
			Key: "040904b0",
			Entries: []pefixture.VersionStringEntry{
				{Key: "CompanyName", Value: "Acme"},
			},
		}},
	})

	t.Run("UnrelatedRuleSkipsVersionInfo", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe" rule r { condition: pe.is_pe == 1 and pe.machine == pe.MACHINE_AMD64 }`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()
		r, err := s.Scan(data)
		if err != nil || !r.RuleResults["r"] {
			t.Fatalf("got (%v, %v)", r.RuleResults, err)
		}
		if s.moduleCache.pe.resources != nil || s.moduleCache.pe.versionInfo != nil {
			t.Fatal("unrelated rule populated resources or versionInfo cache")
		}
	})

	t.Run("CountOnlyAvoidsDictListAndResourceDetails", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe" rule r { condition: pe.number_of_version_infos == 1 }`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()
		r, err := s.Scan(data)
		if err != nil || !r.RuleResults["r"] {
			t.Fatalf("got (%v, %v)", r.RuleResults, err)
		}
		img := s.moduleCache.pe
		if img.versionInfo == nil || img.versionInfo.dict.Type != ModuleUndefined || img.versionInfo.list.Type != ModuleUndefined {
			t.Fatalf("count materialized dict/list: %+v", img.versionInfo)
		}
		if img.resources == nil || img.resources.details.Type != ModuleUndefined {
			t.Fatal("version info query materialized pe.resources array wrappers")
		}
	})

	t.Run("AccessOrderCacheSharing", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			src  string
			dict bool
			list bool
		}{
			{
				name: "ResourcesThenDict",
				src:  `import "pe" rule r { condition: pe.number_of_resources == 1 and pe.version_info["CompanyName"] == "Acme" }`,
				dict: true,
			},
			{
				name: "ListThenResources",
				src:  `import "pe" rule r { condition: pe.version_info_list[0].value == "Acme" and pe.resources[0].type == pe.RESOURCE_TYPE_VERSION }`,
				list: true,
			},
		} {
			p, err := NewCompiler().CompileSource(tc.src)
			if err != nil {
				t.Fatal(err)
			}
			s := p.NewScanner()
			r, err := s.Scan(data)
			if err != nil || !r.RuleResults["r"] {
				s.Close()
				t.Fatalf("%s: got (%v, %v)", tc.name, r.RuleResults, err)
			}
			vi := s.moduleCache.pe.versionInfo
			if (vi.dict.Type != ModuleUndefined) != tc.dict || (vi.list.Type != ModuleUndefined) != tc.list {
				s.Close()
				t.Fatalf("%s: unexpected dict/list materialization: dict=%v list=%v", tc.name, vi.dict.Type, vi.list.Type)
			}
			s.Close()
		}
	})
}

func TestPEVersionInfoMalformedPartialHostAndLegacy(t *testing.T) {
	t.Run("UnpairedSurrogateReplacement", func(t *testing.T) {
		data := pefixture.VersionInfoPE(true, pefixture.VersionInfoSpec{
			StringTables: []pefixture.VersionStringTableSpec{{
				Key: "040904b0",
				Entries: []pefixture.VersionStringEntry{
					{Key: "Surrogate", RawValueUnits: []uint16{'A', 0xd800, 'B'}},
				},
			}},
		})
		// Intentional divergence from libyara documented in docs/pe-module.md:
		// go-pe emits UTF-8 U+FFFD for unpaired surrogates, so low-byte
		// projection preserves 0xfd instead of truncating at 0xd800.
		p, err := NewCompiler().CompileSource(`import "pe" rule r { condition: pe.version_info["Surrogate"] == "A\xfdB" }`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()
		ok, err := s.Matches(data)
		if err != nil || !ok {
			t.Fatalf("Matches = (%t, %v)", ok, err)
		}
	})

	t.Run("StrictMalformedAndPartialInput", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe"
rule strict_bad {
	condition:
		pe.is_pe == 1 and
		pe.number_of_resources == 1 and
		not defined pe.number_of_version_infos and
		not defined pe.version_info["CompanyName"] and
		not defined pe.version_info_list[0].key
}`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()

		malformed := pefixture.WithResources(pefixture.New(true), true, &pefixture.ResourceNodeSpec{
			Entries: []pefixture.ResourceEntrySpec{{
				ID: 16,
				Subdir: &pefixture.ResourceNodeSpec{
					Entries: []pefixture.ResourceEntrySpec{{
						ID: 1,
						Subdir: &pefixture.ResourceNodeSpec{
							Entries: []pefixture.ResourceEntrySpec{{
								ID:   1033,
								Leaf: &pefixture.ResourceLeafSpec{Payload: []byte{0x10, 0, 0, 0, 'B', 0, 'A', 0, 'D', 0}},
							}},
						},
					}},
				},
			}},
		})
		if r, err := s.Scan(malformed); err != nil || !r.RuleResults["strict_bad"] {
			t.Fatalf("malformed VS_VERSION_INFO: %+v err=%v", r.RuleResults, err)
		}

		// Directory metadata is in the first 64 KiB reader prefix while RT_VERSION
		// payload sits past the retained prefix.
		payload := pefixture.VersionInfoPayload(pefixture.VersionInfoSpec{
			StringTables: []pefixture.VersionStringTableSpec{{
				Key:     "040904b0",
				Entries: []pefixture.VersionStringEntry{{Key: "CompanyName", Value: "Far"}},
			}},
		})
		farPayloadPE := pefixture.WithResources(pefixture.New(true), true, &pefixture.ResourceNodeSpec{
			ExtraTailBytes: 70000,
			Entries: []pefixture.ResourceEntrySpec{{
				ID: 16,
				Subdir: &pefixture.ResourceNodeSpec{
					Entries: []pefixture.ResourceEntrySpec{{
						ID: 1,
						Subdir: &pefixture.ResourceNodeSpec{
							Entries: []pefixture.ResourceEntrySpec{{
								ID:   1033,
								Leaf: &pefixture.ResourceLeafSpec{Payload: payload},
							}},
						},
					}},
				},
			}},
		})
		if r, err := s.ScanReader(bytes.NewReader(farPayloadPE)); err != nil || !r.RuleResults["strict_bad"] {
			t.Fatalf("ScanReader out-of-prefix payload: %+v err=%v", r.RuleResults, err)
		}

		// Truncate leaf payload in-memory.
		truncated := append([]byte(nil), pefixture.VersionInfoPE(true, pefixture.VersionInfoSpec{
			StringTables: []pefixture.VersionStringTableSpec{{
				Key:     "040904b0",
				Entries: []pefixture.VersionStringEntry{{Key: "CompanyName", Value: "Trimmed"}},
			}},
		})...)
		truncated = truncated[:len(truncated)-8]
		// Ensure the test still compiles/evaluates against truncated file size via CustomSize/truncation:
		small := pefixture.WithResources(pefixture.New(true), true, &pefixture.ResourceNodeSpec{
			Entries: []pefixture.ResourceEntrySpec{{
				ID: 16,
				Subdir: &pefixture.ResourceNodeSpec{
					Entries: []pefixture.ResourceEntrySpec{{
						ID: 1,
						Subdir: &pefixture.ResourceNodeSpec{
							Entries: []pefixture.ResourceEntrySpec{{
								ID: 1033,
								Leaf: &pefixture.ResourceLeafSpec{
									Payload:       payload,
									HasCustomSize: true,
									CustomSize:    uint32(len(payload) + 0x10000), //checkednarrow:ignore bounded fixture test size
								},
							}},
						},
					}},
				},
			}},
		})
		if r, err := s.Scan(small); err != nil || !r.RuleResults["strict_bad"] {
			t.Fatalf("out-of-bounds leaf size (%d): %+v err=%v", len(truncated), r.RuleResults, err)
		}
	})

	t.Run("HostSnapshotRoundTripAndLegacySchema", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe"
rule host_vi {
	condition:
		pe.number_of_version_infos == 2 and
		pe.version_info["CompanyName"] == "Second" and
		pe.version_info_list[0].key == "CompanyName" and
		pe.version_info_list[0].value == "First" and
		for any k, v in pe.version_info : (k == "CompanyName" and v == "Second")
}
rule host_absent {
	condition:
		not defined pe.number_of_version_infos and
		not defined pe.version_info["CompanyName"] and
		not for any e in pe.version_info_list : (true)
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

		hs := roundTrip.NewScanner(WithModuleData("pe", map[string]any{
			"number_of_version_infos": 2,
			"version_info": map[string]any{
				"CompanyName": "Second",
			},
			"version_info_list": []any{
				map[string]any{"key": "CompanyName", "value": "First"},
				map[string]any{"key": "CompanyName", "value": "Second"},
			},
		}))
		defer hs.Close()
		r, err := hs.Scan(pefixture.New(true))
		if err != nil || !r.RuleResults["host_vi"] || r.RuleResults["host_absent"] || hs.moduleCache.pe != nil {
			t.Fatalf("host snapshot: results=%v err=%v cached=%v", r.RuleResults, err, hs.moduleCache.pe)
		}

		partialHost := roundTrip.NewScanner(WithModuleData("pe", map[string]any{"machine": 0x8664}))
		defer partialHost.Close()
		r, err = partialHost.Scan(pefixture.New(true))
		if err != nil || r.RuleResults["host_vi"] || !r.RuleResults["host_absent"] || partialHost.moduleCache.pe != nil {
			t.Fatalf("partial host snapshot: results=%v err=%v cached=%v", r.RuleResults, err, partialHost.moduleCache.pe)
		}

		prevProg, err := NewCompiler().CompileSource(`import "pe" rule legacy { condition: pe.is_pe == 1 and pe.number_of_resources == 1 }`)
		if err != nil {
			t.Fatal(err)
		}
		prevProg.moduleSchemas["pe"] = legacyPESchemas()[8]
		prevBlob, err := prevProg.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		restored, err := UnmarshalCompiledProgram(prevBlob)
		if err != nil {
			t.Fatal(err)
		}
		if !restored.Rules[0].nativePE {
			t.Fatal("expected legacy peResourcesSchema program to retain nativePE=true")
		}
		ls := restored.NewScanner()
		defer ls.Close()
		if ok, err := ls.Matches(pefixture.Resources(true, 1)); err != nil || !ok {
			t.Fatalf("legacy schema scan = (%t, %v)", ok, err)
		}
	})
}

func TestPEVersionInfoCancel(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe" rule r { condition: pe.version_info["CompanyName"] == "Acme" }`)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner()
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	data := pefixture.VersionInfoPE(true, pefixture.VersionInfoSpec{
		StringTables: []pefixture.VersionStringTableSpec{{
			Key:     "040904b0",
			Entries: []pefixture.VersionStringEntry{{Key: "CompanyName", Value: "Acme"}},
		}},
	})
	// Check non-zero binary field ensures data isn't empty slice.
	if len(data) == 0 || binary.LittleEndian.Uint16(data[:2]) != 0x5a4d {
		t.Fatal("invalid fixture")
	}
	if _, err := s.ScanWithContext(ctx, data); err == nil {
		t.Fatal("expected canceled scan error")
	}
}

func BenchmarkPEVersionInfo(b *testing.B) {
	b.Run("Compile", func(b *testing.B) {
		const src = `import "pe"
rule r {
	condition:
		pe.number_of_version_infos > 0 and
		pe.version_info["CompanyName"] == "Acme Corp" and
		for any e in pe.version_info_list : (e.key == "FileVersion" and e.value == "1.0.0.0")
}`
		b.ReportAllocs()
		for b.Loop() {
			if _, err := NewCompiler().CompileSource(src); err != nil {
				b.Fatal(err)
			}
		}
	})

	entries := make([]pefixture.VersionStringEntry, 16)
	for i := range entries {
		entries[i] = pefixture.VersionStringEntry{
			Key:   "Key" + string(rune('A'+i)),
			Value: "Value" + string(rune('0'+(i%10))),
		}
	}
	entries[0] = pefixture.VersionStringEntry{Key: "CompanyName", Value: "Acme Corp"}
	entries[15] = pefixture.VersionStringEntry{Key: "FileVersion", Value: "1.0.0.0"}
	data := pefixture.VersionInfoPE(true, pefixture.VersionInfoSpec{
		StringTables: []pefixture.VersionStringTableSpec{{Key: "040904b0", Entries: entries}},
	})

	for _, tc := range []struct {
		name string
		src  string
		in   []byte
		want bool
	}{
		{"CountOnly", `import "pe" rule r { condition: pe.number_of_version_infos == 16 }`, data, true},
		{"DictLookup", `import "pe" rule r { condition: pe.version_info["CompanyName"] == "Acme Corp" }`, data, true},
		{"ListLoop", `import "pe" rule r { condition: for any e in pe.version_info_list : (e.key == "FileVersion" and e.value == "1.0.0.0") }`, data, true},
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
