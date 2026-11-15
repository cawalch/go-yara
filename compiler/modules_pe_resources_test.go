package compiler

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestPEResourcesFieldsAndConstants(t *testing.T) {
	const source = `import "pe"

rule consts {
	condition:
		pe.RESOURCE_TYPE_CURSOR == 1 and
		pe.RESOURCE_TYPE_BITMAP == 2 and
		pe.RESOURCE_TYPE_ICON == 3 and
		pe.RESOURCE_TYPE_MENU == 4 and
		pe.RESOURCE_TYPE_DIALOG == 5 and
		pe.RESOURCE_TYPE_STRING == 6 and
		pe.RESOURCE_TYPE_FONTDIR == 7 and
		pe.RESOURCE_TYPE_FONT == 8 and
		pe.RESOURCE_TYPE_ACCELERATOR == 9 and
		pe.RESOURCE_TYPE_RCDATA == 10 and
		pe.RESOURCE_TYPE_MESSAGETABLE == 11 and
		pe.RESOURCE_TYPE_GROUP_CURSOR == 12 and
		pe.RESOURCE_TYPE_GROUP_ICON == 14 and
		pe.RESOURCE_TYPE_VERSION == 16 and
		pe.RESOURCE_TYPE_DLGINCLUDE == 17 and
		pe.RESOURCE_TYPE_PLUGPLAY == 19 and
		pe.RESOURCE_TYPE_VXD == 20 and
		pe.RESOURCE_TYPE_ANICURSOR == 21 and
		pe.RESOURCE_TYPE_ANIICON == 22 and
		pe.RESOURCE_TYPE_HTML == 23 and
		pe.RESOURCE_TYPE_MANIFEST == 24
}

rule metadata {
	condition:
		pe.is_pe == 1 and
		pe.resource_timestamp == 0x12345678 and
		pe.resource_version.major == 2 and
		pe.resource_version.minor == 5 and
		pe.number_of_resources == 5 and
		pe.resources[0].type_string == "T\x00Y\x00P\x00E\x00" and
		not defined pe.resources[0].type and
		pe.resources[0].name_string == "\xdc\x00T\x00F\x00" and
		not defined pe.resources[0].id and
		pe.resources[0].language_string == "L\x00A\x00N\x00G\x00" and
		not defined pe.resources[0].language and
		pe.resources[0].offset > 0x800 and
		pe.resources[0].rva > 0x3000 and
		pe.resources[0].length == 7 and
		pe.resources[1].type == pe.RESOURCE_TYPE_RCDATA and
		not defined pe.resources[1].type_string and
		pe.resources[1].id == 5 and
		not defined pe.resources[1].name_string and
		pe.resources[1].language == 0x0309 and
		not defined pe.resources[1].language_string and
		pe.resources[2].type == pe.RESOURCE_TYPE_VERSION and
		not defined pe.resources[2].id and
		not defined pe.resources[2].language and
		pe.resources[3].type == pe.RESOURCE_TYPE_MANIFEST and
		pe.resources[3].id == 1 and
		not defined pe.resources[3].language and
		pe.resources[4].type == pe.RESOURCE_TYPE_ICON and
		pe.resources[4].rva == 0x99990000 and
		not defined pe.resources[4].offset and
		pe.locale(0x0309) == 1 and
		pe.locale(0x0409) == 0 and
		pe.locale(-1) == 0 and
		pe.language(0x09) == 1 and
		pe.language(0x0309) == 0 and
		pe.language(-1) == 0
}

rule absent_dir {
	condition:
		pe.is_pe == 1 and
		not defined pe.resource_timestamp and
		not defined pe.resource_version.major and
		not defined pe.resource_version.minor and
		pe.number_of_resources == 0 and
		not defined pe.resources[0].rva and
		pe.locale(1033) == 0 and
		pe.language(9) == 0
}

rule non_pe {
	condition:
		pe.is_pe == 0 and
		consts and
		not defined pe.resource_timestamp and
		not defined pe.resource_version.major and
		not defined pe.number_of_resources and
		not defined pe.locale(1033) and
		not defined pe.language(9)
}
`
	p, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}

	root := &pefixture.ResourceNodeSpec{
		TimeDateStamp: 0x12345678,
		MajorVersion:  2,
		MinorVersion:  5,
		Entries: []pefixture.ResourceEntrySpec{
			// Entry 0: 3-level named UTF-16LE (including BMP non-ASCII).
			{
				Named: true,
				Name:  "TYPE",
				Subdir: &pefixture.ResourceNodeSpec{
					Entries: []pefixture.ResourceEntrySpec{
						{
							Named: true,
							Name:  "ÜTF",
							Subdir: &pefixture.ResourceNodeSpec{
								Entries: []pefixture.ResourceEntrySpec{
									{Named: true, Name: "LANG", Leaf: &pefixture.ResourceLeafSpec{Payload: []byte("payload")}},
								},
							},
						},
					},
				},
			},
			// Entry 1: numeric with 0x0309 (language & 0xff == 0x09).
			{
				ID: 10,
				Subdir: &pefixture.ResourceNodeSpec{
					Entries: []pefixture.ResourceEntrySpec{
						{
							ID: 5,
							Subdir: &pefixture.ResourceNodeSpec{
								Entries: []pefixture.ResourceEntrySpec{
									{ID: 0x0309, Leaf: &pefixture.ResourceLeafSpec{Payload: []byte("en")}},
								},
							},
						},
					},
				},
			},
			// Entry 2: incomplete 1-level leaf.
			{ID: 16, Leaf: &pefixture.ResourceLeafSpec{Payload: []byte("d1")}},
			// Entry 3: incomplete 2-level leaf.
			{
				ID: 24,
				Subdir: &pefixture.ResourceNodeSpec{
					Entries: []pefixture.ResourceEntrySpec{
						{ID: 1, Leaf: &pefixture.ResourceLeafSpec{Payload: []byte("d2")}},
					},
				},
			},
			// Entry 4: unmapped DataRVA -> rva defined, offset undefined.
			{
				ID: 3,
				Subdir: &pefixture.ResourceNodeSpec{
					Entries: []pefixture.ResourceEntrySpec{
						{
							ID: 2,
							Subdir: &pefixture.ResourceNodeSpec{
								Entries: []pefixture.ResourceEntrySpec{
									{
										ID: 0x040c,
										Leaf: &pefixture.ResourceLeafSpec{
											HasCustomRVA:  true,
											CustomRVA:     0x99990000,
											HasCustomSize: true,
											CustomSize:    12,
										},
									},
								},
							},
						},
					},
				},
			},
			// Entry 5: 4-level leaf must be excluded from YARA's 3-level resource table.
			{
				ID: 99,
				Subdir: &pefixture.ResourceNodeSpec{
					Entries: []pefixture.ResourceEntrySpec{
						{
							ID: 1,
							Subdir: &pefixture.ResourceNodeSpec{
								Entries: []pefixture.ResourceEntrySpec{
									{
										ID: 1033,
										Subdir: &pefixture.ResourceNodeSpec{
											Entries: []pefixture.ResourceEntrySpec{
												{ID: 7, Leaf: &pefixture.ResourceLeafSpec{Payload: []byte("deep4")}},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, prog := range []*CompiledProgram{p, loaded} {
		s := prog.NewScanner()
		defer s.Close()
		for _, is64 := range []bool{false, true} {
			withRsrc := pefixture.WithResources(pefixture.New(is64), is64, root)
			r, err := s.Scan(withRsrc)
			if err != nil || !r.RuleResults["consts"] || !r.RuleResults["metadata"] || r.RuleResults["absent_dir"] || r.RuleResults["non_pe"] {
				t.Fatalf("PE64=%t withRsrc: results=%v err=%v", is64, r.RuleResults, err)
			}

			// Scanner reuse immediately onto PE with no resource directory.
			noDir := pefixture.New(is64)
			r, err = s.Scan(noDir)
			if err != nil || !r.RuleResults["consts"] || !r.RuleResults["absent_dir"] || r.RuleResults["metadata"] || r.RuleResults["non_pe"] {
				t.Fatalf("PE64=%t noDir: results=%v err=%v", is64, r.RuleResults, err)
			}

			// Re-scan PE with empty root resource directory.
			emptyRoot := pefixture.WithResources(pefixture.New(is64), is64, &pefixture.ResourceNodeSpec{
				TimeDateStamp: 0x01020304,
				MajorVersion:  9,
				MinorVersion:  1,
			})
			r, err = s.Scan(emptyRoot)
			if err != nil || r.RuleResults["absent_dir"] || r.RuleResults["metadata"] {
				t.Fatalf("PE64=%t emptyRoot: results=%v err=%v", is64, r.RuleResults, err)
			}
		}

		// Non-PE input after PE scans.
		r, err := s.Scan([]byte("plain data"))
		if err != nil || !r.RuleResults["non_pe"] || r.RuleResults["absent_dir"] || r.RuleResults["metadata"] {
			t.Fatalf("nonPE: results=%v err=%v", r.RuleResults, err)
		}
	}
}

func TestPEResourcesLazyAndStrictErrors(t *testing.T) {
	t.Run("UnrelatedRuleSkipsResources", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe" rule r { condition: pe.is_pe == 1 and pe.machine == pe.MACHINE_AMD64 }`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()
		r, err := s.Scan(pefixture.Resources(true, 4))
		if err != nil || !r.RuleResults["r"] {
			t.Fatalf("got (%v, %v)", r, err)
		}
		if s.moduleCache.pe.resources != nil {
			t.Fatal("unrelated PE rule parsed resources")
		}
	})

	t.Run("CountAndLocaleAvoidDetailsAllocation", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe"
rule q { condition: pe.resource_timestamp == 0x12345678 and pe.resource_version.major == 2 and pe.number_of_resources == 4 and pe.locale(1033) and pe.language(9) }`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()
		r, err := s.Scan(pefixture.Resources(true, 4))
		if err != nil || !r.RuleResults["q"] {
			t.Fatalf("got (%v, %v)", r, err)
		}
		if s.moduleCache.pe.resources == nil || s.moduleCache.pe.resources.details.Type != ModuleUndefined {
			t.Fatal("scalar/locale queries materialized resources array objects")
		}
	})

	t.Run("MalformedCycleLeavesResourcesUndefined", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe"
rule r {
	condition:
		pe.is_pe == 1 and
		not defined pe.resource_timestamp and
		not defined pe.resource_version.major and
		not defined pe.number_of_resources and
		not defined pe.resources[0].rva and
		not defined pe.locale(1033) and
		not defined pe.language(9)
}`)
		if err != nil {
			t.Fatal(err)
		}
		data := pefixture.Resources(true, 1)
		// Repoint root entry 0 back to root directory offset 0.
		binary.LittleEndian.PutUint32(data[0x800+16+4:], 0x80000000)
		s := p.NewScanner()
		defer s.Close()
		r, err := s.Scan(data)
		if err != nil || !r.RuleResults["r"] {
			t.Fatalf("cyclic resources: %v err=%v", r, err)
		}
	})
}

func TestPEResourcesReaderAndOutOfPrefix(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule in_prefix {
	condition:
		pe.is_pe == 1 and
		pe.number_of_resources == 1 and
		pe.resources[0].offset > 0x10000 and
		pe.resources[0].length == 11 and
		pe.locale(1033) == 1
}
rule past_prefix {
	condition:
		pe.is_pe == 1 and
		not defined pe.resource_timestamp and
		not defined pe.number_of_resources and
		not defined pe.locale(1033)
}`)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner()
	defer s.Close()

	// Directory metadata stays near offset 0x800 (< 64 KiB prefix) while payload
	// lives past the 64 KiB retained reader prefix.
	prefixMetaOutPayload := pefixture.WithResources(pefixture.New(true), true, &pefixture.ResourceNodeSpec{
		TimeDateStamp:  1,
		ExtraTailBytes: 70000,
		Entries: []pefixture.ResourceEntrySpec{
			{
				ID: 10,
				Subdir: &pefixture.ResourceNodeSpec{
					Entries: []pefixture.ResourceEntrySpec{
						{
							ID: 1,
							Subdir: &pefixture.ResourceNodeSpec{
								Entries: []pefixture.ResourceEntrySpec{
									{ID: 1033, Leaf: &pefixture.ResourceLeafSpec{Payload: []byte("far-payload")}},
								},
							},
						},
					},
				},
			},
		},
	})

	r, err := s.ScanReader(bytes.NewReader(prefixMetaOutPayload))
	if err != nil || !r.RuleResults["in_prefix"] || r.RuleResults["past_prefix"] {
		t.Fatalf("reader prefix meta + out-of-prefix payload: %v err=%v", r, err)
	}

	// Shift .rsrc section itself past 64 KiB reader prefix (adding a 70 KiB .data pad).
	shifted := pefixture.WithResources(pefixture.Imports(true, 1), true, &pefixture.ResourceNodeSpec{
		TimeDateStamp: 1,
		Entries: []pefixture.ResourceEntrySpec{
			{ID: 10, Leaf: &pefixture.ResourceLeafSpec{Payload: []byte("x")}},
		},
	})
	// Truncate reader test using Disjoint BlockScanner (< dir end) vs Reader past 64 KiB:
	blocks := p.NewBlockScanner()
	defer blocks.Close()
	if err := blocks.Scan(0, shifted[:0x800]); err != nil {
		t.Fatal(err)
	}
	if err := blocks.Scan(0x800, shifted[0x800:]); err != nil {
		t.Fatal(err)
	}
	br, err := blocks.Finish()
	if err != nil || !br.RuleResults["past_prefix"] {
		t.Fatalf("disjoint blocks missing .rsrc in block 0: %v err=%v", br, err)
	}
}

func TestPEResourcesHostAndLegacySchema(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule host_loop {
	condition:
		pe.resource_timestamp == 42 and
		pe.resource_version.major == 1 and
		pe.resource_version.minor == 3 and
		pe.number_of_resources == 2 and
		pe.locale(0x0409) == 1 and
		pe.language(0x09) == 1 and
		for any r in pe.resources : (r.type == pe.RESOURCE_TYPE_RCDATA and r.offset == 4096)
}
rule host_absent {
	condition:
		not defined pe.resource_timestamp and
		not defined pe.number_of_resources and
		not defined pe.locale(0x0409) and
		not for any r in pe.resources : (r.length > 0)
}`)
	if err != nil {
		t.Fatal(err)
	}

	hs := p.NewScanner(WithModuleData("pe", map[string]any{
		"resource_timestamp":  42,
		"resource_version":    map[string]any{"major": 1, "minor": 3},
		"number_of_resources": 2,
		"resources": []any{
			map[string]any{"type": 10, "id": 1, "language": 0x0409, "offset": 4096, "length": 16},
			map[string]any{"type": 16, "id": 1, "language": 0x040c, "offset": 8192, "length": 8},
		},
	}))
	defer hs.Close()
	r, err := hs.Scan(pefixture.Resources(true, 4))
	if err != nil || !r.RuleResults["host_loop"] || r.RuleResults["host_absent"] || hs.moduleCache.pe != nil {
		t.Fatalf("host snapshot: results=%v err=%v cached=%v", r.RuleResults, err, hs.moduleCache.pe)
	}

	emptyHost := p.NewScanner(WithModuleData("pe", map[string]any{"machine": 0x8664}))
	defer emptyHost.Close()
	r, err = emptyHost.Scan(pefixture.Resources(true, 4))
	if err != nil || r.RuleResults["host_loop"] || !r.RuleResults["host_absent"] || emptyHost.moduleCache.pe != nil {
		t.Fatalf("partial host snapshot: results=%v err=%v cached=%v", r.RuleResults, err, emptyHost.moduleCache.pe)
	}

	// Programs serialized against peSignatureVerifySchema must retain nativePE=true.
	prevProg, err := NewCompiler().CompileSource(`import "pe" rule legacy { condition: pe.is_pe == 1 and pe.number_of_sections == 2 }`)
	if err != nil {
		t.Fatal(err)
	}
	prevProg.moduleSchemas["pe"] = peSignatureVerifySchema
	blob, err := prevProg.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalCompiledProgram(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.Rules[0].nativePE {
		t.Fatal("expected legacy peSignatureVerifySchema program to retain nativePE=true")
	}
	ls := restored.NewScanner()
	defer ls.Close()
	if ok, err := ls.Matches(pefixture.New(true)); err != nil || !ok {
		t.Fatalf("legacy schema scan = (%t, %v)", ok, err)
	}
}

func TestPEResourcesCancel(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe" rule r { condition: pe.locale(1033) == 1 }`)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner()
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ScanWithContext(ctx, pefixture.Resources(true, 4)); err == nil {
		t.Fatal("expected canceled scan error")
	}
}

func BenchmarkPEResources(b *testing.B) {
	b.Run("Compile", func(b *testing.B) {
		const src = `import "pe"
rule r {
	condition:
		pe.number_of_resources > 0 and
		pe.locale(1033) == 1 and
		for any res in pe.resources : (res.type == pe.RESOURCE_TYPE_RCDATA and res.offset > 0)
}`
		b.ReportAllocs()
		for b.Loop() {
			if _, err := NewCompiler().CompileSource(src); err != nil {
				b.Fatal(err)
			}
		}
	})

	data := pefixture.Resources(true, 256)
	for _, tc := range []struct {
		name string
		src  string
		in   []byte
		want bool
	}{
		{"LocaleQuery", `import "pe" rule r { condition: pe.locale(1033) == 1 and pe.language(9) == 1 }`, data, true},
		{"ResourceLoop", `import "pe" rule r { condition: for any res in pe.resources : (res.id == 256 and res.length > 0) }`, data, true},
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
