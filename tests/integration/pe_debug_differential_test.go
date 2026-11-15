package integration

import (
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestPEDebugPDBPathDifferential(t *testing.T) {
	libyaraOracle(t)

	const debugTypeCodeView = 2
	const debugTypeMisc = 4

	for _, tc := range []struct {
		name       string
		data       []byte
		predicates []string
	}{
		{
			name: "pe32_rsds",
			data: pefixture.DebugPE(false, pefixture.DebugEntrySpec{
				Type:    debugTypeCodeView,
				Payload: pefixture.RSDSPayload([]byte("C:\\src\\tool.pdb\x00")),
			}),
			predicates: []string{
				`pe.is_pe == 1`,
				`defined pe.pdb_path`,
				`pe.pdb_path == "C:\\src\\tool.pdb"`,
			},
		},
		{
			name: "pe64_nb10",
			data: pefixture.DebugPE(true, pefixture.DebugEntrySpec{
				Type:    debugTypeCodeView,
				Payload: pefixture.NB10Payload([]byte("legacy20.pdb\x00")),
			}),
			predicates: []string{
				`pe.is_pe == 1`,
				`defined pe.pdb_path`,
				`pe.pdb_path == "legacy20.pdb"`,
			},
		},
		{
			name: "rva_only",
			data: pefixture.DebugPE(true, pefixture.DebugEntrySpec{
				Type:    debugTypeCodeView,
				RVAOnly: true,
				Payload: pefixture.RSDSPayload([]byte("rva.pdb\x00")),
			}),
			predicates: []string{`pe.pdb_path == "rva.pdb"`},
		},
		{
			name: "ptr_only_overlay",
			data: pefixture.DebugPE(true, pefixture.DebugEntrySpec{
				Type:      debugTypeCodeView,
				InOverlay: true,
				Payload:   pefixture.RSDSPayload([]byte("overlay.pdb\x00")),
			}),
			predicates: []string{`pe.pdb_path == "overlay.pdb"`},
		},
		{
			name: "mixed_entries_first_recognized_cv_wins",
			data: pefixture.DebugPE(true,
				pefixture.DebugEntrySpec{Type: debugTypeMisc, Payload: []byte("misc")},
				pefixture.DebugEntrySpec{Type: debugTypeCodeView, Payload: append([]byte("XXXX"), make([]byte, 20)...)},
				pefixture.DebugEntrySpec{Type: debugTypeCodeView, Payload: pefixture.NB10Payload([]byte("first.pdb\x00"))},
				pefixture.DebugEntrySpec{Type: debugTypeCodeView, Payload: pefixture.RSDSPayload([]byte("second.pdb\x00"))},
			),
			predicates: []string{
				`defined pe.pdb_path`,
				`pe.pdb_path == "first.pdb"`,
			},
		},
		{
			name: "empty_string_rsds_first",
			data: pefixture.DebugPE(true,
				pefixture.DebugEntrySpec{Type: debugTypeCodeView, Payload: pefixture.RSDSPayload([]byte{0})},
				pefixture.DebugEntrySpec{Type: debugTypeCodeView, Payload: pefixture.RSDSPayload([]byte("second.pdb\x00"))},
			),
			predicates: []string{
				`defined pe.pdb_path`,
				`pe.pdb_path == ""`,
			},
		},
		{
			name: "header_only_rsds_sz24",
			data: pefixture.DebugPE(true, pefixture.DebugEntrySpec{
				Type:    debugTypeCodeView,
				Payload: pefixture.RSDSPayload(nil),
			}),
			predicates: []string{
				`defined pe.pdb_path`,
				`pe.pdb_path == ""`,
			},
		},
		{
			name: "header_only_nb10_sz16",
			data: pefixture.DebugPE(false, pefixture.DebugEntrySpec{
				Type:    debugTypeCodeView,
				Payload: pefixture.NB10Payload(nil),
			}),
			predicates: []string{
				`defined pe.pdb_path`,
				`pe.pdb_path == ""`,
			},
		},
		{
			name: "embedded_nul_and_non_ascii",
			data: pefixture.DebugPE(true, pefixture.DebugEntrySpec{
				Type:    debugTypeCodeView,
				Payload: pefixture.RSDSPayload([]byte{'p', 0xff, 'd', 'b', 0, 'x', 'y', 0}),
			}),
			predicates: []string{
				`defined pe.pdb_path`,
				`pe.pdb_path == "p\xffdb"`,
			},
		},
		{
			name: "only_misc_entry",
			data: pefixture.DebugPE(true, pefixture.DebugEntrySpec{
				Type:    debugTypeMisc,
				Payload: []byte("misc"),
			}),
			predicates: []string{
				`pe.is_pe == 1`,
				`defined pe.pdb_path`,
			},
		},
		{
			name:       "no_debug_directory",
			data:       pefixture.New(true),
			predicates: []string{`pe.is_pe == 1`, `defined pe.pdb_path`},
		},
		{
			name:       "non_pe",
			data:       []byte("not a portable executable"),
			predicates: []string{`pe.is_pe == 0`, `defined pe.pdb_path`},
		},
		{
			name:       "empty",
			data:       nil,
			predicates: []string{`pe.is_pe == 0`, `defined pe.pdb_path`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkPEPaths(t, peProbeSource(tc.predicates), tc.data)
		})
	}
}
