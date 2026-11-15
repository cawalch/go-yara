package integration

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/internal/pefixture"
)

// TestLibyaraPECapabilityMatrix verifies behavioral parity with libyara for
// representative PE rule patterns observed across the compiling subset of the
// YARA Forge 20261108 corpus (including cross-rule private dependencies and
// loop-variable aliasing) over generated PE32, PE32+, overlay, and non-PE inputs.
func TestLibyaraPECapabilityMatrix(t *testing.T) {
	libyaraOracle(t)

	// Patterns reflect real rule idioms from the compiling subset without
	// bundling third-party corpus text in the repository.
	const source = `
import "pe"

private rule pe_gate_private {
	strings:
		$mz = "MZ"
	condition:
		$mz at 0 and pe.is_pe == 1
}

rule cap_imphash_and_imports {
	condition:
		pe_gate_private and
		pe.imphash() != "" and
		pe.number_of_imports == 1 and
		pe.imports("Example.DLL") > 0 and
		pe.imports("example.dll", "NamedFunction") and
		pe.imports(/example\.dll/i, /^Named/)
}

rule cap_import_ordinal {
	condition:
		pe.is_pe == 1 and
		pe.imports("Example.DLL", 99) == 1
}

rule cap_exports_and_details {
	condition:
		pe_gate_private and
		pe.number_of_exports == 4 and
		pe.exports("Function00000") and
		pe.exports(/^Function0000[0-3]$/) and
		for any exp in pe.export_details : (exp.name == "Function00002" and exp.offset > 0)
}

rule cap_sections_and_directories {
	condition:
		pe.is_pe == 1 and
		pe.number_of_sections == 2 and
		pe.section_index(".text") == 0 and
		pe.sections[0].raw_data_offset == 0x200 and
		pe.sections[0].raw_data_size == 0x200 and
		pe.sections[0].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
		for any sec in pe.sections : (sec.name == ".data" and sec.characteristics & pe.SECTION_MEM_WRITE != 0) and
		pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].size == 0
}

rule cap_overlay_and_machine {
	condition:
		pe.is_pe == 1 and
		pe.overlay.size > 0 and
		pe.overlay.offset > 0 and
		pe.is_32bit() and
		not pe.is_64bit() and
		not pe.is_dll() and
		(pe.characteristics & pe.DLL) == 0 and
		pe.machine == pe.MACHINE_I386 and
		pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI and
		pe.timestamp == 0xf1234567
}

rule cap_64bit_variant {
	condition:
		pe.is_pe == 1 and
		pe.is_64bit() and
		not pe.is_32bit() and
		pe.machine == pe.MACHINE_AMD64
}

rule cap_signatures_metadata {
	condition:
		pe_gate_private and
		pe.number_of_signatures > 0 and
		for any sig in pe.signatures : (
			sig.serial != "" and
			sig.subject != "" and
			sig.issuer != "" and
			sig.thumbprint != "" and
			sig.not_before < sig.not_after
		)
}

rule cap_signatures_verified {
	condition:
		pe_gate_private and
		pe.is_signed == 1 and
		for any sig in pe.signatures : (
			sig.verified == 1 and
			for any cs in sig.countersignatures : (
				cs.verified == 1
			)
		)
}

rule cap_resources_and_locales {
	condition:
		pe_gate_private and
		pe.resource_timestamp == 0x12345678 and
		pe.resource_version.major == 2 and
		pe.resource_version.minor == 5 and
		pe.number_of_resources == 2 and
		pe.locale(1033) == 1 and
		pe.language(9) == 1 and
		for any res in pe.resources : (
			res.type == pe.RESOURCE_TYPE_RCDATA and
			res.length > 0 and
			res.offset > 0
		)
}

rule cap_version_info {
	condition:
		pe_gate_private and
		pe.number_of_version_infos == 2 and
		pe.version_info["CompanyName"] == "Example Corp" and
		pe.version_info["FileVersion"] == "1.0.0.0" and
		pe.version_info_list[0].key == "CompanyName" and
		pe.version_info_list[1].value == "1.0.0.0" and
		for any k, v in pe.version_info : (k == "CompanyName" and v == "Example Corp")
}

rule cap_rich_signature {
	condition:
		pe_gate_private and
		pe.rich_signature.offset == 128 and
		pe.rich_signature.length == 40 and
		pe.rich_signature.key == 0x11223344 and
		pe.rich_signature.version(29500) == 20 and
		pe.rich_signature.version(29500, 259) == 17 and
		pe.rich_signature.toolid(259) == 17 and
		pe.rich_signature.toolid(257, 29500) == 3
}
`

	ordinal64 := pefixture.Imports(true, 3)
	pefixture.ImportOrdinal(ordinal64, 1, 99)

	exportsOverlay32 := append(pefixture.Exports(false, 4), []byte("OVERLAY_PAYLOAD")...)
	sigBlob, _ := pefixture.AuthenticodeBlob(pefixture.AuthenticodeOptions{IncludeChain: true})
	signed32 := pefixture.WithCertificates(pefixture.New(false), pefixture.CertificateRecord{Type: 2, Payload: sigBlob})
	verified32, _ := pefixture.SignedAuthenticodePE(false, nil, pefixture.SignedAuthenticodeOptions{
		UseRSA:    true,
		PKCS9At:   time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		RFC3161At: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
	})

	versionSpec := pefixture.VersionInfoSpec{
		StringTables: []pefixture.VersionStringTableSpec{{
			Key: "040904b0",
			Entries: []pefixture.VersionStringEntry{
				{Key: "CompanyName", Value: "Example Corp"},
				{Key: "FileVersion", Value: "1.0.0.0"},
			},
		}},
	}
	richOpts := pefixture.RichOptions{
		Key: 0x11223344,
		Entries: []pefixture.RichEntry{
			{ToolID: 259, Version: 29500, Count: 12},
			{ToolID: 257, Version: 29500, Count: 3},
			{ToolID: 259, Version: 29500, Count: 5},
		},
	}

	fixtures := []struct {
		name string
		data []byte
	}{
		{name: "pe32_headers_only", data: pefixture.New(false)},
		{name: "pe64_imports_ordinal", data: ordinal64},
		{name: "pe32_exports_overlay", data: exportsOverlay32},
		{name: "pe64_exports", data: pefixture.Exports(true, 4)},
		{name: "pe32_signed", data: signed32},
		{name: "pe32_verified", data: verified32},
		{name: "pe32_resources", data: pefixture.Resources(false, 2)},
		{name: "pe64_resources", data: pefixture.Resources(true, 2)},
		{name: "pe32_version_info", data: pefixture.VersionInfoPE(false, versionSpec)},
		{name: "pe64_version_info", data: pefixture.VersionInfoPE(true, versionSpec)},
		{name: "pe32_rich", data: pefixture.RichPE(false, richOpts)},
		{name: "pe64_rich", data: pefixture.RichPE(true, richOpts)},
		{name: "non_pe", data: []byte("not a portable executable payload")},
		{name: "empty", data: nil},
	}

	for _, tc := range fixtures {
		t.Run(tc.name, func(t *testing.T) {
			checkPEPaths(t, source, tc.data)
		})
	}
}

// TestPECapabilityMatrixUnsupportedAndStrict verifies that planned-but-unimplemented
// PE feature slices are rejected explicitly at compile time and that strict
// malformed-PE rejections remain deterministic against libyara.
func TestPECapabilityMatrixUnsupportedAndStrict(t *testing.T) {
	oracle := libyaraOracle(t)

	unsupportedSlices := []struct {
		slice   string
		rule    string
		errText string
	}{
		{
			slice:   "#477_pdb_path",
			rule:    `import "pe" rule r { condition: pe.pdb_path == "example.pdb" }`,
			errText: "pdb_path",
		},
	}

	for _, tc := range unsupportedSlices {
		t.Run("unsupported/"+tc.slice, func(t *testing.T) {
			if _, err := scanWithLibyara(t, oracle, tc.rule, pefixture.New(false)); err != nil {
				t.Fatalf("expected libyara to compile %s: %v", tc.slice, err)
			}
			c := compiler.NewCompiler()
			if _, err := c.CompileSourceWithContext(context.Background(), tc.rule); err == nil {
				t.Fatalf("expected compile rejection for unsupported slice %s", tc.slice)
			}
			stats := c.GetStats()
			if len(stats.Errors) == 0 || stats.Errors[0].Phase != "semantic" || !strings.Contains(stats.Errors[0].Message, tc.errText) {
				t.Fatalf("unexpected compiler diagnostics for %s: %+v", tc.slice, stats.Errors)
			}
		})
	}

	t.Run("strict_malformed_directory_count", func(t *testing.T) {
		// Deliberate strict-parser difference: go-pe rejects number_of_rva_and_sizes > 16
		// (exposing is_pe == 0 and leaving fields undefined), whereas libyara
		// clamps the directory count and still reports is_pe == 1.
		malformed := pefixture.Imports(false, 2)
		binary.LittleEndian.PutUint32(malformed[0xf4:], 17)
		const src = `import "pe"
rule strict_rejected { condition: pe.is_pe == 0 and not defined pe.number_of_imports and not defined pe.machine }
rule libyara_permissive { condition: pe.is_pe == 1 and pe.number_of_imports == 1 }`

		want, err := scanWithLibyara(t, oracle, src, malformed)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := want["libyara_permissive"]; !ok || len(want) != 1 {
			t.Fatalf("expected libyara permissive match on >16 data directories, got %v", want)
		}

		p, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), src)
		if err != nil {
			t.Fatal(err)
		}
		res, err := p.Scan(malformed)
		if err != nil {
			t.Fatal(err)
		}
		assertReleaseScanResult(t, map[string][]span{"strict_rejected": nil}, res)
	})
}
