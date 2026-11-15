package integration

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestLibyaraPEVersionInfo(t *testing.T) {
	libyaraOracle(t)

	longKey := strings.Repeat("K", 70)
	longVal := strings.Repeat("V", 270)
	key63 := strings.Repeat("K", 63)
	val255 := strings.Repeat("V", 255)

	specs := []pefixture.VersionInfoSpec{
		{
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
		{
			StringTables: []pefixture.VersionStringTableSpec{{
				Key: "040904b0",
				Entries: []pefixture.VersionStringEntry{
					{Key: "CompanyName", Value: "Second Corp"},
					{Key: longKey, Value: longVal},
				},
			}},
		},
	}

	predicates := []string{
		`defined pe.number_of_version_infos`,
		`pe.number_of_version_infos == 0`,
		`pe.number_of_version_infos == 10`,
		`defined pe.version_info["CompanyName"]`,
		`pe.version_info["CompanyName"] == "Second Corp"`,
		`pe.version_info["EmptyOmitted"] == ""`,
		`pe.version_info["EmptyTerminated"] == ""`,
		`defined pe.version_info[""]`,
		`pe.version_info[""] == "BlankKey"`,
		`pe.version_info["ProductName"] == "Caf\xe9\xac"`,
		`pe.version_info["LegalCopyright"] == "\xa9 2026"`,
		`pe.version_info["Emoji"] == "=\x80!"`,
		`defined pe.version_info["StopLowZero"]`,
		`pe.version_info["StopLowZero"] == ""`,
		`defined pe.version_info["Translation"]`,
		fmt.Sprintf(`pe.version_info[%q] == %q`, key63, val255),
		fmt.Sprintf(`defined pe.version_info[%q]`, longKey),
		`defined pe.version_info_list[0].key`,
		`pe.version_info_list[0].key == "CompanyName"`,
		`pe.version_info_list[0].value == "First Corp"`,
		`pe.version_info_list[1].key == "EmptyOmitted"`,
		`pe.version_info_list[1].value == ""`,
		`pe.version_info_list[2].key == "EmptyTerminated"`,
		`pe.version_info_list[2].value == ""`,
		`pe.version_info_list[3].key == ""`,
		`pe.version_info_list[3].value == "BlankKey"`,
		`pe.version_info_list[8].key == "CompanyName"`,
		`pe.version_info_list[8].value == "Second Corp"`,
		`defined pe.version_info_list[10].key`,
		`for any e in pe.version_info_list : (e.key == "CompanyName" and e.value == "First Corp")`,
		`for any k, v in pe.version_info : (k == "CompanyName" and v == "Second Corp")`,
		`for any k, v in pe.version_info : (k == "CompanyName" and v == "First Corp")`,
	}

	source := peProbeSource(predicates)
	fixtures := map[string][]byte{
		"non_pe":        []byte("not a portable executable"),
		"empty":         nil,
		"no_dir_pe32":   pefixture.New(false),
		"no_dir_pe64":   pefixture.New(true),
		"no_version_pe": pefixture.Resources(true, 2),
		"multi_pe32":    pefixture.VersionInfoPE(false, specs...),
		"multi_pe64":    pefixture.VersionInfoPE(true, specs...),
	}
	for name, data := range fixtures {
		t.Run(name, func(t *testing.T) {
			checkPEPaths(t, source, data)
		})
	}
}
