package integration

import (
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestLibyaraPEImphash(t *testing.T) {
	const (
		named3   = "52ee6f8c06f82c1a4906c4287b38a731"
		ord7     = "0f948aa3b9e326a6839786fa30cdafd2"
		ws2      = "9eabaab1d2b00efbb780e43d7604d6c6"
		ws2ord   = "fce110908ca6849f7afa977d1ae99f5f"
		oleaut   = "3dc76082b322e4bf41120e4657c7f5c6"
		emptyMD5 = "d41d8cd98f00b204e9800998ecf8427e"
	)
	for _, is64 := range []bool{false, true} {
		for _, tc := range []struct {
			name   string
			data   []byte
			fields []string
		}{
			{"named", pefixture.Imports(is64, 3), []string{`defined pe.imphash()`, `pe.imphash() == "` + named3 + `"`}},
			{"ordinal", func() []byte {
				data := pefixture.Imports(is64, 3)
				pefixture.ImportOrdinal(data, 1, 7)
				return data
			}(), []string{`pe.imphash() == "` + ord7 + `"`}},
			{"ws2", func() []byte {
				data := pefixture.Imports(is64, 1)
				pefixture.ImportOrdinal(data, 0, 1)
				copy(data[0x428:], "WS2_32.DLL\x00")
				return data
			}(), []string{`pe.imphash() == "` + ws2 + `"`}},
			{"ws2-fallback", func() []byte {
				data := pefixture.Imports(is64, 1)
				pefixture.ImportOrdinal(data, 0, 501)
				copy(data[0x428:], "ws2_32.dll\x00")
				return data
			}(), []string{`pe.imphash() == "` + ws2ord + `"`}},
			{"oleaut", func() []byte {
				data := pefixture.Imports(is64, 1)
				pefixture.ImportOrdinal(data, 0, 2)
				copy(data[0x428:], "OLEAUT32.DLL\x00")
				return data
			}(), []string{`pe.imphash() == "` + oleaut + `"`}},
			{"empty", pefixture.New(is64), []string{`pe.imphash() == "` + emptyMD5 + `"`}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				checkPEPaths(t, peProbeSource(tc.fields), tc.data)
			})
		}
	}
	for name, data := range map[string][]byte{"non_pe": []byte("ordinary"), "empty": nil, "mz_only": []byte("MZ")} {
		t.Run(name, func(t *testing.T) {
			checkPEPaths(t, peProbeSource([]string{`not defined pe.imphash()`}), data)
		})
	}
}
