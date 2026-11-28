package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

const elasticCorpusRuleCount = 3070 // protections-artifacts@418cfd9aaa89

func TestElasticCorpusCompatibility(t *testing.T) {
	rulesDir := os.Getenv("GO_YARA_ELASTIC_RULES")
	if rulesDir == "" {
		t.Skip("set GO_YARA_ELASTIC_RULES to the pinned Elastic yara/rules directory")
	}
	yara, err := locateOracle()
	if err != nil {
		t.Fatal(err)
	}
	yarac := filepath.Join(filepath.Dir(yara), "yarac")
	version, err := exec.CommandContext(t.Context(), yarac, "--version").CombinedOutput()
	if err != nil || strings.TrimSpace(string(version)) != strings.TrimSpace(oracleVersion) {
		t.Fatalf("need yarac %s beside yara, got %q (%v)", strings.TrimSpace(oracleVersion), version, err)
	}

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "elastic.yar")
	writeElasticCorpusSource(t, rulesDir, sourcePath)
	compiledPath := filepath.Join(dir, "elastic.yarc")
	if out, err := exec.CommandContext(t.Context(), yarac, "--no-warnings", sourcePath, compiledPath).CombinedOutput(); err != nil {
		t.Fatalf("libyara could not compile the Elastic corpus: %v\n%s", err, out)
	}

	program, err := compiler.NewCompiler().CompileFileWithContext(t.Context(), sourcePath)
	if err != nil {
		t.Fatalf("go-yara could not compile the Elastic corpus: %v", err)
	}
	if count := program.GetRuleCount(); count != elasticCorpusRuleCount {
		t.Fatalf("compiled %d Elastic rules, want %d", count, elasticCorpusRuleCount)
	}
	t.Logf("compiled the pinned %d-rule Elastic corpus with go-yara and libyara %s", elasticCorpusRuleCount, strings.TrimSpace(string(version)))

	// Inert format bytes and product banners exercise hex and text occurrences.
	upx := append([]byte("format fixture\nUPX!\x12\x34\x56\x78"), make([]byte, 12)...)
	xmrig := []byte("Corpus text fixture:\nUsage: xmrig [OPTIONS]\nXMRIG_VERSION\nmining.set_target\nXMRIG_HOSTNAME\nXMRIG_VERSION\n")
	for _, tc := range []struct {
		name  string
		data  []byte
		rule  string
		spans []span
	}{
		{"upx_header", upx, "Linux_Packer_Patched_UPX_62e11c64", []span{{ID: "$a", Off: 15, Len: 20}}},
		{"xmrig_banner", xmrig, "MacOS_Cryptominer_Xmrig_241780a1", []span{
			{ID: "$a1", Off: 58, Len: 17}, {ID: "$a2", Off: 76, Len: 14}, {ID: "$a3", Off: 21, Len: 22},
			{ID: "$a4", Off: 44, Len: 13}, {ID: "$a4", Off: 91, Len: 13},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fixture.bin")
			if err := os.WriteFile(path, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.CommandContext(t.Context(), yara, "--compiled-rules", "--no-warnings", "-s", "-L", compiledPath, path).CombinedOutput()
			if err != nil {
				t.Fatalf("libyara scan failed: %v\n%s", err, out)
			}
			want, err := parseLibyaraScanOutput(out)
			if err != nil {
				t.Fatal(err)
			}
			golden := map[string][]span{tc.rule: tc.spans}
			if len(want) != len(golden) || !reflect.DeepEqual(flatten(want), flatten(golden)) {
				t.Fatalf("libyara = %v, want known-positive spans %v", want, golden)
			}
			result, err := program.ScanWithContext(t.Context(), tc.data)
			if err != nil {
				t.Fatal(err)
			}
			assertReleaseScanResult(t, want, result)
		})
	}
}

// Assemble the flat upstream directory in lexical order. Both compilers see
// the same source, with every rule and import kept intact.
func writeElasticCorpusSource(t *testing.T, rulesDir, sourcePath string) {
	t.Helper()
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	var source strings.Builder
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yar" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(rulesDir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		source.Write(data)
		source.WriteByte('\n')
	}
	if err := os.WriteFile(sourcePath, []byte(source.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}
