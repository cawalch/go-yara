package integration

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"testing"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/utils/fs"
)

// Compare both rule identities and every occurrence: an empty span list alone
// cannot distinguish a matching stringless rule from a non-matching rule.
func assertReleaseScanResult(t *testing.T, want map[string][]span, result *compiler.ScanResult) {
	t.Helper()
	got := make(map[string][]span)
	for _, rule := range result.MatchedRules {
		got[rule.Rule] = nil
		for id, matches := range rule.Matches {
			for _, match := range matches {
				got[rule.Rule] = append(got[rule.Rule], span{ID: id, Off: match.Offset, Len: match.Length})
			}
		}
	}
	if !slices.Equal(slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(want))) ||
		!reflect.DeepEqual(flatten(got), flatten(want)) {
		t.Fatalf("libyara = %v; go-yara = %v", want, got)
	}
}

func checkReleaseScanPaths(t *testing.T, source string, data []byte) {
	t.Helper()
	want, err := scanWithLibyara(t, libyaraOracle(t), source, data)
	if err != nil {
		t.Fatal(err)
	}
	program, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	scanner := program.NewScanner()
	defer scanner.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for name, scan := range map[string]func() (*compiler.ScanResult, error){
		"buffer":       func() (*compiler.ScanResult, error) { return scanner.Scan(data) },
		"file":         func() (*compiler.ScanResult, error) { return scanner.ScanFile(path) },
		"file_context": func() (*compiler.ScanResult, error) { return scanner.ScanFileWithContext(ctx, path) },
		"program_file": func() (*compiler.ScanResult, error) { return program.ScanFile(path) },
	} {
		t.Run(name, func(t *testing.T) {
			result, err := scan()
			if err != nil {
				t.Fatal(err)
			}
			assertReleaseScanResult(t, want, result)
		})
	}
}

func TestLibyaraReleaseRegexWindows(t *testing.T) {
	libyaraOracle(t)
	cases := []struct{ pattern, text string }{
		{`^token_[a-z]{1,4}_valid`, "token_test_valid"},
		{`token_[a-z]{1,4}_valid$`, "token_test_valid"},
		{`^token_[a-z]{1,4}_valid$`, "token_test_valid"},
		{`\btoken_[a-z]{1,4}_valid\b`, "token_test_valid"},
		{`\Btoken_[a-z]{1,4}_valid\B`, "xtoken_test_validx"},
		{`\btoken_[a-z]{1,4}_valid\b`, "xtoken_test_validx"},
		{`(foo|barbaz)[0-9]{1,4}qux\b`, "barbaz1234qux"},
		{`token_[a-z]+_valid\b`, "token_test_valid"},
		{`[a-z]{0,4}token_[0-9]{1,4}\b`, "abcdtoken_1234"},
		{`token_[0-9]{1,4}(tail)?$`, "token_1234tail"},
		{`[Tt][Oo][Kk][Ee][Nn]_[0-9]{1,4}\b`, "ToKeN_1234"},
		{`token_[a-z]{1,4}_valid\b`, "token_test_valid token_x_valid"},
	}
	for i, tc := range cases {
		for _, modifier := range []string{"ascii", "wide", "ascii wide", "nocase"} {
			for _, location := range []string{"start", "middle", "end", "exact"} {
				t.Run(fmt.Sprintf("case_%02d/%s/%s", i, modifier, location), func(t *testing.T) {
					text := []byte(tc.text)
					if modifier == "wide" || modifier == "ascii wide" {
						text = releaseWideBytes(text)
					}
					var data []byte
					if location == "middle" || location == "end" {
						data = bytes.Repeat([]byte("!"), 65) // Odd offset exercises wide alignment.
					}
					data = append(data, text...)
					if location == "start" || location == "middle" {
						data = append(data, bytes.Repeat([]byte("!"), 80)...)
					}
					source := fmt.Sprintf(`rule probe { strings: $a = /%s/ %s condition: $a }`, tc.pattern, modifier)
					checkReleaseScanPaths(t, source, data)
				})
			}
		}
	}
}

func releaseWideBytes(data []byte) []byte {
	wide := make([]byte, len(data)*2)
	for i, b := range data {
		wide[2*i] = b
	}
	return wide
}

func TestLibyaraReleaseMmapThreshold(t *testing.T) {
	libyaraOracle(t)
	const source = `
rule empty { condition: filesize == 0 }
rule nonempty { condition: filesize > 0 }
rule probe {
    strings:
        $a = /\btoken_[a-z]{1,4}_valid\b/ ascii wide
        $start = /^token_[a-z]{1,4}_valid/
        $end = /token_[a-z]{1,4}_valid$/
    condition: any of them
}
rule occurrences {
    strings: $a = /\btoken_[a-z]{1,4}_valid\b/ ascii wide
    condition: #a == 4 and @a[1] == 0 and !a[1] == 16 and !a[3] == 32
}`
	for _, size := range []int{0, fs.MinMmapFileSize - 1, fs.MinMmapFileSize, fs.MinMmapFileSize + 1, 2 * fs.MinMmapFileSize} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			data := bytes.Repeat([]byte("!"), size)
			if size > 0 {
				text := []byte("token_test_valid")
				copy(data, text)
				copy(data[4091:], text) // Cross an OS page boundary.
				copy(data[size/2+1:], releaseWideBytes(text))
				copy(data[size-len(text):], text)
			}
			checkReleaseScanPaths(t, source, data)
		})
	}
}
