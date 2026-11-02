package semantic

import (
	"fmt"
	"strings"
	"testing"
)

func BenchmarkIdentifierSuggestions(b *testing.B) {
	for _, count := range []int{16, 1024, 4096} {
		var names []string
		for i := range count {
			names = append(names, fmt.Sprintf("Threat_Family_Detection_Signature_%04d", i))
		}
		names = append(names, "filesize", "entrypoint", "them")
		for _, target := range []string{"filename", "filesze", "Threat_Family_Detectoin_Signature_0000"} {
			b.Run(fmt.Sprintf("names=%d/%s", count, target), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					findSimilarIdentifier(target, names)
				}
			})
		}
	}
	for _, tc := range []struct {
		name, target string
		candidates   []string
	}{
		{"prefix", "payload", []string{"$payload", "$content"}},
		{"case", "PAYLOAD", []string{"$payload", "$content"}},
		{"unicode", "καλημερα", []string{"καλημέρα", "καλησπερα", "$καλημέρα"}},
		{"long", strings.Repeat("a", 256), []string{strings.Repeat("a", 255) + "b", strings.Repeat("b", 256)}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				findSimilarIdentifier(tc.target, tc.candidates)
			}
		})
	}
}
