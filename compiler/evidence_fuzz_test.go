package compiler

import (
	"reflect"
	"slices"
	"testing"
)

func FuzzEvidenceSerialization(f *testing.F) {
	program, err := NewCompiler().CompileSource(`
rule fuzz_evidence {
    strings:
        $pair = /user=([^ ]+) secret=([^ ]+)/ capture(username = 1, secret = 2)
    evidence:
        credential = (username, secret) within 64 of secret
    condition:
        $pair
}
`)
	if err != nil {
		f.Fatalf("CompileSource() error = %v", err)
	}
	blob, err := program.MarshalBinary()
	if err != nil {
		f.Fatalf("MarshalBinary() error = %v", err)
	}
	loaded, err := UnmarshalCompiledProgram(blob)
	if err != nil {
		f.Fatalf("UnmarshalCompiledProgram() error = %v", err)
	}
	f.Add([]byte("user=alice secret=hunter2"))
	f.Add([]byte("user=a secret=b user=c secret=d"))
	f.Add([]byte("no candidate"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		originalScanner := program.NewScanner(WithEvidence(64))
		defer originalScanner.Close()
		loadedScanner := loaded.NewScanner(WithEvidence(64))
		defer loadedScanner.Close()
		original, originalErr := originalScanner.Scan(data)
		restored, restoredErr := loadedScanner.Scan(data)
		if (originalErr == nil) != (restoredErr == nil) {
			t.Fatalf("round-trip scan errors differ: %v / %v", originalErr, restoredErr)
		}
		if originalErr == nil && !reflect.DeepEqual(original, restored) {
			t.Fatalf("round-trip evidence differs\n original: %#v\nrestored: %#v", original, restored)
		}
	})
}

func FuzzEvidenceCorrelationOrder(f *testing.F) {
	f.Add([]byte{10, 20, 30, 40})
	f.Add([]byte{1, 1, 1})
	f.Fuzz(func(t *testing.T, offsets []byte) {
		if len(offsets) == 0 || len(offsets) > 64 {
			return
		}
		occurrences := make([]captureOccurrence, 0, len(offsets))
		for index, raw := range offsets {
			name := "username"
			if index%3 == 0 {
				name = "secret"
			}
			occurrences = append(occurrences, captureOccurrence{
				capture: Capture{Name: name, Offset: int64(raw), Length: 1, Data: []byte{raw}},
				parent:  captureParent{pattern: string(rune(index + 1))},
			})
		}
		plan := EvidencePlan{Name: "credential", Fields: []string{"username", "secret"}, Anchor: "secret", Within: 64}
		sortCaptureOccurrences(occurrences)
		forward := correlateEvidence([]EvidencePlan{plan}, occurrences)
		slices.Reverse(occurrences)
		sortCaptureOccurrences(occurrences)
		reversed := correlateEvidence([]EvidencePlan{plan}, occurrences)
		if !reflect.DeepEqual(forward, reversed) {
			t.Fatalf("correlation depends on occurrence order")
		}
	})
}
