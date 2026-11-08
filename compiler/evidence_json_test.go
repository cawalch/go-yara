package compiler

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestAppendEvidenceJSON_MatchesStdJSON(t *testing.T) {
	source := `rule test_evidence {
		strings:
			$a = /token=([a-z]+):([a-z]*)/ capture(name=1, secret=2, whole=0)
		evidence:
			pair = (name, secret) within 0 of secret
		condition:
			#a > 0
	}`

	p, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		input    string
		borrowed bool
	}{
		{"single", "token=admin:password123!", false},
		{"single_borrowed", "token=admin:password123!", true},
		{"multiple", "token=admin:secret!\ntoken=user:pass!\n", false},
		{"empty_secret", "token=empty:!\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := []ScannerOption{WithEvidence(64)}
			if tc.borrowed {
				opts = append(opts, WithBorrowedEvidence(true))
			}
			scanner := p.NewScanner(opts...)
			defer scanner.Close()

			res, err := scanner.Scan([]byte(tc.input))
			if err != nil {
				t.Fatal(err)
			}

			ruleEvidence := res.Evidence["test_evidence"]
			if len(ruleEvidence) == 0 {
				t.Fatal("expected evidence findings")
			}

			// Generate JSON via std library json.Marshal
			stdJSON, err := json.Marshal(ruleEvidence)
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}

			// Generate JSON via streaming AppendEvidenceJSON
			streamJSON := AppendEvidenceJSON(nil, ruleEvidence)

			// Both must be valid JSON
			if !json.Valid(streamJSON) {
				t.Fatalf("AppendEvidenceJSON produced invalid JSON: %s", string(streamJSON))
			}

			// Must decode to identical data structures
			var fromStd, fromStream map[string][]EvidenceFinding
			if err := json.Unmarshal(stdJSON, &fromStd); err != nil {
				t.Fatalf("unmarshaling stdJSON failed: %v", err)
			}
			if err := json.Unmarshal(streamJSON, &fromStream); err != nil {
				t.Fatalf("unmarshaling streamJSON failed: %v", err)
			}

			if !reflect.DeepEqual(fromStd, fromStream) {
				t.Fatalf("unmarshaled values differ:\nfromStd:    %+v\nfromStream: %+v", fromStd, fromStream)
			}

			// Also test WriteEvidenceJSON matches AppendEvidenceJSON
			var buf bytes.Buffer
			if err := WriteEvidenceJSON(&buf, ruleEvidence); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf.Bytes(), streamJSON) {
				t.Fatalf("WriteEvidenceJSON output does not match AppendEvidenceJSON:\ngot:  %s\nwant: %s", buf.String(), string(streamJSON))
			}
		})
	}
}

func TestAppendEvidenceJSON_EdgeCases(t *testing.T) {
	// Empty evidence map
	empty := AppendEvidenceJSON(nil, nil)
	if string(empty) != "{}" {
		t.Fatalf("expected {}, got %s", string(empty))
	}

	// Capture with nil Data
	cNil := Capture{
		Name:    "null_field",
		Pattern: "$a",
		Group:   1,
		Offset:  10,
		Length:  0,
		Data:    nil,
	}
	f := EvidenceFinding{
		Anchor: cNil,
		Status: EvidenceStatusPartial,
		Fields: map[string][]Capture{"null_field": {cNil}},
	}
	ev := map[string][]EvidenceFinding{"plan_nil": {f}}

	out := AppendEvidenceJSON(nil, ev)
	if !strings.Contains(string(out), `"Data":null`) {
		t.Fatalf("expected \"Data\":null in output, got %s", string(out))
	}

	// Capture with special chars that require escaping
	cEsc := Capture{
		Name:    "quoted\"name\nnewline",
		Pattern: "$b",
		Group:   0,
		Offset:  20,
		Length:  4,
		Data:    []byte("test"),
	}
	fEsc := EvidenceFinding{
		Anchor: cEsc,
		Status: EvidenceStatusReady,
		Fields: map[string][]Capture{"quoted\"name\nnewline": {cEsc}},
	}
	evEsc := map[string][]EvidenceFinding{"plan_esc": {fEsc}}

	outEsc := AppendEvidenceJSON(nil, evEsc)
	if !json.Valid(outEsc) {
		t.Fatalf("expected valid JSON for escaped characters, got %s", string(outEsc))
	}
	var roundTrip map[string][]EvidenceFinding
	if err := json.Unmarshal(outEsc, &roundTrip); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if roundTrip["plan_esc"][0].Anchor.Name != "quoted\"name\nnewline" {
		t.Fatalf("escaped name corrupted: %s", roundTrip["plan_esc"][0].Anchor.Name)
	}
}

func BenchmarkEvidenceJSONSerialization(b *testing.B) {
	source := `rule test_evidence {
		strings:
			$a = /token=([a-z]+):([a-z]*)/ capture(name=1, secret=2, whole=0)
		evidence:
			pair = (name, secret) within 0 of secret
		condition:
			#a > 0
	}`

	p, err := NewCompiler().CompileSource(source)
	if err != nil {
		b.Fatal(err)
	}

	scanner := p.NewScanner(WithEvidence(64), WithBorrowedEvidence(true))
	defer scanner.Close()

	input := []byte(strings.Repeat("token=admin:secretpassword123!\n", 128))
	res, err := scanner.Scan(input)
	if err != nil {
		b.Fatal(err)
	}
	evidence := res.Evidence["test_evidence"]

	b.Run("std_json_marshal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			data, err := json.Marshal(evidence)
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(data)))
		}
	})

	b.Run("streaming_append_json", func(b *testing.B) {
		buf := make([]byte, 0, 32*1024)
		b.ReportAllocs()
		for b.Loop() {
			buf = AppendEvidenceJSON(buf[:0], evidence)
			b.SetBytes(int64(len(buf)))
		}
	})
}
