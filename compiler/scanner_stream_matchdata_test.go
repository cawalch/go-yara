package compiler

import (
	"bytes"
	"testing"
)

func TestScanReaderMatchedDataRequiresOption(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule r { strings: $a = "needle" condition: $a }`)
	data := []byte("xx needle yy")

	scanner := program.NewScanner()
	defer scanner.Close()
	result, err := scanner.ScanReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	matches := result.Matches["r"]["$a"]
	if len(matches) != 1 {
		t.Fatalf("matches = %+v, want one", matches)
	}
	if matches[0].MatchedData != nil || matches[0].MatchedDataTruncated {
		t.Fatalf("default reader scan materialized MatchedData = %q (truncated=%v)", matches[0].MatchedData, matches[0].MatchedDataTruncated)
	}

	scanner2 := program.NewScanner(WithMatchData(2))
	defer scanner2.Close()
	result, err = scanner2.ScanReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	matches = result.Matches["r"]["$a"]
	if len(matches) != 1 || string(matches[0].MatchedData) != "ne" || !matches[0].MatchedDataTruncated {
		t.Fatalf("WithMatchData(2) matches = %+v", matches)
	}
}
