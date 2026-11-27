package rulecompare

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestCompare(t *testing.T) {
	dir := t.TempDir()
	write := func(name, value string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	baseline := write("base.yar", `external active
rule example { strings: $a = "approved" condition: active and $a }`)
	candidate := write("new.yar", `external active
rule example { strings: $a = "approved" $b = "ordinary" condition: active and any of them }`)
	positive := write("positive.txt", "approved")
	negative := write("negative.txt", "ordinary")
	bindings := write("externals.json", `{"active": true}`)
	var out bytes.Buffer
	args := []string{"-baseline", baseline, "-candidate", candidate, "-externals", bindings, "positive=" + positive, "negative=" + negative}
	if err := RunCLI(t.Context(), args, &out); err != nil {
		t.Fatal(err)
	}
	first := bytes.Clone(out.Bytes())
	out.Reset()
	if err := RunCLI(t.Context(), args, &out); err != nil || !bytes.Equal(first, out.Bytes()) {
		t.Fatalf("repeat report differs: %v", err)
	}
	var report comparison
	if err := json.Unmarshal(first, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Fixtures) != 2 || report.Fixtures[0].Fixture != "negative" ||
		!slices.Equal(report.Fixtures[0].Added, []string{"example"}) ||
		len(report.Fixtures[1].Added) != 0 || report.BaselineSHA256 == report.CandidateSHA256 || !slices.Equal(report.ExternalNames, []string{"active"}) {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestComparePCAP(t *testing.T) {
	const dir = "../../examples/pcap/update-review/"
	var out bytes.Buffer
	if err := RunCLI(t.Context(), []string{"-baseline", dir + "baseline.yar", "-candidate", dir + "candidate.yar",
		"positive=" + dir + "positive.pcap", "control=" + dir + "control.pcap"}, &out); err != nil {
		t.Fatal(err)
	}
	var report comparison
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Fixtures) != 2 || report.Fixtures[0].Fixture != "control" ||
		!slices.Equal(report.Fixtures[0].Removed, []string{"revoked_update"}) ||
		len(report.Fixtures[1].Removed) != 0 {
		t.Fatalf("unexpected report: %+v", report)
	}
}
