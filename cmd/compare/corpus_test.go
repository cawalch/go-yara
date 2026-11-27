package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

const corpusFixtures = "../../examples/pcap/update-review/"

func TestCompareCorpus(t *testing.T) {
	args := []string{
		"-baseline", corpusFixtures + "baseline.yar", "-candidate", corpusFixtures + "candidate.yar",
		"-expect", corpusFixtures + "corpus.json", "unavailable=" + corpusFixtures + "unavailable.pcap",
		"split=" + corpusFixtures + "positive-split.pcap", "control=" + corpusFixtures + "control.pcap",
		"positive=" + corpusFixtures + "positive.pcap",
	}
	var output, repeat bytes.Buffer
	if err := compare(t.Context(), args, &output); err != nil {
		t.Fatalf("%v\n%s", err, output.Bytes())
	}
	slices.Reverse(args[6:])
	if err := compare(t.Context(), args, &repeat); err != nil || !bytes.Equal(output.Bytes(), repeat.Bytes()) {
		t.Fatalf("manifest report changed with fixture argument order: %v", err)
	}
	var report comparison
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != 1 || report.Limits == nil || len(report.Fixtures) != 4 {
		t.Fatalf("unexpected corpus report: %+v", report)
	}
	control, positive, split, unavailable := report.Fixtures[0], report.Fixtures[1], report.Fixtures[2], report.Fixtures[3]
	if !slices.Equal(control.Removed, []string{"revoked_update"}) ||
		control.Evidence.Baseline.Outcome != outcomeMatch || len(control.Evidence.Baseline.Evidence) != 0 ||
		control.Evidence.Candidate.Outcome != outcomeNegative {
		t.Fatalf("unexpected cross-transaction control: %+v", control.Evidence)
	}
	if positive.SHA256 == split.SHA256 ||
		positive.Evidence.Candidate.Evidence[0].ResponsePacket == split.Evidence.Candidate.Evidence[0].ResponsePacket ||
		!sameSemanticObservation(positive.Evidence.Candidate, split.Evidence.Candidate) {
		t.Fatalf("bad comparison across split: %+v %+v", positive.Evidence, split.Evidence)
	}
	if unavailable.Evidence.Baseline.Outcome != outcomeUnobservable || unavailable.Evidence.Candidate.Outcome != outcomeUnobservable {
		t.Fatalf("unexpected clipped response: %+v", unavailable.Evidence)
	}
	if bytes.Contains(output.Bytes(), []byte("REVOKED-BUILD")) || bytes.Contains(output.Bytes(), []byte("/updates/client")) {
		t.Fatal("corpus report included captured content")
	}
}

func TestCompareCorpusWrongTransaction(t *testing.T) {
	dir := t.TempDir()
	candidate := writeTestFile(t, dir, "wrong.yar", []byte(`import "pcap"
external case_enabled
rule revoked_update {
    condition: case_enabled contains "fixture" and
        for any tx in pcap.http : (tx.target == "/diagnostics" and tx.response_body contains "diagnostics-only")
}
`))
	baselineSource, err := os.ReadFile(corpusFixtures + "candidate.yar")
	if err != nil {
		t.Fatal(err)
	}
	baseline := writeTestFile(t, dir, "before.yar", append([]byte("external case_enabled\n"), baselineSource...))
	bindings := writeTestFile(t, dir, "external.json", []byte(`{"case_enabled":"secret-fixture-value"}`))
	fixture := corpusFixtures + "entities.pcap"
	want := expectation{Outcome: outcomeMatch, Evidence: []ruleAnchor{{RequestPacket: 2, ResponsePacket: 3}}}
	manifest := testManifest(t, dir, fixture, httpMode, "revoked_update", want)
	args := []string{"-baseline", baseline, "-candidate", candidate, "-expect", manifest,
		"-externals", bindings, "-binding-revision", "binding-17", "fixture=" + fixture}
	var output bytes.Buffer
	err = compare(t.Context(), args, &output)
	if !errors.Is(err, errExpectationMismatch) || exitCode(err) != 2 {
		t.Fatalf("wrong transaction: %v\n%s", err, output.Bytes())
	}
	var report comparison
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	row := report.Fixtures[0]
	if len(row.Added)+len(row.Removed) != 0 || !row.Evidence.EvidenceChanged ||
		!slices.Equal(row.Evidence.Mismatches, []string{"candidate_evidence"}) ||
		row.Evidence.Baseline.Evidence[0].ResponsePacket != 3 || row.Evidence.Candidate.Evidence[0].ResponsePacket != 7 {
		t.Fatalf("wrong transaction evidence missing: %+v", row.Evidence)
	}
	if report.BindingRevision != "binding-17" || !slices.Equal(report.ExternalNames, []string{"case_enabled"}) ||
		bytes.Contains(output.Bytes(), []byte("secret-fixture-value")) {
		t.Fatalf("unexpected binding provenance: %s", output.Bytes())
	}
	// A different fixture at the same path label cannot reuse the old packet locators.
	args[len(args)-1] = "fixture=" + corpusFixtures + "control.pcap"
	output.Reset()
	if err := compare(t.Context(), args, &output); exitCode(err) != 2 || !bytes.Contains(output.Bytes(), []byte("fixture_digest")) {
		t.Fatalf("fixture digest mismatch: %v\n%s", err, output.Bytes())
	}
	args[len(args)-1] = "fixture=" + filepath.Join(dir, "missing.pcap")
	output.Reset()
	if err := compare(t.Context(), args, &output); exitCode(err) != 1 || !bytes.Contains(output.Bytes(), []byte("fixture read failed")) {
		t.Fatalf("fixture execution failure: %v\n%s", err, output.Bytes())
	}
}

func TestCompareCorpusArtifact(t *testing.T) {
	dir := t.TempDir()
	rule := corpusFixtures + "entity.yar"
	spec := corpusManifest{SchemaVersion: corpusSchemaVersion}
	var paths []string
	for _, fixture := range []struct {
		id, name, equivalent string
		request, response    int
	}{
		{"positive", "positive.pcap", "", 4, 5},
		{"split", "positive-split.pcap", "positive", 4, 6},
		{"entities", "entities.pcap", "", 2, 3},
	} {
		path := corpusFixtures + fixture.name
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want := expectation{Outcome: outcomeMatch, Evidence: []ruleAnchor{{
			RequestPacket: fixture.request, ResponsePacket: fixture.response,
			EntityMatches: []matchSpan{{Pattern: "$id", Offset: 12, Length: 17}},
		}}}
		spec.Fixtures = append(spec.Fixtures, fixtureExpectation{
			ID: fixture.id, SHA256: digest(data), Mode: artifactMode, Rule: "revoked_update_entity",
			Baseline: want, Candidate: want, EquivalentTo: fixture.equivalent,
		})
		paths = append(paths, fixture.id+"="+path)
	}
	manifest := writeTestManifest(t, dir, spec)
	var output bytes.Buffer
	err := compare(t.Context(), append([]string{"-baseline", rule, "-candidate", rule, "-expect", manifest}, paths...), &output)
	if err != nil {
		t.Fatalf("artifact scan: %v\n%s", err, output.Bytes())
	}
	if bytes.Contains(output.Bytes(), []byte("REVOKED-BUILD")) {
		t.Fatalf("artifact report included entity bytes: %s", output.Bytes())
	}
}

//nolint:revive // argument-limit: independent fixture inputs are explicit in tests.
func testManifest(t *testing.T, dir, fixture, mode, rule string, want expectation) string {
	t.Helper()
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	manifest := corpusManifest{SchemaVersion: corpusSchemaVersion, Fixtures: []fixtureExpectation{{
		ID: "fixture", SHA256: digest(data), Rule: rule, Mode: mode, Baseline: want, Candidate: want,
	}}}
	return writeTestManifest(t, dir, manifest)
}

func writeTestManifest(t *testing.T, dir string, manifest corpusManifest) string {
	t.Helper()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return writeTestFile(t, dir, "corpus.json", encoded)
}

//nolint:revive // argument-limit: the helper records file-write failures at the test.
func writeTestFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
