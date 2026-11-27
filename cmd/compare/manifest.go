package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	corpusSchemaVersion = 1
	maxManifest         = 1 << 20
	maxCorpusFixtures   = 32
	maxCorpusRows       = 32
	maxCorpusSpans      = 64
	maxCorpusScanBytes  = 128 << 20

	httpMode     = "http"
	artifactMode = "artifact"

	outcomeMatch        = "match"
	outcomeNegative     = "complete_negative"
	outcomeUnobservable = "unobservable"
)

var errExpectationMismatch = errors.New("one or more corpus expectations did not match")

type corpusManifest struct {
	SchemaVersion int                  `json:"schema_version"`
	Fixtures      []fixtureExpectation `json:"fixtures"`
}

type fixtureExpectation struct {
	ID           string      `json:"id"`
	SHA256       string      `json:"sha256"`
	Rule         string      `json:"rule"`
	Mode         string      `json:"mode"`
	Baseline     expectation `json:"baseline"`
	Candidate    expectation `json:"candidate"`
	EquivalentTo string      `json:"equivalent_to,omitempty"`
}

type expectation struct {
	Outcome  string       `json:"outcome"`
	Evidence []ruleAnchor `json:"evidence,omitempty"`
}

type ruleAnchor struct {
	RequestPacket  int         `json:"request_packet"`
	RequestOffset  int         `json:"request_offset"`
	ResponsePacket int         `json:"response_packet"`
	ResponseOffset int         `json:"response_offset"`
	EntityMatches  []matchSpan `json:"entity_matches,omitempty"`
}

type matchSpan struct {
	Pattern string `json:"pattern"`
	Offset  int64  `json:"offset"`
	Length  int    `json:"length"`
}

func readManifest(path string, paths map[string]string) (map[string]fixtureExpectation, error) {
	data, err := readAtMost(path, maxManifest)
	if err != nil {
		return nil, errors.New("corpus manifest read failed or exceeded 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest corpusManifest
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid corpus manifest JSON")
	}
	if manifest.SchemaVersion != corpusSchemaVersion {
		return nil, errors.New("unsupported corpus schema version")
	}
	if len(manifest.Fixtures) == 0 || len(manifest.Fixtures) > maxCorpusFixtures || len(manifest.Fixtures) != len(paths) {
		return nil, errors.New("corpus manifest must describe each of the 1–32 fixture arguments")
	}
	fixtures := make(map[string]fixtureExpectation, len(paths))
	for _, fixture := range manifest.Fixtures {
		if _, duplicate := fixtures[fixture.ID]; duplicate || paths[fixture.ID] == "" || !fixture.valid() {
			return nil, fmt.Errorf("invalid or duplicate corpus fixture ID %q", fixture.ID)
		}
		fixtures[fixture.ID] = fixture
	}
	for _, fixture := range manifest.Fixtures {
		if fixture.EquivalentTo == "" {
			continue
		}
		other, ok := fixtures[fixture.EquivalentTo]
		if !ok || fixture.ID == other.ID || fixture.Mode != other.Mode || fixture.Rule != other.Rule || fixture.SHA256 == other.SHA256 {
			return nil, fmt.Errorf("invalid equivalent fixture for %q", fixture.ID)
		}
	}
	return fixtures, nil
}

func (f fixtureExpectation) valid() bool {
	if len(f.ID) == 0 || len(f.ID) > 128 || len(f.Rule) == 0 || len(f.Rule) > 128 ||
		(f.Mode != httpMode && f.Mode != artifactMode) || len(f.SHA256) != 64 || f.SHA256 != strings.ToLower(f.SHA256) {
		return false
	}
	_, err := hex.DecodeString(f.SHA256)
	return err == nil && f.Baseline.valid(f.Mode) && f.Candidate.valid(f.Mode)
}

func (e expectation) valid(mode string) bool {
	switch e.Outcome {
	case outcomeNegative, outcomeUnobservable:
		return len(e.Evidence) == 0
	case outcomeMatch:
		if len(e.Evidence) > maxCorpusRows {
			return false
		}
	default:
		return false
	}
	for _, anchor := range e.Evidence {
		if anchor.RequestPacket < 0 || anchor.ResponsePacket < 0 || anchor.RequestOffset < 0 || anchor.ResponseOffset < 0 ||
			len(anchor.EntityMatches) > maxCorpusSpans || (mode == httpMode && len(anchor.EntityMatches) != 0) {
			return false
		}
		for _, span := range anchor.EntityMatches {
			if len(span.Pattern) == 0 || span.Offset < 0 || span.Length < 0 {
				return false
			}
		}
	}
	return true
}
