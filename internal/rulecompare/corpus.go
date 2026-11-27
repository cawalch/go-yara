package rulecompare

import (
	"cmp"
	"context"
	"errors"
	"runtime/debug"
	"slices"

	pcap "github.com/cawalch/go-pcap"

	"github.com/cawalch/go-yara/compiler"
)

type corpusLimits struct {
	ManifestBytes     int `json:"manifest_bytes"`
	Fixtures          int `json:"fixtures"`
	FixtureBytes      int `json:"fixture_bytes"`
	Transactions      int `json:"http_transactions_per_fixture"`
	MatchSpans        int `json:"match_spans_per_entity"`
	ScanBytes         int `json:"rule_scan_bytes_per_fixture"`
	EntityBytes       int `json:"entity_bytes"`
	HTTPEvidenceBytes int `json:"http_evidence_bytes_per_capture"`
}

func defaultCorpusLimits() *corpusLimits {
	return &corpusLimits{
		ManifestBytes: maxManifest, Fixtures: maxCorpusFixtures, FixtureBytes: maxInput,
		Transactions: maxCorpusRows, MatchSpans: maxCorpusSpans, ScanBytes: maxCorpusScanBytes,
		EntityBytes: pcap.MaxHTTPBodyBytes, HTTPEvidenceBytes: pcap.MaxHTTP1RequestEvidenceBytesPerScan,
	}
}

func parserVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path != "github.com/cawalch/go-pcap" {
				continue
			}
			switch {
			case dep.Replace == nil:
				return dep.Version
			case dep.Replace.Version != "":
				return dep.Replace.Version
			default:
				return "(local replacement)"
			}
		}
	}
	return "unknown"
}

type ruleComparison struct {
	Rule            string       `json:"rule"`
	Mode            string       `json:"mode"`
	Baseline        *observation `json:"baseline,omitempty"`
	Candidate       *observation `json:"candidate,omitempty"`
	EvidenceChanged bool         `json:"evidence_changed"`
	Mismatches      []string     `json:"mismatches"`
}

type observation struct {
	Outcome  string             `json:"outcome"`
	Evidence []observedEvidence `json:"evidence"`
	Matches  []string           `json:"matches,omitempty"`
}

type observedEvidence struct {
	ruleAnchor
	Transaction  int `json:"transaction"`
	DecodedBytes int `json:"decoded_bytes"`
	StatusCode   int `json:"status_code"`
}

type corpusInput struct {
	data         []byte
	rows         []pcap.HTTP1Transaction
	completeRows []int
	complete     bool
	rule         string
}

type revisions struct {
	baseline  revision
	candidate revision
}

func (pair revisions) validate(ctx context.Context, data []byte, want fixtureExpectation) change {
	row := change{Fixture: want.ID, SHA256: digest(data), Added: []string{}, Removed: []string{}}
	report := &ruleComparison{Rule: want.Rule, Mode: want.Mode, Mismatches: []string{}}
	row.Evidence = report
	if want.SHA256 != "" && row.SHA256 != want.SHA256 {
		report.Mismatches = append(report.Mismatches, "fixture_digest")
		return row
	}
	if !pair.baseline.hasPublicRule(want.Rule) || !pair.candidate.hasPublicRule(want.Rule) {
		row.Error = "corpus rule must be public in both revisions"
		return row
	}
	input, err := readCorpusInput(ctx, data, want)
	if err != nil {
		row.Error = err.Error()
		return row
	}
	baseline, err := input.observe(ctx, pair.baseline.Scanner, want.Mode)
	if err != nil {
		row.Error = "baseline evidence scan failed"
		return row
	}
	report.Baseline = &baseline
	candidate, err := input.observe(ctx, pair.candidate.Scanner, want.Mode)
	if err != nil {
		row.Error = "candidate evidence scan failed"
		return row
	}
	report.Candidate = &candidate
	if want.SHA256 != "" {
		report.check("baseline", baseline, want.Baseline)
		report.check("candidate", candidate, want.Candidate)
	}
	matchedBefore, matchedAfter := baseline.Outcome == outcomeMatch, candidate.Outcome == outcomeMatch
	switch {
	case !matchedBefore && matchedAfter:
		row.Added = append(row.Added, want.Rule)
	case matchedBefore && !matchedAfter:
		row.Removed = append(row.Removed, want.Rule)
	case matchedBefore && matchedAfter:
		report.EvidenceChanged = !slices.EqualFunc(baseline.Evidence, candidate.Evidence, sameObservedEvidence)
	}
	return row
}

func readCorpusInput(ctx context.Context, data []byte, want fixtureExpectation) (corpusInput, error) {
	if err := ctx.Err(); err != nil {
		return corpusInput{}, err
	}
	capture, err := pcap.New(data)
	if err != nil {
		return corpusInput{}, errors.New("fixture is not a readable capture")
	}
	rows, err := capture.HTTP1Transactions(data)
	if err != nil {
		return corpusInput{}, errors.New("HTTP transaction extraction failed")
	}
	if len(rows) > maxCorpusRows {
		return corpusInput{}, errors.New("fixture exceeded the corpus transaction limit")
	}
	input := corpusInput{data: data, rows: rows, rule: want.Rule}
	var scanBytes int64
	for i, row := range rows {
		if artifact := row.ResponseArtifact(); artifact.Coverage == pcap.HTTP1ArtifactComplete {
			input.completeRows = append(input.completeRows, i)
			scanBytes += int64(len(artifact.Body))
		}
	}
	input.complete = len(rows) != 0 && len(input.completeRows) == len(rows) && !capture.InputTruncated()
	if want.Mode == httpMode {
		// Each revision scans the capture, the empty view, and up to one view per complete response.
		scanBytes = int64(len(data)) * int64(2+len(input.completeRows))
	}
	if 2*scanBytes > maxCorpusScanBytes {
		return corpusInput{}, errors.New("fixture exceeded the corpus rule scan byte budget")
	}
	return input, nil
}

func (input corpusInput) observe(ctx context.Context, scanner *compiler.Scanner, mode string) (observation, error) {
	result := observation{Outcome: outcomeUnobservable, Evidence: []observedEvidence{}}
	if input.complete {
		result.Outcome = outcomeNegative
	}
	var inspect func(context.Context, pcap.HTTP1Transaction) (*compiler.ScanResult, error)
	switch mode {
	case httpMode:
		full, err := scanner.ScanWithPCAPHTTP1(ctx, input.data, input.rows)
		if err != nil {
			return observation{}, err
		}
		for _, match := range full.MatchedRules {
			result.Matches = append(result.Matches, match.Rule)
		}
		slices.Sort(result.Matches)
		if !hasRuleMatch(full, input.rule) {
			return result, nil
		}
		result.Outcome = outcomeMatch
		empty, err := scanner.ScanWithPCAPHTTP1(ctx, input.data, nil)
		if err != nil {
			return observation{}, err
		}
		if hasRuleMatch(empty, input.rule) {
			return result, nil
		}
		inspect = func(ctx context.Context, row pcap.HTTP1Transaction) (*compiler.ScanResult, error) {
			return scanner.ScanWithPCAPHTTP1(ctx, input.data, []pcap.HTTP1Transaction{row})
		}
	case artifactMode:
		inspect = func(ctx context.Context, row pcap.HTTP1Transaction) (*compiler.ScanResult, error) {
			scan, err := scanner.ScanHTTP1Response(ctx, row.ResponseArtifact())
			return scan.Result, err
		}
	}
	for _, index := range input.completeRows {
		row := input.rows[index]
		scan, err := inspect(ctx, row)
		if err != nil {
			return observation{}, err
		}
		match := findRuleMatch(scan, input.rule)
		if match == nil {
			continue
		}
		evidence := responseEvidence(index, row)
		if mode == artifactMode {
			evidence.EntityMatches, err = matchSpans(match)
			if err != nil {
				return observation{}, err
			}
		}
		result.Outcome = outcomeMatch
		result.Evidence = append(result.Evidence, evidence)
	}
	return result, ctx.Err()
}

func hasRuleMatch(result *compiler.ScanResult, name string) bool {
	return findRuleMatch(result, name) != nil
}

func findRuleMatch(result *compiler.ScanResult, name string) *compiler.RuleMatch {
	if result != nil {
		for i := range result.MatchedRules {
			if result.MatchedRules[i].Rule == name {
				return &result.MatchedRules[i]
			}
		}
	}
	return nil
}

func responseEvidence(index int, row pcap.HTTP1Transaction) observedEvidence {
	artifact := row.ResponseArtifact()
	return observedEvidence{
		ruleAnchor: ruleAnchor{
			RequestPacket: artifact.ID.PacketIndex, RequestOffset: artifact.ID.PacketPayloadOffset,
			ResponsePacket: artifact.ResponsePacketIndex, ResponseOffset: artifact.ResponsePacketPayloadOffset,
		},
		Transaction: index, DecodedBytes: len(artifact.Body), StatusCode: row.Response.StatusCode,
	}
}

func matchSpans(rule *compiler.RuleMatch) ([]matchSpan, error) {
	var spans []matchSpan
	for pattern, matches := range rule.Matches {
		if len(matches) > maxCorpusSpans-len(spans) {
			return nil, errors.New("entity exceeded the corpus match span limit")
		}
		for _, match := range matches {
			spans = append(spans, matchSpan{Pattern: pattern, Offset: match.Offset, Length: match.Length})
		}
	}
	slices.SortFunc(spans, func(a, b matchSpan) int {
		if order := cmp.Compare(a.Offset, b.Offset); order != 0 {
			return order
		}
		if order := cmp.Compare(a.Length, b.Length); order != 0 {
			return order
		}
		return cmp.Compare(a.Pattern, b.Pattern)
	})
	return spans, nil
}

func sameAnchor(a, b ruleAnchor) bool {
	return a.RequestPacket == b.RequestPacket && a.RequestOffset == b.RequestOffset &&
		a.ResponsePacket == b.ResponsePacket && a.ResponseOffset == b.ResponseOffset &&
		slices.Equal(a.EntityMatches, b.EntityMatches)
}

func sameObservedEvidence(a, b observedEvidence) bool {
	return sameAnchor(a.ruleAnchor, b.ruleAnchor) && sameSemanticEvidence(a, b)
}

func sameSemanticEvidence(a, b observedEvidence) bool {
	return a.Transaction == b.Transaction && a.DecodedBytes == b.DecodedBytes && a.StatusCode == b.StatusCode &&
		slices.Equal(a.EntityMatches, b.EntityMatches)
}

func (report *ruleComparison) check(stage string, got observation, want expectation) {
	if got.Outcome != want.Outcome {
		report.Mismatches = append(report.Mismatches, stage+"_outcome")
		return
	}
	if !slices.EqualFunc(got.Evidence, want.Evidence, func(actual observedEvidence, expected ruleAnchor) bool {
		return sameAnchor(actual.ruleAnchor, expected)
	}) {
		report.Mismatches = append(report.Mismatches, stage+"_evidence")
	}
}

func compareEquivalentFixtures(rows []change, manifest map[string]fixtureExpectation) bool {
	if manifest == nil {
		return false
	}
	byID := make(map[string]*ruleComparison, len(rows))
	for _, row := range rows {
		byID[row.Fixture] = row.Evidence
	}
	var mismatch bool
	for _, row := range rows {
		report := row.Evidence
		if report == nil {
			continue
		}
		if other := byID[manifest[row.Fixture].EquivalentTo]; other != nil {
			if !sameSemanticObservation(report.Baseline, other.Baseline) {
				report.Mismatches = append(report.Mismatches, "equivalence_baseline")
			}
			if !sameSemanticObservation(report.Candidate, other.Candidate) {
				report.Mismatches = append(report.Mismatches, "equivalence_candidate")
			}
		}
		mismatch = mismatch || len(report.Mismatches) != 0
	}
	return mismatch
}

func sameSemanticObservation(a, b *observation) bool {
	return a != nil && b != nil && a.Outcome == b.Outcome &&
		slices.EqualFunc(a.Evidence, b.Evidence, sameSemanticEvidence)
}
