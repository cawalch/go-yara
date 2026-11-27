package rulecompare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// CaptureReview supplies one capture and a public rule name shared by both
// revisions. Source and capture bytes are borrowed for this call.
type CaptureReview struct {
	Baseline, Candidate string
	Fixture, Rule       string
	Data                []byte
	InputLimit          int
}

// ReviewCapture writes the same versioned observation fields used by -expect,
// with no expectations attached. The caller sets the input limit.
func ReviewCapture(ctx context.Context, review CaptureReview) ([]byte, error) {
	if review.InputLimit <= 0 || len(review.Data) > review.InputLimit {
		return nil, errors.New("capture exceeds input limit")
	}
	if len(review.Rule) == 0 || len(review.Rule) > 128 {
		return nil, errors.New("enter a rule name shared by both revisions")
	}
	left, err := compileSource(ctx, review.Baseline, nil)
	if err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	defer left.Close()
	right, err := compileSource(ctx, review.Candidate, nil)
	if err != nil {
		return nil, fmt.Errorf("candidate: %w", err)
	}
	defer right.Close()
	pair := revisions{left, right}
	report := pairReport(pair, "default", []string{})
	report.setCorpusMetadata(review.InputLimit, "")
	report.Fixtures = []change{pair.validate(ctx, review.Data, fixtureExpectation{ID: review.Fixture, Rule: review.Rule, Mode: httpMode})}
	return json.Marshal(report)
}
