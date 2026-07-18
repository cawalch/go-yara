package compiler

import (
	"context"
	"fmt"
	"slices"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
)

// Capture is an exact source span exposed by a capture modifier.
type Capture struct {
	Name          string
	Pattern       string
	Group         int
	Offset        int64
	Length        int
	Data          []byte
	DataTruncated bool
}

// EvidenceStatus describes whether a finding can be handed to a validator.
type EvidenceStatus string

const (
	// EvidenceStatusReady has exactly one complete capture for every field.
	EvidenceStatusReady EvidenceStatus = "ready"
	// EvidenceStatusPartial is missing a field or contains a truncated capture.
	EvidenceStatusPartial EvidenceStatus = "partial"
	// EvidenceStatusAmbiguous retains multiple plausible candidates rather than guessing.
	EvidenceStatusAmbiguous EvidenceStatus = "ambiguous"
)

// EvidenceFinding is one candidate tuple rooted at an anchor occurrence.
type EvidenceFinding struct {
	Anchor Capture
	Status EvidenceStatus
	Fields map[string][]Capture
}

type captureParent struct {
	pattern string
	offset  int64
	length  int
}

type captureOccurrence struct {
	capture Capture
	parent  captureParent
}

type captureInput struct {
	data       []byte
	start, end int
	base       int64
}

type captureInputProvider func(Match) (captureInput, bool)

//nolint:revive // evidence replay needs rule matches and their scan-specific byte provider
func (s *Scanner) populateRuleEvidence(
	ctx context.Context,
	rule *CompiledRule,
	matches map[string][]Match,
	inputFor captureInputProvider,
) (map[string][]EvidenceFinding, error) {
	if s.evidenceMax <= 0 || rule == nil || len(rule.CaptureBindings) == 0 {
		return nil, nil
	}

	occurrences := make([]captureOccurrence, 0)
	patterns := make([]string, 0, len(rule.CaptureBindings))
	for pattern := range rule.CaptureBindings {
		patterns = append(patterns, pattern)
	}
	slices.Sort(patterns)
	for _, pattern := range patterns {
		bindings := rule.CaptureBindings[pattern]
		perPattern := matches[pattern]
		for index := range perPattern {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			match := &perPattern[index]
			input, ok := inputFor(*match)
			if !ok {
				return nil, fmt.Errorf("capture source for %s at offset %d is unavailable", pattern, match.Offset)
			}
			spans, err := replayCaptureSpans(rule, pattern, bindings, input)
			if err != nil {
				return nil, fmt.Errorf("replaying captures for %s at offset %d: %w", pattern, match.Offset, err)
			}
			parent := captureParent{pattern: pattern, offset: match.Offset, length: match.Length}
			for _, binding := range bindings {
				span, exists := spans[binding.Group]
				if !exists || !span.Matched {
					continue
				}
				capture := Capture{
					Name:    binding.Name,
					Pattern: pattern,
					Group:   binding.Group,
					Offset:  input.base + int64(span.Start),
					Length:  span.End - span.Start,
				}
				copyLength := min(capture.Length, s.evidenceMax)
				capture.Data = copyBytes(input.data[span.Start : span.Start+copyLength])
				capture.DataTruncated = copyLength < capture.Length
				match.Captures = append(match.Captures, capture)
				occurrences = append(occurrences, captureOccurrence{capture: capture, parent: parent})
			}
		}
		matches[pattern] = perPattern
	}

	sortCaptureOccurrences(occurrences)
	evidence := correlateEvidence(rule.EvidencePlans, occurrences)
	if len(evidence) == 0 {
		return nil, nil
	}
	return evidence, nil
}

//nolint:revive // capture replay keeps the compiled rule and concrete outer match explicit
func replayCaptureSpans(
	rule *CompiledRule,
	pattern string,
	bindings []ast.CaptureBinding,
	input captureInput,
) (map[int]regex.CaptureSpan, error) {
	spans := make(map[int]regex.CaptureSpan, len(bindings))
	for _, binding := range bindings {
		if binding.Group == 0 {
			spans[0] = regex.CaptureSpan{Start: input.start, End: input.end, Matched: true}
		}
	}
	positive := positiveBindingGroups(bindings)
	if len(positive) == 0 {
		return spans, nil
	}
	regexPattern, ok := rule.RegexPatterns[pattern]
	if !ok || len(regexPattern.CaptureCode) == 0 {
		return nil, fmt.Errorf("compiled capture program is missing")
	}
	modifiers := rule.StringModifiers[pattern]
	flagOptions := replayFlagOptions(regexPattern.Flags, modifiers)
	for _, flags := range flagOptions {
		captured, matched := regex.ExecCapturesAt(
			regexPattern.CaptureCode,
			input.data,
			flags,
			input.start,
			input.end,
			len(regexPattern.CaptureGroups),
		)
		if !matched {
			continue
		}
		for slot, group := range regexPattern.CaptureGroups {
			if slot < len(captured) {
				spans[group] = captured[slot]
			}
		}
		return spans, nil
	}
	return nil, fmt.Errorf("tagged regex did not reproduce the outer match")
}

func positiveBindingGroups(bindings []ast.CaptureBinding) []int {
	var groups []int
	for _, binding := range bindings {
		if binding.Group > 0 && !slices.Contains(groups, binding.Group) {
			groups = append(groups, binding.Group)
		}
	}
	return groups
}

func replayFlagOptions(flags regex.Flags, modifiers []ast.StringModifier) []regex.Flags {
	hasWide := hasModifier(modifiers, ast.StringModifierWide)
	hasASCII := hasModifier(modifiers, ast.StringModifierASCII)
	options := make([]regex.Flags, 0, 2)
	if hasWide {
		options = append(options, flags|regex.FlagsWide)
	}
	if !hasWide || hasASCII {
		options = append(options, flags&^regex.FlagsWide)
	}
	return options
}

func correlateEvidence(plans []EvidencePlan, occurrences []captureOccurrence) map[string][]EvidenceFinding {
	if len(plans) == 0 {
		return nil
	}
	result := make(map[string][]EvidenceFinding, len(plans))
	for _, plan := range plans {
		anchors := occurrencesNamed(occurrences, plan.Anchor)
		if len(anchors) == 0 {
			continue
		}
		findings := make([]EvidenceFinding, len(anchors))
		ambiguous := make([]bool, len(anchors))
		for index, anchor := range anchors {
			findings[index] = EvidenceFinding{
				Anchor: anchor.capture,
				Fields: make(map[string][]Capture, len(plan.Fields)),
			}
			findings[index].Fields[plan.Anchor] = []Capture{anchor.capture}
		}
		for _, field := range plan.Fields {
			if field == plan.Anchor {
				continue
			}
			for _, candidate := range occurrencesNamed(occurrences, field) {
				assignCaptureCandidate(findings, ambiguous, anchors, field, candidate, plan.Within)
			}
		}
		for index := range findings {
			findings[index].Status = evidenceFindingStatus(findings[index].Fields, plan.Fields, ambiguous[index])
		}
		result[plan.Name] = findings
	}
	return result
}

//nolint:revive // explicit correlation inputs keep per-plan assignment state visible
func assignCaptureCandidate(
	findings []EvidenceFinding,
	ambiguous []bool,
	anchors []captureOccurrence,
	field string,
	candidate captureOccurrence,
	within int64,
) {
	for index, anchor := range anchors {
		if candidate.parent == anchor.parent {
			findings[index].Fields[field] = append(findings[index].Fields[field], candidate.capture)
			return
		}
	}

	minimum := int64(-1)
	nearest := make([]int, 0, 2)
	for index, anchor := range anchors {
		distance := captureSpanDistance(candidate.capture, anchor.capture)
		if distance > within {
			continue
		}
		switch {
		case minimum < 0 || distance < minimum:
			minimum = distance
			nearest = append(nearest[:0], index)
		case distance == minimum:
			nearest = append(nearest, index)
		}
	}
	for _, index := range nearest {
		findings[index].Fields[field] = append(findings[index].Fields[field], candidate.capture)
		if len(nearest) > 1 {
			ambiguous[index] = true
		}
	}
}

func evidenceFindingStatus(fields map[string][]Capture, required []string, tied bool) EvidenceStatus {
	if tied {
		return EvidenceStatusAmbiguous
	}
	partial := false
	for _, field := range required {
		candidates := fields[field]
		if len(candidates) > 1 {
			return EvidenceStatusAmbiguous
		}
		if len(candidates) == 0 || candidates[0].DataTruncated {
			partial = true
		}
	}
	if partial {
		return EvidenceStatusPartial
	}
	return EvidenceStatusReady
}

func captureSpanDistance(left, right Capture) int64 {
	leftEnd := left.Offset + int64(left.Length)
	rightEnd := right.Offset + int64(right.Length)
	switch {
	case leftEnd < right.Offset:
		return right.Offset - leftEnd
	case rightEnd < left.Offset:
		return left.Offset - rightEnd
	default:
		return 0
	}
}

func occurrencesNamed(occurrences []captureOccurrence, name string) []captureOccurrence {
	result := make([]captureOccurrence, 0)
	for _, occurrence := range occurrences {
		if occurrence.capture.Name == name {
			result = append(result, occurrence)
		}
	}
	return result
}

func sortCaptureOccurrences(occurrences []captureOccurrence) {
	slices.SortStableFunc(occurrences, func(left, right captureOccurrence) int {
		switch {
		case left.capture.Offset < right.capture.Offset:
			return -1
		case left.capture.Offset > right.capture.Offset:
			return 1
		case left.capture.Pattern < right.capture.Pattern:
			return -1
		case left.capture.Pattern > right.capture.Pattern:
			return 1
		case left.capture.Group < right.capture.Group:
			return -1
		case left.capture.Group > right.capture.Group:
			return 1
		case left.capture.Name < right.capture.Name:
			return -1
		case left.capture.Name > right.capture.Name:
			return 1
		default:
			return 0
		}
	})
}
