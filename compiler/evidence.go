package compiler

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
)

// Capture represents an exact source byte span extracted by a capture modifier
// on a string pattern ($str = ... capture(name = group)).
type Capture struct {
	// Name is the logical identifier assigned to this capture (e.g. "secret" or "endpoint").
	Name string
	// Pattern is the rule string identifier that matched (e.g. "$token").
	Pattern string
	// Group is the capture group index (0 for full pattern match, >= 1 for regex sub-groups).
	Group int
	// Offset is the absolute zero-based byte offset in the scanned input where the capture starts.
	Offset int64
	// Length is the total byte length of the captured span in the scanned input.
	Length int
	// Data contains the copied bytes of the capture span, bounded by WithEvidence(maxCaptureBytes).
	// The result owns these bytes independently of the input and scanner lifetime.
	// Captures and findings in the same result can reference the same bytes.
	Data []byte
	// DataTruncated indicates whether Length exceeded the scanner's configured byte limit,
	// causing Data to contain only the initial prefix of the match.
	DataTruncated bool
}

// EvidenceStatus classifies whether a correlated finding tuple is complete, partial, or ambiguous.
type EvidenceStatus string

const (
	// EvidenceStatusReady indicates that every field declared in the evidence statement has
	// exactly one unambiguous candidate capture within the proximity window, and none were truncated.
	// Ready findings can typically be dispatched directly to credentials validators.
	EvidenceStatusReady EvidenceStatus = "ready"

	// EvidenceStatusPartial indicates that one or more declared fields are missing within the
	// proximity window of the anchor, or that a capture's data was truncated by the byte limit.
	EvidenceStatusPartial EvidenceStatus = "partial"

	// EvidenceStatusAmbiguous indicates that multiple candidate captures for a field were located
	// within the proximity window (such as equidistant occurrences or multiple competing spans).
	// Rather than guessing which span is intended, all candidates are preserved in Fields.
	EvidenceStatusAmbiguous EvidenceStatus = "ambiguous"
)

// EvidenceFinding represents a correlated candidate tuple for an evidence declaration,
// rooted at an occurrence of its designated anchor capture.
//
// In multi-pattern rules, findings correlate scattered credentials (e.g. username,
// password, and endpoint) that appear within a configured byte window of each other.
type EvidenceFinding struct {
	// Anchor is the designated anchor capture that serves as the spatial center of this finding.
	Anchor Capture
	// Status evaluates whether all declared fields were resolved unambiguously without truncation.
	Status EvidenceStatus
	// Fields maps each declared field name in the evidence declaration to candidate captures
	// found within the configured byte distance of the anchor.
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

	var occurrencesBuf [16]captureOccurrence
	occurrences := s.evidenceOccurrences
	if occurrences == nil {
		occurrences = occurrencesBuf[:0]
	}
	overflowed := false
	defer func() {
		clear(occurrences)
		if overflowed {
			clear(s.evidenceOccurrences[:cap(s.evidenceOccurrences)])
		}
	}()
	var storage captureStorage
	var patternsBuf [8]string
	patterns := patternsBuf[:0]
	for pattern := range rule.CaptureBindings {
		patterns = append(patterns, pattern)
	}
	if len(patterns) > 1 {
		slices.Sort(patterns)
	}
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
			captured, groups, err := replayCaptureSpans(&s.captureScratch, rule, pattern, bindings, input)
			if err != nil {
				return nil, fmt.Errorf("replaying captures for %s at offset %d: %w", pattern, match.Offset, err)
			}
			totalCopyBytes := 0
			matchedCount := 0
			for _, binding := range bindings {
				span := resolveBindingCaptureSpan(binding.Group, input, captured, groups)
				if !span.Matched {
					continue
				}
				matchedCount++
				totalCopyBytes += min(span.End-span.Start, s.evidenceMax)
			}
			if matchedCount == 0 {
				continue
			}
			dataSlab := storage.bytes(totalCopyBytes, len(perPattern)-index)
			if cap(match.Captures) < len(match.Captures)+matchedCount {
				grown := storage.capturesFor(len(match.Captures)+matchedCount, len(perPattern)-index)[:len(match.Captures)]
				copy(grown, match.Captures)
				match.Captures = grown
			}
			slabPos := 0
			parent := captureParent{pattern: pattern, offset: match.Offset, length: match.Length}
			for _, binding := range bindings {
				span := resolveBindingCaptureSpan(binding.Group, input, captured, groups)
				if !span.Matched {
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
				if copyLength > 0 {
					copy(dataSlab[slabPos:slabPos+copyLength], input.data[span.Start:span.Start+copyLength])
					capture.Data = dataSlab[slabPos : slabPos+copyLength : slabPos+copyLength]
					slabPos += copyLength
				} else {
					capture.Data = []byte{}
				}
				capture.DataTruncated = copyLength < capture.Length
				match.Captures = append(match.Captures, capture)
				if len(rule.EvidencePlans) == 0 {
					continue
				}
				if len(occurrences) == cap(occurrences) {
					if len(occurrences) >= 1024 {
						// Keep the bounded prefix scratch, discard overflow on return.
						occurrences = slices.Grow(occurrences, len(occurrences))
						overflowed = true
					} else {
						// The small local buffer never escapes into the scanner.
						s.evidenceOccurrences = make([]captureOccurrence, 0, 2*len(occurrences))
						copy(s.evidenceOccurrences[:len(occurrences)], occurrences)
						occurrences = s.evidenceOccurrences[:len(occurrences)]
					}
				}
				occurrences = append(occurrences, captureOccurrence{capture: capture, parent: parent})
			}
		}
		matches[pattern] = perPattern
	}

	if len(occurrences) > 1 {
		sortCaptureOccurrences(occurrences)
	}
	evidence := correlateEvidence(rule.EvidencePlans, occurrences)
	if len(evidence) == 0 {
		return nil, nil
	}
	return evidence, nil
}

//nolint:revive // helper keeps capture group and outer match span explicit
func resolveBindingCaptureSpan(
	group int,
	input captureInput,
	captured []regex.CaptureSpan,
	groups []int,
) regex.CaptureSpan {
	if group == 0 {
		return regex.CaptureSpan{Start: input.start, End: input.end, Matched: true}
	}
	for slot, candidateGroup := range groups {
		if candidateGroup == group && slot < len(captured) {
			return captured[slot]
		}
	}
	return regex.CaptureSpan{}
}

//nolint:revive // capture replay keeps the compiled rule and concrete outer match explicit
func replayCaptureSpans(
	scratch *regex.CaptureScratch,
	rule *CompiledRule,
	pattern string,
	bindings []ast.CaptureBinding,
	input captureInput,
) ([]regex.CaptureSpan, []int, error) {
	if !hasPositiveBindingGroups(bindings) {
		return nil, nil, nil
	}
	regexPattern, ok := rule.RegexPatterns[pattern]
	if !ok || len(regexPattern.CaptureCode) == 0 {
		return nil, nil, errors.New("compiled capture program is missing")
	}
	modifiers := rule.StringModifiers[pattern]
	flagOptions, optionCount := replayFlagOptions(regexPattern.Flags, modifiers)
	for _, flags := range flagOptions[:min(optionCount, len(flagOptions))] {
		margin := regexWindowMarginASCII
		isWide := (flags & regex.FlagsWide) != 0
		if isWide {
			margin = regexWindowMarginWide
		}
		windowStart := max(0, input.start-margin)
		if isWide && (input.start-windowStart)&1 != 0 {
			windowStart--
		}
		if windowStart < 0 {
			windowStart = 0
		}
		windowEnd := min(len(input.data), input.end+margin)
		scanData := input.data[windowStart:windowEnd]
		captured, matched := regex.ExecCapturesAtWithScratch(
			scratch,
			regexPattern.CaptureCode,
			scanData,
			flags,
			input.start-windowStart,
			input.end-windowStart,
			len(regexPattern.CaptureGroups),
		)
		if !matched {
			continue
		}
		for i := range captured {
			captured[i].Start += windowStart
			captured[i].End += windowStart
		}
		return captured, regexPattern.CaptureGroups, nil
	}
	return nil, nil, errors.New("tagged regex did not reproduce the outer match")
}

func hasPositiveBindingGroups(bindings []ast.CaptureBinding) bool {
	for _, binding := range bindings {
		if binding.Group > 0 {
			return true
		}
	}
	return false
}

func replayFlagOptions(flags regex.Flags, modifiers []ast.StringModifier) ([2]regex.Flags, int) {
	hasWide := hasModifier(modifiers, ast.StringModifierWide)
	hasASCII := hasModifier(modifiers, ast.StringModifierASCII)
	var options [2]regex.Flags
	count := 0
	if hasWide {
		options[count] = flags | regex.FlagsWide
		count++
	}
	if !hasWide || hasASCII {
		options[count] = flags &^ regex.FlagsWide
		count++
	}
	return options, count
}

func correlateEvidence(plans []EvidencePlan, occurrences []captureOccurrence) map[string][]EvidenceFinding {
	if len(plans) == 0 {
		return nil
	}
	result := make(map[string][]EvidenceFinding, len(plans))
	for _, plan := range plans {
		var anchorsBuf [8]int
		anchors := occurrenceIndicesNamedInto(anchorsBuf[:0], occurrences, plan.Anchor)
		if len(anchors) == 0 {
			continue
		}
		findings := make([]EvidenceFinding, len(anchors))
		var ambiguousBuf [8]bool
		var ambiguous []bool
		if len(anchors) <= len(ambiguousBuf) {
			ambiguous = ambiguousBuf[:len(anchors)]
		} else {
			ambiguous = make([]bool, len(anchors))
		}
		captureSlab := make([]Capture, 0, len(occurrences))
		for index, at := range anchors {
			anchor := occurrences[at]
			findings[index] = EvidenceFinding{
				Anchor: anchor.capture,
				Fields: make(map[string][]Capture, len(plan.Fields)),
			}
			pos := len(captureSlab)
			captureSlab = append(captureSlab, anchor.capture)
			findings[index].Fields[plan.Anchor] = captureSlab[pos : pos+1 : pos+1]
		}
		for _, field := range plan.Fields {
			if field == plan.Anchor {
				continue
			}
			for _, candidate := range occurrences {
				if candidate.capture.Name != field {
					continue
				}
				assignCaptureCandidate(findings, ambiguous, anchors, occurrences, field, candidate, plan.Within, &captureSlab)
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
	anchors []int,
	occurrences []captureOccurrence,
	field string,
	candidate captureOccurrence,
	within int64,
	captureSlab *[]Capture,
) {
	for index, at := range anchors {
		anchor := occurrences[at]
		if candidate.parent == anchor.parent {
			existing := findings[index].Fields[field]
			if len(existing) == 0 && len(*captureSlab) < cap(*captureSlab) {
				pos := len(*captureSlab)
				*captureSlab = append(*captureSlab, candidate.capture)
				findings[index].Fields[field] = (*captureSlab)[pos : pos+1 : pos+1]
			} else {
				findings[index].Fields[field] = append(existing, candidate.capture)
			}
			return
		}
	}

	minimum := int64(-1)
	var nearestBuf [4]int
	nearest := nearestBuf[:0]
	for index, at := range anchors {
		anchor := occurrences[at]
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
		existing := findings[index].Fields[field]
		if len(existing) == 0 && len(*captureSlab) < cap(*captureSlab) {
			pos := len(*captureSlab)
			*captureSlab = append(*captureSlab, candidate.capture)
			findings[index].Fields[field] = (*captureSlab)[pos : pos+1 : pos+1]
		} else {
			findings[index].Fields[field] = append(existing, candidate.capture)
		}
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

func occurrenceIndicesNamedInto(dst []int, occurrences []captureOccurrence, name string) []int {
	count := 0
	for _, occurrence := range occurrences {
		if occurrence.capture.Name == name {
			count++
		}
	}
	result := slices.Grow(dst, count)
	for index, occurrence := range occurrences {
		if occurrence.capture.Name == name {
			result = append(result, index)
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
