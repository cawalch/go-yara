package compiler

import (
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func TestValidateSerializedRegexPattern(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule patterns {
strings:
  $literal = /^token/
  $alternatives = /cats|dogs/ ascii wide
  $gap = /[A-Z][0-9]{1,4}(alpha|bravo)/
  $fixed = /[ab][xy]/
  $capture = /key=([a-z0-9]+)/ capture(value = 1)
  $bounded = /(cat|cats){1,3}/
  $repeat = /(xy|x)+/
  $suffix = /[a-z]+;/
  $forward = /[a-z]+/
  $reverse = /[0-9]{2,10}_needle/
condition:
  any of them
}`)
	serialized := make(map[string]serializedRegexPattern)
	for id, pattern := range program.Rules[0].RegexPatterns {
		serialized[id] = serializeRegexPattern(pattern)
		if err := validateSerializedRegexPattern(serialized[id]); err != nil {
			t.Fatalf("valid pattern %s: %v", id, err)
		}
	}

	for _, tc := range []struct {
		name    string
		id      string
		message string
		change  func(*serializedRegexPattern)
	}{
		{"missing main code", "$literal", "regex code", func(p *serializedRegexPattern) { p.Code = nil }},
		{"unknown flag", "$literal", "flags", func(p *serializedRegexPattern) { p.Flags |= regex.Flags(1 << 31) }},
		{"wide metadata", "$literal", "wide encoding", func(p *serializedRegexPattern) { p.WidePrefix = nil }},
		{"finite extent", "$literal", "stream length", func(p *serializedRegexPattern) { p.MaxLength = math.MaxInt }},
		{"offset range", "$literal", "atom bounds", func(p *serializedRegexPattern) { p.AtomMinOffset = -1 }},
		{"sparse byte set", "$fixed", "byte-set", func(p *serializedRegexPattern) { p.ByteSetCount++ }},
		{"fixed byte set", "$fixed", "fixed byte set", func(p *serializedRegexPattern) {
			p.FixedByteSets = [][]byte{{'b', 'a'}}
		}},
		{"prefix repetition", "$reverse", "prefix repeat", func(p *serializedRegexPattern) {
			p.PrefixRepeatMin, p.PrefixRepeatMax = 5, 3
		}},
		{"gap range", "$gap", "leading gap", func(p *serializedRegexPattern) {
			gap := *p.LeadingGap
			gap.GapMax = -2
			p.LeadingGap = &gap
		}},
		{"capture metadata", "$capture", "capture group", func(p *serializedRegexPattern) { p.CaptureGroups = []int{1, 1} }},
		{"empty capture code", "$capture", "capture code", func(p *serializedRegexPattern) { p.CaptureCode = nil }},
		{"verification mask", "$suffix", "verification atom", func(p *serializedRegexPattern) {
			plan := *p.Verification
			plan.Atoms = slices.Clone(plan.Atoms)
			plan.Atoms[0].Mask = nil
			p.Verification = &plan
		}},
		{"empty verification code", "$forward", "forward code", func(p *serializedRegexPattern) {
			plan := *p.Verification
			plan.Atoms = slices.Clone(plan.Atoms)
			plan.Atoms[0].Forward = nil
			p.Verification = &plan
		}},
		{"empty alternation tail", "$bounded", "tail code", func(p *serializedRegexPattern) {
			plan := *p.BoundedAlternation
			plan.Tail = nil
			p.BoundedAlternation = &plan
		}},
		{"repeat branch bounds", "$repeat", "literal branch", func(p *serializedRegexPattern) {
			plan := *p.BoundedAlternation
			repeat := *plan.Repeat
			repeat.Branches = slices.Clone(repeat.Branches)
			repeat.Branches[0].AtomOffset = -1
			plan.Repeat = &repeat
			p.BoundedAlternation = &plan
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pattern := serialized[tc.id]
			tc.change(&pattern)
			if err := validateSerializedRegexPattern(pattern); err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("validateSerializedRegexPattern() = %v, want %q error", err, tc.message)
			}
		})
	}
}
