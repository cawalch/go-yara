// Package matrix defines the canonical rules and payloads used by the
// go-yara versus yara-x benchmark tournament.
package matrix

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"slices"
	"strings"
)

// RuleCase is one rule-shape axis in the tournament.
type RuleCase struct {
	Name        string
	Description string
	Source      string
}

// ContentCase is one punctuation-density x match-density axis.
type ContentCase struct {
	Name             string
	DensePunctuation bool
	DenseMatches     bool
}

// Sizes is the fixed input-size axis.
var Sizes = []int{16 << 10, 256 << 10, 1 << 20}

// Contents is the fixed content-shape axis.
var Contents = []ContentCase{
	{Name: "punct_sparse/match_sparse"},
	{Name: "punct_dense/match_sparse", DensePunctuation: true},
	{Name: "punct_sparse/match_dense", DenseMatches: true},
	{Name: "punct_dense/match_dense", DensePunctuation: true, DenseMatches: true},
}

// Rules returns all fixed rule-shape cases. Generated cases use stable source
// so both engines always compile exactly the same rules.
func Rules() []RuleCase {
	return []RuleCase{
		{
			Name:        "literal_single",
			Description: "one literal string",
			Source:      `rule literal_single { strings: $s = "cardnumber" condition: $s }`,
		},
		{
			Name:        "literal_set",
			Description: "overlapping card-field literal set",
			Source: `rule literal_set {
				strings:
					$s1 = "cardnumber"
					$s2 = "cardnum"
					$s3 = "ccnumber"
					$s4 = "cardholder"
					$s5 = "nameoncard"
				condition: any of them
			}`,
		},
		{
			Name:        "regex_literal_alternation",
			Description: "literal-alternation regex",
			Source: `rule regex_literal_alternation {
				strings: $s = /(cardholder|nameoncard|expiry|expiration)\b/
				condition: $s
			}`,
		},
		{
			Name:        "regex_literal_alternation_nocase",
			Description: "nocase literal-alternation regex",
			Source: `rule regex_literal_alternation_nocase {
				strings: $s = /(cardholder|nameoncard|expiry|expiration)\b/ nocase
				condition: $s
			}`,
		},
		{
			Name:        "regex_leading_class",
			Description: "leading character class with required inner literals",
			Source: `rule regex_leading_class {
				strings: $s = /["'#.\[]\s*(cardnumber|cvv|cardholder)\b/ nocase
				condition: $s
			}`,
		},
		{
			Name:        "regex_optional_separator",
			Description: "alternation with optional separators",
			Source: `rule regex_optional_separator {
				strings: $s = /(cardholder|card[-_ ]?holder|nameoncard|name[-_ ]on[-_ ]card)\b/ nocase
				condition: $s
			}`,
		},
		{
			Name:        "regex_no_atom",
			Description: "leading word-boundary regex without a literal prefix",
			Source: `rule regex_no_atom {
				strings: $s = /\beval\s*\(/
				condition: $s
			}`,
		},
		{
			Name:        "regex_mixed_atoms",
			Description: "one no-atom regex mixed with atom-bearing regexes",
			Source: `rule regex_mixed_atoms {
				strings:
					$exec1 = /\beval\s*\(/
					$exec2 = /new\s+Function\s*\(/
					$hexvar = /_0x[0-9a-f]{4,6}/
					$ws = /new\s+WebSocket\s*\(\s*["']wss?:\/\//
				condition: any of them
			}`,
		},
		{
			Name:        "string_count",
			Description: "string count condition",
			Source: `rule string_count {
				strings: $s = "skimmer"
				condition: #s > 8
			}`,
		},
		{
			Name:        "set_quantifier",
			Description: "set quantifier over literals",
			Source: `rule set_quantifier {
				strings:
					$x1 = "cardnumber" nocase
					$x2 = "cvv" nocase
					$x3 = "expiry" nocase
					$x4 = "cardholder" nocase
					$x5 = "sendBeacon" nocase
				condition: 3 of ($x*)
			}`,
		},
		{
			Name:        "regex_set_16",
			Description: "sixteen atomized regex rules",
			Source:      regexRuleSet(16),
		},
		{
			Name:        "private_shared_8",
			Description: "one private rule referenced by eight public rules",
			Source:      privateSharedRules(8),
		},
		{
			Name:        "combined_card_regexes",
			Description: "four flexible card-field regexes",
			Source:      combinedCardRegexes,
		},
		{
			Name:        "combined_skimmer_regex",
			Description: "realistic private-rule skimmer regex ruleset",
			Source:      combinedSkimmerRegex,
		},
		{
			Name:        "combined_skimmer_literals",
			Description: "literal-string control for the skimmer ruleset",
			Source:      combinedSkimmerLiterals,
		},
	}
}

const combinedCardRegexes = `rule combined_card_regexes {
	strings:
		$c1 = /["'#.\[]\s*(card[-_ ]?number|cardnum|ccnumber|cc[-_]number|pan)\b/ nocase
		$c2 = /["'#.\[]\s*(cvv|cvc|cvv2|card[-_ ]?cvc|securitycode|security[-_ ]code)\b/ nocase
		$c3 = /(exp[-_ ]?date|expir(y|ation)|card[-_ ]?expiry|cc[-_]exp)\b/ nocase
		$c4 = /(cardholder|card[-_ ]?holder|nameoncard|name[-_ ]on[-_ ]card)\b/ nocase
	condition: 2 of ($c*)
}`

const combinedSkimmerRegex = `
private rule card_fields_regex {
	strings:
		$c1 = /["'#.\[]\s*(card[-_ ]?number|cardnum|ccnumber|cc[-_]number|pan)\b/ nocase
		$c2 = /["'#.\[]\s*(cvv|cvc|cvv2|card[-_ ]?cvc|securitycode|security[-_ ]code)\b/ nocase
		$c3 = /(exp[-_ ]?date|expir(y|ation)|card[-_ ]?expiry|cc[-_]exp)\b/ nocase
		$c4 = /(cardholder|card[-_ ]?holder|nameoncard|name[-_ ]on[-_ ]card)\b/ nocase
	condition: 2 of ($c*)
}

private rule script_signals_regex {
	strings:
		$exec1 = /\beval\s*\(/
		$exec2 = /new\s+Function\s*\(/
		$hexvar = /_0x[0-9a-f]{4,6}/
		$ws = /new\s+WebSocket\s*\(\s*["']wss?:\/\//
	condition: any of them
}

rule combined_skimmer_regex {
	strings: $beacon = "sendBeacon"
	condition: card_fields_regex and script_signals_regex and $beacon
}`

const combinedSkimmerLiterals = `
private rule card_fields_literals {
	strings:
		$c1 = "cardnumber" nocase
		$c2 = "card_number" nocase
		$c3 = "cardnum" nocase
		$c4 = "ccnumber" nocase
		$c5 = "cvv" nocase
		$c6 = "cvc" nocase
		$c7 = "cvv2" nocase
		$c8 = "securitycode" nocase
		$c9 = "cardholder" nocase
		$c10 = "nameoncard" nocase
	condition: 2 of ($c*)
}

private rule script_signals_literals {
	strings:
		$exec1 = "eval("
		$exec2 = "new Function("
		$hexvar = "_0x1a2b"
		$ws = "new WebSocket("
	condition: any of them
}

rule combined_skimmer_literals {
	strings: $beacon = "sendBeacon"
	condition: card_fields_literals and script_signals_literals and $beacon
}`

const (
	sparseFiller = " benignFillerCode123 safePayloadToken "
	denseFiller  = `a.b['c']="d";x.y("z");{"key":[1,2,3],"ok":true};`
	matchChunk   = `d={"card_number":q('#cardnumber').v,"cvv":q('input[name="cvv"]').v,"exp_date":q('#expiry').v,"cardholder":q('#nameoncard').v,"cvc":q('#card-cvc').v};sendBeacon; eval( new Function( _0x1a2b new WebSocket("ws:// skimmer skimmer skimmer skimmer skimmer skimmer skimmer skimmer skimmer alpha bravo charlie delta echo marker_00 marker_01 marker_02 marker_03 marker_04 marker_05 marker_06 marker_07 marker_08 marker_09 marker_10 marker_11 marker_12 marker_13 marker_14 marker_15 `
)

// Data returns deterministic input with exactly size bytes.
func Data(content ContentCase, size int) []byte {
	if size <= 0 {
		return nil
	}
	filler := sparseFiller
	if content.DensePunctuation {
		filler = denseFiller
	}
	chunk := filler
	if content.DenseMatches {
		chunk = matchChunk + filler
	}
	var data bytes.Buffer
	data.Grow(size + len(chunk))
	for data.Len() < size {
		data.WriteString(chunk)
	}
	return data.Bytes()[:size]
}

// MatchFingerprint returns a deterministic fingerprint of matching public
// rule names. Zero represents no matching rules.
func MatchFingerprint(names []string) uint32 {
	if len(names) == 0 {
		return 0
	}
	names = slices.Clone(names)
	slices.Sort(names)
	hash := fnv.New32a()
	for _, name := range names {
		_, _ = hash.Write([]byte(name))
		_, _ = hash.Write([]byte{0})
	}
	return hash.Sum32()
}

func regexRuleSet(count int) string {
	var source strings.Builder
	for index := range count {
		fmt.Fprintf(&source, `rule regex_set_%02d {
	strings: $pattern = /["'#.\[]\s*(marker_%02d|token_%02d)\b/ nocase
	condition: $pattern
}
`, index, index, index)
	}
	return source.String()
}

func privateSharedRules(count int) string {
	var source strings.Builder
	source.WriteString(`private rule shared_card_fields {
	strings:
		$s1 = "cardnumber" nocase
		$s2 = "cvv" nocase
		$s3 = "cardholder" nocase
	condition: 2 of them
}
`)
	for index := range count {
		fmt.Fprintf(&source, "rule shared_consumer_%02d { condition: shared_card_fields }\n", index)
	}
	return source.String()
}
