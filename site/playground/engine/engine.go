// Package engine implements the documentation playground's bounded result API.
package engine

import (
	"context"
	_ "embed"
	"encoding/json"
	"sort"
	"time"

	"github.com/cawalch/go-yara/compiler"
)

//go:embed limits.json
var limitsJSON []byte

var Limits struct {
	RulesBytes  int   `json:"rulesBytes"`
	InputBytes  int   `json:"inputBytes"`
	OutputBytes int   `json:"outputBytes"`
	Occurrences int   `json:"occurrences"`
	Rules       int   `json:"rules"`
	MemoryBytes int64 `json:"memoryBytes"`
	HeapBytes   int64 `json:"heapBytes"`
	TimeoutMs   int   `json:"timeoutMs"`
	StartupMs   int   `json:"startupMs"`
}

func init() {
	if err := json.Unmarshal(limitsJSON, &Limits); err != nil {
		panic(err)
	}
}

type Occurrence struct {
	Rule    string `json:"rule"`
	Pattern string `json:"pattern"`
	Offset  int64  `json:"offset"`
	Length  int    `json:"length"`
}

type Reply struct {
	Error           string       `json:"error,omitempty"`
	Rules           []string     `json:"rules"`
	RuleCount       int          `json:"ruleCount"`
	Occurrences     []Occurrence `json:"occurrences"`
	OccurrenceCount int          `json:"occurrenceCount"`
	Truncated       bool         `json:"truncated"`
	CompileMs       float64      `json:"compileMs"`
	ScanMs          float64      `json:"scanMs"`
}

func Run(rules string, data []byte) Reply {
	if len(rules) > Limits.RulesBytes {
		return Reply{Error: "Rule source exceeds 16 KiB."}
	}
	if len(data) > Limits.InputBytes {
		return Reply{Error: "Input exceeds 1 MiB."}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Limits.TimeoutMs)*time.Millisecond)
	defer cancel()
	start := time.Now()
	p, err := compiler.NewCompiler().CompileSourceWithContext(ctx, rules)
	if err != nil {
		return Reply{Error: "Compilation failed: " + err.Error()}
	}
	compiled := time.Since(start)
	s := p.NewScanner()
	defer s.Close()
	start = time.Now()
	result, err := s.ScanWithContext(ctx, data)
	if err != nil {
		return Reply{Error: "Scan did not complete: " + err.Error()}
	}
	reply := Reply{Rules: []string{}, Occurrences: []Occurrence{}, RuleCount: len(result.MatchedRules), CompileMs: float64(compiled.Nanoseconds()) / 1e6, ScanMs: float64(time.Since(start).Nanoseconds()) / 1e6}
	for _, rule := range result.MatchedRules {
		reply.Rules = append(reply.Rules, rule.Rule)
	}
	sort.Strings(reply.Rules)
	if len(reply.Rules) > Limits.Rules {
		reply.Rules = reply.Rules[:Limits.Rules]
	}
	// Limit presentation only. Never cap the scanner's occurrence collection:
	// doing so could change #a, @a, ranges, or other condition results.
	keys := make([]string, 0, len(result.Matches))
	for rule := range result.Matches {
		keys = append(keys, rule)
	}
	sort.Strings(keys)
	for _, rule := range keys {
		patterns := make([]string, 0, len(result.Matches[rule]))
		for pattern := range result.Matches[rule] {
			patterns = append(patterns, pattern)
		}
		sort.Strings(patterns)
		for _, pattern := range patterns {
			matches := result.Matches[rule][pattern]
			reply.OccurrenceCount += len(matches)
			for _, match := range matches {
				if len(reply.Occurrences) >= Limits.Occurrences {
					break
				}
				reply.Occurrences = append(reply.Occurrences, Occurrence{Rule: rule, Pattern: pattern, Offset: match.Offset, Length: match.Length})
			}
		}
	}
	return reply
}

// Encode caps the entire UTF-8 payload, including escaped identifiers and errors.
func Encode(reply Reply) string {
	if len(reply.Error) > 2048 {
		reply.Error = reply.Error[:2048] + "…"
	}
	for {
		reply.Truncated = len(reply.Rules) < reply.RuleCount || len(reply.Occurrences) < reply.OccurrenceCount
		encoded, err := json.Marshal(reply)
		if err != nil {
			return `{"error":"Could not encode scan results."}`
		}
		if len(encoded) <= Limits.OutputBytes {
			return string(encoded)
		}
		if len(reply.Occurrences) > 0 {
			reply.Occurrences = reply.Occurrences[:len(reply.Occurrences)/2]
			continue
		}
		if len(reply.Rules) > 0 {
			reply.Rules = reply.Rules[:len(reply.Rules)/2]
			continue
		}
		return `{"error":"Result exceeds the output budget."}`
	}
}
