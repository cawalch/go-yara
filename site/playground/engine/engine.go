// Package engine implements the documentation playground's bounded result API.
package engine

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/cawalch/go-yara/compiler"
)

//go:embed limits.json
var limitsJSON []byte

var Limits struct {
	EvidenceFindings int   `json:"evidenceFindings"`
	EvidenceRows     int   `json:"evidenceRows"`
	CaptureBytes     int   `json:"captureBytes"`
	RulesBytes       int   `json:"rulesBytes"`
	InputBytes       int   `json:"inputBytes"`
	OutputBytes      int   `json:"outputBytes"`
	Occurrences      int   `json:"occurrences"`
	Rules            int   `json:"rules"`
	MemoryBytes      int64 `json:"memoryBytes"`
	HeapBytes        int64 `json:"heapBytes"`
	TimeoutMs        int   `json:"timeoutMs"`
	StartupMs        int   `json:"startupMs"`
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

// Evidence summaries deliberately have no field for captured bytes.
type EvidenceField struct {
	Name          string `json:"name"`
	Pattern       string `json:"pattern"`
	Offset        int64  `json:"offset"`
	Length        int    `json:"length"`
	DataTruncated bool   `json:"dataTruncated"`
	Missing       bool   `json:"missing"`
}

type Finding struct {
	Rule          string          `json:"rule"`
	Declaration   string          `json:"declaration"`
	Status        string          `json:"status"`
	AnchorOffset  int64           `json:"anchorOffset"`
	FieldRowCount int             `json:"fieldRowCount"`
	Fields        []EvidenceField `json:"fields"`
}

type Reply struct {
	EvidenceEnabled  bool         `json:"evidenceEnabled"`
	Evidence         []Finding    `json:"evidence"`
	EvidenceCount    int          `json:"evidenceCount"`
	EvidenceRowCount int          `json:"evidenceRowCount"`
	Error            string       `json:"error,omitempty"`
	Rules            []string     `json:"rules"`
	RuleCount        int          `json:"ruleCount"`
	Occurrences      []Occurrence `json:"occurrences"`
	OccurrenceCount  int          `json:"occurrenceCount"`
	Truncated        bool         `json:"truncated"`
	CompileMs        float64      `json:"compileMs"`
	ScanMs           float64      `json:"scanMs"`
}

func Run(rules string, data []byte) Reply { return Scan(rules, data, false) }

func Scan(rules string, data []byte, extractEvidence bool) Reply {
	if len(rules) > Limits.RulesBytes {
		return Reply{Error: "Rule source exceeds 16 KiB."}
	}
	if len(data) > Limits.InputBytes {
		return Reply{Error: "Input exceeds 1 MiB."}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Limits.TimeoutMs)*time.Millisecond)
	defer cancel()
	start := time.Now()
	c := compiler.NewCompiler()
	p, err := c.CompileSourceWithContext(ctx, rules)
	if err != nil {
		// Compiler messages can echo source literals. Return only a location.
		message := "Compilation failed. Check rule syntax and declarations."
		if diagnostics := c.GetErrors(); len(diagnostics) > 0 {
			message = fmt.Sprintf("Compilation failed at line %d, column %d. Check rule syntax and declarations.", diagnostics[0].Line, diagnostics[0].Column)
		}
		return Reply{Error: message}
	}
	compiled := time.Since(start)
	var options []compiler.ScannerOption
	if extractEvidence {
		options = append(options, compiler.WithEvidence(Limits.CaptureBytes))
	}
	s := p.NewScanner(options...)
	defer s.Close()
	start = time.Now()
	result, err := s.ScanWithContext(ctx, data)
	if err != nil {
		return Reply{Error: "Scan did not complete. Try a smaller input or simpler rules."}
	}
	reply := Reply{Evidence: []Finding{}, Rules: []string{}, Occurrences: []Occurrence{}, RuleCount: len(result.MatchedRules), CompileMs: float64(compiled.Nanoseconds()) / 1e6, ScanMs: float64(time.Since(start).Nanoseconds()) / 1e6}
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
	if extractEvidence {
		addEvidence(&reply, result, p)
	}
	return reply
}

// addEvidence selects metadata only; capture Data and anchor Data never enter Reply.
func addEvidence(reply *Reply, result *compiler.ScanResult, program *compiler.CompiledProgram) {
	reply.EvidenceEnabled = true
	reply.Evidence = []Finding{}
	rows := 0
	for _, rule := range program.Rules {
		for _, plan := range rule.EvidencePlans {
			for _, finding := range result.Evidence[rule.Name][plan.Name] {
				reply.EvidenceCount++
				summary := Finding{Rule: rule.Name, Declaration: plan.Name, Status: string(finding.Status), AnchorOffset: finding.Anchor.Offset, Fields: []EvidenceField{}}
				selected := len(reply.Evidence) < Limits.EvidenceFindings
				for _, name := range plan.Fields {
					captures := finding.Fields[name]
					reply.EvidenceRowCount += max(1, len(captures))
					summary.FieldRowCount += max(1, len(captures))
					if !selected {
						continue
					}
					if len(captures) == 0 && rows < Limits.EvidenceRows {
						summary.Fields = append(summary.Fields, EvidenceField{Name: name, Missing: true})
						rows++
					}
					for _, capture := range captures {
						if rows >= Limits.EvidenceRows {
							break
						}
						summary.Fields = append(summary.Fields, EvidenceField{Name: name, Pattern: capture.Pattern, Offset: capture.Offset, Length: capture.Length, DataTruncated: capture.DataTruncated})
						rows++
					}
				}
				if selected {
					reply.Evidence = append(reply.Evidence, summary)
				}
			}
		}
	}
}

func evidenceRows(findings []Finding) int {
	rows := 0
	for _, finding := range findings {
		rows += len(finding.Fields)
	}
	return rows
}

// Encode caps the entire UTF-8 payload, including escaped identifiers and errors.
func Encode(reply Reply) string {
	if len(reply.Error) > 2048 {
		reply.Error = reply.Error[:2048] + "…"
	}
	for {
		reply.Truncated = len(reply.Rules) < reply.RuleCount || len(reply.Occurrences) < reply.OccurrenceCount || len(reply.Evidence) < reply.EvidenceCount || evidenceRows(reply.Evidence) < reply.EvidenceRowCount
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
		if len(reply.Evidence) > 0 {
			reply.Evidence = reply.Evidence[:len(reply.Evidence)/2]
			continue
		}
		if len(reply.Rules) > 0 {
			reply.Rules = reply.Rules[:len(reply.Rules)/2]
			continue
		}
		return `{"error":"Result exceeds the output budget."}`
	}
}
