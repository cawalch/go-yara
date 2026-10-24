// Package engine contains the small, deliberately limited Wasm spike API.
package engine

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/cawalch/go-yara/compiler"
)

const MaxRules = 32 * 1024
const MaxInput = 8 * 1024 * 1024

type Session struct{ scanner *compiler.Scanner }
type Reply struct {
	Error   string   `json:"error,omitempty"`
	Matches []string `json:"matches"`
	Millis  float64  `json:"ms"`
}

func (s *Session) Compile(rules string) Reply {
	if s.scanner != nil {
		s.scanner.Close()
		s.scanner = nil
	}
	start := time.Now()
	if len(rules) > MaxRules {
		return Reply{Error: "rules exceed 32 KiB"}
	}
	p, err := compiler.NewCompiler().CompileSource(rules)
	if err != nil {
		return Reply{Error: err.Error()}
	}
	s.scanner = p.NewScanner()
	return Reply{Millis: float64(time.Since(start).Nanoseconds()) / 1e6}
}

func (s *Session) Scan(data []byte) Reply {
	if s.scanner == nil {
		return Reply{Error: "compile rules first"}
	}
	if len(data) > MaxInput {
		return Reply{Error: "input exceeds 8 MiB"}
	}
	start := time.Now()
	result, err := s.scanner.Scan(data)
	if err != nil {
		return Reply{Error: err.Error()}
	}
	// Preserve all reported occurrences for the parity checks. This prototype
	// does not impose a result-size budget or truncate counts used by conditions.
	items := []string{}
	for _, rule := range result.MatchedRules {
		items = append(items, "rule:"+rule.Rule)
	}
	for rule, patterns := range result.Matches {
		for pattern, matches := range patterns {
			for _, match := range matches {
				items = append(items, fmt.Sprintf("%s/%s@%d+%d", rule, pattern, match.Offset, match.Length))
			}
		}
	}
	sort.Strings(items)
	return Reply{Matches: items, Millis: float64(time.Since(start).Nanoseconds()) / 1e6}
}

func (s *Session) Close() {
	if s.scanner != nil {
		s.scanner.Close()
		s.scanner = nil
	}
}

//go:embed fixtures.json
var Fixtures []byte

type Fixture struct {
	Name  string   `json:"name"`
	Rules string   `json:"rules"`
	Hex   string   `json:"hex"`
	Want  []string `json:"want"`
	Error bool     `json:"error"`
}

func Check() (int, error) {
	var fixtures []Fixture
	if err := json.Unmarshal(Fixtures, &fixtures); err != nil {
		return 0, err
	}
	s := new(Session)
	defer s.Close()
	for i, f := range fixtures {
		r := s.Compile(f.Rules)
		if f.Error {
			if r.Error == "" {
				return i, fmt.Errorf("%s: expected compile error", f.Name)
			}
			continue
		}
		if r.Error != "" {
			return i, fmt.Errorf("%s: %s", f.Name, r.Error)
		}
		data, err := hex.DecodeString(f.Hex)
		if err != nil {
			return i, err
		}
		for repeat := 0; repeat < 3; repeat++ {
			r = s.Scan(data)
			if r.Error != "" || !reflect.DeepEqual(r.Matches, f.Want) {
				return i, fmt.Errorf("%s: got %+v, want %v", f.Name, r, f.Want)
			}
		}
	}
	return len(fixtures), nil
}
