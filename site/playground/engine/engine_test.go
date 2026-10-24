package engine

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestFixtures(t *testing.T) {
	data, err := os.ReadFile("../tests/fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name, Rules, Hex string
		Want             []string
		Error            bool
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			data, err := hex.DecodeString(f.Hex)
			if err != nil {
				t.Fatal(err)
			}
			r := Run(f.Rules, data)
			if f.Error {
				if r.Error == "" {
					t.Fatal("expected compilation failure")
				}
				return
			}
			if r.Error != "" {
				t.Fatal(r.Error)
			}
			got := []string{}
			for _, name := range r.Rules {
				got = append(got, "rule:"+name)
			}
			for _, m := range r.Occurrences {
				got = append(got, fmt.Sprintf("%s/%s@%d+%d", m.Rule, m.Pattern, m.Offset, m.Length))
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, f.Want) {
				t.Fatalf("got %v, want %v", got, f.Want)
			}
		})
	}
}

func TestDisplayLimitsPreserveConditions(t *testing.T) {
	r := Run(`rule yes { strings: $a="a" condition: #a == 300 and @a[300] == 299 } rule no { strings: $a="a" condition: #a == 200 }`, []byte(strings.Repeat("a", 300)))
	var wire Reply
	if err := json.Unmarshal([]byte(Encode(r)), &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Error != "" || !reflect.DeepEqual(wire.Rules, []string{"yes"}) || wire.OccurrenceCount != 600 || len(wire.Occurrences) != Limits.Occurrences || !wire.Truncated {
		t.Fatalf("%+v", wire)
	}
}

func TestWireByteBudget(t *testing.T) {
	r := Reply{RuleCount: 100, OccurrenceCount: 200}
	for range 100 {
		r.Rules = append(r.Rules, strings.Repeat("long", 1000))
	}
	for range 200 {
		r.Occurrences = append(r.Occurrences, Occurrence{Rule: strings.Repeat("<&", 1000)})
	}
	encoded := Encode(r)
	if len(encoded) > Limits.OutputBytes || !json.Valid([]byte(encoded)) {
		t.Fatal("invalid output budget")
	}
	if len(Encode(Reply{Error: strings.Repeat("<&", 100000)})) > Limits.OutputBytes {
		t.Fatal("unbounded error")
	}
}

func TestInputLimits(t *testing.T) {
	if Run(strings.Repeat(" ", Limits.RulesBytes+1), nil).Error == "" {
		t.Fatal("source limit")
	}
	if Run(`rule r { condition: true }`, make([]byte, Limits.InputBytes+1)).Error == "" {
		t.Fatal("input limit")
	}
}
