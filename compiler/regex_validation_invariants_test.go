package compiler

import (
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func TestDeserializeRegexPatternNormalizesAbsentAtom(t *testing.T) {
	// Formats 4-19 leave atom bounds at zero when no atom was stored.
	pattern := deserializeRegexPattern(serializedRegexPattern{AtomMaxOffset: 5, AtomMaxSuffix: 5})
	if pattern.atomMinOffset != 0 || pattern.atomMaxOffset != -1 || pattern.atomMaxSuffix != -1 {
		t.Fatalf("absent atom bounds = (%d,%d,%d), want (0,-1,-1)",
			pattern.atomMinOffset, pattern.atomMaxOffset, pattern.atomMaxSuffix)
	}
}

func TestSplitVerificationNodeRejectsZeroStartRange(t *testing.T) {
	child := &regex.Node{Kind: regex.NodeLiteral, Value: 'a'}
	node := &regex.Node{Kind: regex.NodeRange, Start: 0, End: 3, Children: []*regex.Node{child}}
	if _, _, found := splitVerificationNode(node, child); found {
		t.Fatal("splitVerificationNode accepted a {0,n} range target")
	}
}
