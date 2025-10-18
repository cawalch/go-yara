package regex

import "testing"

func TestNewNodeDefaultsGreedy(t *testing.T) {
	n := NewNode(NodeLiteral)
	if !n.Greedy {
		t.Fatal("expected new node to default to greedy=true")
	}
}

