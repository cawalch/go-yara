package ast

import (
	"reflect"
	"testing"

	"github.com/cawalch/go-yara/token"
)

func TestEvidenceASTBuilder(t *testing.T) {
	position := token.Position{Line: 7, Column: 5}
	builder := NewBuilder()
	declaration := builder.EvidenceDeclaration(
		position,
		"credential",
		[]string{"endpoint", "username", "secret"},
		"secret",
		4096,
	)
	if declaration.Pos != position || declaration.Name != "credential" || declaration.Anchor != "secret" || declaration.Within != 4096 ||
		!reflect.DeepEqual(declaration.Fields, []string{"endpoint", "username", "secret"}) {
		t.Fatalf("EvidenceDeclaration() = %#v", declaration)
	}
	if declaration.Position() != position {
		t.Fatalf("Position() = %#v, want %#v", declaration.Position(), position)
	}
	visitor := &evidenceCountingVisitor{}
	if got := declaration.Accept(visitor); got != "credential" || visitor.count != 1 {
		t.Fatalf("Accept() = %#v, count = %d", got, visitor.count)
	}
	rule := builder.Rule(position, "structured")
	rule.Evidence = []*EvidenceDeclaration{declaration}
	rule.Strings = []*String{{
		Identifier: "$pair",
		Modifiers: []StringModifier{{
			Type: StringModifierCapture,
			Value: []CaptureBinding{
				{Name: "username", Group: 1},
				{Name: "secret", Group: 2},
			},
		}},
	}}
	if len(rule.Evidence) != 1 || len(rule.Strings[0].Modifiers) != 1 {
		t.Fatalf("rule evidence AST = %#v", rule)
	}
}

type evidenceCountingVisitor struct {
	BaseVisitor
	count int
}

func (visitor *evidenceCountingVisitor) VisitEvidenceDeclaration(declaration *EvidenceDeclaration) any {
	visitor.count++
	return declaration.Name
}
