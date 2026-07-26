package ast

import (
	"testing"

	"github.com/cawalch/go-yara/token"
)

func TestMetaValueContracts(t *testing.T) {
	tests := []struct {
		name       string
		value      MetaValue
		wantString string
		wantText   string
		wantInt    int64
		wantBool   bool
	}{
		{name: "string", value: MetaString("hello"), wantString: "hello", wantText: "hello"},
		{name: "integer", value: MetaInt(42), wantString: "42", wantInt: 42},
		{name: "true", value: MetaBool(true), wantString: "true", wantBool: true},
		{name: "false", value: MetaBool(false), wantString: "false"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			meta := &Meta{Value: test.value}
			if got := meta.String(); got != test.wantString {
				t.Errorf("String() = %q, want %q", got, test.wantString)
			}
			if got := meta.AsString(); got != test.wantText {
				t.Errorf("AsString() = %q, want %q", got, test.wantText)
			}
			if got := meta.AsInt(); got != test.wantInt {
				t.Errorf("AsInt() = %d, want %d", got, test.wantInt)
			}
			if got := meta.AsBool(); got != test.wantBool {
				t.Errorf("AsBool() = %v, want %v", got, test.wantBool)
			}
		})
	}
}

func TestAdvancedBuilderContracts(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 3, Column: 7}
	value := builder.Literal(pos, token.IntegerLit, 42)
	stringExpr := builder.Identifier(pos, "$a")
	rangeExpr := builder.Identifier(pos, "range")
	condition := builder.Identifier(pos, "condition")

	global := builder.GlobalVariable(pos, "global", value)
	external := builder.ExternalVariable(pos, "external", "binding", "string")
	importNode := builder.Import(pos, "pe")
	include := builder.Include(pos, "common.yar")
	length := builder.StringLength(pos, stringExpr)
	loop := builder.ForLoop(pos, "any", "i", rangeExpr, condition)
	ofExpr := builder.OfExpression(pos, value, stringExpr)
	call := builder.FunctionCall(pos, "pe.section", []Expression{value, stringExpr})

	nodes := []struct {
		name string
		node Node
	}{
		{name: "global variable", node: global},
		{name: "external variable", node: external},
		{name: "import", node: importNode},
		{name: "include", node: include},
		{name: "string length", node: length},
		{name: "for loop", node: loop},
		{name: "of expression", node: ofExpr},
		{name: "function call", node: call},
	}
	for _, test := range nodes {
		t.Run(test.name, func(t *testing.T) {
			if got := test.node.Position(); got != pos {
				t.Fatalf("Position() = %v, want %v", got, pos)
			}
			assertNodeAcceptance(t, test.node, 1)
		})
	}

	if global.Name != "global" || global.Value != value {
		t.Fatalf("GlobalVariable fields = %+v", global)
	}
	if external.Name != "external" || external.Identifier != "binding" || external.TypeHint != "string" {
		t.Fatalf("ExternalVariable fields = %+v", external)
	}
	if importNode.Module != "pe" {
		t.Fatalf("Import.Module = %q, want pe", importNode.Module)
	}
	if include.File != "common.yar" {
		t.Fatalf("Include.File = %q, want common.yar", include.File)
	}
	if length.String != stringExpr {
		t.Fatalf("StringLength.String = %v, want %v", length.String, stringExpr)
	}
	if loop.Quantifier != "any" || len(loop.Variables) != 1 || loop.Variables[0] != "i" ||
		loop.Range != rangeExpr || loop.Condition != condition {
		t.Fatalf("ForLoop fields = %+v", loop)
	}
	if ofExpr.Count != value || ofExpr.Strings != stringExpr {
		t.Fatalf("OfExpression fields = %+v", ofExpr)
	}
	if call.Function != "pe.section" || len(call.Args) != 2 || call.Args[0] != value || call.Args[1] != stringExpr {
		t.Fatalf("FunctionCall fields = %+v", call)
	}
}
