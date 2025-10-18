package ast

import "github.com/cawalch/go-yara/token"

// Node is the base interface for all AST nodes
type Node interface {
	// node() ensures only AST nodes can be assigned to this interface
	node()
	// Position returns the position of the node in the source
	Position() token.Position
	// Accept accepts a visitor
	Accept(Visitor) interface{}
}

// Expression is the interface for expression nodes
type Expression interface {
	Node
	expression()
}

// Statement is the interface for statement nodes
type Statement interface {
	Node
	statement()
}