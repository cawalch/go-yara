package regex

// Compiler turns an AST into bytecode for the Thompson VM layout we target.
// This is an initial subset matching our currently supported AST nodes.

import (
	"errors"
	"fmt"
	"slices"
)

// Compiler emits Thompson VM bytecode from a parsed regex AST.
type Compiler struct {
	e           *Emitter
	nextSplitID byte
}

// NewCompiler constructs a Compiler with a fresh emitter.
func NewCompiler() *Compiler {
	return &Compiler{
		e:           NewEmitter(),
		nextSplitID: 0, // Initialize split ID counter
	}
}

// Compile compiles the AST to bytecode and appends an OpMatch at the end.
func Compile(ast *AST) ([]byte, error) {
	c := NewCompiler()
	if ast == nil || ast.Root == nil {
		return nil, errors.New("regex: empty AST")
	}
	if err := c.emitNode(ast.Root); err != nil {
		return nil, err
	}
	c.e.Emit(OpMatch)
	return c.e.Bytes(), nil
}

func (c *Compiler) cur() int { return len(c.e.buf) }

// int16 bounds used to validate relative jumps/branches.
const (
	minI16 = -1 << 15
	maxI16 = (1 << 15) - 1
)

func toInt16Checked(v int) (int16, error) {
	if v < minI16 || v > maxI16 {
		return 0, fmt.Errorf("relative offset %d out of int16 range", v)
	}
	return int16(v), nil
}

func (c *Compiler) emitSplit(op byte, rel int16) int {
	// Returns index where the 16-bit offset was written (for backpatching).
	c.e.Emit(op)
	c.e.EmitU8(c.nextSplitID)
	c.nextSplitID++
	offIdx := len(c.e.buf)
	c.e.EmitI16(rel)
	return offIdx
}

func (c *Compiler) patchI16(at int, v int16) {
	// at points to the first byte of the 16-bit argument
	// Safe conversion with explicit truncation
	// This conversion is intentional - we're reinterpreting signed int16 bits as uint16 for encoding
	u := uint16(v) // #nosec G115 - intentional reinterpretation of signed bits as unsigned for encoding
	c.e.buf[at+0] = byte(u)
	c.e.buf[at+1] = byte(u >> 8)
}

// emitLiteralNodes handles literal-type nodes
func (c *Compiler) emitLiteralNodes(n *Node) {
	switch n.Kind {
	case NodeLiteral:
		c.e.Emit(OpLiteral).EmitU8(n.Value)
	case NodeNotLiteral:
		c.e.Emit(OpNotLiteral).EmitU8(n.Value)
	case NodeMaskedLiteral:
		c.e.Emit(OpMaskedLiteral).EmitU8(n.Value).EmitU8(n.Mask)
	case NodeMaskedNotLiteral:
		c.e.Emit(OpMaskedNotLiteral).EmitU8(n.Value).EmitU8(n.Mask)
	}
}

// emitClassNodes handles character class nodes
func (c *Compiler) emitClassNodes(n *Node) {
	switch n.Kind {
	case NodeAny:
		c.e.Emit(OpAny)
	case NodeWordChar:
		c.e.Emit(OpWordChar)
	case NodeNonWordChar:
		c.e.Emit(OpNonWordChar)
	case NodeSpace:
		c.e.Emit(OpSpace)
	case NodeNonSpace:
		c.e.Emit(OpNonSpace)
	case NodeDigit:
		c.e.Emit(OpDigit)
	case NodeNonDigit:
		c.e.Emit(OpNonDigit)
	}
}

// emitAnchorNodes handles anchor and boundary nodes
func (c *Compiler) emitAnchorNodes(n *Node) {
	switch n.Kind {
	case NodeAnchorStart:
		c.e.Emit(OpMatchAtStart)
	case NodeAnchorEnd:
		c.e.Emit(OpMatchAtEnd)
	case NodeWordBoundary:
		c.e.Emit(OpWordBoundary)
	case NodeNonWordBoundary:
		c.e.Emit(OpNonWordBoundary)
	}
}

// emitSimpleNode handles simple node types that just emit an opcode
func (c *Compiler) emitSimpleNode(n *Node) {
	switch {
	case n.Kind == NodeLiteral || n.Kind == NodeMaskedLiteral || n.Kind == NodeNotLiteral || n.Kind == NodeMaskedNotLiteral:
		c.emitLiteralNodes(n)
	case n.Kind >= NodeAny && n.Kind <= NodeNonDigit:
		c.emitClassNodes(n)
	case n.Kind >= NodeAnchorStart && n.Kind <= NodeNonWordBoundary:
		c.emitAnchorNodes(n)
	}
}

// emitClassNode handles NodeClass which has complex bitmap logic
func (c *Compiler) emitClassNode(n *Node) {
	c.e.Emit(OpClass)
	// 32-byte bitmap then 1 byte negated
	for i := range 32 {
		c.e.EmitU8(n.Class.Bitmap[i])
	}
	if n.Class.Negated {
		c.e.EmitU8(1)
	} else {
		c.e.EmitU8(0)
	}
}

// emitAltNode handles NodeAlt with split/jump logic
func (c *Compiler) emitAltNode(n *Node) error {
	// split A -> left, B-offset -> right
	splitPos := c.cur()
	offIdx := c.emitSplit(OpSplitA, 0)
	if err := c.emitNode(n.Children[0]); err != nil {
		return err
	}
	// jump over right branch
	jmpPos := c.cur()
	c.e.Emit(OpJump)
	jmpOffIdx := len(c.e.buf)
	c.e.EmitI16(0)
	// patch split to jump to start of right branch
	rightStart := c.cur()
	relI16, err := toInt16Checked(rightStart - splitPos)
	if err != nil {
		return err
	}
	c.patchI16(offIdx, relI16)
	if err = c.emitNode(n.Children[1]); err != nil { //nolint:gocritic // legitimate reassignment, not sloppy
		return err
	}
	end := c.cur()
	// patch jump to end
	jrel, err := toInt16Checked(end - jmpPos)
	if err != nil {
		return err
	}
	c.patchI16(jmpOffIdx, jrel)
	return nil
}

// emitStarNode handles NodeStar with loop logic
func (c *Compiler) emitStarNode(n *Node) error {
	// L1: split L1, L2 (order depends on greediness)
	splitPos := c.cur()
	var offIdx int
	if n.Greedy {
		offIdx = c.emitSplit(OpSplitA, 0)
	} else {
		offIdx = c.emitSplit(OpSplitB, 0)
	}
	// code for e
	if err := c.emitNode(n.Children[0]); err != nil {
		return err
	}
	// jmp back to split
	cur := c.cur()
	back, err := toInt16Checked(splitPos - cur)
	if err != nil {
		return err
	}
	c.e.Emit(OpJump).EmitI16(back)
	// patch split to jump to after loop
	after := c.cur()
	arel, err := toInt16Checked(after - splitPos)
	if err != nil {
		return err
	}
	c.patchI16(offIdx, arel)
	return nil
}

// emitPlusNode handles NodePlus with repetition logic
func (c *Compiler) emitPlusNode(n *Node) error {
	// L1: code for e; split L1, L2 (order depends on greediness)
	start := c.cur()
	if err := c.emitNode(n.Children[0]); err != nil {
		return err
	}
	rel, err := toInt16Checked(start - c.cur())
	if err != nil {
		return err
	}
	if n.Greedy {
		c.emitSplit(OpSplitB, rel)
	} else {
		c.emitSplit(OpSplitA, rel)
	}
	return nil
}

// emitRangeNode handles NodeRange with min/max logic
func (c *Compiler) emitRangeNode(n *Node) error {
	// General lowering for e{min,max}:
	// - Emit 'min' copies of e
	// - If max == min: done
	// - If max is unbounded (we use 65535): then emit a star loop for extra
	// - Else emit (max-min) optional copies via chained splits.
	child := n.Children[0]
	// Emit required minimum copies
	for range n.Start {
		if err := c.emitNode(child); err != nil {
			return err
		}
	}
	if n.End == n.Start {
		return nil
	}
	// Unbounded tail -> star
	if n.End == 65535 {
		star := &Node{Kind: NodeStar, Children: []*Node{child}, Greedy: n.Greedy}
		return c.emitNode(star)
	}
	// Bounded optional tail
	opt := int(n.End - n.Start)
	for range opt {
		splitPos := c.cur()
		var offIdx int
		if n.Greedy {
			offIdx = c.emitSplit(OpSplitA, 0) // try to take one more e first
		} else {
			offIdx = c.emitSplit(OpSplitB, 0) // prefer skipping first
		}
		if err := c.emitNode(child); err != nil {
			return err
		}
		after := c.cur()
		rel, err := toInt16Checked(after - splitPos)
		if err != nil {
			return err
		}
		c.patchI16(offIdx, rel)
	}
	return nil
}

const MaxBytecodeSize = 2 * 1024 * 1024 // 2MB

func (c *Compiler) emitNode(n *Node) error { //nolint:maintidx // high complexity is intentional for performance-critical regex compilation
	if c.cur() > MaxBytecodeSize {
		return fmt.Errorf("regex too large")
	}
	switch n.Kind {
	case NodeClass:
		c.emitClassNode(n)
		return nil
	case NodeConcat:
		return c.emitConcatNode(n)
	case NodeAlt:
		return c.emitAltNode(n)
	case NodeStar:
		return c.emitStarNode(n)
	case NodePlus:
		return c.emitPlusNode(n)
	case NodeRange:
		return c.emitRangeNode(n)
	default:
		// Handle simple nodes
		if c.isSimpleNode(n.Kind) {
			c.emitSimpleNode(n)
			return nil
		}
		return fmt.Errorf("regex: emit unsupported node kind %d", n.Kind)
	}
}

// isSimpleNode checks if the node kind is a simple node
func (c *Compiler) isSimpleNode(kind NodeKind) bool {
	simpleKinds := []NodeKind{
		NodeLiteral, NodeMaskedLiteral, NodeNotLiteral, NodeMaskedNotLiteral,
		NodeAny, NodeWordChar, NodeNonWordChar, NodeSpace, NodeNonSpace,
		NodeDigit, NodeNonDigit, NodeAnchorStart, NodeAnchorEnd,
		NodeWordBoundary, NodeNonWordBoundary,
	}
	return slices.Contains(simpleKinds, kind)
}

// emitConcatNode handles NodeConcat emission
func (c *Compiler) emitConcatNode(n *Node) error {
	for _, ch := range n.Children {
		if err := c.emitNode(ch); err != nil {
			return err
		}
	}
	return nil
}
