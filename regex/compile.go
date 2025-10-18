package regex

// Compiler turns an AST into bytecode for the Thompson VM layout we target.
// This is an initial subset matching our currently supported AST nodes.

import (
	"fmt"
)

// Compiler emits Thompson VM bytecode from a parsed regex AST.
type Compiler struct{
    e *Emitter
    nextSplitID byte
}

 // NewCompiler constructs a Compiler with a fresh emitter.
func NewCompiler() *Compiler { return &Compiler{e: NewEmitter()} }

// Compile compiles the AST to bytecode and appends an OpMatch at the end.
func Compile(ast *AST) ([]byte, error) {
    c := NewCompiler()
    if ast == nil || ast.Root == nil {
        return nil, fmt.Errorf("regex: empty AST")
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
    u := uint16(v) //nolint:gosec // reinterpret signed int16 bits for encoding
    c.e.buf[at+0] = byte(u)
    c.e.buf[at+1] = byte(u >> 8)
}

func (c *Compiler) emitNode(n *Node) error {
    switch n.Kind {
    case NodeLiteral:
        c.e.Emit(OpLiteral).EmitU8(n.Value)
        return nil
    case NodeNotLiteral:
        c.e.Emit(OpNotLiteral).EmitU8(n.Value)
        return nil
    case NodeMaskedLiteral:
        c.e.Emit(OpMaskedLiteral).EmitU8(n.Value).EmitU8(n.Mask)
        return nil
    case NodeMaskedNotLiteral:
        c.e.Emit(OpMaskedNotLiteral).EmitU8(n.Value).EmitU8(n.Mask)
        return nil
    case NodeAny:
        c.e.Emit(OpAny)
        return nil
    case NodeClass:
        c.e.Emit(OpClass)
        // 32-byte bitmap then 1 byte negated
        for i := 0; i < 32; i++ { c.e.EmitU8(n.Class.Bitmap[i]) }
        if n.Class.Negated { c.e.EmitU8(1) } else { c.e.EmitU8(0) }
        return nil
    case NodeWordChar:
        c.e.Emit(OpWordChar); return nil
    case NodeNonWordChar:
        c.e.Emit(OpNonWordChar); return nil
    case NodeSpace:
        c.e.Emit(OpSpace); return nil
    case NodeNonSpace:
        c.e.Emit(OpNonSpace); return nil
    case NodeDigit:
        c.e.Emit(OpDigit); return nil
    case NodeNonDigit:
        c.e.Emit(OpNonDigit); return nil
    case NodeAnchorStart:
        c.e.Emit(OpMatchAtStart); return nil
    case NodeAnchorEnd:
        c.e.Emit(OpMatchAtEnd); return nil
    case NodeWordBoundary:
        c.e.Emit(OpWordBoundary); return nil
    case NodeNonWordBoundary:
        c.e.Emit(OpNonWordBoundary); return nil
    case NodeConcat:
        for _, ch := range n.Children {
            if err := c.emitNode(ch); err != nil { return err }
        }
        return nil
    case NodeAlt:
        // split A -> left, B-offset -> right
        splitPos := c.cur()
        offIdx := c.emitSplit(OpSplitA, 0)
        if err := c.emitNode(n.Children[0]); err != nil { return err }
        // jump over right branch
        jmpPos := c.cur()
        c.e.Emit(OpJump)
        jmpOffIdx := len(c.e.buf)
        c.e.EmitI16(0)
        // patch split to jump to start of right branch
        rightStart := c.cur()
        relI16, err := toInt16Checked(rightStart - splitPos)
        if err != nil { return err }
        c.patchI16(offIdx, relI16)
        if err = c.emitNode(n.Children[1]); err != nil { return err }
        end := c.cur()
        // patch jump to end
        jrel, err := toInt16Checked(end - jmpPos)
        if err != nil { return err }
        c.patchI16(jmpOffIdx, jrel)
        return nil
    case NodeStar:
        // L1: split L1, L2 (order depends on greediness)
        splitPos := c.cur()
        var offIdx int
        if n.Greedy {
            offIdx = c.emitSplit(OpSplitA, 0)
        } else {
            offIdx = c.emitSplit(OpSplitB, 0)
        }
        // code for e
        if err := c.emitNode(n.Children[0]); err != nil { return err }
        // jmp back to split
        cur := c.cur()
        back, err := toInt16Checked(splitPos - cur)
        if err != nil { return err }
        c.e.Emit(OpJump).EmitI16(back)
        // patch split to jump to after loop
        after := c.cur()
        arel, err := toInt16Checked(after - splitPos)
        if err != nil { return err }
        c.patchI16(offIdx, arel)
        return nil
    case NodePlus:
        // L1: code for e; split L1, L2 (order depends on greediness)
        start := c.cur()
        if err := c.emitNode(n.Children[0]); err != nil { return err }
        rel, err := toInt16Checked(start - c.cur())
        if err != nil { return err }
        if n.Greedy {
            c.emitSplit(OpSplitB, rel)
        } else {
            c.emitSplit(OpSplitA, rel)
        }
        return nil
    case NodeRange:
        // General lowering for e{min,max}:
        // - Emit 'min' copies of e
        // - If max == min: done
        // - If max is unbounded (we use 65535): then emit a star loop for extra
        // - Else emit (max-min) optional copies via chained splits.
        child := n.Children[0]
        // Emit required minimum copies
        for i := 0; i < int(n.Start); i++ {
            if err := c.emitNode(child); err != nil { return err }
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
        for i := 0; i < opt; i++ {
            splitPos := c.cur()
            var offIdx int
            if n.Greedy {
                offIdx = c.emitSplit(OpSplitA, 0) // try to take one more e first
            } else {
                offIdx = c.emitSplit(OpSplitB, 0) // prefer skipping first
            }
            if err := c.emitNode(child); err != nil { return err }
            after := c.cur()
            rel, err := toInt16Checked(after - splitPos)
            if err != nil { return err }
            c.patchI16(offIdx, rel)
        }
        return nil
    default:
        return fmt.Errorf("regex: emit unsupported node kind %d", n.Kind)
    }
}

