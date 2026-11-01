package regex

// plusEntry follows libyara's emitted instruction reference, rather than the
// beginning of the child's bytecode. A {0,1} range references its body, so a
// plus backedge skips that optional split (including through concatenations
// and mandatory ranges). The first iteration still executes the whole child.
func (c *Compiler) plusEntry(node *Node, start int) (int, []byte) {
	entry := start
	var saves []byte
	skipped := false
walk:
	for {
		switch node.Kind {
		case NodeGroup:
			if slot, ok := c.captureSlot[node.Group]; ok {
				saves = append(saves, slot)
				entry += 2 // OpSaveStart and its slot.
			}
		case NodeConcat, NodePlus:
		case NodeRange:
			if node.Start == 0 {
				if node.End != 1 {
					break walk
				}
				entry += 3 // Optional split and its relative offset.
				skipped = true
			}
		default:
			break walk
		}
		if len(node.Children) == 0 {
			break walk
		}
		node = node.Children[0]
	}
	if !skipped {
		return start, nil
	}
	return entry, saves
}

// Capture replay needs the same loop target, with the skipped opening tags
// restored on each iteration. Keep these tags on the repeating branch only.
func (c *Compiler) emitCaptureRepeat(entry int, saves []byte, greedy bool) error {
	split := c.cur()
	op := byte(OpSplitB)
	if greedy {
		op = OpSplitA
	}
	offset := c.emitSplit(op, 0)
	for _, slot := range saves {
		c.e.Emit(OpSaveStart).EmitU8(slot)
	}
	back, err := toInt16Checked(entry - c.cur())
	if err != nil {
		return err
	}
	c.e.Emit(OpJump).EmitI16(back)
	after, err := toInt16Checked(c.cur() - split)
	if err != nil {
		return err
	}
	c.patchI16(offset, after)
	return nil
}
