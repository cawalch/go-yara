package regex

import (
	"context"
	"slices"
)

// ExecMatchEndsBatchWithCancel returns every accepting absolute end position for
// an attempt anchored at start. Ends are unique and increasing. Selection flags
// do not prune paths; other flags, including wide and fullword, still apply.
// Results borrow batch storage until the next endpoint collection or Release;
// ordinary matching calls preserve them. With a nil batch the caller owns the
// results. Cancellation discards partial results.
//
//nolint:revive // endpoint storage accompanies the existing VM arguments
func ExecMatchEndsBatchWithCancel(bs *VMBatch, code, input []byte, flags Flags, start int, done <-chan struct{}) ([]int, error) {
	if vmCanceled(done) {
		return nil, context.Canceled
	}
	if len(code) == 0 || start < 0 || start > len(input) {
		return nil, nil
	}
	if bs == nil {
		bs = &VMBatch{}
		defer bs.Release()
		ends, err := ExecMatchEndsBatchWithCancel(bs, code, input, flags, start, done)
		return slices.Clone(ends), err
	}
	if bs.st == nil {
		bs.Prepare(len(code))
	}
	st := bs.st
	if cap(st.visited) < len(code) {
		st.visited = make([]int64, len(code))
	}
	ends := st.ends[:0]
	visited := st.visited[:len(code)]
	cur, next := st.cur[:0], st.next[:0]
	gen := bs.gen
	defer func() {
		bs.gen = gen + 1
		st.gen = gen
		st.cur, st.next = cur[:0], next[:0]
		st.ends = ends[:0]
	}()
	flags |= FlagsGreedy | FlagsExhaustive
	bestEnd := -1
	if addThread(code, input, &cur, 0, start, visited, gen, flags) {
		bestEnd = start
		ends = append(ends, start)
	}
	step := 1
	if flags&FlagsWide != 0 {
		step = 2
	}
	advance := newVMStep(code, input, flags, visited, &cur, &next, &gen, &bestEnd)
	for pos := start; pos+step <= len(input) && len(cur) > 0; pos += step {
		if done != nil && (pos-start)&(vmCancellationInterval-1) == 0 && vmCanceled(done) {
			return nil, context.Canceled
		}
		if step == 2 && !isWidePair(input, pos) {
			break
		}
		previous := bestEnd
		advance(pos, input[pos], step)
		cur, next = next, cur
		if bestEnd > previous {
			ends = append(ends, bestEnd)
		}
	}
	if vmCanceled(done) {
		return nil, context.Canceled
	}
	return ends, nil
}
