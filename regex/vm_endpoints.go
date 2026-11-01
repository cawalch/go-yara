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
	return execMatchEnds(bs, code, input, flags, start, len(input), false, done)
}

// ExecVerifyBatchWithCancel verifies from an atom boundary with a byte budget.
// Forward verification returns the priority endpoint; backwards verification
// returns all starts, using bytecode compiled from the reversed prefix. Input
// remains intact so assertions see physical boundaries, not the budget edge.
// Results have the same ownership as ExecMatchEndsBatchWithCancel.
//
//nolint:revive // explicit VM arguments and verification distance
func ExecVerifyBatchWithCancel(bs *VMBatch, code, input []byte, flags Flags, start, distance int, done <-chan struct{}) ([]int, error) {
	return execMatchEnds(bs, code, input, flags, start, distance, true, done)
}

//nolint:revive // shared directional endpoint driver
func execMatchEnds(bs *VMBatch, code, input []byte, flags Flags, start, distance int, verify bool, done <-chan struct{}) ([]int, error) {
	if vmCanceled(done) {
		return nil, context.Canceled
	}
	if len(code) == 0 || start < 0 || start > len(input) {
		return nil, nil
	}
	if bs == nil {
		bs = &VMBatch{}
		defer bs.Release()
		ends, err := execMatchEnds(bs, code, input, flags, start, distance, verify, done)
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
	backwards := verify && flags&FlagsBackwards != 0
	if verify {
		flags &^= FlagsFullwordEnd
	}
	flags |= FlagsGreedy | FlagsExhaustive
	if verify && !backwards {
		flags &^= FlagsExhaustive
	}
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
	if backwards { //nolint:nestif // separate directional loops preserve the ordinary endpoint hot path
		limit := max(0, start-distance)
		for pos := start; pos-step >= limit && len(cur) > 0; pos -= step {
			if done != nil && (start-pos)&(vmCancellationInterval-1) == 0 && vmCanceled(done) {
				return nil, context.Canceled
			}
			if step == 2 && !isWidePair(input, pos-step) {
				break
			}
			advance(pos, input[pos-step], -step)
			cur, next = next, cur
			if visited[len(code)-1] == gen {
				ends = append(ends, pos-step)
			}
		}
	} else {
		limit := start + min(distance, len(input)-start)
		for pos := start; pos+step <= limit && len(cur) > 0; pos += step {
			if done != nil && (pos-start)&(vmCancellationInterval-1) == 0 && vmCanceled(done) {
				return nil, context.Canceled
			}
			if step == 2 && !isWidePair(input, pos) {
				break
			}
			previous := bestEnd
			// This shortcut accepts only terminal consuming loops, with no
			// assertions. Its input can therefore stop at the byte budget.
			if verify && step == 1 && len(cur) == 1 && fastForwardGreedyTerminalLoop(code, &cur, input[:limit], &pos, flags, &bestEnd, done) {
				if bestEnd > previous {
					ends = append(ends[:0], bestEnd)
				}
				break
			}
			advance(pos, input[pos], step)
			cur, next = next, cur
			if bestEnd > previous {
				if verify {
					ends = append(ends[:0], bestEnd)
				} else {
					ends = append(ends, bestEnd)
				}
			}
		}
	}

	if vmCanceled(done) {
		return nil, context.Canceled
	}
	return ends, nil
}
