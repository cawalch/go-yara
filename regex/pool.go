package regex

import (
	"sync"
	"sync/atomic"
)

// vmState holds the reusable per-match buffers for runAtMatch.
// Using sync.Pool avoids the dominant allocation cost in the regex VM:
// every call to runAtMatch previously allocated visited ([]int64 generation counter),
// cur, and next ([]thread).
//
// The visited array uses a generation counter (int64) instead of []bool to avoid
// calling clear() on every step/thread iteration. A global atomic counter ensures
// each runAtMatch call gets a fresh generation even when the buffer is reused.
type vmState struct {
	visited []int64 // generation counter per bytecode position
	cur     []thread
	next    []thread
}

// vmGen is a global monotonically increasing generation counter.
// Each call to runAtMatch atomically increments it so that pooled visited[]
// arrays never need to be zeroed — stale entries from previous uses are
// automatically invalidated by the new generation value.
var vmGen atomic.Int64

// vmPool is a sync.Pool for vmState instances.
var vmPool = sync.Pool{
	New: func() any {
		return &vmState{
			visited: make([]int64, 256),
			cur:     make([]thread, 0, 32),
			next:    make([]thread, 0, 32),
		}
	},
}

// getVMState retrieves a vmState from the pool, growing visited if needed.
// Returns the start of a generation block for this match attempt.
// Each match reserves a block of 1M generation values to avoid atomic overhead per step.
// Stale values in the visited array are safe because the new block start is unique.
func getVMState(codeLen int) (*vmState, int64) {
	st := vmPool.Get().(*vmState)
	if cap(st.visited) < codeLen {
		st.visited = make([]int64, codeLen)
	}
	st.visited = st.visited[:codeLen]
	st.cur = st.cur[:0]
	st.next = st.next[:0]
	return st, vmGen.Add(1 << 20) // Reserve 1M generation values per match
}

// putVMState returns a vmState to the pool.
// If visited is very large (> 4KB) we don't return it to avoid keeping
// huge slices in the pool for one-off large regexes.
func putVMState(st *vmState) {
	if cap(st.visited) > 4096 {
		// Too large to pool; let GC handle it.
		return
	}
	st.visited = st.visited[:0]
	st.cur = st.cur[:0]
	st.next = st.next[:0]
	vmPool.Put(st)
}

// vmBatchState holds a vmState pinned for a batch of runAtMatch calls.
// This avoids sync.Pool Get/Put overhead when runAtMatch is called
// thousands of times in a tight loop (e.g., addRegexMatches).
type vmBatchState struct {
	st  *vmState
	gen int64 // remaining generation values in current batch
}

// NewVMBatch acquires a vmState for a batch of runAtMatch calls.
// Returns a release function to call when the batch is complete.
// Use when calling runAtMatch thousands of times in a tight loop.
func NewVMBatch(codeLen int) (*vmBatchState, func()) {
	st := vmPool.Get().(*vmState)
	if cap(st.visited) < codeLen {
		st.visited = make([]int64, codeLen)
	}
	bs := &vmBatchState{
		st:  st,
		gen: vmGen.Add(1 << 20),
	}
	return bs, func() {
		if cap(st.visited) <= 4096 {
			st.visited = st.visited[:0]
			st.cur = st.cur[:0]
			st.next = st.next[:0]
			vmPool.Put(st)
		}
	}
}

// get returns a vmState and generation token for one runAtMatch call.
// The visited, cur, and next slices are reset for each call.
// NOTE: This method is inlined directly into runAtMatchBatch for performance.
// The inlined version avoids the method call overhead.
