package regex

import "testing"

// TestGetVMStateGrowsVisited covers the basic acquire/reslice path.
func TestGetVMStateGrowsVisited(t *testing.T) {
	st, gen := getVMState(16)
	if st == nil || gen <= 0 {
		t.Fatalf("getVMState(16) = (%v, %d), want non-nil state and positive gen", st, gen)
	}
	if len(st.visited) != 16 {
		t.Fatalf("visited len = %d, want 16", len(st.visited))
	}
	putVMState(st)
}

// TestGetVMStateResetsOverflowedGeneration pins the gen <= 0 recovery. sync.Pool
// gives no identity guarantee (and may drop entries at any GC), so the test
// re-primes until the pool hands the prepared state back. That converges in a
// few attempts and fails loudly under the mutation, which leaves gen at 0.
func TestGetVMStateResetsOverflowedGeneration(t *testing.T) {
	st := &vmState{
		visited: make([]int64, 4),
		cur:     make([]thread, 0, 4),
		next:    make([]thread, 0, 4),
	}
	for attempt := 0; attempt < 1000; attempt++ {
		st.gen = -1
		_ = vmPool.Get()
		vmPool.Put(st)
		got, gen := getVMState(4)
		if got != st {
			continue
		}
		if gen != 1 || got.gen != 1 {
			t.Fatalf("getVMState() gen = %d, state gen = %d, want 1 after overflow", gen, got.gen)
		}
		putVMState(got)
		return
	}
	t.Fatal("sync.Pool never returned the primed state")
}

// TestVMBatchPrepareReusesExactCapacity pins Prepare's cap < codeLen guard.
func TestVMBatchPrepareReusesExactCapacity(t *testing.T) {
	b := &VMBatch{st: &vmState{visited: make([]int64, 8)}}
	base := &b.st.visited[0]
	b.Prepare(8)
	if b.st == nil || b.gen <= 0 {
		t.Fatal("Prepare did not initialize the batch")
	}
	if &b.st.visited[0] != base {
		t.Fatal("Prepare reallocated visited despite exact capacity")
	}
	b.Release()
}

// TestVMBatchPrepareResetsOverflowedGeneration pins Prepare's gen <= 0 recovery.
func TestVMBatchPrepareResetsOverflowedGeneration(t *testing.T) {
	b := &VMBatch{st: &vmState{visited: make([]int64, 4), gen: -1}}
	b.Prepare(4)
	if b.gen != 1 {
		t.Fatalf("Prepare gen = %d, want 1 after overflow", b.gen)
	}
	b.Release()
}

// TestVMBatchReleaseNilGuards pins the nil-receiver and nil-state early returns.
func TestVMBatchReleaseNilGuards(t *testing.T) {
	var nilBatch *VMBatch
	nilBatch.Release() // must not panic
	(&VMBatch{}).Release()
}

// Mutation-test classification for regex/pool.go (gremlins v0.6.0, --workers 1):
//   - getVMState 36:21 (cap < codeLen -> <=): equivalent-mode. Reallocating when
//     cap == codeLen yields a functionally identical, generation-tagged slice;
//     stale entries from the reused backing array can never match the new gen.
//   - putVMState 54:21 and VMBatch.Release 96:21 (cap thresholds around 4096):
//     equivalent-mode. Pooling a large state is a GC/retention optimization;
//     skipping the pool is always safe and unobservable to callers.
//   - getVMState 43:12 and VMBatch.Prepare 81:14 (gen <= 0), and Release
//     90:7/90:22 (nil guards): pinned by the tests above.
