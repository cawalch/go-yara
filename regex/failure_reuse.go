package regex

// Failure reuse is limited to one immutable input/program/flag tuple per batch.
// Each bit records a consuming PC reached by a completed, unsuccessful attempt
// at that absolute input position. Every such state is unable to accept. A later
// attempt whose entire frontier is covered can stop without selecting an endpoint.
const failureReuseLimit = 4096

type failureReuse struct {
	enabled, armed, learning, ready bool
	code                            *byte
	input                           []byte
	offset                          int
	codeLen                         int
	flags                           Flags
	masks                           []uint64
}

// EnableFailureReuse permits bounded reuse of unsuccessful ordinary matches.
// Code and input must remain immutable until Prepare or Release. The cache is
// discarded when the code, flags, or input end changes. Removing an input prefix
// is safe: cached frontiers contain consuming states, so future assertions see
// the same bytes and physical end. Prepare and Release end the reuse scope.
// Budgeted verification does not use this cache because its bound moves with
// each atom. Scratch is at most 32 KiB per batch, allocated only after a failed
// attempt performs at least 128 VM steps; unsupported inputs use ordinary VM work.
func (b *VMBatch) EnableFailureReuse() { b.failure.enabled = true }

func (b *VMBatch) prepareFailureReuse(code, input []byte, flags Flags) {
	f := &b.failure
	if !f.enabled {
		return
	}
	if len(code) > 64 || len(input) == 0 || len(input) < 128 && !f.ready || len(input) > failureReuseLimit {
		*f = failureReuse{enabled: f.enabled}
		return
	}
	offset := len(f.input) - len(input)
	if f.code != &code[0] || f.codeLen != len(code) || f.flags != flags || offset < 0 || &f.input[offset] != &input[0] {
		*f = failureReuse{enabled: true, code: &code[0], input: input, codeLen: len(code), flags: flags}
		offset = 0
	}
	f.offset = offset
	if f.armed && !f.ready {
		if cap(b.st.failureMasks) < len(f.input) {
			b.st.failureMasks = make([]uint64, len(f.input))
		}
		f.masks = b.st.failureMasks[:len(f.input)]
		clear(f.masks)
		f.learning = true
	}
}

func (b *VMBatch) finishFailureReuse(matched, canceled bool, work int64) {
	f := &b.failure
	if !f.enabled || f.code == nil {
		return
	}
	if canceled || matched && f.learning {
		*f = failureReuse{} // Partial or successful traces prove no failed states.
		return
	}
	if f.learning {
		f.learning, f.ready = false, true
	} else if !matched && work >= 128 {
		f.armed = true
	}
}

func (f *failureReuse) rejects(cur []thread, pos int) bool {
	var mask uint64
	for _, t := range cur {
		mask |= uint64(1) << uint(t.pc)
	}
	if f.learning {
		f.masks[pos+f.offset] = mask
		return false
	}
	return mask != 0 && mask&^f.masks[pos+f.offset] == 0
}
