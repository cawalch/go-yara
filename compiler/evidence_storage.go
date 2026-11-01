package compiler

// captureStorage allocates disjoint, result-owned slices in small chunks. It is
// local to one rule materialization and is never pooled or retained by a scanner.
// The first allocation is exact-sized; subsequent allocations batch nearby
// captures without reserving storage for every possible optional group.
// Full slice expressions keep append from overwriting a neighboring capture.
type captureStorage struct {
	captures []Capture
	data     []byte
}

func (s *captureStorage) capturesFor(count, remaining int) []Capture {
	if len(s.captures) < count {
		capacity := count
		if s.captures != nil {
			capacity = max(count, min(64, count*min(remaining, 64)))
		}
		s.captures = make([]Capture, capacity)
	}
	result := s.captures[:count:count]
	s.captures = s.captures[count:]
	return result
}

func (s *captureStorage) bytes(count, remaining int) []byte {
	if count == 0 {
		return nil
	}
	if len(s.data) < count {
		capacity := count
		if s.data != nil && count < 4096 {
			capacity = min(4096, count*min(remaining, 4096))
		}
		s.data = make([]byte, capacity)
	}
	result := s.data[:count:count]
	s.data = s.data[count:]
	return result
}
