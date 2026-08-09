package compiler

const (
	scanCancellationInterval = 4 * 1024
	cancelableSearchWindow   = 1 * 1024 * 1024
)

func scanCanceled(done <-chan struct{}) bool {
	if done == nil {
		return false
	}
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func scanCanceledAt(done <-chan struct{}, index int) bool {
	return done != nil && index&(scanCancellationInterval-1) == 0 && scanCanceled(done)
}
