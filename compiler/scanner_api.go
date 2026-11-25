package compiler

import (
	"context"
	"io"
	"os"

	"github.com/cawalch/go-yara/utils/fs"
)

// Scan scans the provided byte slice against the compiled rules.
func (s *Scanner) Scan(data []byte) (*ScanResult, error) {
	return s.ScanWithContext(context.Background(), data)
}

// Matches reports whether at least one public rule matches data.
// It leverages the allocation-free prefilter rejection fast-path for non-matching inputs.
func (s *Scanner) Matches(data []byte) (bool, error) {
	return s.MatchesWithContext(context.Background(), data)
}

// MatchesReader reports whether at least one public rule matches r.
// Integer reads have the same retained-header limit as ScanReaderWithContext.
func (s *Scanner) MatchesReader(r io.Reader) (bool, error) {
	return s.MatchesReaderWithContext(context.Background(), r)
}

// MatchesReaderWithContext reports whether at least one public rule matches r.
// It uses the bounded input window described by ScanReaderWithContext.
// Occurrence spans needed for condition evaluation can grow with the number
// of matches, even though the result is a boolean.
// Integer reads have the same retained-header limit as ScanReaderWithContext.
func (s *Scanner) MatchesReaderWithContext(ctx context.Context, r io.Reader) (bool, error) {
	if s == nil || s.program == nil {
		return false, nil
	}
	prevOmitMatches := s.omitMatches
	prevOmitRuleResults := s.omitRuleResults
	prevReportedMatchesOnly := s.reportedMatchesOnly
	prevEarly := s.streamEarlyTermination

	s.omitMatches = true
	s.omitRuleResults = true
	s.reportedMatchesOnly = true
	s.streamEarlyTermination = true

	defer func() {
		s.omitMatches = prevOmitMatches
		s.omitRuleResults = prevOmitRuleResults
		s.reportedMatchesOnly = prevReportedMatchesOnly
		s.streamEarlyTermination = prevEarly
	}()

	result, err := s.ScanReaderWithContext(ctx, r)
	if err != nil {
		return false, err
	}
	return len(result.MatchedRules) > 0, nil
}

func (s *Scanner) prepareScanCall(ctx context.Context) (context.Context, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || s.program == nil {
		return ctx, false, nil
	}
	if err := s.scanError(); err != nil {
		return ctx, false, err
	}
	if err := ctx.Err(); err != nil {
		return ctx, false, err
	}
	s.skipSharedTeddyGate = false
	return ctx, true, nil
}

// MatchesWithContext reports whether at least one public rule matches data.
func (s *Scanner) MatchesWithContext(ctx context.Context, data []byte) (matched bool, err error) {
	ctx, ready, err := s.prepareScanCall(ctx)
	if !ready || err != nil {
		return false, err
	}
	if s.compactPrefilterFanoutRejects(ctx, data) {
		err := ctx.Err()
		if err == nil && s.hookMask&hookBitTelemetry != 0 && s.telemetrySink != nil {
			s.telemetrySink.PrefilterRejects++
		}
		if s.hookMask&(hookBitTelemetry|hookBitScanLifecycle) != 0 {
			start := s.beginScan(ctx, int64(len(data)))
			start.finish(nil, 0, err)
		}
		return false, err
	}
	s.clearRuleResultsIfDirty()
	if s.hookMask&(hookBitTelemetry|hookBitScanLifecycle) != 0 {
		return s.matchesWithObservedLifecycle(ctx, data)
	}
	return s.matchesUnobserved(ctx, data)
}

func (s *Scanner) matchesWithObservedLifecycle(ctx context.Context, data []byte) (matched bool, err error) {
	start := s.beginScan(ctx, int64(len(data)))
	defer func() {
		count := 0
		if matched {
			count = 1
		}
		start.finish(nil, count, err)
	}()
	return s.matchesUnobserved(ctx, data)
}

func (s *Scanner) matchesUnobserved(ctx context.Context, data []byte) (bool, error) {
	if matched, handled, err := s.matchBooleanRouting(ctx, data); handled || err != nil {
		s.clearRuleResultsIfDirty()
		return matched, err
	}
	evaluation, err := s.evaluatePublicRulesAfterCompact(ctx, data, nil)
	s.clearRuleResultsIfDirty()
	if err != nil {
		return false, err
	}
	return evaluation.allGlobalMatched && evaluation.matchedPublic, nil
}

// MatchingRules returns detailed public rule matches without constructing the
// all-rules maps in ScanResult. The returned slice and RuleMatch values are
// owned by the caller and remain valid across later scanner calls.
func (s *Scanner) MatchingRules(data []byte) ([]RuleMatch, error) {
	return s.MatchingRulesWithContext(context.Background(), data)
}

// MatchingRulesWithContext returns detailed public rule matches without
// constructing the all-rules maps in ScanResult.
func (s *Scanner) MatchingRulesWithContext(ctx context.Context, data []byte) ([]RuleMatch, error) {
	ctx, ready, err := s.prepareScanCall(ctx)
	if !ready || err != nil {
		return nil, err
	}

	if s.hookMask&(hookBitTelemetry|hookBitScanLifecycle) != 0 {
		start := s.beginScan(ctx, int64(len(data)))
		matches, err := s.matchingRulesWithContextCore(ctx, data)
		start.finishRuleList(matches, err)
		return matches, err
	}
	return s.matchingRulesWithContextCore(ctx, data)
}

func (s *Scanner) matchingRulesWithContextCore(ctx context.Context, data []byte) ([]RuleMatch, error) {
	s.clearRuleResultsIfDirty()
	s.matchedRuleIndices = s.matchedRuleIndices[:0]
	evaluation, err := s.evaluatePublicRules(ctx, data, &s.matchedRuleIndices)
	if err != nil {
		s.clearRuleResultsIfDirty()
		return nil, err
	}
	matches, err := s.materializeMatchingRules(ctx, data, evaluation)
	s.clearRuleResultsIfDirty()
	return matches, err
}

// ScanReader reads from the reader and scans the data.
// Its memory use and retained-header limit are described by ScanReaderWithContext.
func (s *Scanner) ScanReader(r io.Reader) (*ScanResult, error) {
	return s.ScanReaderWithContext(context.Background(), r)
}

// ScanReaderWithContext reads from the reader and scans the data in chunks.
// Its input buffer is bounded by the chunk size, overlap, lookahead, and
// retained header. Retained occurrence spans grow with the number of matches.
// Reported match bytes and evidence add storage that can grow with their size
// and number. WithFastScan reduces occurrence retention for eligible rules.
// WithMatchContext byte windows are not retained for reader scans; use Scan or
// BlockScanner when surrounding match context is required.
// Cancellation is checked between chunk reads and pattern evaluation.
// Integer reads in conditions must lie entirely within the first 64 KiB of input;
// reads outside that retained header are undefined, even for longer streams.
// The pcap module can also read capture data from a seekable io.ReaderAt,
// starting at the current stream position. For sequential readers, the entire
// capture must fit in the retained header for TLS metadata to be available.
func (s *Scanner) ScanReaderWithContext(ctx context.Context, r io.Reader) (*ScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.scanReaderStream(ctx, r)
}

// ScanFile scans the given file.
func (s *Scanner) ScanFile(filename string) (*ScanResult, error) {
	return s.ScanFileWithContext(context.Background(), filename)
}

// ScanFileWithContext scans the given file.
// For regular files >= 128 KB, it attempts to use zero-copy memory mapping via fs.MapFile.
// If memory mapping fails, file is < 128 KB, or for special files, it falls back to standard file read.
func (s *Scanner) ScanFileWithContext(ctx context.Context, filename string) (*ScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, statErr := os.Stat(filename)
	if statErr == nil && info.Mode().IsRegular() && info.Size() >= fs.MinMmapFileSize && (s == nil || !s.evidenceBorrowed) {
		data, cleanup, err := fs.MapFile(filename)
		if err == nil {
			defer cleanup()
			return s.ScanWithContext(ctx, data)
		}
	}
	if statErr == nil && !info.Mode().IsRegular() {
		// Devices, FIFOs, and sockets have no finite size. Stream them so an
		// endless source (for example /dev/zero) cannot be read into memory
		// without bound.
		file, err := os.Open(filename) // #nosec G304 - caller intentionally scans this path
		if err != nil {
			return nil, err
		}
		defer func() { _ = file.Close() }()
		return s.ScanReaderWithContext(ctx, file)
	}
	if ctx.Done() == nil {
		data, err := os.ReadFile(filename) // #nosec G304 - caller intentionally scans this path
		if err != nil {
			return nil, err
		}
		return s.ScanWithContext(ctx, data)
	}
	file, err := os.Open(filename) // #nosec G304 - caller intentionally scans this path
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return s.ScanReaderWithContext(ctx, file)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}
