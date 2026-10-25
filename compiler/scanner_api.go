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
func (s *Scanner) MatchesReader(r io.Reader) (bool, error) {
	return s.MatchesReaderWithContext(context.Background(), r)
}

// MatchesReaderWithContext reports whether at least one public rule matches r using constant-memory streaming.
func (s *Scanner) MatchesReaderWithContext(ctx context.Context, r io.Reader) (bool, error) {
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

// MatchesWithContext reports whether at least one public rule matches data.
func (s *Scanner) MatchesWithContext(ctx context.Context, data []byte) (matched bool, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || s.program == nil {
		return false, nil
	}
	if err := s.scanError(); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	clear(s.ruleResultsDense)
	defer func() {
		clear(s.ruleResultsDense)
	}()
	if s.hookMask&(hookBitTelemetry|hookBitScanLifecycle) != 0 {
		start := s.beginScan(ctx, int64(len(data)))
		defer func() {
			count := 0
			if matched {
				count = 1
			}
			start.finish(nil, count, err)
		}()
	}

	if matched, handled, err := s.matchBooleanRouting(ctx, data); handled || err != nil {
		return matched, err
	}
	evaluation, err := s.evaluatePublicRules(ctx, data, nil)
	if err != nil {
		return false, err
	}
	hasMatch := evaluation.matchedPublicGlobal ||
		evaluation.allGlobalMatched && evaluation.matchedPublicNonGlobal

	return hasMatch, nil
}

// MatchingRules returns detailed public rule matches without constructing the
// all-rules maps in ScanResult. The returned slice and RuleMatch values are
// owned by the caller and remain valid across later scanner calls.
func (s *Scanner) MatchingRules(data []byte) ([]RuleMatch, error) {
	return s.MatchingRulesWithContext(context.Background(), data)
}

// MatchingRulesWithContext returns detailed public rule matches without
// constructing the all-rules maps in ScanResult.
func (s *Scanner) MatchingRulesWithContext(ctx context.Context, data []byte) (matches []RuleMatch, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || s.program == nil {
		return nil, nil
	}
	if err := s.scanError(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if s.hookMask&(hookBitTelemetry|hookBitScanLifecycle) != 0 {
		start := s.beginScan(ctx, int64(len(data)))
		defer func() { start.finishRuleList(matches, err) }()
	}

	clear(s.ruleResultsDense)
	defer func() {
		clear(s.ruleResultsDense)
	}()
	s.matchedRuleIndices = s.matchedRuleIndices[:0]
	evaluation, err := s.evaluatePublicRules(ctx, data, &s.matchedRuleIndices)
	if err != nil {
		return nil, err
	}
	return s.materializeMatchingRules(ctx, data, evaluation)
}

// ScanReader reads from the reader and scans the data.
func (s *Scanner) ScanReader(r io.Reader) (*ScanResult, error) {
	return s.ScanReaderWithContext(context.Background(), r)
}

// ScanReaderWithContext reads from the reader and scans the data using constant-memory streaming.
// Cancellation is checked between chunk reads and pattern evaluation.
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
	if statErr == nil && info.Mode().IsRegular() && info.Size() >= fs.MinMmapFileSize {
		data, cleanup, err := fs.MapFile(filename)
		if err == nil {
			defer cleanup()
			return s.ScanWithContext(ctx, data)
		}
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
