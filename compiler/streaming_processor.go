package compiler

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sync"

	"github.com/cawalch/go-yara/regex"
)

const (
	defaultStreamingChunkSize  = 1 * 1024 * 1024
	defaultStreamingBufferSize = 64 * 1024
	streamingBoundaryContext   = 2
)

// StreamingProcessor handles large file processing with chunked I/O.
//
// StreamingProcessor reports exact text-pattern matches. It does not evaluate
// rule conditions or report regex and hex matches. Use Scanner for full rule
// evaluation.
//
// A StreamingProcessor is not safe for concurrent Process calls. GetProgress
// may be called while a scan is running.
type StreamingProcessor struct {
	// Configuration
	ChunkSize        int  // Size of each chunk (default: 1MB)
	BufferSize       int  // Read buffer size (default: 64KB)
	EarlyTermination bool // Stop processing after the first chunk containing matches
	ChunkHook        ChunkHook

	chunkProcessor streamingChunkProcessor
	maxPatternLen  int
	progress       *streamingProgress
}

type streamingChunkProcessor struct {
	program *CompiledProgram
}

type streamingWindow struct {
	data          []byte
	offset        int64
	primaryStart  int64
	primaryEnd    int64
	copyMatchData bool
}

// StreamingMatch represents a text-pattern match found during chunked
// streaming. It does not imply that the containing rule's condition matched.
// Data returned by ProcessFile is owned by the match. Data returned by
// ProcessBytes aliases the caller-provided input.
type StreamingMatch struct {
	Rule    string
	Pattern string
	Offset  int64
	Length  int
	Data    []byte
}

type streamingProgress struct {
	mu           sync.Mutex
	totalBytes   int64
	processed    int64
	matchesFound int
}

// NewStreamingProcessor creates a new streaming processor.
func NewStreamingProcessor(program *CompiledProgram) *StreamingProcessor {
	maxPatternLen := 1
	if program != nil {
		for _, rule := range program.Rules {
			if rule == nil || rule.automaton == nil {
				continue
			}
			for _, str := range rule.automaton.strings {
				maxPatternLen = max(maxPatternLen, str.Length)
			}
		}
	}

	return &StreamingProcessor{
		ChunkSize:        defaultStreamingChunkSize,
		BufferSize:       defaultStreamingBufferSize,
		EarlyTermination: true,
		chunkProcessor:   streamingChunkProcessor{program: program},
		maxPatternLen:    maxPatternLen,
		progress:         &streamingProgress{},
	}
}

// ProcessFile reports text-pattern matches from a file using chunked I/O.
func (sp *StreamingProcessor) ProcessFile(ctx context.Context, filename string) ([]StreamingMatch, error) {
	sp.resetProgress(0)
	ctx = streamingContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	file, err := os.Open(filename) // #nosec G304 - callers intentionally select the scanned path
	if err != nil {
		return nil, fmt.Errorf("open streaming input: %w", err)
	}
	defer func() { _ = file.Close() }()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat streaming input: %w", err)
	}

	sp.resetProgress(fileInfo.Size())
	return sp.processFileChunks(ctx, file, fileInfo)
}

// ProcessBytes reports text-pattern matches from data using chunked processing.
func (sp *StreamingProcessor) ProcessBytes(ctx context.Context, data []byte) ([]StreamingMatch, error) {
	sp.resetProgress(int64(len(data)))
	ctx = streamingContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return sp.processDataChunks(ctx, data)
}

func streamingContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (sp *StreamingProcessor) effectiveChunkSize() int {
	if sp.ChunkSize <= 0 {
		return defaultStreamingChunkSize
	}
	return sp.ChunkSize
}

func (sp *StreamingProcessor) effectiveBufferSize() int {
	if sp.BufferSize <= 0 {
		return defaultStreamingBufferSize
	}
	return max(sp.BufferSize, streamingBoundaryContext)
}

func (sp *StreamingProcessor) effectiveOverlapSize() (int, error) {
	patternOverlap := max(sp.maxPatternLen-1, 0)
	if patternOverlap > math.MaxInt-streamingBoundaryContext {
		return 0, errors.New("streaming overlap size is too large")
	}
	return patternOverlap + streamingBoundaryContext, nil
}

// processFileChunks processes a file sequentially with enough overlap for a
// boundary-crossing pattern and enough lookahead to validate fullword.
func (sp *StreamingProcessor) processFileChunks(
	ctx context.Context,
	file *os.File,
	fileInfo os.FileInfo,
) ([]StreamingMatch, error) {
	reader := bufio.NewReaderSize(contextReader{ctx, file}, sp.effectiveBufferSize())
	chunkSize := sp.effectiveChunkSize()
	overlapCapacity, err := sp.effectiveOverlapSize()
	if err != nil {
		return nil, err
	}

	bufSize := chunkSize
	if fileInfo.Mode().IsRegular() && fileInfo.Size() < int64(bufSize) {
		bufSize = int(fileInfo.Size())
	}
	if bufSize > math.MaxInt-overlapCapacity-streamingBoundaryContext {
		return nil, errors.New("streaming chunk size is too large")
	}

	buf := make([]byte, overlapCapacity+bufSize+streamingBoundaryContext)
	var (
		allMatches          []StreamingMatch
		overlapLen          int
		currentStreamOffset int64
	)

	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("stream file: %w", err)
		}

		readSize := bufSize
		if fileInfo.Mode().IsRegular() {
			remaining := fileInfo.Size() - currentStreamOffset
			if remaining <= 0 {
				break
			}
			if remaining < int64(readSize) {
				readSize = int(remaining)
			}
		}

		targetSlice := buf[overlapLen : overlapLen+readSize]
		n, readErr := io.ReadFull(reader, targetSlice)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("read streaming input: %w", readErr)
		}
		if n == 0 {
			break
		}

		primaryStart := currentStreamOffset
		primaryEnd := primaryStart + int64(n)
		chunkOffset := primaryStart - int64(overlapLen)
		windowLen := overlapLen + n

		lookahead, peekErr := reader.Peek(streamingBoundaryContext)
		if peekErr != nil && peekErr != io.EOF {
			return nil, fmt.Errorf("peek streaming input: %w", peekErr)
		}
		if len(lookahead) > 0 {
			copy(buf[windowLen:], lookahead)
			windowLen += len(lookahead)
		}
		windowData := buf[:windowLen]

		matches, err := sp.chunkProcessor.processChunk(ctx, streamingWindow{
			data:          windowData,
			offset:        chunkOffset,
			primaryStart:  primaryStart,
			primaryEnd:    primaryEnd,
			copyMatchData: true,
		})
		if err != nil {
			return nil, err
		}
		allMatches = append(allMatches, matches...)
		sp.updateProgress(int64(n), len(matches))
		if sp.ChunkHook != nil {
			sp.ChunkHook(primaryStart, n, len(matches))
		}

		if sp.EarlyTermination && len(matches) > 0 {
			break
		}

		nextOverlap := min(overlapCapacity, overlapLen+n)
		copy(buf[:nextOverlap], buf[overlapLen+n-nextOverlap:overlapLen+n])
		overlapLen = nextOverlap
		currentStreamOffset = primaryEnd

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return allMatches, nil
}

// processDataChunks processes byte data sequentially. Matches are owned by the
// chunk containing their final byte, preventing duplicate overlap results.
func (sp *StreamingProcessor) processDataChunks(ctx context.Context, data []byte) ([]StreamingMatch, error) {
	chunkSize := sp.effectiveChunkSize()
	overlapSize, err := sp.effectiveOverlapSize()
	if err != nil {
		return nil, err
	}
	chunkCount := 0
	if len(data) > 0 {
		chunkCount = 1 + (len(data)-1)/chunkSize
	}
	allMatches := make([]StreamingMatch, 0)

	for chunkIndex := range chunkCount {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("stream bytes: %w", err)
		}

		primaryStart := chunkIndex * chunkSize
		primaryEnd := len(data)
		if chunkSize < len(data)-primaryStart {
			primaryEnd = primaryStart + chunkSize
		}
		searchStart := max(primaryStart-overlapSize, 0)
		searchEnd := len(data)
		if streamingBoundaryContext < len(data)-primaryEnd {
			searchEnd = primaryEnd + streamingBoundaryContext
		}

		matches, err := sp.chunkProcessor.processChunk(ctx, streamingWindow{
			data:         data[searchStart:searchEnd],
			offset:       int64(searchStart),
			primaryStart: int64(primaryStart),
			primaryEnd:   int64(primaryEnd),
		})
		if err != nil {
			return nil, err
		}
		allMatches = append(allMatches, matches...)
		sp.updateProgress(int64(primaryEnd-primaryStart), len(matches))
		if sp.ChunkHook != nil {
			sp.ChunkHook(int64(primaryStart), primaryEnd-primaryStart, len(matches))
		}

		if sp.EarlyTermination && len(matches) > 0 {
			break
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return allMatches, nil
}

func (cp *streamingChunkProcessor) processChunk(ctx context.Context, window streamingWindow) ([]StreamingMatch, error) {
	if cp.program == nil || len(window.data) == 0 {
		return nil, ctx.Err()
	}
	var matches []StreamingMatch
	hasShared := cp.program.sharedAutomaton != nil && len(cp.program.sharedLookup) > 0
	if hasShared {
		matches = cp.processChunkShared(ctx, window, matches)
	}
	// The shared automaton omits unreferenced strings. The text-only
	// StreamingProcessor still reports those occurrences.
	for _, rule := range cp.program.Rules {
		if rule == nil || rule.automaton == nil || (hasShared && !rule.hasUnusedText) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		yield := func(match acMatch) bool {
			if match.StringIndex < 0 || match.StringIndex >= len(rule.automaton.strings) {
				return true
			}
			if hasShared && !rule.IsStringDead(match.StringID) {
				return true
			}
			matches = appendStreamingMatch(matches, window, rule, match.StringID, rule.automaton.strings[match.StringIndex], match.Backtrack)
			return true
		}
		if done := ctx.Done(); done != nil {
			rule.automaton.SearchWithCancel(window.data, done, yield)
		} else {
			rule.automaton.Search(window.data, yield)
		}
	}
	return matches, ctx.Err()
}

func (cp *streamingChunkProcessor) processChunkShared(
	ctx context.Context,
	window streamingWindow,
	matches []StreamingMatch,
) []StreamingMatch {
	shared := cp.program.sharedAutomaton
	lookup := cp.program.sharedLookup
	rules := cp.program.Rules
	yield := func(match acMatch) bool {
		if match.StringIndex < 0 || match.StringIndex >= len(lookup) {
			return true
		}
		entry := lookup[match.StringIndex]
		if entry.Kind != StringKindText || entry.RuleIndex < 0 || entry.RuleIndex >= len(rules) {
			return true
		}
		rule := rules[entry.RuleIndex]
		if rule == nil || entry.StringIdx < 0 || entry.StringIdx >= len(rule.IndexToStringID) {
			return true
		}
		matches = appendStreamingMatch(matches, window, rule, rule.IndexToStringID[entry.StringIdx], shared.strings[match.StringIndex], match.Backtrack)
		return true
	}
	if done := ctx.Done(); done != nil {
		shared.SearchWithCancel(window.data, done, yield)
	} else {
		shared.Search(window.data, yield)
	}
	return matches
}

//nolint:revive // argument-limit: hot streaming match helper avoids struct allocation
func appendStreamingMatch(
	matches []StreamingMatch,
	window streamingWindow,
	rule *CompiledRule,
	strID string,
	info acStringInfo,
	position int,
) []StreamingMatch {
	if rule.IsPrivateString(strID) {
		return matches
	}
	if rule.StringKinds != nil && rule.StringKinds[strID] != StringKindText {
		return matches
	}
	if position < 0 || info.Length <= 0 || position+info.Length > len(window.data) {
		return matches
	}
	absoluteStart := window.offset + int64(position)
	absoluteEnd := absoluteStart + int64(info.Length)
	if absoluteEnd <= window.primaryStart || absoluteEnd > window.primaryEnd {
		return matches
	}
	candidate := Match{
		Pattern: strID,
		Offset:  int64(position),
		Length:  info.Length,
	}
	isNocase := (info.Flags & regex.FlagsNoCase) != 0
	isWide := (info.Flags & regex.FlagsWide) != 0
	if !verifyTextMatch(window.data, candidate, info.Data, isNocase) ||
		!matchPassesModifiers(window.data, candidate, rule.StringModifiers[strID], isWide) {
		return matches
	}
	matchData := window.data[position : position+info.Length]
	if window.copyMatchData {
		matchData = copyBytes(matchData)
	}
	return append(matches, StreamingMatch{
		Rule:    rule.Name,
		Pattern: strID,
		Offset:  absoluteStart,
		Length:  info.Length,
		Data:    matchData,
	})
}

func (sp *StreamingProcessor) resetProgress(totalBytes int64) {
	sp.progress.mu.Lock()
	defer sp.progress.mu.Unlock()
	sp.progress.totalBytes = totalBytes
	sp.progress.processed = 0
	sp.progress.matchesFound = 0
}

func (sp *StreamingProcessor) updateProgress(bytesProcessed int64, matchesFound int) {
	sp.progress.mu.Lock()
	defer sp.progress.mu.Unlock()
	sp.progress.processed += bytesProcessed
	sp.progress.matchesFound += matchesFound
}

// GetProgress returns progress for the current or most recent streaming scan.
func (sp *StreamingProcessor) GetProgress() (processed, total int64, percent float64, matches int) {
	sp.progress.mu.Lock()
	defer sp.progress.mu.Unlock()

	processed = sp.progress.processed
	total = sp.progress.totalBytes
	matches = sp.progress.matchesFound
	if total > 0 {
		percent = float64(processed) / float64(total) * 100
	}
	return
}

// SetChunkSize sets the chunk size for processing. Non-positive values are ignored.
func (sp *StreamingProcessor) SetChunkSize(size int) {
	if size > 0 {
		sp.ChunkSize = size
	}
}

// EnableEarlyTermination configures whether processing stops after the first
// chunk containing matches.
func (sp *StreamingProcessor) EnableEarlyTermination(enable bool) {
	sp.EarlyTermination = enable
}
