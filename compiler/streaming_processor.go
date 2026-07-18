package compiler

import (
	"bufio"
	"context"
	"fmt"
	"io"
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

	compiledProgram *CompiledProgram
	chunkProcessor  *streamingChunkProcessor
	maxPatternLen   int
	progress        *streamingProgress
}

type streamingChunkProcessor struct {
	rules []*CompiledRule
}

type streamingWindow struct {
	data         []byte
	offset       int64
	primaryStart int64
	primaryEnd   int64
}

// StreamingMatch represents a text-pattern match found during chunked
// streaming. It does not imply that the containing rule's condition matched.
type StreamingMatch struct {
	Rule    string
	Pattern string
	Offset  int64
	Length  int
	Data    []byte
}

type streamingProgress struct {
	mu           sync.RWMutex
	totalBytes   int64
	processed    int64
	matchesFound int
}

// NewStreamingProcessor creates a new streaming processor.
func NewStreamingProcessor(program *CompiledProgram) *StreamingProcessor {
	maxPatternLen := 1
	if program != nil {
		for _, rule := range program.Rules {
			if rule == nil || rule.Automaton == nil {
				continue
			}
			for _, str := range rule.Automaton.Strings {
				maxPatternLen = max(maxPatternLen, str.Length)
			}
		}
	}

	return &StreamingProcessor{
		ChunkSize:        defaultStreamingChunkSize,
		BufferSize:       defaultStreamingBufferSize,
		EarlyTermination: true,
		compiledProgram:  program,
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
	sp.prepareScan()
	return sp.processFileChunks(ctx, file)
}

// ProcessBytes reports text-pattern matches from data using chunked processing.
func (sp *StreamingProcessor) ProcessBytes(ctx context.Context, data []byte) ([]StreamingMatch, error) {
	sp.resetProgress(int64(len(data)))
	ctx = streamingContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sp.prepareScan()
	return sp.processDataChunks(ctx, data)
}

func streamingContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (sp *StreamingProcessor) prepareScan() {
	var rules []*CompiledRule
	if sp.compiledProgram != nil {
		rules = sp.compiledProgram.Rules
	}
	sp.chunkProcessor = &streamingChunkProcessor{
		rules: rules,
	}
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

// processFileChunks processes a file sequentially with enough overlap for a
// boundary-crossing pattern and enough lookahead to validate fullword.
func (sp *StreamingProcessor) processFileChunks(ctx context.Context, file *os.File) ([]StreamingMatch, error) {
	reader := bufio.NewReaderSize(file, sp.effectiveBufferSize())
	chunkSize := sp.effectiveChunkSize()
	overlapCapacity := max(sp.maxPatternLen-1, 0) + streamingBoundaryContext

	var (
		allMatches          []StreamingMatch
		overlap             []byte
		currentStreamOffset int64
	)

	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("stream file: %w", err)
		}

		overlapSize := min(overlapCapacity, len(overlap))
		chunk := make([]byte, overlapSize+chunkSize, overlapSize+chunkSize+streamingBoundaryContext)
		copy(chunk, overlap[len(overlap)-overlapSize:])

		n, readErr := io.ReadFull(reader, chunk[overlapSize:])
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("read streaming input: %w", readErr)
		}
		if n == 0 {
			break
		}

		chunk = chunk[:overlapSize+n]
		if lookahead, _ := reader.Peek(streamingBoundaryContext); len(lookahead) > 0 {
			chunk = append(chunk, lookahead...)
		}

		primaryStart := currentStreamOffset
		primaryEnd := primaryStart + int64(n)
		chunkOffset := primaryStart - int64(overlapSize)
		matches := sp.chunkProcessor.processChunk(streamingWindow{
			data:         chunk,
			offset:       chunkOffset,
			primaryStart: primaryStart,
			primaryEnd:   primaryEnd,
		})
		allMatches = append(allMatches, matches...)
		sp.updateProgress(int64(n), len(matches))

		if sp.EarlyTermination && len(matches) > 0 {
			break
		}

		withoutLookahead := chunk[:overlapSize+n]
		nextOverlapSize := min(overlapCapacity, len(withoutLookahead))
		overlap = append(overlap[:0], withoutLookahead[len(withoutLookahead)-nextOverlapSize:]...)
		currentStreamOffset = primaryEnd

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
	}

	return allMatches, nil
}

// processDataChunks processes byte data sequentially. Matches are owned by the
// chunk containing their final byte, preventing duplicate overlap results.
func (sp *StreamingProcessor) processDataChunks(ctx context.Context, data []byte) ([]StreamingMatch, error) {
	chunkSize := sp.effectiveChunkSize()
	overlapSize := max(sp.maxPatternLen-1, 0) + streamingBoundaryContext
	chunkCount := (len(data) + chunkSize - 1) / chunkSize
	allMatches := make([]StreamingMatch, 0)

	for chunkIndex := range chunkCount {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("stream bytes: %w", err)
		}

		primaryStart := chunkIndex * chunkSize
		primaryEnd := min(primaryStart+chunkSize, len(data))
		searchStart := max(primaryStart-overlapSize, 0)
		searchEnd := min(primaryEnd+streamingBoundaryContext, len(data))

		matches := sp.chunkProcessor.processChunk(streamingWindow{
			data:         data[searchStart:searchEnd],
			offset:       int64(searchStart),
			primaryStart: int64(primaryStart),
			primaryEnd:   int64(primaryEnd),
		})
		allMatches = append(allMatches, matches...)
		sp.updateProgress(int64(primaryEnd-primaryStart), len(matches))

		if sp.EarlyTermination && len(matches) > 0 {
			break
		}
	}

	return allMatches, nil
}

func (cp *streamingChunkProcessor) processChunk(window streamingWindow) []StreamingMatch {
	var matches []StreamingMatch
	for _, rule := range cp.rules {
		if rule == nil || rule.Automaton == nil {
			continue
		}
		matches = append(matches, cp.processRule(window, rule)...)
	}
	return matches
}

func (cp *streamingChunkProcessor) processRule(window streamingWindow, rule *CompiledRule) []StreamingMatch {
	var matches []StreamingMatch
	for match := range rule.Automaton.SearchIter(window.data) {
		ruleMatch, ok := cp.createRuleMatch(window, rule, match)
		if !ok {
			continue
		}
		matches = append(matches, ruleMatch)
	}
	return matches
}

func (cp *streamingChunkProcessor) createRuleMatch(
	window streamingWindow,
	rule *CompiledRule,
	match ACMatch,
) (StreamingMatch, bool) {
	if rule == nil || rule.Automaton == nil || rule.IsPrivateString(match.StringID) {
		return StreamingMatch{}, false
	}
	if rule.StringKinds != nil && rule.StringKinds[match.StringID] != StringKindText {
		return StreamingMatch{}, false
	}
	if match.StringIndex < 0 || match.StringIndex >= len(rule.Automaton.Strings) {
		return StreamingMatch{}, false
	}

	info := rule.Automaton.Strings[match.StringIndex]
	position := match.Backtrack
	if position < 0 || info.Length <= 0 || position+info.Length > len(window.data) {
		return StreamingMatch{}, false
	}

	absoluteStart := window.offset + int64(position)
	absoluteEnd := absoluteStart + int64(info.Length)
	if absoluteEnd <= window.primaryStart || absoluteEnd > window.primaryEnd {
		return StreamingMatch{}, false
	}

	candidate := Match{
		Pattern: match.StringID,
		Offset:  int64(position),
		Length:  info.Length,
	}
	isNocase := (info.Flags & regex.FlagsNoCase) != 0
	isWide := (info.Flags & regex.FlagsWide) != 0
	if !verifyTextMatch(window.data, candidate, info.Data, isNocase) ||
		!matchPassesModifiers(window.data, candidate, rule.StringModifiers[match.StringID], isWide) {
		return StreamingMatch{}, false
	}

	return StreamingMatch{
		Rule:    rule.Name,
		Pattern: match.StringID,
		Offset:  absoluteStart,
		Length:  info.Length,
		Data:    window.data[position : position+info.Length],
	}, true
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
	sp.progress.mu.RLock()
	defer sp.progress.mu.RUnlock()

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
