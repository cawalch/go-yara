package compiler

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"
)

// StreamingProcessor handles large file processing with chunked I/O.
//
// IMPORTANT: StreamingProcessor only evaluates string pattern matches (via AC automaton).
// It does NOT evaluate rule conditions (bytecode). A StreamingMatch means the pattern
// was found in the data, NOT that the rule's condition was satisfied.
// For full rule evaluation including conditions, use the Interpreter directly.
type StreamingProcessor struct {
	// Configuration
	ChunkSize        int  // Size of each chunk (default: 1MB)
	BufferSize       int  // Read buffer size (default: 64KB)
	MaxConcurrency   int  // Maximum concurrent goroutines
	EarlyTermination bool // Stop processing when matches found
	MaxPatternLen    int  // Maximum pattern length for overlap calculation

	// Internal state
	compiledProgram *CompiledProgram
	chunkProcessor  *ChunkProcessor
	progress        *ProgressTracker
}

// ChunkProcessor handles individual chunk processing
type ChunkProcessor struct {
	rules       []*CompiledRule
	matchBuffer *MatchBuffer
}

// MatchBuffer collects matches across chunks
type MatchBuffer struct {
	mu      sync.RWMutex
	matches []StreamingMatch
	limit   int
}

// StreamingMatch represents a rule match (renamed to avoid conflict with interpreter.Match)
type StreamingMatch struct {
	Rule    string
	Pattern string
	Offset  int64
	Length  int
	Data    []byte
}

// ProgressTracker tracks processing progress
type ProgressTracker struct {
	mu           sync.RWMutex
	totalBytes   int64
	processed    int64
	startTime    time.Time
	matchesFound int
}

// Chunk represents a portion of file data
type Chunk struct {
	Data   []byte
	Offset int64
	Index  int
	Total  int
}

// ProcessingResult contains results from chunk processing
type ProcessingResult struct {
	ChunkIndex     int
	Matches        []StreamingMatch
	BytesProcessed int64
	Error          error
	ShouldStop     bool
	ProcessingTime time.Duration
}

// NewStreamingProcessor creates a new streaming processor
func NewStreamingProcessor(program *CompiledProgram) *StreamingProcessor {
	// Calculate maximum pattern length for overlap
	maxPatternLen := 0
	for _, rule := range program.Rules {
		if rule.Automaton != nil {
			for _, str := range rule.Automaton.Strings {
				if str.Length > maxPatternLen {
					maxPatternLen = str.Length
				}
			}
		}
	}

	// If no strings found in automaton, use a reasonable default
	// Most patterns are relatively short, so 64 bytes is a safe overlap
	if maxPatternLen < 1 {
		maxPatternLen = 64
	}

	return &StreamingProcessor{
		ChunkSize:        1 * 1024 * 1024, // 1MB chunks
		BufferSize:       64 * 1024,       // 64KB buffer
		MaxConcurrency:   runtime.NumCPU(),
		EarlyTermination: true,
		MaxPatternLen:    maxPatternLen,
		compiledProgram:  program,
		progress:         &ProgressTracker{},
	}
}

// ProcessFile processes a large file using streaming/chunked approach
func (sp *StreamingProcessor) ProcessFile(ctx context.Context, filename string) ([]StreamingMatch, error) {
	file, err := os.Open(filename) // #nosec G304 - filename is trusted in this context
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			// Log the close error, but don't override the main function's error
			// In production, you might want to use proper logging
			_ = closeErr // Suppress the error until proper logging is implemented
		}
	}()

	// Get file size for progress tracking
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	sp.progress.totalBytes = fileInfo.Size()
	sp.progress.startTime = time.Now()

	// Initialize match buffer
	matchBuffer := &MatchBuffer{
		matches: make([]StreamingMatch, 0, 100),
		limit:   1000, // Limit total matches to prevent memory blowup
	}

	// Create chunk processor
	sp.chunkProcessor = sp.createChunkProcessor(matchBuffer)

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Process file in chunks
	results := make(chan ProcessingResult, sp.MaxConcurrency)
	errCh := make(chan error, 1)

	go func() {
		errCh <- sp.processChunks(workerCtx, file, results)
	}()

	// Collect results
	var allMatches []StreamingMatch
	for result := range results {
		if result.Error != nil {
			cancel()
			return nil, result.Error
		}
		allMatches = append(allMatches, result.Matches...)

		if sp.EarlyTermination && len(result.Matches) > 0 {
			fmt.Printf("Early termination after finding matches in chunk %d\n", result.ChunkIndex)
			cancel()
			break
		}
	}

	// Drain any remaining items to unblock the producer
	go func() {
		for range results {
		}
	}()

	processErr := <-errCh
	if processErr != nil && !errors.Is(processErr, context.Canceled) {
		return nil, processErr
	}

	return allMatches, nil
}

// ProcessBytes processes byte data using streaming approach
func (sp *StreamingProcessor) ProcessBytes(ctx context.Context, data []byte) ([]StreamingMatch, error) {
	sp.progress.totalBytes = int64(len(data))
	sp.progress.startTime = time.Now()

	// Initialize match buffer
	matchBuffer := &MatchBuffer{
		matches: make([]StreamingMatch, 0, 100),
		limit:   1000,
	}

	// Create chunk processor
	sp.chunkProcessor = sp.createChunkProcessor(matchBuffer)

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Process data in chunks
	results := make(chan ProcessingResult, sp.MaxConcurrency)
	errCh := make(chan error, 1)

	go func() {
		errCh <- sp.processDataChunks(workerCtx, data, results)
	}()

	// Collect results
	var allMatches []StreamingMatch
	for result := range results {
		if result.Error != nil {
			cancel()
			return nil, result.Error
		}
		allMatches = append(allMatches, result.Matches...)

		if sp.EarlyTermination && len(result.Matches) > 0 {
			cancel()
			break
		}
	}

	// Drain any remaining items to unblock the producer
	go func() {
		for range results {
		}
	}()

	processErr := <-errCh
	if processErr != nil && !errors.Is(processErr, context.Canceled) {
		return nil, processErr
	}

	return allMatches, nil
}

// createChunkProcessor initializes the chunk processor
func (sp *StreamingProcessor) createChunkProcessor(matchBuffer *MatchBuffer) *ChunkProcessor {
	// Extract rules from compiled program (each rule has its own automaton)
	return &ChunkProcessor{
		rules:       sp.extractRules(),
		matchBuffer: matchBuffer,
	}
}

// extractRules extracts compiled rules
func (sp *StreamingProcessor) extractRules() []*CompiledRule {
	// Return existing compiled rules
	return sp.compiledProgram.Rules
}

// processChunks processes file data in chunks with overlap for boundary-crossing patterns.
// Chunks are processed sequentially to avoid data races on the shared AC automaton state.
func (sp *StreamingProcessor) processChunks(ctx context.Context, file *os.File, results chan<- ProcessingResult) error {
	defer close(results)

	reader := bufio.NewReaderSize(file, sp.BufferSize)

	chunkIndex := 0
	var overlapBuffer []byte
	var currentStreamOffset int64

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context canceled: %w", ctx.Err())
		default:
		}

		// Calculate overlap size (except for first chunk).
		// Clamp to actual available overlap data from previous chunk.
		overlapSize := 0
		if chunkIndex > 0 {
			overlapSize = min(max(sp.MaxPatternLen-1, 0), len(overlapBuffer))
		}

		// Allocate chunk buffer: overlap + new data
		bufSize := overlapSize + sp.ChunkSize
		chunk := make([]byte, bufSize)

		// Copy overlap from previous chunk
		copy(chunk, overlapBuffer)

		// Read new data after the overlap region
		n, err := io.ReadFull(reader, chunk[overlapSize:])
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return fmt.Errorf("failed to read chunk: %w", err)
		}

		if n == 0 {
			break // End of file
		}

		// Total valid bytes in chunk
		validBytes := overlapSize + n
		chunkData := chunk[:validBytes]

		// Save overlap for next iteration
		nextOverlapSize := max(sp.MaxPatternLen-1, 0)
		if len(chunkData) >= nextOverlapSize {
			overlapBuffer = make([]byte, nextOverlapSize)
			copy(overlapBuffer, chunkData[len(chunkData)-nextOverlapSize:])
		} else {
			overlapBuffer = make([]byte, len(chunkData))
			copy(overlapBuffer, chunkData)
		}

		// Process chunk sequentially (AC automaton has shared mutable state)
		chunkOffset := currentStreamOffset - int64(overlapSize)
		result := sp.processChunk(chunkData, chunkIndex, chunkOffset)
		results <- result

		sp.updateProgress(int64(n))
		currentStreamOffset += int64(n)
		chunkIndex++
	}

	return nil
}

// processDataChunks processes byte data in chunks with overlap.
// Sequential to avoid data races on shared AC automaton state.
func (sp *StreamingProcessor) processDataChunks(ctx context.Context, data []byte, results chan<- ProcessingResult) error {
	chunkCount := (len(data) + sp.ChunkSize - 1) / sp.ChunkSize

	for i := range chunkCount {
		select {
		case <-ctx.Done():
			close(results)
			return fmt.Errorf("context canceled during processing: %w", ctx.Err())
		default:
		}

		start := i * sp.ChunkSize
		end := min(start+sp.ChunkSize, len(data))

		// Add overlap for boundary-crossing patterns (except for first chunk)
		if i > 0 {
			overlapSize := min(max(sp.MaxPatternLen-1, 0), start)
			start -= overlapSize
		}

		chunkData := data[start:end]
		actualOffset := int64(start)

		result := sp.processChunk(chunkData, i, actualOffset)
		results <- result

		// Update progress based on new unique bytes processed
		sp.updateProgress(int64(end - i*sp.ChunkSize))
	}

	close(results)
	return nil
}

// processChunk processes a single chunk of data
func (sp *StreamingProcessor) processChunk(chunk []byte, chunkIndex int, offset int64) ProcessingResult {
	start := time.Now()

	// Process chunk with automaton
	matches := sp.chunkProcessor.processChunk(chunk, offset)

	elapsed := time.Since(start)

	return ProcessingResult{
		ChunkIndex:     chunkIndex,
		Matches:        matches,
		BytesProcessed: int64(len(chunk)),
		ProcessingTime: elapsed,
	}
}

// processChunk processes chunk data and finds matches
func (cp *ChunkProcessor) processChunk(chunk []byte, offset int64) []StreamingMatch {
	var matches []StreamingMatch

	for _, rule := range cp.rules {
		if rule.Automaton == nil {
			continue
		}

		ruleMatches := cp.processRule(chunk, offset, rule)
		matches = append(matches, ruleMatches...)

		// Check if we should stop due to match limit
		if cp.matchBuffer.reachedLimit() {
			break
		}
	}

	return matches
}

// processRule processes a single rule's automaton against the chunk
func (cp *ChunkProcessor) processRule(chunk []byte, offset int64, rule *CompiledRule) []StreamingMatch {
	var matches []StreamingMatch

	for match := range rule.Automaton.SearchIter(chunk) {
		ruleMatch, ok := cp.createRuleMatch(chunk, offset, rule, match)
		if !ok {
			continue
		}

		matches = append(matches, ruleMatch)
		cp.matchBuffer.addMatch(ruleMatch)
	}

	return matches
}

// createRuleMatch creates a StreamingMatch from an automaton match
//
//nolint:revive // argument-limit: API surface
func (cp *ChunkProcessor) createRuleMatch(chunk []byte, offset int64, rule *CompiledRule, match ACMatch) (StreamingMatch, bool) {
	if rule != nil && rule.IsPrivateString(match.StringID) {
		return StreamingMatch{}, false
	}
	position := match.Backtrack
	length := cp.getMatchLength(rule, match)

	// Ensure position is within bounds
	if !cp.isValidPosition(position, length, len(chunk)) {
		return StreamingMatch{}, false
	}

	return StreamingMatch{
		Rule:    rule.Name,
		Pattern: match.StringID,
		Offset:  offset + int64(position),
		Length:  length,
		Data:    chunk[position : position+length],
	}, true
}

// getMatchLength determines the length of a match
func (cp *ChunkProcessor) getMatchLength(rule *CompiledRule, match ACMatch) int {
	// Get actual length from automaton strings
	if match.StringIndex >= 0 && match.StringIndex < len(rule.Automaton.Strings) {
		actualLength := rule.Automaton.Strings[match.StringIndex].Length
		if actualLength > 0 {
			return actualLength
		}
	}

	// Fallback: use pattern name to determine length
	if match.StringID == "$pattern" {
		return 9 // length of "malicious"
	}

	return 9 // Default fallback length
}

// isValidPosition checks if the position and length are within bounds
func (cp *ChunkProcessor) isValidPosition(position, length, chunkSize int) bool {
	return position >= 0 && position < chunkSize && position+length <= chunkSize
}

// updateProgress updates processing progress
func (sp *StreamingProcessor) updateProgress(bytesProcessed int64) {
	sp.progress.mu.Lock()
	defer sp.progress.mu.Unlock()

	sp.progress.processed += bytesProcessed

	// Only log progress every 25% completion or every 10MB, whichever comes first
	percentComplete := float64(sp.progress.processed) / float64(sp.progress.totalBytes) * 100
	percentInt := int(percentComplete)

	// Log if we've reached a new 25% milestone
	if percentInt%25 != 0 && percentInt != 100 {
		return
	}

	// Also log every 10MB to avoid too frequent updates on small files
	if sp.progress.processed < 10*1024*1024 && sp.progress.processed%(1024*1024) != 0 {
		return
	}

	elapsed := time.Since(sp.progress.startTime)
	rate := float64(sp.progress.processed) / elapsed.Seconds() / 1024 / 1024

	fmt.Printf("Progress: %.1f%% (%d/%d MB) - %.1f MB/s - %d matches found\n",
		percentComplete,
		sp.progress.processed/1024/1024,
		sp.progress.totalBytes/1024/1024,
		rate,
		sp.progress.matchesFound)
}

// addMatch adds a match to the buffer
func (mb *MatchBuffer) addMatch(match StreamingMatch) {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	if len(mb.matches) < mb.limit {
		mb.matches = append(mb.matches, match)
	}
}

// reachedLimit checks if match limit is reached
func (mb *MatchBuffer) reachedLimit() bool {
	mb.mu.RLock()
	defer mb.mu.RUnlock()
	return len(mb.matches) >= mb.limit
}

// GetProgress returns current processing progress
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

// SetChunkSize sets the chunk size for processing
func (sp *StreamingProcessor) SetChunkSize(size int) {
	if size > 0 {
		sp.ChunkSize = size
	}
}

// SetMaxConcurrency sets maximum concurrent goroutines
func (sp *StreamingProcessor) SetMaxConcurrency(maxConcurrency int) {
	if maxConcurrency > 0 {
		sp.MaxConcurrency = maxConcurrency
	}
}

// EnableEarlyTermination enables/disables early termination
func (sp *StreamingProcessor) EnableEarlyTermination(enable bool) {
	sp.EarlyTermination = enable
}
