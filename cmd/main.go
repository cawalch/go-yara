// Package main provides a command-line tool for inspecting, compiling, and
// executing YARA rules.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/utils/fs"
)

const (
	modeCompile = "compile"
	modeLex     = "lex"
	modeParse   = "parse"
	modeExecute = "execute"
)

var version = "dev"

type commandArgs struct {
	filename          string
	target            string
	mode              string
	dataFile          string
	enableStreaming   bool
	chunkSize         int
	earlyTermination  bool
	matchDataBytes    int
	matchContextBytes int
	maxMatchSpan      int

	explicitExecute bool

	// Standard YARA parity options
	recursive    bool
	threads      int
	printStrings bool
	printMeta    bool
	printTags    bool
	countOnly    bool
	tagFilter    string
	identFilter  string
	negate       bool
	fastScan     bool
	jsonOutput   bool
}

func (args *commandArgs) isStandardScan() bool {
	if args.mode == modeLex || args.mode == modeParse || args.mode == modeCompile {
		return false
	}
	if args.enableStreaming {
		return false
	}
	if args.explicitExecute && !args.hasStandardFlags() {
		return false
	}
	return args.target != ""
}

func (args *commandArgs) hasStandardFlags() bool {
	return args.recursive || args.threads > 0 || args.printStrings ||
		args.printMeta || args.printTags || args.countOnly ||
		args.tagFilter != "" || args.identFilter != "" ||
		args.negate || args.fastScan || args.jsonOutput
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(rawArgs []string) error {
	args, err := parseArgs(rawArgs)
	if err != nil {
		return err
	}

	content, err := readFileContent(args.filename)
	if err != nil {
		return err
	}
	return runMode(args.mode, content, args)
}

func parseArgs(rawArgs []string) (*commandArgs, error) {
	flagSet := flag.NewFlagSet("go-yara", flag.ContinueOnError)

	mode := flagSet.String("mode", "", "processing mode: lex, parse, compile, execute (default: compile or execute if target given)")
	dataFile := flagSet.String("data", "", "data file to match against (for --mode=execute)")
	streaming := flagSet.Bool("streaming", false, "enable streaming processing for large files")
	chunkSize := flagSet.Int("chunk-size", 1024*1024, "chunk size in bytes (default: 1MB)")
	earlyTermination := flagSet.Bool("early-termination", false, "enable early termination when matches found")
	matchData := flagSet.Int("match-data", 0, "include up to n matched bytes in execute output")
	matchContext := flagSet.Int("match-context", 0, "include n bytes before and after each match in execute output")
	maxMatchSpan := flagSet.Int("max-match-span", 0, "bound maximum bytes evaluated for a single regex match (default: unlimited)")

	recursive := flagSet.Bool("recursive", false, "recursively search directories")
	flagSet.BoolVar(recursive, "r", false, "recursively search directories (shorthand)")

	threads := flagSet.Int("threads", 0, "number of worker threads for parallel scanning (default: NumCPU)")
	flagSet.IntVar(threads, "p", 0, "number of worker threads for parallel scanning (shorthand)")

	printStrings := flagSet.Bool("print-strings", false, "print matching strings")
	flagSet.BoolVar(printStrings, "s", false, "print matching strings (shorthand)")

	printMeta := flagSet.Bool("print-meta", false, "print metadata")
	flagSet.BoolVar(printMeta, "m", false, "print metadata (shorthand)")

	printTags := flagSet.Bool("print-tags", false, "print tags")
	flagSet.BoolVar(printTags, "g", false, "print tags (shorthand)")

	countOnly := flagSet.Bool("count", false, "print only number of matches")
	flagSet.BoolVar(countOnly, "c", false, "print only number of matches (shorthand)")

	tagFilter := flagSet.String("tag", "", "print only rules tagged as <tag>")
	flagSet.StringVar(tagFilter, "t", "", "print only rules tagged as <tag> (shorthand)")

	identFilter := flagSet.String("identifier", "", "print only rules with name <ident>")
	flagSet.StringVar(identFilter, "i", "", "print only rules with name <ident> (shorthand)")

	negate := flagSet.Bool("negate", false, "print only not satisfied rules")
	flagSet.BoolVar(negate, "n", false, "print only not satisfied rules (shorthand)")

	fastScan := flagSet.Bool("fast-scan", false, "fast scan mode, skips match offset extraction")
	noMatches := flagSet.Bool("no-matches", false, "alias for --fast-scan")

	jsonOutput := flagSet.Bool("json", false, "emit structured JSON output")

	flagSet.Usage = func() {
		_, _ = fmt.Fprintf(flagSet.Output(), "Usage: go-yara <yara-file> [options] [target]\n\n")
		_, _ = fmt.Fprintf(flagSet.Output(), "Options:\n")
		flagSet.PrintDefaults()
		_, _ = fmt.Fprintf(flagSet.Output(), "\nModes: lex, parse, compile (default), execute\n")
	}

	if len(rawArgs) == 0 {
		flagSet.Usage()
		return nil, errors.New("missing YARA file")
	}
	if rawArgs[0] == "-h" || rawArgs[0] == "--help" {
		return nil, flagSet.Parse(rawArgs)
	}
	if rawArgs[0] == "-v" || rawArgs[0] == "--version" || rawArgs[0] == "-version" {
		_, _ = fmt.Fprintf(flagSet.Output(), "go-yara version %s\n", version)
		return nil, flag.ErrHelp
	}

	// Extract the positional filename (first non-flag argument)
	filename := rawArgs[0]
	if filename == "" {
		return nil, errors.New("missing YARA file")
	}
	flagArgs := rawArgs[1:]
	// If the first arg looks like a flag, there's no positional filename
	if rawArgs[0][0] == '-' {
		flagSet.Usage()
		return nil, errors.New("YARA file must be the first argument")
	}

	if err := flagSet.Parse(flagArgs); err != nil {
		return nil, err
	}

	var target string
	if flagSet.NArg() == 1 {
		target = flagSet.Arg(0)
	} else if flagSet.NArg() > 1 {
		return nil, fmt.Errorf("unexpected argument %q", flagSet.Arg(1))
	}

	if target == "" && *dataFile != "" {
		target = *dataFile
	}
	if *dataFile == "" && target != "" {
		*dataFile = target
	}

	explicitExecute := false
	finalMode := *mode
	switch finalMode {
	case "":
		if target != "" || *streaming {
			finalMode = modeExecute
		} else {
			finalMode = modeCompile
		}
	case modeExecute:
		explicitExecute = true
	}

	// Validate mode
	switch finalMode {
	case modeLex, modeParse, modeCompile, modeExecute:
		// ok
	default:
		return nil, fmt.Errorf("unknown mode %q", finalMode)
	}

	// Validate --data is provided for execute mode
	if finalMode == modeExecute && target == "" {
		return nil, errors.New("--mode=execute requires --data <data-file>")
	}
	if *chunkSize <= 0 {
		return nil, errors.New("--chunk-size must be positive")
	}
	if *matchData < 0 {
		return nil, errors.New("--match-data must be non-negative")
	}
	if *matchContext < 0 {
		return nil, errors.New("--match-context must be non-negative")
	}
	if *maxMatchSpan < 0 {
		return nil, errors.New("--max-match-span must be non-negative")
	}
	if *threads < 0 {
		return nil, errors.New("--threads must be non-negative")
	}

	return &commandArgs{
		filename:          filename,
		target:            target,
		mode:              finalMode,
		dataFile:          *dataFile,
		enableStreaming:   *streaming,
		chunkSize:         *chunkSize,
		earlyTermination:  *earlyTermination,
		matchDataBytes:    *matchData,
		matchContextBytes: *matchContext,
		maxMatchSpan:      *maxMatchSpan,
		explicitExecute:   explicitExecute,
		recursive:         *recursive,
		threads:           *threads,
		printStrings:      *printStrings,
		printMeta:         *printMeta,
		printTags:         *printTags,
		countOnly:         *countOnly,
		tagFilter:         *tagFilter,
		identFilter:       *identFilter,
		negate:            *negate,
		fastScan:          *fastScan || *noMatches,
		jsonOutput:        *jsonOutput,
	}, nil
}

func readFileContent(filename string) ([]byte, error) {
	content, err := fs.ReadFile("", filename) // #nosec G304 - file reading is intentional
	if err != nil {
		return nil, fmt.Errorf("reading YARA file: %w", err)
	}
	return content, nil
}

func runMode(mode string, content []byte, args *commandArgs) error {
	if args.isStandardScan() {
		return runStandardScan(string(content), args)
	}

	switch mode {
	case modeLex:
		return runLexerMode(string(content))
	case modeParse:
		return runParserMode(string(content), args.filename)
	case modeCompile:
		return runCompileMode(string(content), args.filename)
	case modeExecute:
		return runExecuteMode(string(content), args.dataFile, args.filename, args)
	default:
		return fmt.Errorf("unsupported mode: %s", mode)
	}
}

func compileRulesQuiet(content, filename string) (*compiler.CompiledProgram, error) {
	comp := compiler.NewCompiler()
	comp.SetBaseDir(filepath.Dir(filename))
	compiledProgram, err := comp.CompileSourceWithContext(context.Background(), content)
	if err != nil {
		return nil, fmt.Errorf("compiling rules: %w", err)
	}

	compilationErrors := comp.GetErrors()
	if len(compilationErrors) > 0 {
		for _, cerr := range compilationErrors {
			fmt.Fprintf(os.Stderr, "  [%s] %s\n", cerr.Phase, cerr.Message)
		}
		return nil, errors.New("compilation errors detected")
	}
	return compiledProgram, nil
}

func collectTargets(target string, recursive bool) ([]string, error) {
	cleanTarget := filepath.Clean(target)
	info, err := os.Stat(cleanTarget) // #nosec G703 - caller intentionally inspects scan target
	if err != nil {
		return nil, fmt.Errorf("stat target %s: %w", target, err)
	}
	if !info.IsDir() {
		return []string{cleanTarget}, nil
	}
	if !recursive {
		return nil, fmt.Errorf("target %s is a directory (use -r / --recursive to scan directories)", target)
	}
	var files []string
	err = filepath.WalkDir(cleanTarget, func(path string, d os.DirEntry, err error) error { // #nosec G703 - caller intentionally inspects scan target
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scanning directory %s: %w", target, err)
	}
	sort.Strings(files)
	return files, nil
}

func buildScannerOptions(args *commandArgs) []compiler.ScannerOption {
	var opts []compiler.ScannerOption
	if args.tagFilter != "" {
		opts = append(opts, compiler.WithTagsFilter([]string{args.tagFilter}))
	}
	if args.fastScan {
		opts = append(opts, compiler.WithFastScan(), compiler.WithoutMatches())
	}
	if args.maxMatchSpan > 0 {
		opts = append(opts, compiler.WithMaxMatchSpan(args.maxMatchSpan))
	}
	if args.printStrings && !args.fastScan {
		opts = append(opts, compiler.WithMatchData(1024))
	}
	return opts
}

func runStandardScan(content string, args *commandArgs) error {
	compiledProgram, err := compileRulesQuiet(content, args.filename)
	if err != nil {
		return err
	}

	targets, err := collectTargets(args.target, args.recursive)
	if err != nil {
		return err
	}

	return scanTargets(compiledProgram, targets, args)
}

func scanTargets(compiledProgram *compiler.CompiledProgram, targets []string, args *commandArgs) error {
	numWorkers := args.threads
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}
	if numWorkers > len(targets) {
		numWorkers = len(targets)
	}
	if numWorkers <= 0 {
		numWorkers = 1
	}

	scannerOptions := buildScannerOptions(args)
	results := make([]fileScanResult, len(targets))

	jobs := make(chan fileJob, numWorkers*2)
	go func() {
		for i, t := range targets {
			jobs <- fileJob{idx: i, path: t}
		}
		close(jobs)
	}()

	var firstErr error
	var errMu sync.Mutex
	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanner := compiler.NewScanner(compiledProgram, scannerOptions...)
			defer scanner.Close()

			for job := range jobs {
				var data []byte
				var cleanup func()
				var err error

				info, statErr := os.Stat(job.path)
				if statErr == nil && info.Mode().IsRegular() && info.Size() >= fs.MinMmapFileSize {
					data, cleanup, err = fs.MapFile(job.path)
				}
				if data == nil || err != nil {
					data, err = os.ReadFile(job.path) // #nosec G304,G703 - user specified target
					cleanup = func() {}
				}
				if err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("reading target %s: %w", job.path, err)
					}
					errMu.Unlock()
					continue
				}

				res, err := scanner.Scan(data)
				if err != nil {
					cleanup()
					errMu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("scanning target %s: %w", job.path, err)
					}
					errMu.Unlock()
					continue
				}

				// If string matches or JSON output aren't requested, data is no longer needed;
				// release the memory mapping immediately to minimize active memory footprint.
				needsData := (args.printStrings || args.jsonOutput) && len(res.MatchedRules) > 0
				if !needsData {
					cleanup()
					cleanup = nil
					data = nil
				}

				results[job.idx] = fileScanResult{target: job.path, res: res, data: data, cleanup: cleanup}
			}
		}()
	}
	wg.Wait()

	defer func() {
		for _, r := range results {
			if r.cleanup != nil {
				r.cleanup()
			}
		}
	}()

	if firstErr != nil {
		return firstErr
	}

	isMulti := len(targets) > 1
	for _, r := range results {
		if r.res != nil {
			if err := outputFileResult(r, args, isMulti); err != nil {
				return err
			}
		}
		if r.cleanup != nil {
			r.cleanup()
			r.cleanup = nil
		}
	}
	return nil
}

func readOrMapDataFile(dataFile string) ([]byte, func(), error) {
	info, statErr := os.Stat(dataFile)
	if statErr == nil && info.Mode().IsRegular() && info.Size() >= fs.MinMmapFileSize {
		data, cleanup, err := fs.MapFile(dataFile)
		if err == nil {
			return data, cleanup, nil
		}
	}
	data, err := fs.ReadFile("", dataFile) // #nosec G304 - intentional file reading
	if err != nil {
		return nil, nil, fmt.Errorf("reading data file %s: %w", dataFile, err)
	}
	return data, func() {}, nil
}

//nolint:revive // argument-limit: CLI entry point
func runExecuteMode(content, dataFile, filename string, args *commandArgs) error {
	if args.enableStreaming {
		if err := printStreamingDataSummary(dataFile); err != nil {
			return err
		}
		compiledProgram, err := compileRules(content, filename)
		if err != nil {
			return err
		}
		return executeRulesStreaming(compiledProgram, dataFile, args)
	}

	data, cleanup, err := readOrMapDataFile(dataFile)
	if err != nil {
		return err
	}
	defer cleanup()

	printDataSummary(dataFile, data)

	compiledProgram, err := compileRules(content, filename)
	if err != nil {
		return err
	}

	return executeRules(compiledProgram, data, args)
}

func compileRules(content, filename string) (*compiler.CompiledProgram, error) {
	comp := compiler.NewCompiler()
	comp.SetBaseDir(filepath.Dir(filename))
	compiledProgram, err := comp.CompileSourceWithContext(context.Background(), content)
	if err != nil {
		return nil, fmt.Errorf("compiling rules: %w", err)
	}

	compilationErrors := comp.GetErrors()
	if len(compilationErrors) > 0 {
		fmt.Printf("\nCompilation errors (%d):\n", len(compilationErrors))
		for _, cerr := range compilationErrors {
			fmt.Printf("  [%s] %s\n", cerr.Phase, cerr.Message)
		}
		return nil, errors.New("compilation errors detected")
	}

	fmt.Printf("Compilation: Successfully compiled %d rules\n\n", len(compiledProgram.Rules))
	return compiledProgram, nil
}

func executeRules(compiledProgram *compiler.CompiledProgram, data []byte, args *commandArgs) error {
	scannerOptions := make([]compiler.ScannerOption, 0, 3)
	if args.matchDataBytes > 0 {
		scannerOptions = append(scannerOptions, compiler.WithMatchData(args.matchDataBytes))
	}
	if args.matchContextBytes > 0 {
		scannerOptions = append(scannerOptions, compiler.WithMatchContext(args.matchContextBytes, args.matchContextBytes))
	}
	if args.maxMatchSpan > 0 {
		scannerOptions = append(scannerOptions, compiler.WithMaxMatchSpan(args.maxMatchSpan))
	}
	scanner := compiler.NewScanner(compiledProgram, scannerOptions...)
	defer scanner.Close()

	result, err := scanner.Scan(data)
	if err != nil {
		return fmt.Errorf("executing rules: %w", err)
	}

	totalMatches := 0
	for _, rule := range compiledProgram.Rules {
		fmt.Printf("Executing rule: %s\n", rule.GetName())

		printEntries := matchEntriesFromMatches(rule, result.Matches[rule.GetName()])
		totalMatches += printPatternMatches(printEntries)

		fmt.Printf("  Execution: Success\n")
		if result.RuleResults[rule.GetName()] {
			fmt.Printf("  Result: MATCH (value: 1)\n")
		} else {
			fmt.Printf("  Result: NO MATCH\n")
		}

		fmt.Println()
	}

	fmt.Printf("Total matches found: %d\n", totalMatches)
	return nil
}

// executeRulesStreaming reports chunked pattern matches. It does not evaluate rule conditions.
func executeRulesStreaming(compiledProgram *compiler.CompiledProgram, dataFile string, args *commandArgs) error {
	fmt.Printf("Streaming pattern scan enabled (chunk size: %d bytes)\n", args.chunkSize)
	fmt.Printf("Note: streaming mode reports literal text-pattern matches only; regex, hex, and rule conditions are not evaluated.\n")

	// Configure streaming
	compiledProgram.EnableStreaming(true)
	compiledProgram.SetStreamingChunkSize(args.chunkSize)
	compiledProgram.EnableStreamingEarlyTermination(args.earlyTermination)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Process with streaming
	start := time.Now()
	matches, err := compiledProgram.ProcessFileStreaming(ctx, dataFile)
	if err != nil {
		return fmt.Errorf("streaming execution: %w", err)
	}
	elapsed := time.Since(start)

	// Print results
	fmt.Printf("\nStreaming Pattern Results:\n")
	fmt.Printf("  Processing time: %v\n", elapsed)
	fmt.Printf("  Total pattern matches: %d\n", len(matches))

	if len(matches) > 0 {
		fmt.Printf("  Pattern matches found:\n")
		for _, match := range matches {
			fmt.Printf("    Rule: %s, Pattern: %s, Offset: %d, Length: %d\n",
				match.Rule, match.Pattern, match.Offset, match.Length)
		}
	}

	// Show final progress
	processed, total, percent, _ := compiledProgram.GetStreamingProgress()
	fmt.Printf("  Progress: %d/%d bytes (%.1f%%)\n", processed, total, percent)

	if elapsed > 0 && processed > 0 {
		throughput := float64(processed) / elapsed.Seconds() / 1024 / 1024
		fmt.Printf("  Throughput: %.2f MB/s\n", throughput)
	}
	return nil
}
