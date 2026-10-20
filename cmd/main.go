// Package main provides a command-line tool for inspecting, compiling, and
// executing YARA rules.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
	"github.com/cawalch/go-yara/token"
	"github.com/cawalch/go-yara/utils/fs"
)

const (
	modeCompile = "compile"
	modeLex     = "lex"
	modeParse   = "parse"
	modeExecute = "execute"
)

var version = "dev"

// formatToken formats a token for display
func formatToken(tok token.Token) string {
	if tok.Type == token.EOF {
		return fmt.Sprintf("{EOF @ %d:%d}", tok.Pos.Line, tok.Pos.Column)
	}
	return fmt.Sprintf("{%v %q @ %d:%d}", tok.Type, tok.Literal, tok.Pos.Line, tok.Pos.Column)
}

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
	fs := flag.NewFlagSet("go-yara", flag.ContinueOnError)

	mode := fs.String("mode", "", "processing mode: lex, parse, compile, execute (default: compile or execute if target given)")
	dataFile := fs.String("data", "", "data file to match against (for --mode=execute)")
	streaming := fs.Bool("streaming", false, "enable streaming processing for large files")
	chunkSize := fs.Int("chunk-size", 1024*1024, "chunk size in bytes (default: 1MB)")
	earlyTermination := fs.Bool("early-termination", false, "enable early termination when matches found")
	matchData := fs.Int("match-data", 0, "include up to n matched bytes in execute output")
	matchContext := fs.Int("match-context", 0, "include n bytes before and after each match in execute output")
	maxMatchSpan := fs.Int("max-match-span", 0, "bound maximum bytes evaluated for a single regex match (default: unlimited)")

	recursive := fs.Bool("recursive", false, "recursively search directories")
	fs.BoolVar(recursive, "r", false, "recursively search directories (shorthand)")

	threads := fs.Int("threads", 0, "number of worker threads for parallel scanning (default: NumCPU)")
	fs.IntVar(threads, "p", 0, "number of worker threads for parallel scanning (shorthand)")

	printStrings := fs.Bool("print-strings", false, "print matching strings")
	fs.BoolVar(printStrings, "s", false, "print matching strings (shorthand)")

	printMeta := fs.Bool("print-meta", false, "print metadata")
	fs.BoolVar(printMeta, "m", false, "print metadata (shorthand)")

	printTags := fs.Bool("print-tags", false, "print tags")
	fs.BoolVar(printTags, "g", false, "print tags (shorthand)")

	countOnly := fs.Bool("count", false, "print only number of matches")
	fs.BoolVar(countOnly, "c", false, "print only number of matches (shorthand)")

	tagFilter := fs.String("tag", "", "print only rules tagged as <tag>")
	fs.StringVar(tagFilter, "t", "", "print only rules tagged as <tag> (shorthand)")

	identFilter := fs.String("identifier", "", "print only rules with name <ident>")
	fs.StringVar(identFilter, "i", "", "print only rules with name <ident> (shorthand)")

	negate := fs.Bool("negate", false, "print only not satisfied rules")
	fs.BoolVar(negate, "n", false, "print only not satisfied rules (shorthand)")

	fastScan := fs.Bool("fast-scan", false, "fast scan mode, skips match offset extraction")
	noMatches := fs.Bool("no-matches", false, "alias for --fast-scan")

	jsonOutput := fs.Bool("json", false, "emit structured JSON output")

	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "Usage: go-yara <yara-file> [options] [target]\n\n")
		_, _ = fmt.Fprintf(fs.Output(), "Options:\n")
		fs.PrintDefaults()
		_, _ = fmt.Fprintf(fs.Output(), "\nModes: lex, parse, compile (default), execute\n")
	}

	if len(rawArgs) == 0 {
		fs.Usage()
		return nil, errors.New("missing YARA file")
	}
	if rawArgs[0] == "-h" || rawArgs[0] == "--help" {
		return nil, fs.Parse(rawArgs)
	}
	if rawArgs[0] == "-v" || rawArgs[0] == "--version" || rawArgs[0] == "-version" {
		_, _ = fmt.Fprintf(fs.Output(), "go-yara version %s\n", version)
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
		fs.Usage()
		return nil, errors.New("YARA file must be the first argument")
	}

	if err := fs.Parse(flagArgs); err != nil {
		return nil, err
	}

	var target string
	if fs.NArg() == 1 {
		target = fs.Arg(0)
	} else if fs.NArg() > 1 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(1))
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
		return nil, fmt.Errorf("reading YARA file %s: %w", filename, err)
	}
	return content, nil
}

func runMode(mode string, content []byte, args *commandArgs) error {
	if args.isStandardScan() {
		return runStandardScan(string(content), args)
	}

	fmt.Printf("Processing YARA file: %s (mode: %s)\n", args.filename, mode)
	fmt.Printf("File content:\n%s\n\n", string(content))

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
		return fmt.Errorf("unknown mode %q", mode)
	}
}

type jsonMatchEntry struct {
	Identifier string `json:"identifier"`
	Offset     int64  `json:"offset"`
	Length     int    `json:"length"`
	Data       string `json:"data,omitempty"`
}

type jsonMatchReport struct {
	Target  string           `json:"target"`
	Rule    string           `json:"rule"`
	Tags    []string         `json:"tags,omitempty"`
	Meta    map[string]any   `json:"meta,omitempty"`
	Matches []jsonMatchEntry `json:"matches,omitempty"`
}

type jsonCountReport struct {
	Target string `json:"target"`
	Count  int    `json:"count"`
}

type fileJob struct {
	idx  int
	path string
}

type fileScanResult struct {
	target string
	res    *compiler.ScanResult
	data   []byte
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
		return nil, fmt.Errorf("compilation error: %s", compilationErrors[0].Message)
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

	jobs := make(chan fileJob, len(targets))
	for i, t := range targets {
		jobs <- fileJob{idx: i, path: t}
	}
	close(jobs)

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
				data, err := os.ReadFile(job.path) // #nosec G304,G703 - user specified target
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
					errMu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("scanning target %s: %w", job.path, err)
					}
					errMu.Unlock()
					continue
				}

				results[job.idx] = fileScanResult{target: job.path, res: res, data: data}
			}
		}()
	}
	wg.Wait()

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
	}
	return nil
}

func filterNegatedRules(res *compiler.ScanResult, identFilter string) []compiler.RuleMatch {
	var rules []compiler.RuleMatch
	for ruleName, matched := range res.RuleResults {
		if !matched {
			if identFilter != "" && ruleName != identFilter {
				continue
			}
			rules = append(rules, compiler.RuleMatch{Rule: ruleName})
		}
	}
	return rules
}

func filterMatchedRules(res *compiler.ScanResult, identFilter string) []compiler.RuleMatch {
	var rules []compiler.RuleMatch
	for _, r := range res.MatchedRules {
		if identFilter != "" && r.Rule != identFilter {
			continue
		}
		rules = append(rules, r)
	}
	return rules
}

func filterScanRules(res *compiler.ScanResult, args *commandArgs) []compiler.RuleMatch {
	var rules []compiler.RuleMatch
	if args.negate {
		rules = filterNegatedRules(res, args.identFilter)
	} else {
		rules = filterMatchedRules(res, args.identFilter)
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Rule < rules[j].Rule
	})
	return rules
}

func outputFileResult(r fileScanResult, args *commandArgs, isMultiTarget bool) error {
	matchedRules := filterScanRules(r.res, args)

	if args.jsonOutput {
		return outputJSONResult(r, matchedRules, args)
	}

	if args.countOnly {
		if isMultiTarget {
			fmt.Printf("%s: %d\n", r.target, len(matchedRules))
		} else {
			fmt.Printf("%d\n", len(matchedRules))
		}
		return nil
	}

	for _, rule := range matchedRules {
		tagStr := ""
		if args.printTags && len(rule.Tags) > 0 {
			tagStr = fmt.Sprintf(" [%s]", strings.Join(rule.Tags, ","))
		}
		metaStr := ""
		if args.printMeta && len(rule.Meta) > 0 {
			metaStr = " " + formatMetaBracket(rule.Meta)
		}
		fmt.Printf("%s%s%s %s\n", rule.Rule, tagStr, metaStr, r.target)

		if args.printStrings && !args.fastScan {
			printRuleMatchStrings(rule, r.data)
		}
	}
	return nil
}

func formatMetaBracket(meta map[string]any) string {
	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := meta[k]
		switch val := v.(type) {
		case string:
			parts = append(parts, fmt.Sprintf("%s=%q", k, val))
		default:
			parts = append(parts, fmt.Sprintf("%s=%v", k, val))
		}
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func printRuleMatchStrings(r compiler.RuleMatch, data []byte) {
	var entries []printEntry
	for id, matches := range r.Matches {
		for _, m := range matches {
			entries = append(entries, printEntry{
				id:     id,
				offset: int(m.Offset),
				length: m.Length,
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].offset != entries[j].offset {
			return entries[i].offset < entries[j].offset
		}
		return entries[i].id < entries[j].id
	})
	for _, e := range entries {
		var sVal string
		if e.offset >= 0 && e.offset+e.length <= len(data) {
			raw := data[e.offset : e.offset+e.length]
			if isAllPrintableASCII(raw) {
				sVal = string(raw)
			} else {
				sVal = fmt.Sprintf("%q", raw)
			}
		}
		fmt.Printf("0x%x:%s: %s\n", e.offset, e.id, sVal)
	}
}

func isAllPrintableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func collectJSONMatches(r compiler.RuleMatch, data []byte) []jsonMatchEntry {
	if len(r.Matches) == 0 {
		return nil
	}
	var entries []printEntry
	for id, ms := range r.Matches {
		for _, m := range ms {
			entries = append(entries, printEntry{
				id:     id,
				offset: int(m.Offset),
				length: m.Length,
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].offset != entries[j].offset {
			return entries[i].offset < entries[j].offset
		}
		return entries[i].id < entries[j].id
	})
	jsonEntries := make([]jsonMatchEntry, 0, len(entries))
	for _, e := range entries {
		var sVal string
		if e.offset >= 0 && e.offset+e.length <= len(data) {
			raw := data[e.offset : e.offset+e.length]
			if isAllPrintableASCII(raw) {
				sVal = string(raw)
			} else {
				sVal = fmt.Sprintf("%q", raw)
			}
		}
		jsonEntries = append(jsonEntries, jsonMatchEntry{
			Identifier: e.id,
			Offset:     int64(e.offset),
			Length:     e.length,
			Data:       sVal,
		})
	}
	return jsonEntries
}

func outputJSONResult(r fileScanResult, rules []compiler.RuleMatch, args *commandArgs) error {
	if args.countOnly {
		rep := jsonCountReport{Target: r.target, Count: len(rules)}
		enc, err := json.Marshal(rep)
		if err != nil {
			return err
		}
		fmt.Println(string(enc))
		return nil
	}

	for _, rule := range rules {
		rep := jsonMatchReport{
			Target: r.target,
			Rule:   rule.Rule,
			Tags:   rule.Tags,
			Meta:   rule.Meta,
		}
		if !args.fastScan {
			rep.Matches = collectJSONMatches(rule, r.data)
		}
		enc, err := json.Marshal(rep)
		if err != nil {
			return err
		}
		fmt.Println(string(enc))
	}
	return nil
}

func runLexerMode(content string) error {
	// Create lexer
	l := lexer.New(content)

	// Parse all tokens
	fmt.Println("Tokens:")
	for {
		tok := l.NextToken()
		fmt.Printf("  %s\n", formatToken(tok))
		if tok.Type == token.EOF {
			break
		}
	}

	// Check for lexer errors
	lexerErrors := l.Errors()
	if len(lexerErrors) > 0 {
		fmt.Printf("\nLexer errors (%d):\n", len(lexerErrors))
		for _, err := range lexerErrors {
			fmt.Printf("  %s\n", err.Error())
		}
		return errors.New("lexer errors detected")
	}

	fmt.Printf("\nSuccessfully lexed with no errors!\n")
	return nil
}

func runParserMode(content, filename string) error {
	program, err := parseContent(content)
	if err != nil {
		return err
	}

	if err := processIncludes(program, filename); err != nil {
		return err
	}
	printParseSummary(program)
	return nil
}

func parseContent(content string) (*ast.Program, error) {
	l := lexer.New(content)
	p := parser.New(l)

	program, err := p.ParseRulesWithContext(context.Background())
	if err != nil {
		printParserErrors(p, err)
		return nil, err
	}

	return program, nil
}

func printParserErrors(p *parser.Parser, mainErr error) {
	fmt.Printf("Parser error: %v\n", mainErr)
	parserErrors := p.Errors()
	if len(parserErrors) > 0 {
		fmt.Printf("\nParser errors (%d):\n", len(parserErrors))
		for _, err := range parserErrors {
			fmt.Printf("  %s\n", err.Error())
		}
	}
}

func processIncludes(program *ast.Program, filename string) error {
	if len(program.Includes) == 0 {
		return nil
	}

	comp := compiler.NewCompiler()
	comp.SetBaseDir(filepath.Dir(filename))

	if err := comp.ProcessIncludes(program); err != nil {
		return fmt.Errorf("processing includes: %w", err)
	}
	return nil
}

func printParseSummary(program *ast.Program) {
	fmt.Printf("Successfully parsed!\n")
	fmt.Printf("Program contains %d rules\n", len(program.Rules))
	fmt.Printf("Program contains %d includes\n", len(program.Includes))

	printRuleSummary(program.Rules)
	printIncludeSummary(program.Includes)
}

func printRuleSummary(rules []*ast.Rule) {
	for i, rule := range rules {
		fmt.Printf("  Rule %d: %s\n", i+1, rule.Name)
		if len(rule.Tags) > 0 {
			fmt.Printf("    Tags: %v\n", rule.Tags)
		}
		if len(rule.Strings) > 0 {
			fmt.Printf("    Strings: %d patterns\n", len(rule.Strings))
		}
	}
}

func printIncludeSummary(includes []*ast.Include) {
	for i, include := range includes {
		fmt.Printf("  Include %d: %s\n", i+1, include.File)
	}
}

func runCompileMode(content, filename string) error {
	// Create compiler
	comp := compiler.NewCompiler()
	// Set base directory for resolving includes
	comp.SetBaseDir(filepath.Dir(filename))

	// Compile program (this includes parsing, semantic analysis, and code generation)
	compiledProgram, err := comp.CompileSourceWithContext(context.Background(), content)
	if err != nil {
		fmt.Printf("Compilation error: %v\n", err)
		// Print detailed errors
		compilationErrors := comp.GetErrors()
		if len(compilationErrors) > 0 {
			fmt.Printf("\nCompilation errors (%d):\n", len(compilationErrors))
			for _, cerr := range compilationErrors {
				fmt.Printf("  [%s] %s\n", cerr.Phase, cerr.Message)
			}
		}
		return fmt.Errorf("compilation failed: %w", err)
	}

	compilationErrors := comp.GetErrors()
	if len(compilationErrors) > 0 {
		fmt.Printf("\nCompilation errors (%d):\n", len(compilationErrors))
		for _, cerr := range compilationErrors {
			fmt.Printf("  [%s] %s\n", cerr.Phase, cerr.Message)
		}
		return errors.New("compilation errors detected")
	}

	fmt.Printf("Compilation: Successfully compiled %d rules\n", len(compiledProgram.Rules))

	// Print compilation summary
	for i, rule := range compiledProgram.Rules {
		fmt.Printf("  Rule %d: %s (%d bytes)\n", i+1, rule.GetName(), len(rule.GetBytecode()))
	}
	return nil
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

	data, err := validateAndReadDataFile(dataFile)
	if err != nil {
		return err
	}

	printDataSummary(dataFile, data)

	compiledProgram, err := compileRules(content, filename)
	if err != nil {
		return err
	}

	return executeRules(compiledProgram, data, args)
}

func printStreamingDataSummary(dataFile string) error {
	file, err := os.Open(dataFile) // #nosec G304,G703 - caller intentionally selects scan input
	if err != nil {
		return fmt.Errorf("reading data file %s: %w", dataFile, err)
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("reading data file %s: %w", dataFile, err)
	}
	preview, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil {
		return fmt.Errorf("reading data file %s: %w", dataFile, err)
	}
	truncated := len(preview) > 256
	if truncated {
		preview = preview[:256]
	}

	fmt.Printf("Data file: %s (%d bytes)\n", dataFile, info.Size())
	fmt.Printf("Data content (first 256 bytes):\n")
	fmt.Printf("%s", string(preview))
	if truncated {
		fmt.Printf("...")
	}
	fmt.Printf("\n\n")
	return nil
}

func validateAndReadDataFile(dataFile string) ([]byte, error) {
	// Use centralized file reading utility with validation
	data, err := fs.ReadFile("", dataFile) // #nosec G304 - file reading is intentional
	if err != nil {
		return nil, fmt.Errorf("reading data file %s: %w", dataFile, err)
	}

	return data, nil
}

func printDataSummary(dataFile string, data []byte) {
	fmt.Printf("Data file: %s (%d bytes)\n", dataFile, len(data))
	fmt.Printf("Data content (first 256 bytes):\n")
	if len(data) > 256 {
		fmt.Printf("%s...\n\n", string(data[:256]))
	} else {
		fmt.Printf("%s\n\n", string(data))
	}
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

func matchEntriesFromMatches(rule *compiler.CompiledRule, matchesByID map[string][]compiler.Match) []printEntry {
	entries := make([]printEntry, 0)
	for id, matches := range matchesByID {
		if rule != nil && rule.IsPrivateString(id) {
			continue
		}
		for _, m := range matches {
			entries = append(entries, printEntry{
				id:                   id,
				offset:               int(m.Offset),
				length:               m.Length,
				matchedData:          m.MatchedData,
				contextBefore:        m.ContextBefore,
				contextAfter:         m.ContextAfter,
				matchedDataTruncated: m.MatchedDataTruncated,
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].offset != entries[j].offset {
			return entries[i].offset < entries[j].offset
		}
		if entries[i].id != entries[j].id {
			return entries[i].id < entries[j].id
		}
		return entries[i].length < entries[j].length
	})
	return entries
}

func printPatternMatches(printEntries []printEntry) int {
	fmt.Printf("  Pattern matches: %d\n", len(printEntries))
	totalMatches := 0
	for _, e := range printEntries {
		fmt.Printf("    - %s at offset %d (length: %d)\n", e.id, e.offset, e.length)
		if e.matchedData != nil || e.matchedDataTruncated {
			fmt.Printf("      matched-data: %s", formatBytes(e.matchedData))
			if e.matchedDataTruncated {
				fmt.Printf(" (truncated)")
			}
			fmt.Println()
		}
		if e.contextBefore != nil || e.contextAfter != nil {
			fmt.Printf("      context-before: %s\n", formatBytes(e.contextBefore))
			fmt.Printf("      context-after: %s\n", formatBytes(e.contextAfter))
		}
		totalMatches++
	}
	return totalMatches
}

func formatBytes(data []byte) string {
	return fmt.Sprintf("%q", data)
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

type printEntry struct {
	id                   string
	offset               int
	length               int
	matchedData          []byte
	contextBefore        []byte
	contextAfter         []byte
	matchedDataTruncated bool
}
