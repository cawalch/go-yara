// Command parity runs official YARA and go-yara on the same inputs and reports diffs.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type RunResult struct {
	Ok           bool
	ExitCode     int
	Stdout       string
	Stderr       string
	Err          error
	MatchedRules []string
}

type Case struct {
	RulePath string
	DataPath string
}

func main() {
	yaraBin := flag.String("yara-bin", "./yara/yara", "Path to official yara binary")
	goYaraCmd := flag.String("go-yara-cmd", "go run ./cmd/main.go", "Command to run go-yara CLI")
	rulesCSV := flag.String("rules", strings.Join(defaultRules(), ","), "Comma-separated list of rule file paths")
	data := flag.String("data", defaultData(), "Data file path to scan")
	timeout := flag.Duration("timeout", 15*time.Second, "Per-process timeout")
	outPath := flag.String("out", "docs/Parity_Report.md", "Output report path (markdown)")
	skipRegex := flag.Bool("skip-regex", false, "Skip rules that contain regex strings /.../")
	skipIncludes := flag.Bool("skip-includes", false, "Skip rules that contain include directives")
	skipModules := flag.Bool("skip-modules", false, "Skip rules that contain module imports (import \"...\")")
	regexSuite := flag.Bool("regex-suite", false, "Run curated regex-only parity suite (uses testdata/regex)")
	flag.Parse()

	// Build cases
	var cases []Case
	if *regexSuite {
		cases = buildRegexSuiteCases()
	} else {
		skipped := struct{ regex, includes, modules int }{}
		for _, r := range splitCSV(*rulesCSV) {
			// Apply skip filters
			if *skipRegex {
				if has, err := fileHasRegex(r); err == nil {
					if has {
						skipped.regex++
						continue
					}
				} else {
					fmt.Fprintf(os.Stderr, "warn: cannot read %s for regex check: %v\n", r, err)
				}
			}
			if *skipIncludes {
				if has, err := fileHasInclude(r); err == nil {
					if has {
						skipped.includes++
						continue
					}
				} else {
					fmt.Fprintf(os.Stderr, "warn: cannot read %s for include check: %v\n", r, err)
				}
			}
			if *skipModules {
				if has, err := fileHasImport(r); err == nil {
					if has {
						skipped.modules++
						continue
					}
				} else {
					fmt.Fprintf(os.Stderr, "warn: cannot read %s for import check: %v\n", r, err)
				}
			}
			cases = append(cases, Case{RulePath: r, DataPath: *data})
		}
	}

	// Execute matrix
	var rows []string
	header := "| Rule file | YARA matches | go-yara matches | Status |\n|---|---|---|---|"
	rows = append(rows, header)

	parityOK := 0
	mismatches := 0
	errorsCount := 0

	for _, c := range cases {
		off := runOfficial(*yaraBin, c.RulePath, c.DataPath, *timeout)
		gores := runGoYara(*goYaraCmd, c.RulePath, c.DataPath, *timeout)

		status := classify(off, gores)
		switch status {
		case "parity_ok":
			parityOK++
		case "mismatch":
			mismatches++
		default:
			if strings.HasPrefix(status, "error") {
				errorsCount++
			}
		}

		rows = append(rows, fmt.Sprintf("| %s | %s | %s | %s |",
			c.RulePath,
			strings.Join(off.MatchedRules, ", "),
			strings.Join(gores.MatchedRules, ", "),
			status,
		))
	}

	// Compose report
	var b strings.Builder
	b.WriteString("# Parity Report: official YARA vs go-yara\n\n")
	b.WriteString(fmt.Sprintf("Date: %s\n\n", time.Now().Format("2006-01-02 15:04:05 MST")))
	b.WriteString("## Summary\n")
	b.WriteString(fmt.Sprintf("- Parity OK: %d\n- Mismatches: %d\n- Errors: %d\n\n", parityOK, mismatches, errorsCount))
	b.WriteString("## Matrix\n")
	for _, r := range rows {
		b.WriteString(r)
		b.WriteString("\n")
	}

	// Write file
	if err := os.MkdirAll(filepath.Dir(*outPath), 0o750); err != nil { // reduced perms for gosec
		fmt.Fprintf(os.Stderr, "failed to create report dir: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outPath, []byte(b.String()), 0o600); err != nil { // reduced perms for gosec
		fmt.Fprintf(os.Stderr, "failed to write report: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Report written to %s\n", *outPath)
}

func defaultRules() []string {
	// Default small set present in the repo
	return []string{
		"tmp/always_true.yar",
		"tmp/filesize_rule.yar",
		"tmp/simple_string.yar",
		"tmp/simple_hex.yar",
		"tmp/simple_regex.yar",
		"yara/sample.rules",
		"yara/tests/data/foo.yar",
	}
}

func defaultData() string { return "yara/sample.file" }

func buildRegexSuiteCases() []Case {
	baseRules := "testdata/regex/rules"
	baseData := "testdata/regex/data"
	pairs := [][2]string{
		{"literals.yar", "literals.txt"},
		{"anchors.yar", "anchors_exact_abc.txt"},
		{"alternation.yar", "alternation.txt"},
		{"classes.yar", "classes.txt"},
		{"quantifiers.yar", "quantifiers.txt"},
		{"boundaries.yar", "boundaries.txt"},
	}
	cases := make([]Case, 0, len(pairs))
	for _, p := range pairs {
		cases = append(cases, Case{
			RulePath: filepath.Join(baseRules, p[0]),
			DataPath: filepath.Join(baseData, p[1]),
		})
	}
	return cases
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func classify(off, gores RunResult) string {
	if off.Err != nil || !off.Ok {
		if gores.Err != nil || !gores.Ok {
			return "error: both failed"
		}
		return "error: official failed"
	}
	if gores.Err != nil || !gores.Ok {
		return "error: go-yara failed"
	}
	if eqStringSets(off.MatchedRules, gores.MatchedRules) {
		return "parity_ok"
	}
	return "mismatch"
}

func eqStringSets(a, b []string) bool {
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	if len(aa) != len(bb) {
		return false
	}
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func runOfficial(yaraBin, rules, data string, timeout time.Duration) RunResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, yaraBin, rules, data)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()

	rr := RunResult{Stdout: outBuf.String(), Stderr: errBuf.String(), Err: err}
	if ctx.Err() == context.DeadlineExceeded {
		rr.Err = errors.New("timeout")
		return rr
	}
	if ee, ok := err.(*exec.ExitError); ok {
		rr.ExitCode = ee.ExitCode()
	}

	// Parse matched rule names: typical line format: "RuleName <file>"
	rr.MatchedRules = parseYaraOutput(rr.Stdout)
	rr.Ok = (rr.Err == nil)
	return rr
}

var reYaraLine = regexp.MustCompile(`^([A-Za-z0-9_\.\-]+)\s+.+$`)

func parseYaraOutput(stdout string) []string {
	rules := map[string]struct{}{}
	sc := bufio.NewScanner(strings.NewReader(stdout))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if m := reYaraLine.FindStringSubmatch(line); m != nil {
			rules[m[1]] = struct{}{}
		}
	}
	out := make([]string, 0, len(rules))
	for k := range rules {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func runGoYara(goCmd, rules, data string, timeout time.Duration) RunResult {
	// goCmd like: "go run ./cmd/main.go"
	parts := strings.Fields(goCmd)
	args := parts[1:]
	args = append(args, rules, "--execute", "--data", data)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Validate command parts to prevent injection
	if len(parts) == 0 || parts[0] == "" {
		return RunResult{Err: fmt.Errorf("empty command")}
	}
	// Basic command injection protection - check for dangerous characters
	for _, part := range parts {
		if strings.ContainsAny(part, ";&|`$()<>\"'\\\n\r\t") {
			return RunResult{Err: fmt.Errorf("potentially dangerous command characters detected")}
		}
	}
	// Validate file paths to prevent traversal
	if strings.Contains(rules, "..") || strings.HasPrefix(rules, "/") {
		return RunResult{Err: fmt.Errorf("invalid rules path: potential path traversal")}
	}
	if strings.Contains(data, "..") || strings.HasPrefix(data, "/") {
		return RunResult{Err: fmt.Errorf("invalid data path: potential path traversal")}
	}
	//nolint:gosec // controlled development harness; command/args come from local flags
	cmd := exec.CommandContext(ctx, parts[0], args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()

	rr := RunResult{Stdout: outBuf.String(), Stderr: errBuf.String(), Err: err}
	if ctx.Err() == context.DeadlineExceeded {
		rr.Err = errors.New("timeout")
		return rr
	}
	if ee, ok := err.(*exec.ExitError); ok {
		rr.ExitCode = ee.ExitCode()
	}

	rr.MatchedRules = parseGoYaraMatches(rr.Stdout)
	rr.Ok = (rr.Err == nil)
	return rr
}

var (
	reExecRule    = regexp.MustCompile(`^Executing rule:\s+(.+)$`)
	reResultMatch = regexp.MustCompile(`^\s*Result:\s+MATCH`) // associates with last seen rule
)

func parseGoYaraMatches(stdout string) []string {
	matches := map[string]struct{}{}
	var current string
	sc := bufio.NewScanner(strings.NewReader(stdout))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if m := reExecRule.FindStringSubmatch(line); m != nil {
			current = m[1]
			continue
		}
		if reResultMatch.MatchString(line) && current != "" {
			matches[current] = struct{}{}
			current = ""
		}
	}
	out := make([]string, 0, len(matches))
	for k := range matches {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// naive detectors for features in rule files
var reRegexLiteral = regexp.MustCompile(`/(?:[^/\\]|\\.)+/`)
var reInclude = regexp.MustCompile(`(?m)^\s*include\s+\"[^\"]+\"`)
var reImport = regexp.MustCompile(`(?m)^\s*import\s+\"[^\"]+\"`)

func fileHasRegex(path string) (bool, error) {
	// Validate path to prevent traversal
	if path == "" {
		return false, fmt.Errorf("empty path")
	}
	// Basic path traversal protection
	if strings.Contains(path, "..") || strings.HasPrefix(path, "/") {
		return false, fmt.Errorf("invalid path: potential path traversal")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	return reRegexLiteral.Find(b) != nil, nil
}

func fileHasInclude(path string) (bool, error) {
	// Validate path to prevent traversal
	if path == "" {
		return false, fmt.Errorf("empty path")
	}
	// Basic path traversal protection
	if strings.Contains(path, "..") || strings.HasPrefix(path, "/") {
		return false, fmt.Errorf("invalid path: potential path traversal")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	return reInclude.Match(b), nil
}

func fileHasImport(path string) (bool, error) {
	// Validate path to prevent traversal
	if path == "" {
		return false, fmt.Errorf("empty path")
	}
	// Basic path traversal protection
	if strings.Contains(path, "..") || strings.HasPrefix(path, "/") {
		return false, fmt.Errorf("invalid path: potential path traversal")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	return reImport.Match(b), nil
}
