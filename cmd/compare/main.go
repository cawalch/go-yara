// Command compare compares rule matches on the same labeled inputs.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"slices"
	"sort"
	"strings"

	"github.com/cawalch/go-yara/compiler"
)

const maxInput = 64 << 20

type change struct {
	Fixture string   `json:"fixture"`
	SHA256  string   `json:"sha256,omitempty"`
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	Error   string   `json:"error,omitempty"`
}

type comparison struct {
	Engine          string   `json:"engine"`
	Namespace       string   `json:"namespace"`
	ExternalNames   []string `json:"external_names"`
	ScanOptions     string   `json:"scan_options"`
	BaselineSHA256  string   `json:"baseline_compiled_sha256"`
	CandidateSHA256 string   `json:"candidate_compiled_sha256"`
	Fixtures        []change `json:"fixtures"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := compare(ctx, os.Args[1:], os.Stdout)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func compare(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("compare", flag.ContinueOnError)
	baseline := flags.String("baseline", "", "baseline YARA source file")
	candidate := flags.String("candidate", "", "candidate YARA source file")
	namespace := flags.String("namespace", "default", "rule namespace label in the report")
	bindingFile := flags.String("externals", "", "JSON object supplying declared external variables")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *baseline == "" || *candidate == "" || *namespace == "" || flags.NArg() == 0 {
		return errors.New("usage: compare -baseline old.yar -candidate new.yar [-namespace name] [-externals bindings.json] fixture=path")
	}
	fixtures := make(map[string]string, flags.NArg())
	var ids []string
	for _, arg := range flags.Args() {
		id, path, ok := strings.Cut(arg, "=")
		if !ok || id == "" || path == "" || fixtures[id] != "" {
			return errors.New("each fixture needs a unique id=path argument")
		}
		fixtures[id] = path
		ids = append(ids, id)
	}
	slices.Sort(ids)
	bindings, names, err := readBindings(*bindingFile)
	if err != nil {
		return err
	}
	left, leftDigest, err := compile(ctx, *baseline, bindings)
	if err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	defer left.Close()
	right, rightDigest, err := compile(ctx, *candidate, bindings)
	if err != nil {
		return fmt.Errorf("candidate: %w", err)
	}
	defer right.Close()

	report := comparison{Engine: engineVersion(), Namespace: *namespace,
		ScanOptions: "default scanner", ExternalNames: names, BaselineSHA256: leftDigest, CandidateSHA256: rightDigest}
	var failed bool
	for _, id := range ids {
		row := change{Fixture: id, Added: []string{}, Removed: []string{}}
		data, readErr := readBounded(fixtures[id])
		if readErr != nil {
			row.Error = "fixture read failed or exceeded 64 MiB"
		} else {
			row.SHA256 = digest(data)
			before, leftErr := left.ScanWithContext(ctx, data)
			after, rightErr := right.ScanWithContext(ctx, data)
			switch {
			case leftErr != nil || rightErr != nil:
				row.Error = "scan did not complete"
			default:
				row.Added, row.Removed = matchDifference(before, after)
			}
		}
		failed = failed || row.Error != ""
		report.Fixtures = append(report.Fixtures, row)
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return err
	}
	if failed {
		return errors.New("one or more fixture scans failed")
	}
	return nil
}

func compile(ctx context.Context, path string, bindings map[string]any) (*compiler.Scanner, string, error) {
	data, err := readBounded(path)
	if err != nil {
		return nil, "", errors.New("rule source read failed or exceeded 64 MiB")
	}
	program, err := compiler.NewCompiler().CompileSourceWithContext(ctx, string(data))
	if err != nil {
		return nil, "", errors.New("rule compilation failed")
	}
	artifact, err := program.MarshalBinary()
	if err != nil {
		return nil, "", errors.New("compiled rule encoding failed")
	}
	scanner := program.NewScanner()
	if len(bindings) != 0 {
		if err := scanner.SetExternalVariables(bindings); err != nil {
			scanner.Close()
			return nil, "", errors.New("external bindings do not match declared variables")
		}
	}
	return scanner, digest(artifact), nil
}

func readBindings(path string) (map[string]any, []string, error) {
	names := []string{}
	if path == "" {
		return nil, names, nil
	}
	data, err := readBounded(path)
	if err != nil {
		return nil, nil, errors.New("external bindings read failed")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var values map[string]any
	if decoder.Decode(&values) != nil || values == nil || decoder.Decode(new(any)) != io.EOF {
		return nil, nil, errors.New("external bindings must be a JSON object")
	}
	for name, value := range values {
		switch value := value.(type) {
		case string, bool:
		case json.Number:
			if number, err := value.Int64(); err == nil {
				values[name] = number
			} else if number, err := value.Float64(); err == nil && strings.ContainsAny(string(value), ".eE") {
				values[name] = number
			} else {
				return nil, nil, errors.New("external binding number exceeds its range")
			}
		default:
			return nil, nil, errors.New("external bindings must be strings, booleans or numbers")
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return values, names, nil
}

func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxInput+1))
	if err == nil && len(data) > maxInput {
		err = errors.New("input exceeded 64 MiB")
	}
	return data, err
}

func matchDifference(before, after *compiler.ScanResult) (added, removed []string) {
	left := make(map[string]bool, len(before.MatchedRules))
	right := make(map[string]bool, len(after.MatchedRules))
	for _, match := range before.MatchedRules {
		left[match.Rule] = true
	}
	for _, match := range after.MatchedRules {
		right[match.Rule] = true
	}
	added, removed = []string{}, []string{}
	for name := range right {
		if !left[name] {
			added = append(added, name)
		}
	}
	for name := range left {
		if !right[name] {
			removed = append(removed, name)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func engineVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	version := info.Main.Version + " " + info.GoVersion
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			version += " " + setting.Value
		case "vcs.modified":
			if setting.Value == "true" {
				version += " (modified)"
			}
		}
	}
	return version
}
