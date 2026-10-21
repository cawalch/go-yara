package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/cawalch/go-yara/compiler"
)

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
	target  string
	res     *compiler.ScanResult
	data    []byte
	cleanup func()
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

func printDataSummary(dataFile string, data []byte) {
	fmt.Printf("Data file: %s (%d bytes)\n", dataFile, len(data))
	fmt.Printf("Data content (first 256 bytes):\n")
	if len(data) > 256 {
		fmt.Printf("%s...\n\n", string(data[:256]))
	} else {
		fmt.Printf("%s\n\n", string(data))
	}
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
