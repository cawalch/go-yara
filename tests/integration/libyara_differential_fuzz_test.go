package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

// libyaraOracle locates the reference `yara` binary. When it is absent the
// differential tests skip instead of failing, so the suite stays portable.
func libyaraOracle(t testing.TB) string {
	t.Helper()
	bin, err := exec.LookPath("yara")
	if err != nil {
		t.Skip("libyara `yara` binary not found; differential test requires it")
	}
	return bin
}

type span struct {
	ID  string `json:"id"`
	Off int64  `json:"off"`
	Len int    `json:"len"`
}

type divergence struct {
	Kind string `json:"kind"`
	Src  string `json:"src"`
	Data []byte `json:"data"`
	Rule string `json:"rule,omitempty"`
	Want []span `json:"libyara"`
	Got  []span `json:"goyara"`
	Err  string `json:"err"`
}

var (
	yaraSpanRE = regexp.MustCompile(`^0x([0-9a-fA-F]+):(\d+):(\$[A-Za-z0-9_]*):`)
	anonVarRE  = regexp.MustCompile(`\$([A-Za-z0-9_*]*)`)
)

func replaceIsolatedDollar(s, replacement string) string {
	return anonVarRE.ReplaceAllStringFunc(s, func(match string) string {
		if match == "$" {
			return replacement
		}
		return match
	})
}

func replaceAnonDecls(s string) (string, int) {
	var sb strings.Builder
	inQuote, inHex, inRegex := false, false, false
	count := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote {
			sb.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				i++
				sb.WriteByte(s[i])
			} else if c == '"' {
				inQuote = false
			}
			continue
		}
		if inHex {
			sb.WriteByte(c)
			if c == '}' {
				inHex = false
			}
			continue
		}
		if inRegex {
			sb.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				i++
				sb.WriteByte(s[i])
			} else if c == '/' {
				inRegex = false
			}
			continue
		}

		switch c {
		case '"':
			inQuote = true
			sb.WriteByte(c)
		case '{':
			inHex = true
			sb.WriteByte(c)
		case '/':
			inRegex = true
			sb.WriteByte(c)
		case '$':
			// Check if this is an anonymous string: '$' followed by optional whitespace then '='
			j := i + 1
			for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r' || s[j] == '\n') {
				j++
			}
			if j < len(s) && s[j] == '=' && (j+1 >= len(s) || s[j+1] != '=') {
				count++
				fmt.Fprintf(&sb, "$_anon_%d", count)
			} else {
				sb.WriteByte(c)
			}
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String(), count
}

// normalizeAnonymousStrings translates anonymous strings ($ = ...) into uniquely named
// patterns ($_anon_N = ...) and maps condition references ($ -> any of ($_anon_*))
// so the reference libyara CLI (which skips printing unnamed strings with `yara -s`)
// reports their occurrence spans consistently for differential comparison.
func normalizeAnonymousStrings(src string) (string, bool) {
	strIdx := strings.Index(src, "strings:")
	if strIdx == -1 {
		return src, false
	}
	condIdx := strings.Index(src[strIdx:], "condition:")
	if condIdx == -1 {
		return src, false
	}
	condIdx += strIdx

	stringsNorm, count := replaceAnonDecls(src[strIdx:condIdx])
	if count == 0 {
		return src, false
	}

	head := src[:strIdx] + stringsNorm
	tail := src[condIdx:]

	if count == 1 {
		tail = replaceIsolatedDollar(tail, "$_anon_1")
	} else {
		tail = replaceIsolatedDollar(tail, "any of ($_anon_*)")
	}

	return head + tail, true
}

// skipSource filters constructs libyara's CLI cannot report on or parse reliably:
// comment delimiters and include directives make mutation comparison unreliable.
func skipSource(src string) bool {
	if !strings.Contains(src, "rule ") {
		return true
	}
	if strings.Contains(src, "include ") || strings.Contains(src, "//") || strings.Contains(src, "/*") {
		return true
	}
	return false
}

//nolint:revive // argument-limit: oracle plumbing keeps the libyara binary path explicit.
func scanWithLibyara(t testing.TB, bin, src string, data []byte) (map[string][]span, error) {
	t.Helper()
	dir := t.TempDir()
	rp := filepath.Join(dir, "r.yar")
	dp := filepath.Join(dir, "d.bin")
	if err := os.WriteFile(rp, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "-s", "-L", "--no-warnings", rp, dp).Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return nil, fmt.Errorf("libyara invocation failed: %w", err)
		}
		combined := string(out) + string(ee.Stderr)
		if strings.Contains(combined, "error:") {
			return nil, fmt.Errorf("libyara rejected rule: %s", strings.TrimSpace(combined))
		}
		return map[string][]span{}, nil
	}
	res := map[string][]span{}
	var lastRule string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if m := yaraSpanRE.FindStringSubmatch(line); m != nil {
			off, err := strconv.ParseInt(m[1], 16, 64)
			if err != nil {
				return nil, err
			}
			ln, err := strconv.Atoi(m[2])
			if err != nil {
				return nil, err
			}
			if lastRule != "" {
				res[lastRule] = append(res[lastRule], span{ID: m[3], Off: off, Len: ln})
			}
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			lastRule = parts[0]
		}
	}
	return res, nil
}

func scanWithGoYara(src string, data []byte) (map[string][]span, error) {
	c := compiler.NewCompiler()
	prog, err := c.CompileSourceWithContext(context.Background(), src)
	if err != nil {
		return nil, fmt.Errorf("go-yara rejected rule: %w", err)
	}
	res, err := prog.Scan(data)
	if err != nil {
		return nil, fmt.Errorf("go-yara scan failed: %w", err)
	}
	out := map[string][]span{}
	for _, rm := range res.MatchedRules {
		for id, ms := range rm.Matches {
			for _, m := range ms {
				out[rm.Rule] = append(out[rm.Rule], span{ID: id, Off: m.Offset, Len: m.Length})
			}
		}
	}
	return out, nil
}

func flatten(m map[string][]span) []span {
	var all []span
	for rule, sp := range m {
		for _, s := range sp {
			s.ID = rule + ":" + s.ID
			all = append(all, s)
		}
	}
	for i := range all {
		for j := i + 1; j < len(all); j++ {
			if all[j].Off < all[i].Off ||
				(all[j].Off == all[i].Off && all[j].ID < all[i].ID) ||
				(all[j].Off == all[i].Off && all[j].ID == all[i].ID && all[j].Len < all[i].Len) {
				all[i], all[j] = all[j], all[i]
			}
		}
	}
	return all
}

// classifyDivergence groups findings so one fuzz run yields distinct bug
// classes instead of thousands of copies of the same defect.
func classifyDivergence(d *divergence) string {
	if d.Kind == "GO-REJECTS" {
		e := d.Err
		e = strings.ReplaceAll(e, "compiling condition: ", "")
		e = strings.ReplaceAll(e, "compiling strings: ", "")
		e = strings.ReplaceAll(e, "compiling rule: ", "")
		if i := strings.Index(e, "compiling rule "); i >= 0 {
			j := strings.Index(e[i:], ": ")
			e = e[:i] + e[i+j+2:]
		}
		if i := strings.Index(e, "compiling string "); i >= 0 {
			j := strings.Index(e[i:], ": ")
			e = e[:i] + e[i+j+2:]
		}
		return "REJECT | " + strings.TrimSpace(e)
	}
	miss := map[span]int{}
	extra := map[span]int{}
	for _, s := range d.Want {
		miss[s]++
	}
	for _, s := range d.Got {
		extra[s]++
	}
	for _, s := range d.Want {
		delete(extra, s)
	}
	for _, s := range d.Got {
		delete(miss, s)
	}
	// A duplicate is an extra span that shares (rule:string, offset) with a
	// reported libyara span: the same occurrence reported twice.
	dupOffset := map[string]bool{}
	for _, s := range d.Want {
		dupOffset[fmt.Sprintf("%s@%d", s.ID, s.Off)] = true
	}
	isDup := true
	for s := range extra {
		if !dupOffset[fmt.Sprintf("%s@%d", s.ID, s.Off)] {
			isDup = false
			break
		}
	}
	hasMiss, hasExtra := len(miss) > 0, len(extra) > 0
	n := int64(len(d.Data))
	switch {
	case hasExtra && !hasMiss && isDup:
		return "DUPLICATE | same offset reported with two lengths"
	case hasExtra && !hasMiss:
		for s := range extra {
			if s.Len == 0 && s.Off == n {
				return "FALSE-POSITIVE | spurious zero-length match at end of buffer"
			}
		}
		for s := range extra {
			if s.Len == 0 {
				return "FALSE-POSITIVE | extra zero-length match"
			}
		}
		return "FALSE-POSITIVE | extra occurrence"
	case hasMiss && !hasExtra:
		for s := range miss {
			if s.Len == 0 {
				return "FALSE-NEGATIVE | missing zero-length match"
			}
		}
		return "FALSE-NEGATIVE | missing occurrence"
	case hasMiss && hasExtra:
		ms, es := map[int64]bool{}, map[int64]bool{}
		for s := range miss {
			ms[s.Off] = true
		}
		for s := range extra {
			es[s.Off] = true
		}
		same := len(ms) == len(es)
		for o := range ms {
			if !es[o] {
				same = false
				break
			}
		}
		if same {
			return "LENGTH | same offsets, different reported length"
		}
		return "MIXED | offset and length divergence"
	default:
		return "ORDER | span multiset differs only in multiplicity"
	}
}

var findingsMu sync.Mutex

func recordFinding(path string, d divergence) {
	sig := classifyDivergence(&d)
	findingsMu.Lock()
	defer findingsMu.Unlock()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	d.Kind = sig
	enc, _ := json.Marshal(d)
	_, _ = f.Write(append(enc, '\n'))
}

//nolint:revive // argument-limit: oracle binary, findings path, rule and input.
func compareOnce(t testing.TB, bin, outPath, src string, data []byte) {
	t.Helper()
	evalSrc := src
	if norm, ok := normalizeAnonymousStrings(src); ok {
		if _, origErr := scanWithGoYara(src, data); origErr != nil {
			recordFinding(outPath, divergence{
				Kind: "GO-REJECTS", Src: src, Data: data, Err: origErr.Error(),
			})
			return
		}
		evalSrc = norm
	}

	want, yerr := scanWithLibyara(t, bin, evalSrc, data)
	if yerr != nil {
		return // libyara cannot compile it: nothing to compare
	}
	got, gerr := scanWithGoYara(evalSrc, data)
	if gerr != nil {
		recordFinding(outPath, divergence{
			Kind: "GO-REJECTS", Src: evalSrc, Data: data, Err: gerr.Error(), Want: flatten(want),
		})
		return
	}
	w, g := flatten(want), flatten(got)
	if fmt.Sprint(w) == fmt.Sprint(g) {
		return
	}
	recordFinding(outPath, divergence{Kind: "MATCH", Src: evalSrc, Data: data, Want: w, Got: g})
}

func differentialSeeds() [][2]string {
	return [][2]string{
		{`rule r { strings: $a = "abc" condition: $a }`, "xxabcxx"},
		{`rule r { strings: $a = "abc" nocase condition: $a }`, "AbC aBc ABC"},
		{`rule r { strings: $a = "abc" wide condition: $a }`, "a\x00b\x00c\x00"},
		{`rule r { strings: $a = "abc" ascii condition: $a }`, "abc"},
		{`rule r { strings: $a = "abc" fullword condition: $a }`, " abc "},
		{`rule r { strings: $a = "abc" xor(1-3) condition: $a }`, "\x02\x03\x04"},
		{`rule r { strings: $a = "ABC" xor wide condition: $a }`, "A\x00B\x00C\x00"},
		{`rule r { strings: $a = "abc" base64 condition: $a }`, "YWJj"},
		{`rule r { strings: $a = "test" base64wide condition: $a }`, "d\x00G\x00V\x00z\x00d\x00A\x00=\x00=\x00"},
		{`rule r { strings: $a = /a+b/ condition: $a }`, "aaab"},
		{`rule r { strings: $a = /^(ab|a)c$/ condition: $a }`, "abc"},
		{`rule r { strings: $a = { 41 42 43 } condition: $a }`, "ABC"},
		{`rule r { strings: $a = { 41 ?? 43 } condition: $a }`, "ABCAXC"},
		{`rule r { strings: $a = "abc" condition: #a == 2 }`, "abcabc"},
		{`rule r { strings: $a = "abc" condition: $a at 0 }`, "abc"},
		{`rule r { strings: $a = "abc" condition: $a in (0..3) }`, "abc"},
		{`rule r { strings: $a = "abc" $b = "xyz" condition: 1 of them }`, "abc"},
		{`rule r { strings: $a = "abc" condition: for any i in (1..2) : ( @a[i] == 3 ) }`, "abcabc"},
		{`rule r { strings: $a = "abc" condition: !a == 3 }`, "abc"},
		{`rule r { strings: $a = "foo" condition: defined @a[1] and not defined @a[2] }`, "foo"},
		{`rule r { strings: $a = /[a-c]+/ condition: $a }`, "abcd"},
		{`rule r { strings: $a = "abc" nocase wide condition: $a }`, "ABC\x00"},
		{`rule r { strings: $a = { 41 [1-2] 43 } condition: $a }`, "AABCAXC"},
		{`rule r { strings: $a = { 01 ( 02 | 03 [1-2] 04 ) 05 } condition: $a }`, "\x01\x03\xaa\x04\x05"},
		{`rule r { condition: uint16be(0) == 0x0102 and uint32be(0) == 0x01020304 }`, "\x01\x02\x03\x04"},
		{`rule r { condition: int16be(0) == -2 }`, "\xff\xfe"},
		{`rule r { strings: $a = "foo" condition: "hello123world" matches /[0-9]+/ and $a }`, "foo"},
		{`rule r { strings: $a = "a" $b = "b" condition: 50% of them }`, "ab"},
		{`rule r { strings: $a = "abc" condition: for any i in (1, 2, 3) : ( i == 2 ) and $a }`, "abc"},
		{`rule r { strings: $a = "abc" condition: for all i in (10, 20) : ( i >= 10 ) and $a }`, "abc"},
		{`rule r { strings: $a = "abc" condition: for none i in (1, 2) : ( i == 5 ) and $a }`, "abc"},
		{`rule r { strings: $a = "abc" condition: for any i in (0, 3) : ( $a at i ) }`, "abc"},
		{`rule r { strings: $a = "hello" $b = "world" condition: for any i in (1..#a) : ( for any j in (1..#b) : ( @b[j] > @a[i] and @b[j] - @a[i] < 10 ) ) }`, "hello world"},
		{`rule r { strings: $a = "abc" condition: (3 | 1 & 2 == 3) and $a }`, "abc"},
		{`rule r { strings: $a = "abc" condition: (3 & 1 << 2 == 0) and $a }`, "abc"},
		{`rule r { strings: $a = "abc" condition: (10 \ 3 == 3) and $a }`, "abc"},
		{`rule r { strings: $a = "abc" condition: for any i in (0) : ( $a at i ) }`, "abc"},
		{`rule r { strings: $ = "abc" condition: any of them }`, "abc"},
		{`rule r { strings: $ = "abc" $ = "xyz" condition: 1 of them }`, "abc"},
		{`rule r { strings: $ = "abc" condition: all of them }`, "abc"},
		{`rule r { strings: $ = "abc" condition: 1 of ($*) }`, "abc"},
	}
}

// diffOutPath returns the JSONL findings file. Set DIFF_OUT to aggregate
// findings across fuzz workers; without it the corpus test uses a private
// path so the normal test suite stays deterministic.
func diffOutPath(t testing.TB) string {
	if p := os.Getenv("DIFF_OUT"); p != "" {
		return p
	}
	return filepath.Join(t.TempDir(), "go-yara-diff-findings.jsonl")
}

// fuzzOutPath must be stable across the separate fuzz worker processes, so it
// falls back to a fixed shared path when DIFF_OUT is not set.
func fuzzOutPath(f *testing.F) string {
	if p := os.Getenv("DIFF_OUT"); p != "" {
		return p
	}
	return filepath.Join(os.TempDir(), "go-yara-diff-findings.jsonl")
}

// FuzzLibyaraDifferential mutates YARA source and scan input jointly, using
// libyara as the differential oracle. A finding is a semantic divergence.
func FuzzLibyaraDifferential(f *testing.F) {
	bin := libyaraOracle(f)
	out := fuzzOutPath(f)
	f.Logf("differential findings file: %s (set DIFF_OUT to choose your own)", out)
	for _, s := range differentialSeeds() {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, src, data string) {
		if len(src) > 2048 || len(data) > 2048 || skipSource(src) {
			return
		}
		compareOnce(t, bin, out, src, []byte(data))
	})
}

// TestLibyaraDifferentialCorpus replays the curated seeds and every recorded
// finding, failing once per distinct divergence class.
func TestLibyaraDifferentialCorpus(t *testing.T) {
	bin := libyaraOracle(t)
	out := diffOutPath(t)
	seen := map[string]divergence{}
	add := func(d divergence) {
		sig := classifyDivergence(&d)
		d.Kind = sig
		if _, ok := seen[sig]; !ok {
			seen[sig] = d
		}
	}
	evaluate := func(src, data string) {
		if skipSource(src) {
			return
		}
		evalSrc := src
		if norm, ok := normalizeAnonymousStrings(src); ok {
			if _, origErr := scanWithGoYara(src, []byte(data)); origErr != nil {
				add(divergence{Kind: "GO-REJECTS", Src: src, Data: []byte(data), Err: origErr.Error()})
				return
			}
			evalSrc = norm
		}
		want, yerr := scanWithLibyara(t, bin, evalSrc, []byte(data))
		if yerr != nil {
			return
		}
		got, gerr := scanWithGoYara(evalSrc, []byte(data))
		if gerr != nil {
			add(divergence{Kind: "GO-REJECTS", Src: evalSrc, Data: []byte(data), Err: gerr.Error(), Want: flatten(want)})
			return
		}
		w, g := flatten(want), flatten(got)
		if fmt.Sprint(w) == fmt.Sprint(g) {
			return
		}
		add(divergence{Kind: "MATCH", Src: evalSrc, Data: []byte(data), Want: w, Got: g})
	}
	for _, s := range differentialSeeds() {
		evaluate(s[0], s[1])
	}
	if raw, err := os.ReadFile(out); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var d divergence
			if json.Unmarshal([]byte(line), &d) != nil {
				continue
			}
			seen[d.Kind] = d
		}
	}
	if len(seen) == 0 {
		t.Log("no divergences found")
		return
	}
	t.Logf("distinct divergence classes: %d", len(seen))
	for sig, d := range seen {
		t.Errorf("DIVERGENCE [%s]\n  rule : %s\n  input: %q\n  libyara: %v\n  go-yara: %v\n  err: %s",
			sig, d.Src, d.Data, d.Want, d.Got, d.Err)
	}
}
