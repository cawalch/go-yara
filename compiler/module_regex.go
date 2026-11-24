package compiler

import (
	"context"
	"errors"
	"fmt"

	"github.com/cawalch/go-yara/regex"
)

const allowedModuleRegexFlags = regex.FlagsNoCase | regex.FlagsDotAll

// CompiledRegex is an immutable, precompiled regular expression passed as a
// module function argument. Its compiled program is owned by the compiled rule
// and shared read-only across scans while honoring the active scan's
// cancellation signal.
type CompiledRegex struct {
	program    *compiledModuleRegex
	cancelDone <-chan struct{}
}

type compiledModuleRegex struct {
	code  []byte
	flags regex.Flags
}

// CompileModuleRegex parses and compiles a YARA regex literal (such as
// "/pattern/i") into an immutable CompiledRegex value.
func CompileModuleRegex(literal string) (CompiledRegex, error) {
	compiled, err := compileModuleRegexLiteral(literal)
	if err != nil {
		return CompiledRegex{}, err
	}
	return CompiledRegex{program: compiled}, nil
}

// Match reports whether data matches the compiled regular expression.
func (r CompiledRegex) Match(data []byte) (bool, error) {
	return r.matchBatch(data, nil)
}

func (r CompiledRegex) matchBatch(data []byte, batch *regex.VMBatch) (bool, error) {
	if r.cancelDone != nil {
		select {
		case <-r.cancelDone:
			return false, context.Canceled
		default:
		}
	}
	if r.program == nil {
		return false, errors.New("uninitialized compiled regex")
	}
	return regex.ExecBatchWithCancel(batch, r.program.code, data, r.program.flags|regex.FlagsScan, r.cancelDone)
}

// MatchString reports whether s matches the compiled regular expression.
func (r CompiledRegex) MatchString(s string) (bool, error) {
	return r.matchStringBatch(s, nil)
}

func (r CompiledRegex) matchStringBatch(s string, batch *regex.VMBatch) (bool, error) {
	if r.cancelDone != nil {
		select {
		case <-r.cancelDone:
			return false, context.Canceled
		default:
		}
	}
	if r.program == nil {
		return false, errors.New("uninitialized compiled regex")
	}
	var stack [512]byte
	var data []byte
	if len(s) <= len(stack) {
		n := copy(stack[:], s)
		data = stack[:n]
	} else {
		data = []byte(s)
	}
	return regex.ExecBatchWithCancel(batch, r.program.code, data, r.program.flags|regex.FlagsScan, r.cancelDone)
}

func compileModuleRegexLiteral(literal string) (*compiledModuleRegex, error) {
	pattern, flags, err := parseModuleRegexLiteral(literal)
	if err != nil {
		return nil, err
	}
	parsed, err := regex.NewParser(0).Parse(pattern)
	if err != nil {
		return nil, fmt.Errorf("parse regex: %w", err)
	}
	code, err := regex.Compile(parsed)
	if err != nil {
		return nil, fmt.Errorf("compile regex: %w", err)
	}
	return &compiledModuleRegex{code: code, flags: flags}, nil
}

func parseModuleRegexLiteral(literal string) (string, regex.Flags, error) {
	if len(literal) < 2 || literal[0] != '/' {
		return "", 0, errors.New("module regex must be delimited with '/'")
	}
	endIdx := -1
	inClass := false
	classStart := false
	classNegated := false
	for idx := 1; idx < len(literal); idx++ {
		ch := literal[idx]
		if ch == '\\' {
			idx++
			classStart = false
			continue
		}
		if inClass {
			if classStart && ch == '^' && !classNegated {
				classNegated = true
				continue
			}
			if ch == ']' && !classStart {
				inClass = false
			}
			classStart = false
			continue
		}
		if ch == '[' {
			inClass = true
			classStart = true
			classNegated = false
			continue
		}
		if ch == '/' {
			endIdx = idx
			break
		}
	}
	if endIdx <= 0 {
		return "", 0, errors.New("unterminated module regex literal")
	}
	var flags regex.Flags
	for idx := endIdx + 1; idx < len(literal); idx++ {
		switch literal[idx] {
		case 'i', 'I':
			flags |= regex.FlagsNoCase
		case 's', 'S':
			flags |= regex.FlagsDotAll
		default:
			return "", 0, fmt.Errorf("unsupported regex flag %q", literal[idx])
		}
	}
	return literal[1:endIdx], flags, nil
}

func validateCompiledModuleRegex(entry *compiledModuleRegex) error {
	if entry == nil || len(entry.code) == 0 {
		return errors.New("empty module regex bytecode")
	}
	if entry.flags&^allowedModuleRegexFlags != 0 {
		return fmt.Errorf("invalid module regex flags %#x", entry.flags)
	}
	return nil
}
