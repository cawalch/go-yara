package compiler

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
	return regex.ExecWithCancel(r.program.code, data, r.program.flags|regex.FlagsScan, r.cancelDone)
}

// MatchString reports whether s matches the compiled regular expression.
func (r CompiledRegex) MatchString(s string) (bool, error) {
	return r.Match([]byte(s))
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
	endIdx := strings.LastIndexByte(literal, '/')
	if endIdx <= 0 || isEscapedSlash(literal, endIdx) {
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

func isEscapedSlash(s string, slashIdx int) bool {
	backslashes := 0
	for idx := slashIdx - 1; idx >= 0 && s[idx] == '\\'; idx-- {
		backslashes++
	}
	return backslashes%2 == 1
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
