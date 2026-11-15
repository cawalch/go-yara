// Package int64ops provides checked 64-bit signed integer arithmetic and shift
// helpers shared between semantic validation, constant folding, and runtime execution.
package int64ops

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// DivStatus describes the outcome of checked integer division or modulo.
type DivStatus uint8

const (
	// DivOK indicates division or modulo produced a valid int64 result.
	DivOK DivStatus = iota
	// DivByZero indicates the divisor was zero.
	DivByZero
	// DivOverflow indicates the signed quotient or remainder at math.MinInt64 / -1 overflows int64.
	DivOverflow
)

// Add returns a + b and true, or (0, false) on signed 64-bit overflow.
func Add(a, b int64) (int64, bool) {
	if (b > 0 && a > math.MaxInt64-b) || (b < 0 && a < math.MinInt64-b) {
		return 0, false
	}
	return a + b, true
}

// Sub returns a - b and true, or (0, false) on signed 64-bit overflow.
func Sub(a, b int64) (int64, bool) {
	if (b < 0 && a > math.MaxInt64+b) || (b > 0 && a < math.MinInt64+b) {
		return 0, false
	}
	return a - b, true
}

// Mul returns a * b and true, or (0, false) on signed 64-bit overflow.
func Mul(a, b int64) (int64, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	if (a == math.MinInt64 && b == -1) || (a == -1 && b == math.MinInt64) {
		return 0, false
	}
	prod := a * b
	if prod/a != b {
		return 0, false
	}
	return prod, true
}

// Div performs signed 64-bit integer division and distinguishes division by
// zero from math.MinInt64 / -1 overflow.
func Div(a, b int64) (int64, DivStatus) {
	if b == 0 {
		return 0, DivByZero
	}
	if a == math.MinInt64 && b == -1 {
		return 0, DivOverflow
	}
	return a / b, DivOK
}

// Mod performs signed 64-bit remainder and distinguishes division by zero from
// the math.MinInt64 % -1 boundary (undefined in libyara).
func Mod(a, b int64) (int64, DivStatus) {
	if b == 0 {
		return 0, DivByZero
	}
	if a == math.MinInt64 && b == -1 {
		return 0, DivOverflow
	}
	return a % b, DivOK
}

// ShiftLeft evaluates a << count matching libyara semantics: negative counts
// return ok=false, counts >= 64 return (0, true), and 0..63 shift 64 bits.
func ShiftLeft(a, count int64) (int64, bool) {
	if count < 0 {
		return 0, false
	}
	if count >= 64 {
		return 0, true
	}
	return a << uint64(count), true // #nosec G115 -- count bounded within [0, 63]
}

// ShiftRight evaluates arithmetic a >> count matching libyara semantics:
// negative counts return ok=false, counts >= 64 return (0, true).
func ShiftRight(a, count int64) (int64, bool) {
	if count < 0 {
		return 0, false
	}
	if count >= 64 {
		return 0, true
	}
	return a >> uint64(count), true // #nosec G115 -- count bounded within [0, 63]
}

// ParseIntLiteral parses decimal, octal, and 64-bit two's-complement hex integer literals.
func ParseIntLiteral(s string) (int64, error) {
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		bits, err := strconv.ParseUint(s, 0, 64)
		if err != nil {
			return 0, err
		}
		if bits <= math.MaxInt64 {
			return int64(bits), nil
		}
		return int64(bits-math.MaxInt64-1) - math.MaxInt64 - 1, nil //checkednarrow:ignore bounded within [0, math.MaxInt64]
	}
	return strconv.ParseInt(s, 0, 64)
}

// ParseSizeLiteral parses YARA size literals such as "10KB" or "0x10KB".
func ParseSizeLiteral(literal string) (int64, error) {
	trimmed := strings.TrimSpace(literal)
	if len(trimmed) < 3 {
		return 0, fmt.Errorf("invalid size literal format: %s", literal)
	}
	unit := trimmed[len(trimmed)-2:]
	var multiplier int64
	switch unit {
	case "KB":
		multiplier = 1024
	case "MB":
		multiplier = 1024 * 1024
	case "GB":
		multiplier = 1024 * 1024 * 1024
	case "TB":
		multiplier = 1024 * 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("invalid size literal format: %s", literal)
	}
	prefix := trimmed[:len(trimmed)-2]
	var (
		num int64
		err error
	)
	if strings.HasPrefix(prefix, "0x") || strings.HasPrefix(prefix, "0X") {
		num, err = strconv.ParseInt(prefix, 0, 64)
	} else {
		for i := 0; i < len(prefix); i++ {
			if prefix[i] < '0' || prefix[i] > '9' {
				return 0, fmt.Errorf("invalid size literal format: %s", literal)
			}
		}
		num, err = strconv.ParseInt(prefix, 10, 64)
	}
	if err != nil {
		return 0, fmt.Errorf("invalid number in size literal: %s", prefix)
	}
	if num > math.MaxInt64/multiplier {
		return 0, fmt.Errorf("size literal exceeds int64 range: %s", literal)
	}
	return num * multiplier, nil
}
