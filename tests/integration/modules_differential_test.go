package integration

import (
	"fmt"
	"testing"
)

func TestLibyaraExpandedModules(t *testing.T) {
	cases := []struct {
		name, condition string
		data            []byte
	}{
		{"crc32_string", `hash.crc32("abc") == 891568578`, nil},
		{"checksum_string", `hash.checksum32("a\x00\xff") == 352`, nil},
		{"empty_hash_string", `hash.crc32("") == 0 and hash.checksum32("") == 0`, nil},
		{"empty_hash_range", `defined hash.crc32(0, 0)`, nil},
		{"hash_range", `hash.crc32(1, 99) == hash.crc32("bc") and hash.checksum32(1, 99) == 197`, []byte("abc")},
		{"hash_zero_range", `hash.crc32(0, 0) == 0`, []byte("abc")},
		{"hash_eof", `defined hash.checksum32(filesize, 0)`, []byte("abc")},
		{"hash_negative", `defined hash.sha256(-1, 1) or defined hash.crc32(0, -1)`, []byte("abc")},
		{"hash_overflow", `hash.crc32(1, 0x7fffffffffffffff) == hash.crc32("bc")`, []byte("abc")},
		{"count", `math.count(97, 0, 99) == 2 and math.count(98) == 1`, []byte("aba")},
		{"count_empty", `math.count(97) == 0 and not defined math.count(97, 0, 0)`, nil},
		{"count_zero", `math.count(97, 0, 0) == 0`, []byte("abc")},
		{"invalid_byte", `defined math.count(256) or defined math.percentage(-1, 0, 3)`, []byte("abc")},
		{"percentage", `math.percentage(97) > 0.66 and math.percentage(97, 0, 3) < 0.67`, []byte("aba")},
		{"mode", `math.mode() == 97 and math.mode(1, 2) == 97`, []byte("aba")},
		{"mode_tie", `math.mode() == 97 and math.mode(0, 0) == 0`, []byte("ba")},
		{"mode_empty", `math.mode() == 0 and not defined math.mode(0, 0)`, nil},
		{"scalars", `math.min(-1, 1) == 1 and math.max(-1, 1) == -1 and math.abs(-42) == 42`, nil},
		{"float_range", `math.in_range(2.0, 1.0, 3.0) == 1 and math.in_range(4.0, 1.0, 3.0) == 0`, nil},
		{"to_number", `math.to_number(true) == 1 and math.to_number(false) == 0`, nil},
		{"to_string", `math.to_string(-123) == "-123" and math.to_string(255, 8) == "377" and math.to_string(-1, 16) == "ffffffffffffffff"`, nil},
		{"invalid_base", `defined math.to_string(10, 2)`, nil},
		{"undefined_argument", `defined math.abs(string.to_int("invalid")) or defined string.length(math.to_string(1, 7))`, nil},
		{"string_length", `string.length("a\x00\xff") == 3`, nil},
		{"parse_int", `string.to_int("  -42") == -42 and string.to_int("077") == 63 and string.to_int("0Xff",16) == 255 and string.to_int("z",36) == 35`, nil},
		{"parse_nul", `string.to_int("42\x00suffix") == 42`, nil},
		{"parse_sign_after_prefix", `defined string.to_int("0x-1") or defined string.to_int("0x+1", 16)`, nil},
		{"parse_empty", `defined string.to_int("")`, nil},
		{"parse_trailing_space", `defined string.to_int("42 ")`, nil},
		{"parse_trailing_garbage", `defined string.to_int("42xyz")`, nil},
		{"parse_underscore", `defined string.to_int("1_000")`, nil},
		{"parse_binary", `defined string.to_int("0b10")`, nil},
		{"parse_overflow", `defined string.to_int("9223372036854775808")`, nil},
		{"parse_invalid_base", `defined string.to_int("1", 1)`, nil},
		{"undefined_and_true", `not (string.to_int("bad") == 0 and filesize == 0)`, nil},
		{"undefined_or_false", `not (string.to_int("bad") == 0 or filesize > 0)`, nil},
		{"undefined_not", `not (string.to_int("bad") == 0)`, nil},
		{"undefined_both", `not (string.to_int("bad") == 0 or string.to_int("bad") == 1)`, nil},
		{"float_epsilon", `math.mean("a") + 0.00000000000000001 == 97.0`, nil},
		{"time", `time.now() > 1700000000`, nil},
		{"entropy_string", `math.entropy("aba") > 0.91 and math.entropy("aba") < 0.92`, nil},
		{"mean_string", `math.mean("abc") == 98.0`, nil},
		{"deviation_string", `math.deviation("abc", 98.0) > 0.66 and math.deviation("abc", 98.0) < 0.67`, nil},
		{"deviation_range", `math.deviation(0, 99, 98.0) > 0.66 and math.deviation(0, 99, 98.0) < 0.67`, []byte("abc")},
		{"mean_high_bytes", `math.mean("\xff\x80") == -64.5`, nil},
		{"deviation_high_bytes", `math.deviation("\xff\x80", 0.0) == 64.5`, nil},
		{"serial_high_bytes", `math.serial_correlation("\xff\x80a\x05") != math.serial_correlation(0, filesize)`, []byte{255, 128, 97, 5}},
		{"monte_carlo_signed_byte", `math.monte_carlo_pi("\x80\x00\x00\x00\x00\x00") == 1.0`, nil},
		{"monte_carlo_high_bytes", `math.monte_carlo_pi("\xff\xff\xff\xff\xff\xff") == 1.0`, nil},
		{"mean_zero", `defined math.mean(0, 0) and math.mean(0, 0) != 0.0`, []byte("abc")},
		{"undefined_range", `defined math.mode(-1, 3) or defined math.percentage(97, 0, -1)`, []byte("abc")},
		{"range_eof", `defined math.serial_correlation(filesize, 0) or defined math.monte_carlo_pi(filesize, 0)`, []byte("abcdef")},
		{"parse_min_int", `string.to_int("-9223372036854775808") == -9223372036854775807 - 1`, nil},
		{"serial", `math.serial_correlation(0, filesize) == -0.5 and math.serial_correlation("abc") == -0.5`, []byte("abc")},
		{"serial_constant", `math.serial_correlation("aaa") == -100000.0`, nil},
		{"serial_empty", `math.serial_correlation("") == -100000.0 and not defined math.serial_correlation(0, 0)`, nil},
		{"monte_carlo", `math.monte_carlo_pi("abcdef") > 0.27 and math.monte_carlo_pi(0, filesize) < 0.28`, []byte("abcdef")},
		{"monte_carlo_short", `defined math.monte_carlo_pi("abc") or defined math.monte_carlo_pi(0, filesize)`, []byte("abc")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := fmt.Sprintf(`import "hash" import "math" import "string" import "time"
rule probe { condition: %s }
rule inverse { condition: not (%s) }`, tc.condition, tc.condition)
			checkReleaseScanPaths(t, source, tc.data)
		})
	}
}
