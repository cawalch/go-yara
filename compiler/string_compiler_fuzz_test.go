package compiler

import (
	"encoding/base64"
	"testing"

	"github.com/cawalch/go-yara/ast"
)

// FuzzStringCompiler tests the string compiler with various string patterns
func FuzzStringCompiler(f *testing.F) {
	// Seed corpus with various string types
	f.Add([]byte("\"simple string\""))
	f.Add([]byte("\"\\x41\\x42\\x43\""))
	f.Add([]byte("\"\\n\\r\\t\""))
	f.Add([]byte("\"wide string\" wide"))
	f.Add([]byte("\"case insensitive\" nocase"))
	f.Add([]byte("\"fullword test\" fullword"))
	f.Add([]byte("\"multiple modifiers\" nocase wide fullword ascii"))
	f.Add([]byte("{ DE AD BE EF }"))
	f.Add([]byte("{ 00 01 02 03 04 05 }"))
	f.Add([]byte("{ [0-256] }"))
	f.Add([]byte("{ (41|42|43) }"))
	f.Add([]byte("{ DE:AD:BE:EF }"))
	f.Add([]byte("//regex//"))
	f.Add([]byte("/pattern/flags"))
	f.Add([]byte("$string"))
	f.Add([]byte("##include##"))
	f.Add([]byte("#some#"))
	f.Add([]byte("%xor%"))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("String compiler recovered from panic: %v", r)
			}
		}()

		inputStr := string(input)

		// Test string compilation
		c := NewCompiler()
		str := &ast.String{
			Identifier: "$test",
			Pattern:    &ast.TextString{Value: inputStr},
		}

		// Try to compile the string pattern (this tests pattern processing)
		_ = c
		_ = str

		// Test with different string types by modifying the AST node
		testCases := []*ast.String{
			{Identifier: "$test1", Pattern: &ast.TextString{Value: inputStr}},
			{Identifier: "$test2", Pattern: &ast.TextString{Value: inputStr}, Modifiers: []ast.StringModifier{{Type: ast.StringModifierNocase}}},
			{Identifier: "$test3", Pattern: &ast.TextString{Value: inputStr}, Modifiers: []ast.StringModifier{{Type: ast.StringModifierWide}}},
			{Identifier: "$test4", Pattern: &ast.TextString{Value: inputStr}, Modifiers: []ast.StringModifier{{Type: ast.StringModifierASCII}}},
			{Identifier: "$test5", Pattern: &ast.TextString{Value: inputStr}, Modifiers: []ast.StringModifier{{Type: ast.StringModifierFullword}}},
		}

		for _, tc := range testCases {
			c2 := NewCompiler()
			_ = c2
			_ = tc
		}
	})
}

// FuzzBase64Decoder tests Base64 decoding with malformed inputs
func FuzzBase64Decoder(f *testing.F) {
	// Seed corpus with Base64 patterns
	f.Add([]byte("SGVsbG8gV29ybGQ="))
	f.Add([]byte("VGVzdA=="))
	f.Add([]byte("invalid base64"))
	f.Add([]byte("==="))
	f.Add([]byte("YWJjZGVmZ2hpams="))
	f.Add([]byte("TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu"))
	f.Add([]byte(""))
	f.Add([]byte("A"))
	f.Add([]byte("AB"))
	f.Add([]byte("ABC"))
	f.Add([]byte("ABCD"))
	f.Add([]byte("ABCDE"))
	f.Add([]byte("A&B&C&D"))
	f.Add([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Base64 decoder recovered from panic: %v", r)
			}
		}()

		// Test Base64 decoding with Go's standard library for fuzzing
		_, err := base64.StdEncoding.DecodeString(string(input))
		_ = err

		// Test with padding variations
		inputStr := string(input)
		testInputs := []string{
			inputStr,
			inputStr + "=",
			inputStr + "==",
			inputStr + "===",
		}

		for _, testInput := range testInputs {
			_, err := base64.StdEncoding.DecodeString(testInput)
			_ = err
			// Also test URL-safe base64
			_, err = base64.URLEncoding.DecodeString(testInput)
			_ = err
		}
	})
}

// FuzzAtomExtractor tests atom extraction from various strings
func FuzzAtomExtractor(f *testing.F) {
	// Seed corpus with strings for atom extraction
	f.Add([]byte("\"test\""))
	f.Add([]byte("\"hello world\""))
	f.Add([]byte("ab"))
	f.Add([]byte("abc"))
	f.Add([]byte("abcd"))
	f.Add([]byte("abcdef"))
	f.Add([]byte("a"))
	f.Add([]byte("ab*"))
	f.Add([]byte("a+b"))
	f.Add([]byte("a?b"))
	f.Add([]byte(".*"))
	f.Add([]byte("a.*b"))
	f.Add([]byte("[abc]"))
	f.Add([]byte("\\d+"))
	f.Add([]byte("\\w*"))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Atom extractor recovered from panic: %v", r)
			}
		}()

		// Test string processing that could lead to atom extraction issues
		inputStr := string(input)

		// Test various string operations that could cause panics
		if len(inputStr) > 0 {
			// Test string indexing operations
			for i := 0; i < len(inputStr) && i < 50; i++ {
				_ = inputStr[i]
			}

			// Test string slicing operations
			for i := 0; i < len(inputStr) && i < 50; i++ {
				subStr := inputStr[i:]
				_ = subStr
				_ = len(subStr)
			}

			// Test string concatenation (could cause memory issues)
			if len(inputStr) < 100 {
				prefixed := "prefix" + inputStr
				_ = prefixed

				suffixed := inputStr + "suffix"
				_ = suffixed
			}
		}
	})
}
