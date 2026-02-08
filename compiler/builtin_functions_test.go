package compiler

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestBuiltinHashFunctions(t *testing.T) {
	data := []byte("testdata")
	md5Sum := fmt.Sprintf("%x", md5.Sum(data[1:5]))
	sha1Sum := fmt.Sprintf("%x", sha1.Sum([]byte("abc")))
	sha256Sum := fmt.Sprintf("%x", sha256.Sum256(data[:4]))

	source := fmt.Sprintf(`
rule HashFuncs {
	condition:
		md5(1, 4) == "%s" and
		sha1("abc") == "%s" and
		sha256(0, 4) == "%s"
}`, md5Sum, sha1Sum, sha256Sum)

	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	ok, err := evaluateRule(program.Rules[0], program, data)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !ok {
		t.Fatalf("expected rule to match")
	}
}

func TestBuiltinTextFunctions(t *testing.T) {
	source := `
rule TextFuncs {
	condition:
		concat("a", "b", "c") == "abc" and
		tostring(123) == "123" and
		int("0x10") == 16
}`

	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	ok, err := evaluateRule(program.Rules[0], program, []byte{})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !ok {
		t.Fatalf("expected rule to match")
	}
}
