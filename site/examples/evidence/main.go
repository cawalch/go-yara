package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cawalch/go-yara/compiler"
)

const rules = `
rule credential_candidate {
    strings:
        $uri = /postgres:\/\/([^: @\r\n]+):([^@\r\n]+)@([^\/ \r\n]+)/
            capture(username = 1, secret = 2, endpoint = 3)
        $user = /username=([^ \r\n]+)/ capture(username = 1)
        $pass = /password=([^ \r\n]+)/ capture(secret = 1)
        $host = /endpoint=([^ \r\n]+)/ capture(endpoint = 1)
    evidence:
        credential = (endpoint, username, secret) within 96 of secret
    condition:
        $uri or $pass
}`

type credential struct{ endpoint, username, secret string }
type validator func(context.Context, credential) (string, error)

// Only ready findings reach the validator. An error is unknown, not rejected.
func validate(ctx context.Context, finding compiler.EvidenceFinding, check validator) string {
	if finding.Status != compiler.EvidenceStatusReady {
		return "not checked"
	}
	values := make(map[string]string)
	for _, name := range []string{"endpoint", "username", "secret"} {
		captures := finding.Fields[name]
		if len(captures) != 1 || captures[0].DataTruncated {
			return "not checked"
		}
		values[name] = string(captures[0].Data)
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	outcome, err := check(ctx, credential{values["endpoint"], values["username"], values["secret"]})
	if err != nil {
		return "unknown"
	}
	return outcome
}

// A deterministic test double: no database connection or HTTP request is made.
func fixtureValidator(ctx context.Context, candidate credential) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if candidate.endpoint != "db.example.test" {
		return "", errors.New("endpoint is outside the fixture")
	}
	if candidate.username == "alice" && candidate.secret == "demo-only" {
		return "accepted (fixture)", nil
	}
	return "rejected (fixture)", nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	program, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), rules)
	if err != nil {
		return err
	}
	for _, sample := range []struct {
		name, input  string
		captureLimit int
	}{
		{"URI", "postgres://alice:demo-only@db.example.test", 256},
		{"assignments", "endpoint=db.example.test\nusername=alice\npassword=demo-only", 256},
		{"missing", "endpoint=db.example.test\npassword=demo-only", 256},
		{"ambiguous", "endpoint=db.example.test\nusername=alice\nusername=bob\npassword=demo-only", 256},
		{"truncated", "postgres://alice:demo-only@db.example.test", 4},
		{"rejected", "postgres://alice:wrong-demo@db.example.test", 256},
		{"unknown", "postgres://alice:demo-only@unconfigured.example.test", 256},
	} {
		scanner := program.NewScanner(compiler.WithEvidence(sample.captureLimit))
		result, err := scanner.Scan([]byte(sample.input))
		scanner.Close()
		if err != nil {
			return err
		}
		findings := result.Evidence["credential_candidate"]["credential"]
		if !result.RuleResults["credential_candidate"] || len(findings) != 1 {
			return fmt.Errorf("%s: expected one finding from a matched rule", sample.name)
		}
		finding := findings[0]
		outcome := validate(context.Background(), finding, fixtureValidator)
		// Keep candidate values out of logs; retain status and source spans instead.
		fmt.Printf("%s: %s; %s\n", sample.name, finding.Status, outcome)
	}
	return nil
}
