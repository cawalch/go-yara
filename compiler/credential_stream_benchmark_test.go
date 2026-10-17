package compiler

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
)

const kafkaCredentialRulesSource = `
rule cred_github_pat {
	meta:
		provider = "github"
		severity = "critical"
	strings:
		$pat = /gh[pousr]_[A-Za-z0-9]{36}/ capture(token = 0)
		$fp_x = "ghp_xxxx" nocase
		$fp_zero = "ghp_0000"
		$fp_example = "EXAMPLE"
		$fp_redact = "REDACTED"
	evidence:
		credential = (token) within 0 of token
	condition:
		$pat and not any of ($fp_*)
}

rule cred_github_fine_grained_pat {
	meta:
		provider = "github"
		severity = "critical"
	strings:
		$pat = /github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/ capture(token = 0)
		$fp_x = "github_pat_xxxx" nocase
		$fp_zero = "github_pat_0000"
		$fp_example = "EXAMPLE"
	evidence:
		credential = (token) within 0 of token
	condition:
		$pat and not any of ($fp_*)
}

rule cred_postgres_uri {
	meta:
		provider = "postgres"
		severity = "high"
	strings:
		$uri = /postgres(?:ql)?:\/\/([A-Za-z0-9_.-]+):([^@\s"'\\]{8,64})@([A-Za-z0-9.-]+(?::[0-9]{2,5})?)\/[A-Za-z0-9_.-]+/ capture(username = 1, secret = 2, endpoint = 3)
		$fp_local = "@localhost" nocase
		$fp_loop = "@127.0.0.1"
		$fp_pass = ":password@" nocase
		$fp_pg = ":postgres@" nocase
		$fp_test = ":test@" nocase
		$fp_change = ":changeme@" nocase
		$fp_mask = ":***"
		$fp_placeholder = ":<password>@" nocase
		$fp_redact = ":REDACTED@"
	evidence:
		credential = (username, secret, endpoint) within 160 of secret
	condition:
		$uri and not any of ($fp_*)
}

rule cred_mysql_uri {
	meta:
		provider = "mysql"
		severity = "high"
	strings:
		$uri = /mysql:\/\/([A-Za-z0-9_.-]+):([^@\s"'\\]{8,64})@([A-Za-z0-9.-]+(?::[0-9]{2,5})?)\/[A-Za-z0-9_.-]+/ capture(username = 1, secret = 2, endpoint = 3)
		$fp_local = "@localhost" nocase
		$fp_loop = "@127.0.0.1"
		$fp_pass = ":password@" nocase
		$fp_root = ":root@" nocase
		$fp_test = ":test@" nocase
		$fp_mask = ":***"
		$fp_redact = ":REDACTED@"
	evidence:
		credential = (username, secret, endpoint) within 160 of secret
	condition:
		$uri and not any of ($fp_*)
}

rule cred_mongodb_uri {
	meta:
		provider = "mongodb"
		severity = "high"
	strings:
		$uri = /mongodb(?:\+srv)?:\/\/([A-Za-z0-9_.-]+):([^@\s"'\\]{8,64})@([A-Za-z0-9.-]+(?::[0-9]{2,5})?)/ capture(username = 1, secret = 2, endpoint = 3)
		$fp_local = "@localhost" nocase
		$fp_loop = "@127.0.0.1"
		$fp_pass = ":password@" nocase
		$fp_mask = ":***"
		$fp_placeholder = ":<password>@" nocase
		$fp_redact = ":REDACTED@"
	evidence:
		credential = (username, secret, endpoint) within 160 of secret
	condition:
		$uri and not any of ($fp_*)
}

rule cred_redis_uri {
	meta:
		provider = "redis"
		severity = "high"
	strings:
		$uri = /redis(?:s)?:\/\/([A-Za-z0-9_.-]*):([^@\s"'\\]{8,64})@([A-Za-z0-9.-]+:[0-9]{2,5})/ capture(username = 1, secret = 2, endpoint = 3)
		$fp_local = "@localhost" nocase
		$fp_loop = "@127.0.0.1"
		$fp_pass = ":password@" nocase
		$fp_mask = ":***"
		$fp_redact = ":REDACTED@"
	evidence:
		credential = (username, secret, endpoint) within 160 of secret
	condition:
		$uri and not any of ($fp_*)
}

rule cred_aws_key_pair {
	meta:
		provider = "aws"
		severity = "critical"
	strings:
		$akid = /AKIA[0-9A-Z]{16}/ capture(access_key = 0)
		$sk = /aws_secret_access_key["'\\:=\s]+([A-Za-z0-9\/+=]{40})/ capture(secret_key = 1)
		$fp_example_id = "AKIAIOSFODNN7EXAMPLE"
		$fp_example_sk = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		$fp_redact = "REDACTED"
	evidence:
		credential = (access_key, secret_key) within 256 of secret_key
	condition:
		$akid and $sk and not any of ($fp_*)
}

rule cred_slack_token {
	meta:
		provider = "slack"
		severity = "critical"
	strings:
		$tok = /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32}/ capture(token = 0)
		$fp_zero = "xoxb-0000"
		$fp_x = "xoxb-xxxx" nocase
		$fp_example = "EXAMPLE"
	evidence:
		credential = (token) within 0 of token
	condition:
		$tok and not any of ($fp_*)
}

rule cred_stripe_live_key {
	meta:
		provider = "stripe"
		severity = "critical"
	strings:
		$key = /(?:sk|rk)_live_[0-9a-zA-Z]{24,34}/ capture(token = 0)
		$fp_zero = "_live_0000"
		$fp_x = "_live_xxxx" nocase
		$fp_example = "EXAMPLE"
	evidence:
		credential = (token) within 0 of token
	condition:
		$key and not any of ($fp_*)
}

rule cred_openai_project_key {
	meta:
		provider = "openai"
		severity = "critical"
	strings:
		$key = /sk-proj-[A-Za-z0-9_-]{32,64}/ capture(token = 0)
		$fp_x = "sk-proj-xxxx" nocase
		$fp_zero = "sk-proj-0000"
		$fp_example = "EXAMPLE"
	evidence:
		credential = (token) within 0 of token
	condition:
		$key and not any of ($fp_*)
}

rule cred_anthropic_api_key {
	meta:
		provider = "anthropic"
		severity = "critical"
	strings:
		$key = /sk-ant-api03-[A-Za-z0-9_-]{32,64}/ capture(token = 0)
		$fp_x = "sk-ant-api03-xxxx" nocase
		$fp_zero = "sk-ant-api03-0000"
	evidence:
		credential = (token) within 0 of token
	condition:
		$key and not any of ($fp_*)
}

rule cred_gcp_api_key {
	meta:
		provider = "gcp"
		severity = "high"
	strings:
		$key = /AIza[0-9A-Za-z_-]{35}/ capture(token = 0)
		$fp_example = "AIzaSyEXAMPLE"
		$fp_zero = "AIzaSy0000"
	evidence:
		credential = (token) within 0 of token
	condition:
		$key and not any of ($fp_*)
}

rule cred_sendgrid_api_key {
	meta:
		provider = "sendgrid"
		severity = "critical"
	strings:
		$key = /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/ capture(token = 0)
		$fp_x = "SG.xxxx" nocase
		$fp_zero = "SG.0000"
	evidence:
		credential = (token) within 0 of token
	condition:
		$key and not any of ($fp_*)
}

rule cred_npm_access_token {
	meta:
		provider = "npm"
		severity = "critical"
	strings:
		$key = /npm_[A-Za-z0-9]{36}/ capture(token = 0)
		$fp_x = "npm_xxxx" nocase
		$fp_zero = "npm_0000"
	evidence:
		credential = (token) within 0 of token
	condition:
		$key and not any of ($fp_*)
}

rule cred_pypi_upload_token {
	meta:
		provider = "pypi"
		severity = "critical"
	strings:
		$key = /pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{32,64}/ capture(token = 0)
		$fp_x = "pypi-AgEIcHlwaS5vcmcXXXX"
	evidence:
		credential = (token) within 0 of token
	condition:
		$key and not any of ($fp_*)
}

rule cred_vault_service_token {
	meta:
		provider = "vault"
		severity = "critical"
	strings:
		$key = /hvs\.[A-Za-z0-9_-]{24,48}/ capture(token = 0)
		$fp_x = "hvs.xxxx" nocase
		$fp_example = "hvs.EXAMPLE"
	evidence:
		credential = (token) within 0 of token
	condition:
		$key and not any of ($fp_*)
}

rule cred_huggingface_token {
	meta:
		provider = "huggingface"
		severity = "high"
	strings:
		$key = /hf_[A-Za-z0-9]{34}/ capture(token = 0)
		$fp_x = "hf_xxxx" nocase
		$fp_example = "hf_EXAMPLE"
	evidence:
		credential = (token) within 0 of token
	condition:
		$key and not any of ($fp_*)
}

rule cred_shopify_access_token {
	meta:
		provider = "shopify"
		severity = "critical"
	strings:
		$key = /shpat_[a-fA-F0-9]{32}/ capture(token = 0)
		$fp_zero = "shpat_00000000"
	evidence:
		credential = (token) within 0 of token
	condition:
		$key and not $fp_zero
}

rule cred_shopify_shared_secret {
	meta:
		provider = "shopify"
		severity = "critical"
	strings:
		$key = /shpss_[a-fA-F0-9]{32}/ capture(token = 0)
		$fp_zero = "shpss_00000000"
	evidence:
		credential = (token) within 0 of token
	condition:
		$key and not $fp_zero
}

rule cred_square_oauth_secret {
	meta:
		provider = "square"
		severity = "critical"
	strings:
		$key = /sq0csp-[0-9A-Za-z_-]{43}/ capture(token = 0)
		$fp_x = "sq0csp-xxxx" nocase
	evidence:
		credential = (token) within 0 of token
	condition:
		$key and not $fp_x
}

rule cred_digitalocean_pat {
	meta:
		provider = "digitalocean"
		severity = "critical"
	strings:
		$key = /dop_v1_[a-f0-9]{64}/ capture(token = 0)
		$fp_zero = "dop_v1_00000000"
	evidence:
		credential = (token) within 0 of token
	condition:
		$key and not $fp_zero
}

rule cred_gitlab_pat {
	meta:
		provider = "gitlab"
		severity = "critical"
	strings:
		$key = /glpat-[0-9a-zA-Z_-]{20}/ capture(token = 0)
		$fp_x = "glpat-xxxx" nocase
		$fp_example = "glpat-EXAMPLE"
	evidence:
		credential = (token) within 0 of token
	condition:
		$key and not any of ($fp_*)
}

rule cred_twilio_api_key {
	meta:
		provider = "twilio"
		severity = "high"
	strings:
		$sid = /AC[0-9a-f]{32}/ capture(account_sid = 0)
		$key = /SK[0-9a-f]{32}/ capture(api_key = 0)
		$fp_zero = "SK00000000000000000000000000000000"
	evidence:
		credential = (account_sid, api_key) within 192 of api_key
	condition:
		$sid and $key and not $fp_zero
}

rule cred_jwt_bearer {
	meta:
		provider = "jwt"
		severity = "medium"
	strings:
		$jwt = /Bearer eyJ[A-Za-z0-9_-]{16,64}\.eyJ[A-Za-z0-9_-]{16,128}\.[A-Za-z0-9_-]{16,64}/ capture(token = 0)
		$fp_jwtio = "eyJzdWIiOiIxMjM0NTY3ODkw"
		$fp_example = "EXAMPLE"
	evidence:
		credential = (token) within 0 of token
	condition:
		$jwt and not any of ($fp_*)
}

rule cred_private_key_pem {
	meta:
		provider = "pem"
		severity = "critical"
	strings:
		$pem = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[A-Za-z0-9+\/=\s\\n]{64,256}/ capture(private_key = 0)
		$fp_example = "EXAMPLE"
		$fp_test = "TEST PRIVATE KEY"
	evidence:
		credential = (private_key) within 0 of private_key
	condition:
		$pem and not any of ($fp_*)
}
`

func buildKafkaLogCorpus() [][]byte {
	const totalEvents = 500
	corpus := make([][]byte, 0, totalEvents)

	benignTemplates := []string{
		`{"ts":"2026-10-17T16:20:01.%03dZ","level":"info","service":"checkout-api","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","span_id":"00f067aa0ba902b7","method":"POST","path":"/v2/orders/%d/confirm","status":200,"latency_ms":14.2,"user_id":"usr_%d","region":"us-east-1","msg":"order confirmation processed"}`,
		`{"ts":"2026-10-17T16:20:02.%03dZ","level":"debug","service":"inventory-worker","trace_id":"7a192c3588b34da6a3ce929d0e0e1122","job_id":"job_%d","sku":"SKU-%d-BLK","warehouse":"iad-02","reserved_qty":3,"remaining_qty":148,"msg":"stock reservation committed"}`,
		`{"ts":"2026-10-17T16:20:03.%03dZ","level":"info","service":"auth-proxy","trace_id":"9c812f3577b34da6a3ce929d0e0e8899","client_ip":"10.42.%d.19","user_agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5)","session_id":"sess_%d","mfa_verified":true,"msg":"session token refreshed"}`,
		`{"ts":"2026-10-17T16:20:04.%03dZ","level":"warn","service":"payment-gateway","trace_id":"1d292f3577b34da6a3ce929d0e0e3344","merchant_id":"merch_%d","attempt":%d,"retry_backoff_ms":250,"upstream":"acquirer-eu-west","msg":"transient upstream timeout, scheduling retry"}`,
		`{"ts":"2026-10-17T16:20:05.%03dZ","level":"info","service":"k8s-ingress","pod":"api-gateway-7f9c8b6d4-%d","namespace":"production","bytes_in":%d,"bytes_out":4096,"tls_version":"TLSv1.3","cipher":"TLS_AES_128_GCM_SHA256","msg":"upstream response completed"}`,
	}

	// Near-miss / false-positive events (placeholders, test DBs, masked passwords, example keys).
	// Tokens are assembled via fmt.Sprintf/strings.Repeat so static secret scanners do not flag test fixtures.
	nearMissEvents := []string{
		fmt.Sprintf(`{"ts":"2026-10-17T16:20:10.001Z","level":"info","service":"ci-runner","msg":"initializing github client with placeholder","token":"%s_%s"}`, "ghp", strings.Repeat("x", 36)),
		`{"ts":"2026-10-17T16:20:10.002Z","level":"debug","service":"local-dev","msg":"connecting to local test database","db_url":"postgres://postgres:password@localhost:5432/orders_test"}`,
		`{"ts":"2026-10-17T16:20:10.003Z","level":"warn","service":"db-pool","msg":"connection reset on replica","db_url":"postgresql://app_reader:***@pg-replica-01.internal:5432/ledger"}`,
		fmt.Sprintf(`{"ts":"2026-10-17T16:20:10.004Z","level":"info","service":"config-loader","msg":"loaded sample docs config","aws_access_key_id":"%s%s","aws_secret_access_key":"%s/%s/%s"}`, "AKIA", "IOSFODNN7EXAMPLE", "wJalrXUtnFEMI", "K7MDENG", "bPxRfiCYEXAMPLEKEY"),
		fmt.Sprintf(`{"ts":"2026-10-17T16:20:10.005Z","level":"debug","service":"billing-worker","msg":"using masked stripe key","stripe_key":"%s_%s_%s"}`, "sk", "live", strings.Repeat("0", 24)),
		fmt.Sprintf(`{"ts":"2026-10-17T16:20:10.006Z","level":"debug","service":"auth-test","msg":"validating test vector","authorization":"Bearer %s.%s.%s"}`, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
		`{"ts":"2026-10-17T16:20:10.007Z","level":"info","service":"mongo-sync","msg":"sanitized connection uri","uri":"mongodb+srv://svc_analytics:REDACTED@cluster0.prod.mongodb.net/events"}`,
		`{"ts":"2026-10-17T16:20:10.008Z","level":"info","service":"cache-client","msg":"redis healthcheck","uri":"rediss://default:password@127.0.0.1:6379"}`,
		fmt.Sprintf(`{"ts":"2026-10-17T16:20:10.009Z","level":"debug","service":"llm-proxy","msg":"dry-run key","api_key":"%s-%s"}`, "sk-proj", strings.Repeat("x", 40)),
		fmt.Sprintf(`{"ts":"2026-10-17T16:20:10.010Z","level":"info","service":"notify-worker","msg":"slack test config","bot_token":"%s-%s-%s-%s"}`, "xoxb", strings.Repeat("0", 12), strings.Repeat("0", 13), strings.Repeat("0", 24)),
	}

	// True positive events (0.2% of traffic: 1 in 500 events)
	truePositiveEvent := `{"ts":"2026-10-17T16:20:59.999Z","level":"error","service":"order-worker","trace_id":"deadbeef1234567890abcdef12345678","msg":"failed to connect to primary database, dsn=postgresql://svc_orders_rw:K9mPv2xQr8Lz4Nw7Bt6Yh1Jc@pg-primary.prod.corp.internal:5432/orders_prod sslmode=require"}`

	for i := range totalEvents {
		switch {
		case i == 499:
			corpus = append(corpus, []byte(truePositiveEvent))
		case i%35 == 34 && (i/35) < len(nearMissEvents):
			corpus = append(corpus, []byte(nearMissEvents[i/35]))
		default:
			tmpl := benignTemplates[i%len(benignTemplates)]
			corpus = append(corpus, []byte(fmt.Sprintf(tmpl, i%1000, 10000+i, 500+i)))
		}
	}
	return corpus
}

func TestKafkaCredentialStreamAccuracyAndEvidence(t *testing.T) {
	program, err := NewCompiler().CompileSource(kafkaCredentialRulesSource)
	if err != nil {
		t.Fatalf("CompileSource failed: %v", err)
	}
	corpus := buildKafkaLogCorpus()
	scanner := program.NewScanner(WithEvidence(256), WithReportedMatchesOnly(), WithFastScan())
	defer scanner.Close()

	matchedEvents := 0
	for idx, event := range corpus {
		matches, scanErr := scanner.MatchingRules(event)
		if scanErr != nil {
			t.Fatalf("event %d scan failed: %v", idx, scanErr)
		}
		if idx < 499 {
			if len(matches) != 0 {
				t.Fatalf("event %d unexpectedly matched rule %s on benign/near-miss log: %s", idx, matches[0].Rule, string(event))
			}
			continue
		}
		if len(matches) != 1 || matches[0].Rule != "cred_postgres_uri" {
			t.Fatalf("event %d matches = %+v, want [cred_postgres_uri]", idx, matches)
		}
		findings := matches[0].Evidence["credential"]
		if len(findings) != 1 || findings[0].Status != EvidenceStatusReady {
			t.Fatalf("event %d evidence = %+v, want 1 ready finding", idx, findings)
		}
		if got := string(findings[0].Fields["username"][0].Data); got != "svc_orders_rw" {
			t.Fatalf("username = %q, want svc_orders_rw", got)
		}
		if got := string(findings[0].Fields["secret"][0].Data); got != "K9mPv2xQr8Lz4Nw7Bt6Yh1Jc" {
			t.Fatalf("secret = %q, want K9mPv2xQr8Lz4Nw7Bt6Yh1Jc", got)
		}
		if got := string(findings[0].Fields["endpoint"][0].Data); got != "pg-primary.prod.corp.internal:5432" {
			t.Fatalf("endpoint = %q, want pg-primary.prod.corp.internal:5432", got)
		}
		matchedEvents++
	}
	if matchedEvents != 1 {
		t.Fatalf("matchedEvents = %d, want 1", matchedEvents)
	}

	burstCorpus := buildKafkaBurstCorpus()
	wantBurstRules := []string{
		"cred_postgres_uri",
		"cred_github_pat",
		"cred_stripe_live_key",
		"cred_aws_key_pair",
		"cred_openai_project_key",
	}
	burstHits := 0
	for idx, event := range burstCorpus {
		matches, scanErr := scanner.MatchingRules(event)
		if scanErr != nil {
			t.Fatalf("burst event %d scan failed: %v", idx, scanErr)
		}
		if idx%20 != 19 {
			if len(matches) != 0 {
				t.Fatalf("burst event %d unexpectedly matched %s", idx, matches[0].Rule)
			}
			continue
		}
		wantRule := wantBurstRules[(idx/20)%len(wantBurstRules)]
		if len(matches) != 1 || matches[0].Rule != wantRule {
			t.Fatalf("burst event %d matches = %+v, want [%s]", idx, matches, wantRule)
		}
		findings := matches[0].Evidence["credential"]
		if len(findings) != 1 || findings[0].Status != EvidenceStatusReady {
			t.Fatalf("burst event %d (%s) evidence = %+v, want 1 ready finding", idx, wantRule, findings)
		}
		burstHits++
	}
	if burstHits != 5 {
		t.Fatalf("burstHits = %d, want 5", burstHits)
	}
}

func buildKafkaBurstCorpus() [][]byte {
	base := buildKafkaLogCorpus()
	const burstEvents = 100
	corpus := make([][]byte, 0, burstEvents)

	synthPayload := "9KmPv2xQr8Lz4Nw7Bt6Yh1Jc3Df5Gh7Jk9Lm1Np2Qr"
	truePositiveBurstEvents := []string{
		`{"ts":"2026-10-17T16:21:00.001Z","level":"error","service":"order-worker","msg":"db retry failed dsn=postgresql://svc_orders_rw:K9mPv2xQr8Lz4Nw7Bt6Yh1Jc@pg-primary.prod.corp.internal:5432/orders_prod"}`,
		fmt.Sprintf(`{"ts":"2026-10-17T16:21:00.002Z","level":"error","service":"ci-deployer","msg":"upstream github 401 with token=%s_%s"}`, "ghp", synthPayload[:36]),
		fmt.Sprintf(`{"ts":"2026-10-17T16:21:00.003Z","level":"error","service":"billing-sync","msg":"stripe charge error key=%s_%s_%s"}`, "sk", "live", synthPayload[:26]),
		fmt.Sprintf(`{"ts":"2026-10-17T16:21:00.004Z","level":"error","service":"s3-uploader","msg":"sigv4 failure akid=%s%s aws_secret_access_key=\"%s\""}`, "AKIA", "9KMPV2XQR8LZ4NW7", synthPayload[:40]),
		fmt.Sprintf(`{"ts":"2026-10-17T16:21:00.005Z","level":"error","service":"llm-router","msg":"rate limit header Bearer %s-%s"}`, "sk-proj", synthPayload),
	}

	for i := range burstEvents {
		switch {
		case i%20 == 19:
			corpus = append(corpus, []byte(truePositiveBurstEvents[(i/20)%len(truePositiveBurstEvents)]))
		case i%10 == 4:
			// Pull near-miss events from base corpus (indices 34, 69, 104, ...)
			corpus = append(corpus, base[34+((i/10)%10)*35])
		default:
			corpus = append(corpus, base[i])
		}
	}
	return corpus
}

func BenchmarkKafkaCredentialStream(b *testing.B) {
	program, err := NewCompiler().CompileSource(kafkaCredentialRulesSource)
	if err != nil {
		b.Fatalf("CompileSource failed: %v", err)
	}
	corpus := buildKafkaLogCorpus()
	var totalBytes int64
	for _, event := range corpus {
		totalBytes += int64(len(event))
	}
	avgBytes := totalBytes / int64(len(corpus))

	burstCorpus := buildKafkaBurstCorpus()
	var burstTotalBytes int64
	for _, event := range burstCorpus {
		burstTotalBytes += int64(len(event))
	}
	burstAvgBytes := burstTotalBytes / int64(len(burstCorpus))

	b.Run("SingleWorker_MatchingRules", func(b *testing.B) {
		scanner := program.NewScanner(WithEvidence(256), WithReportedMatchesOnly(), WithFastScan())
		defer scanner.Close()
		b.SetBytes(avgBytes)
		b.ReportAllocs()
		b.ResetTimer()
		idx := 0
		hits := 0
		for b.Loop() {
			event := corpus[idx]
			idx++
			if idx == len(corpus) {
				idx = 0
			}
			matches, scanErr := scanner.MatchingRules(event)
			if scanErr != nil {
				b.Fatal(scanErr)
			}
			hits += len(matches)
		}
		b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "eps")
		_ = hits
	})

	b.Run("SingleWorker_ScanReportedOnly", func(b *testing.B) {
		scanner := program.NewScanner(WithEvidence(256), WithReportedMatchesOnly(), WithFastScan())
		defer scanner.Close()
		b.SetBytes(avgBytes)
		b.ReportAllocs()
		b.ResetTimer()
		idx := 0
		hits := 0
		for b.Loop() {
			event := corpus[idx]
			idx++
			if idx == len(corpus) {
				idx = 0
			}
			res, scanErr := scanner.Scan(event)
			if scanErr != nil {
				b.Fatal(scanErr)
			}
			hits += len(res.MatchedRules)
		}
		b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "eps")
		_ = hits
	})

	b.Run("SingleWorker_BurstTraffic", func(b *testing.B) {
		scanner := program.NewScanner(WithEvidence(256), WithReportedMatchesOnly(), WithFastScan())
		defer scanner.Close()
		b.SetBytes(burstAvgBytes)
		b.ReportAllocs()
		b.ResetTimer()
		idx := 0
		hits := 0
		for b.Loop() {
			event := burstCorpus[idx]
			idx++
			if idx == len(burstCorpus) {
				idx = 0
			}
			matches, scanErr := scanner.MatchingRules(event)
			if scanErr != nil {
				b.Fatal(scanErr)
			}
			hits += len(matches)
		}
		b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "eps")
		_ = hits
	})

	b.Run("ParallelWorkers_MatchingRules", func(b *testing.B) {
		b.SetBytes(avgBytes)
		b.ReportAllocs()
		var totalHits atomic.Uint64
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			scanner := program.NewScanner(WithEvidence(256), WithReportedMatchesOnly(), WithFastScan())
			defer scanner.Close()
			idx := 0
			localHits := uint64(0)
			for pb.Next() {
				event := corpus[idx]
				idx++
				if idx == len(corpus) {
					idx = 0
				}
				matches, scanErr := scanner.MatchingRules(event)
				if scanErr != nil {
					b.Fatal(scanErr)
				}
				localHits += uint64(len(matches))
			}
			totalHits.Add(localHits)
		})
		b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "eps")
	})

	b.Run("ParallelWorkers_BurstTraffic", func(b *testing.B) {
		b.SetBytes(burstAvgBytes)
		b.ReportAllocs()
		var totalHits atomic.Uint64
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			scanner := program.NewScanner(WithEvidence(256), WithReportedMatchesOnly(), WithFastScan())
			defer scanner.Close()
			idx := 0
			localHits := uint64(0)
			for pb.Next() {
				event := burstCorpus[idx]
				idx++
				if idx == len(burstCorpus) {
					idx = 0
				}
				matches, scanErr := scanner.MatchingRules(event)
				if scanErr != nil {
					b.Fatal(scanErr)
				}
				localHits += uint64(len(matches))
			}
			totalHits.Add(localHits)
		})
		b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "eps")
	})
}

func buildLargeAppLogEvent(targetBytes int, index int, includeLeak bool) []byte {
	var sb strings.Builder
	sb.Grow(targetBytes + 512)
	fmt.Fprintf(&sb, `{"ts":"2026-10-17T16:25:%02d.%03dZ","level":"error","service":"checkout-orchestrator","pod":"checkout-orchestrator-6d8f9b7c4-x92k%d","trace_id":"4bf92f3577b34da6a3ce929d0e0e%04x","AccountState":"ACTIVE_ACCOUNT","SkuBatch":"SKU_BATCH_%d","sanitized_auth":"REDACTED","sample_token":"EXAMPLE",`,
		index%60, index%1000, index%9, index, index)
	if !includeLeak && index%20 == 0 {
		sb.WriteString(`"local_fallback_dsn":"postgres://postgres:password@localhost:5432/checkout_local",`)
	}
	sb.WriteString(`"http_request":{"method":"POST","path":"/api/v2/checkout/complete","headers":{"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36","X-Forwarded-For":"10.42.19.88, 127.0.0.1","Accept-Encoding":"gzip, deflate, br","Authorization":"REDACTED"}},`)
	sb.WriteString(`"stack_trace":"goroutine 1482 [running]:\n`)

	frames := []string{
		`github.com/acme-corp/checkout-api/internal/postgres.(*OrderRepository).CommitTx(0x1400048a200, {0x104c8a120, 0x140009123c0}, 0x1400055e180)\n\t/workspace/internal/postgres/order_repository.go:241 +0x3bc\n`,
		`github.com/acme-corp/checkout-api/internal/redis.(*SessionCache).RefreshLock(0x1400021c080, {0x104c8a120, 0x140009123c0}, {0x1400038e000, 0x24})\n\t/workspace/internal/redis/session_cache.go:118 +0x194\n`,
		`github.com/acme-corp/checkout-api/internal/mongodb.(*AuditSink).AppendBatch(0x1400019b400, {0x104c8a120, 0x140009123c0}, {0x14000840000, 0x10, 0x10})\n\t/workspace/internal/mongodb/audit_sink.go:89 +0x2d0\n`,
		`github.com/acme-corp/checkout-api/pkg/payment.(*StripeGateway).AuthorizeCharge(0x1400031a000, {0x104c8a120, 0x140009123c0}, 0x140007c2000)\n\t/workspace/pkg/payment/stripe_gateway.go:175 +0x418\n`,
		`github.com/acme-corp/checkout-api/pkg/http/middleware.TraceAndRecover.func1({0x104c86ee0, 0x14000604000}, 0x14000518200)\n\t/workspace/pkg/http/middleware/recover.go:64 +0x150\n`,
	}

	frameIdx := 0
	for sb.Len()+360 < targetBytes {
		sb.WriteString(frames[frameIdx%len(frames)])
		frameIdx++
	}

	if includeLeak {
		sb.WriteString(`","error_detail":"unhandled driver panic on failover dsn=postgresql://svc_orders_rw:K9mPv2xQr8Lz4Nw7Bt6Yh1Jc@pg-primary.prod.corp.internal:5432/orders_prod sslmode=verify-full"}`)
	} else {
		sb.WriteString(`","error_detail":"context deadline exceeded while awaiting upstream ACK on SK_CHANNEL_04"}`)
	}
	return []byte(sb.String())
}

func buildLargeAppLogCorpus(targetBytes int) [][]byte {
	const totalEvents = 500
	corpus := make([][]byte, 0, totalEvents)
	for i := range totalEvents {
		corpus = append(corpus, buildLargeAppLogEvent(targetBytes, i, i == 499))
	}
	return corpus
}

func buildRealisticMixedSizeCorpus() [][]byte {
	// Realistic production application log size distribution (500 events, 99.8% drop rate):
	// - 70% (350 events): ~1 KB structured JSON microservice logs
	// - 20% (100 events): ~4 KB error/warn logs with multi-frame stack traces
	// -  9% ( 45 events): ~16 KB panic/HTTP dump logs
	// -  1% (  5 events): ~64 KB full state/goroutine dump logs (with 1 true positive at index 499)
	const totalEvents = 500
	corpus := make([][]byte, 0, totalEvents)
	for i := range totalEvents {
		var targetBytes int
		switch {
		case i == 499:
			targetBytes = 16 * 1024
		case i%100 == 99:
			targetBytes = 64 * 1024
		case i%11 == 10:
			targetBytes = 16 * 1024
		case i%5 == 4:
			targetBytes = 4 * 1024
		default:
			targetBytes = 1024
		}
		corpus = append(corpus, buildLargeAppLogEvent(targetBytes, i, i == 499))
	}
	return corpus
}

func TestKafkaLargeApplicationLogs(t *testing.T) {
	program, err := NewCompiler().CompileSource(kafkaCredentialRulesSource)
	if err != nil {
		t.Fatalf("CompileSource failed: %v", err)
	}
	scanner := program.NewScanner(WithEvidence(256), WithReportedMatchesOnly(), WithFastScan())
	defer scanner.Close()

	for _, size := range []int{1024, 4 * 1024, 16 * 1024, 64 * 1024} {
		for _, benignIdx := range []int{0, 1} {
			benign := buildLargeAppLogEvent(size, benignIdx, false)
			matches, scanErr := scanner.MatchingRules(benign)
			if scanErr != nil {
				t.Fatalf("size %d benign[%d] scan failed: %v", size, benignIdx, scanErr)
			}
			if len(matches) != 0 {
				t.Fatalf("size %d benign[%d] log unexpectedly matched %+v", size, benignIdx, matches)
			}
		}

		leaked := buildLargeAppLogEvent(size, 2, true)
		matches, scanErr := scanner.MatchingRules(leaked)
		if scanErr != nil {
			t.Fatalf("size %d leaked scan failed: %v", size, scanErr)
		}
		if len(matches) != 1 || matches[0].Rule != "cred_postgres_uri" {
			t.Fatalf("size %d leaked log matches = %+v, want [cred_postgres_uri]", size, matches)
		}
		findings := matches[0].Evidence["credential"]
		if len(findings) != 1 || findings[0].Status != EvidenceStatusReady {
			t.Fatalf("size %d leaked log evidence = %+v, want ready finding", size, findings)
		}
	}
}

func BenchmarkKafkaCredentialStreamByEventSize(b *testing.B) {
	program, err := NewCompiler().CompileSource(kafkaCredentialRulesSource)
	if err != nil {
		b.Fatalf("CompileSource failed: %v", err)
	}

	cases := []struct {
		name   string
		corpus [][]byte
	}{
		{"1KB_StructuredLog", buildLargeAppLogCorpus(1024)},
		{"4KB_StackTraceLog", buildLargeAppLogCorpus(4 * 1024)},
		{"16KB_PanicAndHTTPDump", buildLargeAppLogCorpus(16 * 1024)},
		{"64KB_FullStateDump", buildLargeAppLogCorpus(64 * 1024)},
		{"MixedRealisticDistribution_Avg3.6KB", buildRealisticMixedSizeCorpus()},
	}

	for _, tc := range cases {
		var totalBytes int64
		for _, event := range tc.corpus {
			totalBytes += int64(len(event))
		}
		avgBytes := totalBytes / int64(len(tc.corpus))

		b.Run("SingleWorker_"+tc.name, func(b *testing.B) {
			scanner := program.NewScanner(WithEvidence(256), WithReportedMatchesOnly(), WithFastScan())
			defer scanner.Close()
			b.SetBytes(avgBytes)
			b.ReportAllocs()
			b.ResetTimer()
			idx := 0
			hits := 0
			for b.Loop() {
				event := tc.corpus[idx]
				idx++
				if idx == len(tc.corpus) {
					idx = 0
				}
				matches, scanErr := scanner.MatchingRules(event)
				if scanErr != nil {
					b.Fatal(scanErr)
				}
				hits += len(matches)
			}
			b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "eps")
			_ = hits
		})

		b.Run("ParallelWorkers_"+tc.name, func(b *testing.B) {
			b.SetBytes(avgBytes)
			b.ReportAllocs()
			var totalHits atomic.Uint64
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				scanner := program.NewScanner(WithEvidence(256), WithReportedMatchesOnly(), WithFastScan())
				defer scanner.Close()
				idx := 0
				localHits := uint64(0)
				for pb.Next() {
					event := tc.corpus[idx]
					idx++
					if idx == len(tc.corpus) {
						idx = 0
					}
					matches, scanErr := scanner.MatchingRules(event)
					if scanErr != nil {
						b.Fatal(scanErr)
					}
					localHits += uint64(len(matches))
				}
				totalHits.Add(localHits)
			})
			b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "eps")
		})
	}
}
