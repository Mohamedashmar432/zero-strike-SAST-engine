//go:build cgo

package engine_test

import (
	"testing"
)

// TestIntegration_InsecureSkipVerifyFiresZSGO021 verifies the disabled-TLS-verification rule
// fires on the struct-literal field form (fields lower to identifier nodes).
func TestIntegration_InsecureSkipVerifyFiresZSGO021(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc client() {\n\tcfg := &tls.Config{InsecureSkipVerify: true}\n\t_ = cfg\n}\n"
	if !hasRule(matchGoSource(t, idx, src), "ZS-GO-021") {
		t.Error("expected ZS-GO-021 to fire on tls.Config{InsecureSkipVerify: true}")
	}
}

// TestIntegration_JwtParseUnverifiedFiresZSGO022 verifies the unverified-JWT rule.
func TestIntegration_JwtParseUnverifiedFiresZSGO022(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc inspect(raw string) {\n\tjwt.ParseUnverified(raw, nil)\n}\n"
	if !hasRule(matchGoSource(t, idx, src), "ZS-GO-022") {
		t.Error("expected ZS-GO-022 to fire on jwt.ParseUnverified()")
	}
}

// TestIntegration_TaintedSprintfFiresZSGO023 verifies tainted-format-string detection.
func TestIntegration_TaintedSprintfFiresZSGO023(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc handler() {\n\tname := r.FormValue(\"name\")\n" +
		"\tgreeting := fmt.Sprintf(\"hello %s\", name)\n\t_ = greeting\n}\n"
	if !hasRule(matchGoSource(t, idx, src), "ZS-GO-023") {
		t.Error("expected ZS-GO-023 to fire when a fmt.Sprintf argument is tainted")
	}
}

// TestIntegration_ConstantSprintfDoesNotFireZSGO023 verifies the negative case.
func TestIntegration_ConstantSprintfDoesNotFireZSGO023(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc greet() {\n\tgreeting := fmt.Sprintf(\"hello %s\", \"world\")\n\t_ = greeting\n}\n"
	if hasRule(matchGoSource(t, idx, src), "ZS-GO-023") {
		t.Error("expected ZS-GO-023 to NOT fire for constant arguments")
	}
}

// TestIntegration_TaintedWriteFileFiresZSGO024 verifies path-traversal-write detection.
func TestIntegration_TaintedWriteFileFiresZSGO024(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc handler() {\n\tdest := r.URL.Query().Get(\"dest\")\n" +
		"\tos.WriteFile(dest, []byte(\"saved\"), 0644)\n}\n"
	if !hasRule(matchGoSource(t, idx, src), "ZS-GO-024") {
		t.Error("expected ZS-GO-024 to fire when the os.WriteFile path is tainted")
	}
}

// TestIntegration_ConstantWriteFileDoesNotFireZSGO024 verifies the negative case.
func TestIntegration_ConstantWriteFileDoesNotFireZSGO024(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc persist() {\n\tos.WriteFile(\"/tmp/out.txt\", []byte(\"saved\"), 0644)\n}\n"
	if hasRule(matchGoSource(t, idx, src), "ZS-GO-024") {
		t.Error("expected ZS-GO-024 to NOT fire for a constant path")
	}
}

// TestIntegration_TaintedCommandContextFiresZSGO025 verifies command-injection detection
// for the context-aware exec variant.
func TestIntegration_TaintedCommandContextFiresZSGO025(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc run() {\n\tbin := os.Args[1]\n\tctx := context.Background()\n" +
		"\texec.CommandContext(ctx, bin)\n}\n"
	if !hasRule(matchGoSource(t, idx, src), "ZS-GO-025") {
		t.Error("expected ZS-GO-025 to fire when an exec.CommandContext argument is tainted")
	}
}

// TestIntegration_ConstantCommandContextDoesNotFireZSGO025 verifies the negative case.
func TestIntegration_ConstantCommandContextDoesNotFireZSGO025(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc run() {\n\tctx := context.Background()\n\texec.CommandContext(ctx, \"ls\")\n}\n"
	if hasRule(matchGoSource(t, idx, src), "ZS-GO-025") {
		t.Error("expected ZS-GO-025 to NOT fire for a constant command")
	}
}

// TestIntegration_WorldWritableChmodFiresZSGO026 verifies the 0777 literal mode.
func TestIntegration_WorldWritableChmodFiresZSGO026(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc relax() {\n\tos.Chmod(\"/var/data/report.txt\", 0777)\n}\n"
	if !hasRule(matchGoSource(t, idx, src), "ZS-GO-026") {
		t.Error("expected ZS-GO-026 to fire on os.Chmod(..., 0777)")
	}
}

// TestIntegration_WorldWritableChmod0o666FiresZSGO026 verifies the Go octal spelling.
func TestIntegration_WorldWritableChmod0o666FiresZSGO026(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc relax() {\n\tos.Chmod(\"/var/data/report.txt\", 0o666)\n}\n"
	if !hasRule(matchGoSource(t, idx, src), "ZS-GO-026") {
		t.Error("expected ZS-GO-026 to fire on os.Chmod(..., 0o666)")
	}
}

// TestIntegration_RestrictiveChmodDoesNotFireZSGO026 verifies the negative case.
func TestIntegration_RestrictiveChmodDoesNotFireZSGO026(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc restrict(p string) {\n\tos.Chmod(p, 0o600)\n}\n"
	if hasRule(matchGoSource(t, idx, src), "ZS-GO-026") {
		t.Error("expected ZS-GO-026 to NOT fire on os.Chmod(p, 0o600)")
	}
}

// TestIntegration_TaintedHttpPostFiresZSGO027 verifies SSRF detection for http.Post.
func TestIntegration_TaintedHttpPostFiresZSGO027(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc handler() {\n\ttarget := r.FormValue(\"endpoint\")\n" +
		"\thttp.Post(target, \"application/json\", nil)\n}\n"
	if !hasRule(matchGoSource(t, idx, src), "ZS-GO-027") {
		t.Error("expected ZS-GO-027 to fire when the http.Post URL is tainted")
	}
}

// TestIntegration_ConstantHttpPostDoesNotFireZSGO027 verifies the negative case.
func TestIntegration_ConstantHttpPostDoesNotFireZSGO027(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc notify() {\n\thttp.Post(\"https://example.com/hook\", \"application/json\", nil)\n}\n"
	if hasRule(matchGoSource(t, idx, src), "ZS-GO-027") {
		t.Error("expected ZS-GO-027 to NOT fire for a constant URL")
	}
}

// TestIntegration_SensitiveLogPrintfFiresZSGO028 verifies sensitive-value-logging detection.
func TestIntegration_SensitiveLogPrintfFiresZSGO028(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc connect() {\n\tpassword := os.Getenv(\"DB_PASSWORD\")\n" +
		"\tlog.Printf(\"connecting with %s\", password)\n}\n"
	if !hasRule(matchGoSource(t, idx, src), "ZS-GO-028") {
		t.Error("expected ZS-GO-028 to fire when a sensitive-looking identifier is logged")
	}
}

// TestIntegration_BenignLogPrintfDoesNotFireZSGO028 verifies the negative case.
func TestIntegration_BenignLogPrintfDoesNotFireZSGO028(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc connect() {\n\thostname := os.Getenv(\"DB_HOST\")\n" +
		"\tlog.Printf(\"connecting to %s\", hostname)\n}\n"
	if hasRule(matchGoSource(t, idx, src), "ZS-GO-028") {
		t.Error("expected ZS-GO-028 to NOT fire for a benign identifier")
	}
}
