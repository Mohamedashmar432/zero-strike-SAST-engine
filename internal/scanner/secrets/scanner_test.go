package secrets

import (
	"context"
	"strings"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"
)

func TestSecretsScanner_AWSKey(t *testing.T) {
	fs := scanContent("test.py", []byte(`aws_key = "AKIAIOSFODNN7EXAMPLE"`))
	if len(fs) == 0 {
		t.Fatal("expected finding for AWS key, got none")
	}
	f := fs[0]
	if f.RuleID != "ZS-SEC-001" {
		t.Errorf("RuleID = %q, want ZS-SEC-001", f.RuleID)
	}
	if f.Kind != core.FindingKindSecret {
		t.Errorf("Kind = %q, want secret", f.Kind)
	}
	if f.Secret == nil || f.Secret.DetectorID != "aws-access-key" {
		t.Errorf("Secret.DetectorID = %v, want aws-access-key", f.Secret)
	}
}

func TestSecretsScanner_GitHubToken(t *testing.T) {
	token := "ghp_" + strings.Repeat("a", 36)
	fs := scanContent("config.js", []byte(`const token = "`+token+`"`))
	if len(fs) == 0 {
		t.Fatal("expected finding for GitHub token, got none")
	}
	if fs[0].RuleID != "ZS-SEC-002" {
		t.Errorf("RuleID = %q, want ZS-SEC-002", fs[0].RuleID)
	}
}

func TestSecretsScanner_PrivateKeyPEM(t *testing.T) {
	fs := scanContent("key.pem", []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEo..."))
	if len(fs) == 0 {
		t.Fatal("expected finding for PEM private key, got none")
	}
	if fs[0].RuleID != "ZS-SEC-005" {
		t.Errorf("RuleID = %q, want ZS-SEC-005", fs[0].RuleID)
	}
}

func TestSecretsScanner_BinaryFileSkipped(t *testing.T) {
	sc := New()
	entry := walker.FileEntry{Path: "binary.bin", IsBinary: true}
	if sc.Accepts(entry) {
		t.Error("Accepts should return false for binary files")
	}
}

func TestSecretsFingerprint_SameSecretSameFingerprint(t *testing.T) {
	data := []byte(`aws_key = "AKIAIOSFODNN7EXAMPLE"`)
	fs1 := scanContent("file1.py", data)
	fs2 := scanContent("file2.py", data)
	if len(fs1) == 0 || len(fs2) == 0 {
		t.Fatal("expected findings in both files")
	}
	if fs1[0].Fingerprint != fs2[0].Fingerprint {
		t.Errorf("same secret in two files should produce same fingerprint: %q vs %q",
			fs1[0].Fingerprint, fs2[0].Fingerprint)
	}
}

func TestSecretsFingerprint_DiffSecretDiffFingerprint(t *testing.T) {
	fs1 := scanContent("f.py", []byte(`k = "AKIAIOSFODNN7EXAMPLE"`))
	fs2 := scanContent("f.py", []byte(`k = "AKIAJLGZNNREXAMPLE2X"`))
	if len(fs1) == 0 || len(fs2) == 0 {
		t.Fatal("expected findings")
	}
	if fs1[0].Fingerprint == fs2[0].Fingerprint {
		t.Error("different secrets should produce different fingerprints")
	}
}

func TestSecretsScanner_LowEntropyNotFlagged(t *testing.T) {
	// "aaaaaaaaaaaaaaaaaaaaaa" has entropy ~0 — should be filtered by SEC-003
	fs := scanContent("config.py", []byte(`api_key = "aaaaaaaaaaaaaaaaaaaaaa"`))
	for _, f := range fs {
		if f.RuleID == "ZS-SEC-003" {
			t.Error("low-entropy API key should not be flagged by ZS-SEC-003")
		}
	}
}

func TestSecretsScanner_APIKey_HighEntropy(t *testing.T) {
	// High-entropy API key should be flagged by ZS-SEC-003
	fs := scanContent("config.py", []byte(`api_key = "aB3xZ9kLmN2pQrStUvWxYz"`))
	found := false
	for _, f := range fs {
		if f.RuleID == "ZS-SEC-003" {
			found = true
		}
	}
	if !found {
		t.Error("high-entropy API key should be flagged by ZS-SEC-003")
	}
}

func TestSecretsScanner_HardcodedPassword(t *testing.T) {
	// Hardcoded password should be flagged by ZS-SEC-004
	fs := scanContent("app.py", []byte(`password = "SuperSecret123!"`))
	found := false
	for _, f := range fs {
		if f.RuleID == "ZS-SEC-004" {
			found = true
		}
	}
	if !found {
		t.Error("hardcoded password should be flagged by ZS-SEC-004")
	}
}

func TestSecretsScanner_Scan(t *testing.T) {
	// Integration smoke test using a temp file — no CGo needed
	sc := New()
	_, _, err := sc.Scan(context.Background(), []walker.FileEntry{})
	if err != nil {
		t.Errorf("Scan on empty slice should not error: %v", err)
	}
}
