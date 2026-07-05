package framework

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/walker"
)

const fixtureRoot = "../../../testdata/framework"

func readFixture(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureRoot, rel))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	return data
}

func TestDjangoDebugCheck(t *testing.T) {
	vuln := detectDjangoDebug("django/vuln_debug.env", readFixture(t, "django/vuln_debug.env"))
	if len(vuln) != 1 || vuln[0].RuleID != "ZS-CFG-001" {
		t.Fatalf("expected 1 ZS-CFG-001 finding, got %+v", vuln)
	}
	if vuln[0].Kind != core.FindingKindConfig || vuln[0].Config == nil || vuln[0].Config.Framework != "django" {
		t.Errorf("unexpected finding shape: %+v", vuln[0])
	}

	clean := detectDjangoDebug("django/clean_debug.env", readFixture(t, "django/clean_debug.env"))
	if len(clean) != 0 {
		t.Errorf("expected no finding on clean_debug.env, got %+v", clean)
	}
}

func TestExpressHelmetCheck(t *testing.T) {
	vuln := detectExpressMissingHelmet("express/vuln_missing_helmet.js", readFixture(t, "express/vuln_missing_helmet.js"))
	if len(vuln) != 1 || vuln[0].RuleID != "ZS-CFG-002" {
		t.Fatalf("expected 1 ZS-CFG-002 finding, got %+v", vuln)
	}

	clean := detectExpressMissingHelmet("express/clean_with_helmet.js", readFixture(t, "express/clean_with_helmet.js"))
	if len(clean) != 0 {
		t.Errorf("expected no finding when helmet is registered, got %+v", clean)
	}
}

func TestCorsWildcardCheck(t *testing.T) {
	vuln := detectCorsWildcard("cors/vuln_wildcard.yaml", readFixture(t, "cors/vuln_wildcard.yaml"))
	if len(vuln) != 1 || vuln[0].RuleID != "ZS-CFG-003" {
		t.Fatalf("expected 1 ZS-CFG-003 finding, got %+v", vuln)
	}

	clean := detectCorsWildcard("cors/clean_restricted.yaml", readFixture(t, "cors/clean_restricted.yaml"))
	if len(clean) != 0 {
		t.Errorf("expected no finding on restricted origin, got %+v", clean)
	}
}

func TestLaravelDebugCheck(t *testing.T) {
	vuln := detectLaravelDebug("laravel/vuln_app_debug.env", readFixture(t, "laravel/vuln_app_debug.env"))
	if len(vuln) != 1 || vuln[0].RuleID != "ZS-CFG-004" {
		t.Fatalf("expected 1 ZS-CFG-004 finding, got %+v", vuln)
	}

	clean := detectLaravelDebug("laravel/clean_app_debug.env", readFixture(t, "laravel/clean_app_debug.env"))
	if len(clean) != 0 {
		t.Errorf("expected no finding when APP_DEBUG=false, got %+v", clean)
	}

	localDebug := detectLaravelDebug("laravel/clean_local_debug.env", readFixture(t, "laravel/clean_local_debug.env"))
	if len(localDebug) != 0 {
		t.Errorf("expected no finding when APP_ENV=local suppresses APP_DEBUG=true, got %+v", localDebug)
	}
}

func TestNonProdEnvFilenameSuppressed(t *testing.T) {
	vuln := detectDjangoDebug("config/.env.example", []byte("DEBUG=True\n"))
	if len(vuln) != 0 {
		t.Errorf("expected .env.example to be suppressed as non-prod, got %+v", vuln)
	}
}

func TestFrameworkScanner_AcceptsAndScan(t *testing.T) {
	sc := New()
	if !sc.Accepts(walker.FileEntry{Path: "app/.env"}) {
		t.Error("Accepts should return true for .env files")
	}
	if sc.Accepts(walker.FileEntry{Path: "app/.env", IsBinary: true}) {
		t.Error("Accepts should return false for binary files")
	}
	if sc.Accepts(walker.FileEntry{Path: "app/main.go"}) {
		t.Error("Accepts should return false for files no check matches")
	}

	findings, _, err := sc.Scan(context.Background(), []walker.FileEntry{
		{Path: filepath.Join(fixtureRoot, "django/vuln_debug.env")},
		{Path: filepath.Join(fixtureRoot, "django/clean_debug.env")},
	})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 1 || findings[0].RuleID != "ZS-CFG-001" {
		t.Errorf("expected exactly 1 ZS-CFG-001 finding from Scan, got %+v", findings)
	}
}
