package framework

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"
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

func TestSpringActuatorExposedCheck(t *testing.T) {
	vuln := detectSpringActuatorExposed("spring/application-vuln-actuator.properties", readFixture(t, "spring/application-vuln-actuator.properties"))
	if len(vuln) != 1 || vuln[0].RuleID != "ZS-CFG-005" {
		t.Fatalf("expected 1 ZS-CFG-005 finding, got %+v", vuln)
	}

	clean := detectSpringActuatorExposed("spring/application-clean-actuator.properties", readFixture(t, "spring/application-clean-actuator.properties"))
	if len(clean) != 0 {
		t.Errorf("expected no finding when actuator exposure is an explicit allowlist, got %+v", clean)
	}
}

func TestSpringCookieInsecureCheck(t *testing.T) {
	vuln := detectSpringCookieInsecure("spring/application-vuln-cookie.properties", readFixture(t, "spring/application-vuln-cookie.properties"))
	if len(vuln) != 1 || vuln[0].RuleID != "ZS-CFG-006" {
		t.Fatalf("expected 1 ZS-CFG-006 finding, got %+v", vuln)
	}

	clean := detectSpringCookieInsecure("spring/application-clean-cookie.properties", readFixture(t, "spring/application-clean-cookie.properties"))
	if len(clean) != 0 {
		t.Errorf("expected no finding when cookie.secure=true, got %+v", clean)
	}
}

func TestAspNetVerboseErrorsCheck(t *testing.T) {
	vuln := detectAspNetVerboseErrors("aspnet/vuln_customerrors/web.config", readFixture(t, "aspnet/vuln_customerrors/web.config"))
	if len(vuln) != 1 || vuln[0].RuleID != "ZS-CFG-007" {
		t.Fatalf("expected 1 ZS-CFG-007 finding, got %+v", vuln)
	}

	clean := detectAspNetVerboseErrors("aspnet/clean_customerrors/web.config", readFixture(t, "aspnet/clean_customerrors/web.config"))
	if len(clean) != 0 {
		t.Errorf("expected no finding when customErrors mode=On, got %+v", clean)
	}
}

func TestAspNetDirectoryBrowseCheck(t *testing.T) {
	vuln := detectAspNetDirectoryBrowse("aspnet/vuln_directorybrowse/web.config", readFixture(t, "aspnet/vuln_directorybrowse/web.config"))
	if len(vuln) != 1 || vuln[0].RuleID != "ZS-CFG-008" {
		t.Fatalf("expected 1 ZS-CFG-008 finding, got %+v", vuln)
	}

	clean := detectAspNetDirectoryBrowse("aspnet/clean_directorybrowse/web.config", readFixture(t, "aspnet/clean_directorybrowse/web.config"))
	if len(clean) != 0 {
		t.Errorf("expected no finding when directoryBrowse enabled=false, got %+v", clean)
	}
}

func TestLaravelSessionCookieCheck(t *testing.T) {
	vuln := detectLaravelSessionCookieInsecure("laravel/vuln_session/config/session.php", readFixture(t, "laravel/vuln_session/config/session.php"))
	if len(vuln) != 1 || vuln[0].RuleID != "ZS-CFG-009" {
		t.Fatalf("expected 1 ZS-CFG-009 finding, got %+v", vuln)
	}

	clean := detectLaravelSessionCookieInsecure("laravel/clean_session/config/session.php", readFixture(t, "laravel/clean_session/config/session.php"))
	if len(clean) != 0 {
		t.Errorf("expected no finding when secure defaults to true via env(), got %+v", clean)
	}
}

func TestLaravelCsrfExceptCheck(t *testing.T) {
	vuln := detectLaravelCsrfExcept("laravel/vuln_csrf/VerifyCsrfToken.php", readFixture(t, "laravel/vuln_csrf/VerifyCsrfToken.php"))
	if len(vuln) != 1 || vuln[0].RuleID != "ZS-CFG-010" {
		t.Fatalf("expected 1 ZS-CFG-010 finding, got %+v", vuln)
	}

	clean := detectLaravelCsrfExcept("laravel/clean_csrf/VerifyCsrfToken.php", readFixture(t, "laravel/clean_csrf/VerifyCsrfToken.php"))
	if len(clean) != 0 {
		t.Errorf("expected no finding when $except is empty, got %+v", clean)
	}
}

func TestPhpIniCookieInsecureCheck(t *testing.T) {
	vuln := detectPhpIniCookieInsecure("php/vuln_ini/php.ini", readFixture(t, "php/vuln_ini/php.ini"))
	if len(vuln) != 2 || vuln[0].RuleID != "ZS-CFG-011" {
		t.Fatalf("expected 2 ZS-CFG-011 findings (httponly + secure), got %+v", vuln)
	}

	clean := detectPhpIniCookieInsecure("php/clean_ini/php.ini", readFixture(t, "php/clean_ini/php.ini"))
	if len(clean) != 0 {
		t.Errorf("expected no finding when both cookie flags are enabled, got %+v", clean)
	}
}

func TestCorsWildcardSourceCallCheck(t *testing.T) {
	for _, lang := range []string{"go", "java", "cs", "php"} {
		path := "cors/vuln_wildcard." + lang
		vuln := detectCorsWildcardSourceCall(path, readFixture(t, path))
		if len(vuln) != 1 || vuln[0].RuleID != "ZS-CFG-003" {
			t.Errorf("%s: expected 1 ZS-CFG-003 finding, got %+v", lang, vuln)
		}
	}

	clean := detectCorsWildcardSourceCall("cors/clean_restricted.go", readFixture(t, "cors/clean_restricted.go"))
	if len(clean) != 0 {
		t.Errorf("expected no finding for a restricted origin, got %+v", clean)
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
	if sc.Accepts(walker.FileEntry{Path: "app/README.md"}) {
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
