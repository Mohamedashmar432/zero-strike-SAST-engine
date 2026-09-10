package walker

import "testing"

func TestClassifyRole(t *testing.T) {
	tests := []struct {
		name string
		path string
		want FileRole
	}{
		// Directory segments.
		{"tests dir", "backend/tests/test_api.py", RoleTest},
		{"test dir singular", "src/test/helpers.py", RoleTest},
		{"jest dir", "web/__tests__/button.tsx", RoleTest},
		{"testdata dir", "benchmark/corpus/go/testdata/vuln_cmdi.go", RoleTest},
		{"fixtures dir", "app/fixtures/users.json", RoleTest},
		{"mocks dir", "app/__mocks__/api.ts", RoleTest},
		{"spec dir", "lib/spec/parser.rb", RoleTest},
		{"nested under tests", "a/tests/deep/nested/prod_looking.py", RoleTest},

		// File names.
		{"conftest", "backend/conftest.py", RoleTest},
		{"pytest prefix", "backend/test_api.py", RoleTest},
		{"pytest suffix", "backend/api_test.py", RoleTest},
		{"go test", "internal/walker/role_test.go", RoleTest},
		{"ts spec", "frontend/lib/api.spec.ts", RoleTest},
		{"tsx test", "frontend/app/page.test.tsx", RoleTest},
		{"java test", "src/main/java/FooTest.java", RoleTest},
		{"csharp tests", "src/BarTests.cs", RoleTest},

		// Production code that must NOT be misclassified. These are the
		// regressions that would silently stop a real scan from reporting.
		{"plain module", "backend/app/services/visits.py", RoleProduction},
		// not_a_test.py is genuinely test material: pytest's default
		// python_files patterns are test_*.py AND *_test.py, so pytest
		// collects it. Classifying it as production would mean scanning a
		// file the test runner owns.
		{"not_a_test matches pytest suffix", "backend/app/not_a_test.py", RoleTest},
		{"substring pentest", "backend/pentest/report.py", RoleProduction},
		{"substring latest", "app/latest/handler.go", RoleProduction},
		{"contest dir", "app/contest/rules.py", RoleProduction},
		{"testify import path", "app/testing_utils.py", RoleProduction},
		{"protest file", "app/protest.ts", RoleProduction},
		{"bare filename", "main.go", RoleProduction},
		{"attestation", "app/attestation/verify.go", RoleProduction},

		// A trailing path component that matches a dir name is still the file
		// name, so it goes through the glob list, not the segment list.
		{"file literally named test", "app/test", RoleProduction},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyRole(tc.path); got != tc.want {
				t.Errorf("ClassifyRole(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestClassifyRole_WindowsSeparators guards the platform this engine is
// developed on: the walker hands over a filepath.Rel result, which uses
// backslashes on Windows, and a classifier that only split on "/" would
// classify every Windows path as production.
func TestClassifyRole_WindowsSeparators(t *testing.T) {
	if got := ClassifyRole(`backend\tests\test_api.py`); got != RoleTest {
		t.Errorf("backslash path classified %q, want %q", got, RoleTest)
	}
}
