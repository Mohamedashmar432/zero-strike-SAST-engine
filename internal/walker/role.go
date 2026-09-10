package walker

import (
	"path/filepath"
	"strings"
)

// FileRole describes what a file is for, which decides whether production-code
// security semantics apply to it.
//
// The distinction matters because most rules encode an assumption that the code
// they match is deployed and reachable by an attacker. In a test path that
// assumption is false, and the same pattern is usually the point rather than a
// defect: `assert response.status_code == 200` is how pytest works, a fixture
// password is scoped to a throwaway database, and a canary credential exists so
// a redaction test can look for it. Applying production semantics there is how a
// scan of one small repository produced 1324 findings of which 3 were real.
type FileRole string

const (
	// RoleProduction is the default — code that ships.
	RoleProduction FileRole = "production"

	// RoleTest covers tests, fixtures, mocks and test data.
	RoleTest FileRole = "test"
)

// testDirSegments are path components that mark every file beneath them as test
// or fixture material. Matched as whole components, so "pentest" or "latest"
// never match "test".
//
// "testdata" is included deliberately, even though this repository's own Go
// benchmark corpus lives there: real repositories keep fixtures in testdata/ and
// users need it suppressed. The corpus opts back in per-manifest instead — see
// benchmark.Manifest.IncludeTests.
var testDirSegments = []string{
	"tests", "test", "__tests__", "testdata",
	"spec", "specs",
	"fixtures", "mocks", "__mocks__",
}

// testFileGlobs are base-name patterns that mark a single file as a test,
// covering the naming conventions of the languages the engine parses.
var testFileGlobs = []string{
	// Python — pytest discovery patterns, plus its fixture module.
	"conftest.py", "test_*.py", "*_test.py",
	// Go.
	"*_test.go",
	// JS/TS — both the .test. and .spec. conventions, all four extensions.
	"*.test.js", "*.test.jsx", "*.test.ts", "*.test.tsx",
	"*.spec.js", "*.spec.jsx", "*.spec.ts", "*.spec.tsx",
	// Java / C# — the xUnit-style suffixes.
	"*Test.java", "*Tests.java",
	"*Test.cs", "*Tests.cs",
	// PHP — PHPUnit.
	"*Test.php",
}

// ClassifyRole reports whether relPath — a path relative to the scan root — is
// test or fixture material. Callers pass a relative path so that scanning a
// checkout that happens to live under a directory called "test" does not
// classify the entire project as test code.
func ClassifyRole(relPath string) FileRole {
	// Normalise both separators explicitly rather than with filepath.ToSlash.
	// ToSlash replaces os.PathSeparator, which on Linux is already "/" -- so a
	// Windows-shaped path arrives with its backslashes intact and every segment
	// collapses into one, classifying the whole path as production. That is a
	// real bug, not just a test artifact: paths reach this function from
	// filepath.Rel on the scanning host, and the same input must classify
	// identically wherever it is evaluated.
	rel := strings.ReplaceAll(relPath, "\\", "/")

	parts := strings.Split(rel, "/")

	// Directory segments win over file names: a production-looking file name
	// inside tests/ is still test material.
	for _, part := range parts[:max(len(parts)-1, 0)] {
		lower := strings.ToLower(part)
		for _, seg := range testDirSegments {
			if lower == seg {
				return RoleTest
			}
		}
	}

	// Last segment rather than filepath.Base, for the same reason: Base is
	// separator-aware and rel is already normalised, so this is both correct
	// and platform-independent. It also guarantees the name handed to
	// filepath.Match contains no backslash, which Match treats as an escape
	// character on Linux but as a separator on Windows.
	base := parts[len(parts)-1]
	for _, glob := range testFileGlobs {
		// filepath.Match only errors on a malformed pattern, and every pattern
		// here is a literal above -- a bad one is a compile-time-visible typo,
		// not a runtime condition worth reporting.
		if ok, _ := filepath.Match(glob, base); ok {
			return RoleTest
		}
	}
	return RoleProduction
}
