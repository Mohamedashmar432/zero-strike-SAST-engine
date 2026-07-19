//go:build cgo

package sast

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/cache"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"
)

func loadAllEmbeddedRules(t *testing.T) []*rules.Rule {
	t.Helper()
	loader := rules.NewLoader(rules.EmbeddedFS)
	var all []*rules.Rule
	for _, dir := range rules.RuleDirs {
		rs, err := loader.LoadDir(dir)
		if err != nil {
			t.Fatalf("load %s: %v", dir, err)
		}
		all = append(all, rs...)
	}
	return all
}

// TestEmbeddedScript_FiresJSRuleWithRebasedLine drives the real SAST scanner
// over an .html file containing both a markup vulnerability and an inline
// <script> with a tainted eval, and asserts:
//   - the markup rule (ZS-HTML-002) fires, and
//   - the JavaScript rule (ZS-JS-001) fires on the embedded code, with its
//     reported line rebased to the eval()'s actual line in the .html file.
func TestEmbeddedScript_FiresJSRuleWithRebasedLine(t *testing.T) {
	// Lines (1-indexed):
	// 1 <!DOCTYPE html>
	// 2 <html>
	// 3 <body>
	// 4 <a href="javascript:x()">l</a>
	// 5 <script>
	// 6 var d = location.hash;
	// 7 eval(d);
	// 8 </script>
	// 9 </body>
	// 10 </html>
	src := "<!DOCTYPE html>\n<html>\n<body>\n" +
		"<a href=\"javascript:x()\">l</a>\n" +
		"<script>\nvar d = location.hash;\neval(d);\n</script>\n" +
		"</body>\n</html>\n"

	dir := t.TempDir()
	path := filepath.Join(dir, "page.html")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	sc := New(loadAllEmbeddedRules(t), dir, cache.NoopCache{}, cache.NoopASTCache{}, false)
	found, _, err := sc.Scan(context.Background(), []walker.FileEntry{{Path: path, Language: core.LangHTML}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	var sawHTML, sawJS bool
	var jsLine int
	for _, f := range found {
		switch f.RuleID {
		case "ZS-HTML-002":
			sawHTML = true
		case "ZS-JS-001":
			sawJS = true
			jsLine = f.Location.StartLine
		}
	}
	if !sawHTML {
		t.Error("expected markup rule ZS-HTML-002 to fire on the javascript: link")
	}
	if !sawJS {
		t.Fatal("expected embedded-JS rule ZS-JS-001 to fire on the inline tainted eval()")
	}
	if jsLine != 7 {
		t.Errorf("ZS-JS-001 line = %d, want 7 (eval() rebased into the .html file)", jsLine)
	}
}
