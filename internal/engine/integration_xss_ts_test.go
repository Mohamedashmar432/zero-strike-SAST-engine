//go:build cgo

package engine_test

import (
	"os"
	"path/filepath"
	"testing"
)

// xssTSCases pairs each Batch C TypeScript XSS rule with its corpus fixture
// stem (benchmark/corpus/ts/cases/{vuln,clean}_xss_<stem>.ts). The same files
// feed the benchmark gate, so the fire and no-fire tests cannot drift from it.
var xssTSCases = []struct {
	rule string
	stem string
}{
	{"ZS-TS-152", "unsafe_parse"},
	{"ZS-TS-153", "jquery_html"},
	{"ZS-TS-154", "setattr_handler"},
	{"ZS-TS-155", "url_attr"},
	{"ZS-TS-156", "href_prop"},
	{"ZS-TS-157", "message_origin"},
	{"ZS-TS-158", "host_check"},
	{"ZS-TS-159", "dangerously"},
	{"ZS-TS-160", "lit_unsafe"},
	{"ZS-TS-161", "sce_trust"},
	{"ZS-TS-162", "safestring"},
	{"ZS-TS-163", "script_json"},
}

func readXSSTSFixture(t *testing.T, prefix, stem string) string {
	t.Helper()
	p := filepath.Join("..", "..", "benchmark", "corpus", "ts", "cases", prefix+"_xss_"+stem+".ts")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(b)
}

func TestIntegration_XSSTSRulesFire(t *testing.T) {
	idx := loadTSRules(t)
	for _, c := range xssTSCases {
		t.Run(c.rule, func(t *testing.T) {
			src := readXSSTSFixture(t, "vuln", c.stem)
			if !hasRule(matchTSSource(t, idx, src), c.rule) {
				t.Errorf("%s: expected to fire on vuln_xss_%s.ts", c.rule, c.stem)
			}
		})
	}
}

func TestIntegration_XSSTSRulesStaySilent(t *testing.T) {
	idx := loadTSRules(t)
	for _, c := range xssTSCases {
		t.Run(c.rule, func(t *testing.T) {
			src := readXSSTSFixture(t, "clean", c.stem)
			if hasRule(matchTSSource(t, idx, src), c.rule) {
				t.Errorf("%s: expected NOT to fire on clean_xss_%s.ts", c.rule, c.stem)
			}
		})
	}
}

// Inline pins for the filters most likely to regress.
func TestIntegration_XSSTSInlinePins(t *testing.T) {
	idx := loadTSRules(t)
	fire := []struct{ rule, src string }{
		{"ZS-TS-154", "const c = location.hash.slice(1); btn.setAttribute('onclick', c);"},
		{"ZS-TS-157", "window.addEventListener('message', (e) => { out.innerHTML = e.data; });"},
	}
	for _, c := range fire {
		if !hasRule(matchTSSource(t, idx, c.src), c.rule) {
			t.Errorf("%s: expected to fire on %q", c.rule, c.src)
		}
	}
	silent := []struct{ rule, src string }{
		{"ZS-TS-157", "window.addEventListener('message', (e) => { if (e.origin !== 'https://a.example') return; out.textContent = e.data; });"},
		{"ZS-TS-157", "ws.addEventListener('message', h);"},
	}
	for _, c := range silent {
		if hasRule(matchTSSource(t, idx, c.src), c.rule) {
			t.Errorf("%s: expected NOT to fire on %q", c.rule, c.src)
		}
	}
}
