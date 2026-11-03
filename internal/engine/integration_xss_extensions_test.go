//go:build cgo

package engine_test

import "testing"

// xssExtCase is one fire / no-fire expectation. jsID and tsID are the mirrored
// JavaScript and TypeScript rule IDs; the same source is run through both.
type xssExtCase struct {
	name string
	jsID string
	tsID string
	src  string
	want bool
}

func runXSSExtCases(t *testing.T, cases []xssExtCase) {
	t.Helper()
	jsIdx := loadJSRules(t)
	tsIdx := loadTSRules(t)
	for _, tc := range cases {
		t.Run("js/"+tc.name, func(t *testing.T) {
			if got := hasRule(matchJSSource(t, jsIdx, tc.src), tc.jsID); got != tc.want {
				t.Errorf("%s fired = %v, want %v\nsource: %s", tc.jsID, got, tc.want, tc.src)
			}
		})
		t.Run("ts/"+tc.name, func(t *testing.T) {
			if got := hasRule(matchTSSource(t, tsIdx, tc.src), tc.tsID); got != tc.want {
				t.Errorf("%s fired = %v, want %v\nsource: %s", tc.tsID, got, tc.want, tc.src)
			}
		})
	}
}

// C1: insertAdjacentHTML matches on any receiver, not only one named `el`.
func TestIntegration_XSSExt_C1_InsertAdjacentHTMLAnyReceiver(t *testing.T) {
	runXSSExtCases(t, []xssExtCase{
		{"fires_on_arbitrary_receiver", "ZS-JS-047", "ZS-TS-045",
			"const h = location.hash;\ncard.insertAdjacentHTML('beforeend', h);\n", true},
		{"fires_on_el_receiver", "ZS-JS-047", "ZS-TS-045",
			"const h = location.hash;\nel.insertAdjacentHTML('beforeend', h);\n", true},
		{"silent_on_constant_markup", "ZS-JS-047", "ZS-TS-045",
			"card.insertAdjacentHTML('beforeend', '<b>static</b>');\n", false},
		{"silent_when_only_position_tainted", "ZS-JS-047", "ZS-TS-045",
			"const p = location.hash;\ncard.insertAdjacentHTML(p, '<b>static</b>');\n", false},
	})
}

// C2: postMessage with a wildcard targetOrigin, on any receiver, argument 1 only.
func TestIntegration_XSSExt_C2_PostMessageWildcardOrigin(t *testing.T) {
	runXSSExtCases(t, []xssExtCase{
		{"fires_on_chained_receiver", "ZS-JS-055", "ZS-TS-053",
			"frame.contentWindow.postMessage(token, '*');\n", true},
		{"fires_on_bare_call", "ZS-JS-055", "ZS-TS-053",
			"postMessage(token, '*');\n", true},
		{"silent_on_explicit_origin", "ZS-JS-055", "ZS-TS-053",
			"frame.contentWindow.postMessage(token, 'https://app.example.com');\n", false},
		{"silent_on_worker_transfer_list", "ZS-JS-055", "ZS-TS-053",
			"worker.postMessage(msg, [buf]);\n", false},
		{"silent_when_star_is_message_not_origin", "ZS-JS-055", "ZS-TS-053",
			"win.postMessage('*', 'https://app.example.com');\n", false},
	})
}

// C3: bare / window. / document. location assignment, not only location.href.
func TestIntegration_XSSExt_C3_LocationAssignment(t *testing.T) {
	runXSSExtCases(t, []xssExtCase{
		{"fires_on_bare_location", "ZS-JS-046", "ZS-TS-044",
			"location = location.hash.slice(1);\n", true},
		{"fires_on_window_location", "ZS-JS-046", "ZS-TS-044",
			"window.location = location.hash.slice(1);\n", true},
		{"fires_on_document_location", "ZS-JS-046", "ZS-TS-044",
			"document.location = location.hash.slice(1);\n", true},
		{"fires_on_location_href", "ZS-JS-046", "ZS-TS-044",
			"location.href = location.hash.slice(1);\n", true},
		{"silent_on_constant_window_location", "ZS-JS-046", "ZS-TS-044",
			"window.location = '/home';\n", false},
		{"silent_on_unrelated_lhs", "ZS-JS-046", "ZS-TS-044",
			"const relocation = location.hash;\nmyrelocation = relocation;\n", false},
	})
}

// C4: an inline sanitizer wrapping the entire right-hand side suppresses the
// assignment sinks; a sanitizer on only part of the expression does not.
func TestIntegration_XSSExt_C4_InlineSanitizerOnAssignmentSinks(t *testing.T) {
	var cases []xssExtCase
	sinks := []struct{ name, lhs, js, ts string }{
		{"innerHTML", "el.innerHTML", "ZS-JS-002", "ZS-TS-002"},
		{"outerHTML", "el.outerHTML", "ZS-JS-005", "ZS-TS-011"},
		{"srcdoc", "frame.srcdoc", "ZS-JS-053", "ZS-TS-051"},
	}
	for _, s := range sinks {
		cases = append(cases,
			xssExtCase{s.name + "_fires_unsanitized", s.js, s.ts,
				s.lhs + " = location.hash.slice(1);\n", true},
			xssExtCase{s.name + "_fires_when_sanitizer_wraps_only_part", s.js, s.ts,
				"const a = '<b>x</b>';\n" + s.lhs + " = DOMPurify.sanitize(a) + location.hash;\n", true},
			xssExtCase{s.name + "_silent_when_domPurify_wraps_whole_rhs", s.js, s.ts,
				s.lhs + " = DOMPurify.sanitize(location.hash.slice(1));\n", false},
			xssExtCase{s.name + "_silent_when_sanitizeHtml_wraps_whole_rhs", s.js, s.ts,
				s.lhs + " = sanitizeHtml(location.hash.slice(1));\n", false},
			xssExtCase{s.name + "_silent_when_filterXSS_wraps_whole_rhs", s.js, s.ts,
				s.lhs + " = filterXSS(location.hash.slice(1));\n", false},
		)
	}
	runXSSExtCases(t, cases)
}

// C5: location.assign / location.replace match on a window. receiver too.
func TestIntegration_XSSExt_C5_LocationAssignReplaceReceiver(t *testing.T) {
	runXSSExtCases(t, []xssExtCase{
		{"assign_fires_on_window_receiver", "ZS-JS-050", "ZS-TS-048",
			"window.location.assign(location.hash.slice(1));\n", true},
		{"assign_fires_on_bare_location", "ZS-JS-050", "ZS-TS-048",
			"location.assign(location.hash.slice(1));\n", true},
		{"assign_silent_on_constant", "ZS-JS-050", "ZS-TS-048",
			"window.location.assign('/home');\n", false},
		{"replace_fires_on_window_receiver", "ZS-JS-051", "ZS-TS-049",
			"window.location.replace(location.hash.slice(1));\n", true},
		{"replace_fires_on_bare_location", "ZS-JS-051", "ZS-TS-049",
			"location.replace(location.hash.slice(1));\n", true},
		{"replace_silent_on_constant", "ZS-JS-051", "ZS-TS-049",
			"window.location.replace('/home');\n", false},
	})
}
