package core

import (
	"errors"
	"testing"
)

// --- Language tests ---

func TestLanguage_IsKnown(t *testing.T) {
	tests := []struct {
		name string
		lang Language
		want bool
	}{
		{"python is known", LangPython, true},
		{"javascript is known", LangJavaScript, true},
		{"typescript is known", LangTypeScript, true},
		{"csharp is known", LangCSharp, true},
		{"unknown is not known", LangUnknown, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.lang.IsKnown(); got != tc.want {
				t.Errorf("Language(%q).IsKnown() = %v, want %v", tc.lang, got, tc.want)
			}
		})
	}
}

func TestLanguage_String(t *testing.T) {
	if got := LangPython.String(); got != "python" {
		t.Errorf("LangPython.String() = %q, want %q", got, "python")
	}
}

// --- Location tests ---

func TestLocation_String(t *testing.T) {
	loc := Location{File: "file.py", StartLine: 10, StartCol: 5}
	want := "file.py:10:5"
	if got := loc.String(); got != want {
		t.Errorf("Location.String() = %q, want %q", got, want)
	}
}

func TestLocation_IsZero(t *testing.T) {
	tests := []struct {
		name string
		loc  Location
		want bool
	}{
		{"zero value", Location{}, true},
		{"non-zero file", Location{File: "a.py"}, false},
		{"non-zero startline", Location{StartLine: 1}, false},
		{"fully populated", Location{File: "a.py", StartLine: 1, StartCol: 0}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.loc.IsZero(); got != tc.want {
				t.Errorf("Location.IsZero() = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- ZeroStrikeError tests ---

func TestZeroStrikeError_Error_WithoutCause(t *testing.T) {
	err := NewError(ErrKindParse, "syntax error", nil)
	want := "zerostrike[parse]: syntax error"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestZeroStrikeError_Error_WithCause(t *testing.T) {
	cause := errors.New("unexpected EOF")
	err := NewError(ErrKindIO, "read failed", cause)
	want := "zerostrike[io]: read failed: unexpected EOF"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestZeroStrikeError_Unwrap(t *testing.T) {
	cause := errors.New("root cause")
	err := NewError(ErrKindInternal, "something broke", cause)
	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestZeroStrikeError_Unwrap_NilCause(t *testing.T) {
	err := NewError(ErrKindConfig, "bad config", nil)
	if unwrapped := err.Unwrap(); unwrapped != nil {
		t.Errorf("Unwrap() = %v, want nil", unwrapped)
	}
}

func TestSeverity_Values(t *testing.T) {
	cases := []struct {
		severity Severity
		want     string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
		{SeverityInfo, "info"},
	}
	for _, tc := range cases {
		if string(tc.severity) != tc.want {
			t.Errorf("Severity %q: got %q, want %q", tc.severity, string(tc.severity), tc.want)
		}
	}
}

func TestConfidence_Values(t *testing.T) {
	cases := []struct {
		conf Confidence
		want string
	}{
		{ConfidenceHigh, "high"},
		{ConfidenceMedium, "medium"},
		{ConfidenceLow, "low"},
	}
	for _, tc := range cases {
		if string(tc.conf) != tc.want {
			t.Errorf("Confidence %q: got %q, want %q", tc.conf, string(tc.conf), tc.want)
		}
	}
}

func TestEvidence_Fields(t *testing.T) {
	ev := Evidence{
		Snippet:   "eval(user_input)",
		StartLine: 10,
		EndLine:   10,
	}
	if ev.Snippet != "eval(user_input)" {
		t.Errorf("Snippet: got %q", ev.Snippet)
	}
	if ev.StartLine != 10 || ev.EndLine != 10 {
		t.Errorf("Lines: got %d-%d", ev.StartLine, ev.EndLine)
	}
}

func TestFinding_Construction(t *testing.T) {
	f := Finding{
		ID:         "FIND-001",
		RuleID:     "ZS-PY-001",
		RuleName:   "Dangerous eval() Usage",
		Category:   "dangerous-functions",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Message:    "Dangerous call to eval()",
		Location:   Location{File: "app.py", StartLine: 42, EndLine: 42},
		Language:   LangPython,
		Evidence: []Evidence{
			{Snippet: "eval(x)", StartLine: 42, EndLine: 42},
		},
		CWE:        []string{"CWE-95"},
		OWASP:      []string{"A03:2021"},
		References: []string{"https://owasp.org"},
		Metadata:   map[string]string{"file_hash": "abc123"},
	}

	if f.RuleID != "ZS-PY-001" {
		t.Errorf("RuleID: got %q", f.RuleID)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("Severity: got %q", f.Severity)
	}
	if f.Confidence != ConfidenceHigh {
		t.Errorf("Confidence: got %q", f.Confidence)
	}
	if len(f.Evidence) != 1 {
		t.Errorf("Evidence count: got %d", len(f.Evidence))
	}
	if len(f.CWE) != 1 || f.CWE[0] != "CWE-95" {
		t.Errorf("CWE: got %v", f.CWE)
	}
}
