package suppress

import "testing"

func TestSuppressed(t *testing.T) {
	tests := []struct {
		name      string
		source    string
		startLine int
		endLine   int
		ruleID    string
		want      bool
	}{
		{
			name:      "bare noqa on the flagged line",
			source:    "x = 1\ny = eval(z)  # noqa\n",
			startLine: 2, endLine: 2, ruleID: "ZS-PY-001",
			want: true,
		},
		{
			name:      "bare nosec on the line above",
			source:    "# nosec\ny = eval(z)\n",
			startLine: 2, endLine: 2, ruleID: "ZS-PY-001",
			want: true,
		},
		{
			name:      "matching rule id",
			source:    "y = eval(z)  # zs-ignore: ZS-PY-001\n",
			startLine: 1, endLine: 1, ruleID: "ZS-PY-001",
			want: true,
		},
		{
			name:      "matching rule id among several",
			source:    "y = eval(z)  # zs-ignore: ZS-PY-004, ZS-PY-001\n",
			startLine: 1, endLine: 1, ruleID: "ZS-PY-001",
			want: true,
		},
		{
			name:      "non-matching rule id does not suppress",
			source:    "y = eval(z)  # zs-ignore: ZS-PY-999\n",
			startLine: 1, endLine: 1, ruleID: "ZS-PY-001",
			want: false,
		},
		{
			// The case that decides whether the three genuine empty-handler
			// findings in the triaged report survive. A ruff code must not
			// read as blanket permission for a security finding.
			name:      "foreign tool code does not suppress",
			source:    "except Exception:  # noqa: BLE001 -- a missing asset must not fail\n\tpass\n",
			startLine: 1, endLine: 1, ruleID: "ZS-PY-024",
			want: false,
		},
		{
			name:      "nosemgrep with a semgrep rule id does not suppress a ZS rule",
			source:    "const re = new RegExp(p); // nosemgrep: javascript.lang.security.detect-non-literal-regexp\n",
			startLine: 1, endLine: 1, ruleID: "ZS-TS-031",
			want: false,
		},
		{
			// A try-node finding anchors at `try:`, but the annotation belongs
			// on the except clause, three lines down.
			name:      "annotation inside the finding span",
			source:    "def f():\n\ttry:\n\t\treturn g()\n\texcept KeyError:  # zs-ignore: ZS-PY-024\n\t\tpass\n",
			startLine: 2, endLine: 5, ruleID: "ZS-PY-024",
			want: true,
		},
		{
			name:      "annotation outside the span is ignored",
			source:    "# zs-ignore: ZS-PY-024\nx = 1\ny = 2\nz = eval(q)\n",
			startLine: 4, endLine: 4, ruleID: "ZS-PY-024",
			want: false,
		},
		{
			// A marker inside a string literal must not suppress: there is no
			// comment starter before it on the line.
			name:      "marker inside a string literal",
			source:    "msg = \"add a noqa here\"\n",
			startLine: 1, endLine: 1, ruleID: "ZS-PY-001",
			want: false,
		},
		{
			name:      "crlf source",
			source:    "x = 1\r\ny = eval(z)  # noqa\r\n",
			startLine: 2, endLine: 2, ruleID: "ZS-PY-001",
			want: true,
		},
		{
			name:      "line zero is not a panic",
			source:    "x = 1\n",
			startLine: 0, endLine: 0, ruleID: "ZS-PY-001",
			want: false,
		},
		{
			name:      "line past end of file is not a panic",
			source:    "x = 1\n",
			startLine: 99, endLine: 99, ruleID: "ZS-PY-001",
			want: false,
		},
		{
			name:      "endLine before startLine is treated as single line",
			source:    "y = eval(z)  # noqa\n",
			startLine: 1, endLine: 0, ruleID: "ZS-PY-001",
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Suppressed([]byte(tc.source), tc.startLine, tc.endLine, tc.ruleID)
			if got != tc.want {
				t.Errorf("Suppressed(%q, %d, %d, %q) = %v, want %v",
					tc.source, tc.startLine, tc.endLine, tc.ruleID, got, tc.want)
			}
		})
	}
}
