package detector

import (
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
)

func TestDetect(t *testing.T) {
	t.Parallel()

	d := NewDetector()

	tests := []struct {
		name    string
		path    string
		content []byte
		want    core.Language
	}{
		// ── Extension map – all entries ──────────────────────────────────────
		{name: ".py → python", path: "script.py", content: nil, want: core.LangPython},
		{name: ".pyw → python", path: "app.pyw", content: nil, want: core.LangPython},
		{name: ".js → javascript", path: "index.js", content: nil, want: core.LangJavaScript},
		{name: ".mjs → javascript", path: "module.mjs", content: nil, want: core.LangJavaScript},
		{name: ".cjs → javascript", path: "common.cjs", content: nil, want: core.LangJavaScript},
		{name: ".jsx → javascript", path: "component.jsx", content: nil, want: core.LangJavaScript},
		{name: ".ts → typescript", path: "types.ts", content: nil, want: core.LangTypeScript},
		{name: ".tsx → typescript", path: "page.tsx", content: nil, want: core.LangTypeScript},
		{name: ".mts → typescript", path: "mod.mts", content: nil, want: core.LangTypeScript},
		{name: ".cts → typescript", path: "compat.cts", content: nil, want: core.LangTypeScript},
		{name: ".cs → csharp", path: "Program.cs", content: nil, want: core.LangCSharp},

		// ── Uppercase extension normalised to lowercase ───────────────────
		{name: ".PY upper → python", path: "SCRIPT.PY", content: nil, want: core.LangPython},
		{name: ".JS upper → javascript", path: "INDEX.JS", content: nil, want: core.LangJavaScript},
		{name: ".TS upper → typescript", path: "TYPES.TS", content: nil, want: core.LangTypeScript},

		// ── No extension, no content ─────────────────────────────────────
		{name: "no ext no content → unknown", path: "Makefile", content: nil, want: core.LangUnknown},
		{name: "empty file → unknown", path: "noext", content: []byte{}, want: core.LangUnknown},

		// ── Shebang detection (no extension) ─────────────────────────────
		{
			name:    "shebang #!/usr/bin/python → python",
			path:    "script",
			content: []byte("#!/usr/bin/python\nprint('hi')\n"),
			want:    core.LangPython,
		},
		{
			name:    "shebang #!/usr/bin/python3 → python",
			path:    "script",
			content: []byte("#!/usr/bin/python3\nprint('hi')\n"),
			want:    core.LangPython,
		},
		{
			name:    "shebang #!/usr/bin/env python → python",
			path:    "script",
			content: []byte("#!/usr/bin/env python\nprint('hi')\n"),
			want:    core.LangPython,
		},
		{
			name:    "shebang #!/usr/bin/env python3 → python",
			path:    "script",
			content: []byte("#!/usr/bin/env python3\nprint('hi')\n"),
			want:    core.LangPython,
		},
		{
			name:    "shebang #!/usr/bin/node → javascript",
			path:    "server",
			content: []byte("#!/usr/bin/node\nconsole.log('hi');\n"),
			want:    core.LangJavaScript,
		},
		{
			name:    "shebang #!/usr/bin/env node → javascript",
			path:    "server",
			content: []byte("#!/usr/bin/env node\nconsole.log('hi');\n"),
			want:    core.LangJavaScript,
		},
		{
			name:    "shebang #!/bin/sh → unknown",
			path:    "run",
			content: []byte("#!/bin/sh\necho hello\n"),
			want:    core.LangUnknown,
		},

		// ── Extension takes priority over shebang ────────────────────────
		{
			name:    "file.py with node shebang → python (ext wins)",
			path:    "tool.py",
			content: []byte("#!/usr/bin/env node\nprint('x')\n"),
			want:    core.LangPython,
		},
		{
			name:    "file.js with python shebang → javascript (ext wins)",
			path:    "tool.js",
			content: []byte("#!/usr/bin/env python3\nconsole.log('x');\n"),
			want:    core.LangJavaScript,
		},

		// ── Shebang with no newline (entire content is shebang) ──────────
		{
			name:    "shebang only no newline → python",
			path:    "script",
			content: []byte("#!/usr/bin/python3"),
			want:    core.LangPython,
		},

		// ── Content that starts with #! but unknown interpreter ──────────
		{
			name:    "unknown shebang → unknown",
			path:    "run",
			content: []byte("#!/usr/bin/perl\nuse strict;\n"),
			want:    core.LangUnknown,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := d.Detect(tc.path, tc.content)
			if got != tc.want {
				t.Errorf("Detect(%q, ...) = %q; want %q", tc.path, got, tc.want)
			}
		})
	}
}
