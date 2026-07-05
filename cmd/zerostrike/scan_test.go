// SPDX-License-Identifier: Apache-2.0
package main

import (
	"reflect"
	"testing"

	"github.com/zerostrike/scanner/internal/core"
)

// TestParseLanguages_AllRegisteredLanguages is a regression test for a
// Sprint 14 QA finding: --lang go/--lang php were silently dropped because
// scan.go's language switch had no case for them (they were wired into
// main.go/langreg but not the CLI), so the scan silently fell back to
// auto-detect instead of restricting to the requested language.
func TestParseLanguages_AllRegisteredLanguages(t *testing.T) {
	cases := []struct {
		flag string
		want core.Language
	}{
		{"python", core.LangPython},
		{"javascript", core.LangJavaScript},
		{"js", core.LangJavaScript},
		{"typescript", core.LangTypeScript},
		{"ts", core.LangTypeScript},
		{"csharp", core.LangCSharp},
		{"cs", core.LangCSharp},
		{"go", core.LangGo},
		{"php", core.LangPHP},
		{"GO", core.LangGo}, // case-insensitive
	}
	for _, c := range cases {
		got := parseLanguages([]string{c.flag})
		if !reflect.DeepEqual(got, []core.Language{c.want}) {
			t.Errorf("parseLanguages(%q) = %v, want [%v]", c.flag, got, c.want)
		}
	}
}

func TestParseLanguages_UnknownFlagDropped(t *testing.T) {
	if got := parseLanguages([]string{"cobol"}); got != nil {
		t.Errorf("expected unrecognized language to be dropped, got %v", got)
	}
}

func TestParseLanguages_Multiple(t *testing.T) {
	got := parseLanguages([]string{"go", "php"})
	want := []core.Language{core.LangGo, core.LangPHP}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseLanguages([go, php]) = %v, want %v", got, want)
	}
}
