package core

// Language identifies the programming language of a source file.
type Language string

const (
	LangPython     Language = "python"
	LangJavaScript Language = "javascript"
	LangTypeScript Language = "typescript"
	LangCSharp     Language = "csharp"
	LangGo         Language = "go"
	LangPHP        Language = "php"
	LangUnknown    Language = "unknown"
)

// IsKnown reports whether the language was successfully identified.
func (l Language) IsKnown() bool {
	return l != LangUnknown
}

// String returns the string representation of the language.
func (l Language) String() string {
	return string(l)
}
