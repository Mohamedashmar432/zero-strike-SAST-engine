package plugin

// Plugin is the extension point for custom rules, languages, and reporters.
// This interface is defined now for future use; no plugins are loaded in v1.
type Plugin interface {
	Name() string
	Version() string
}

// Loader discovers and loads Plugin implementations.
// Sprint future: implement dynamic loading from a plugins/ directory.
type Loader interface {
	Load(dir string) ([]Plugin, error)
}
