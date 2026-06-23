package rules

import "embed"

//go:embed data/python/*.yaml data/js/*.yaml
var EmbeddedFS embed.FS
