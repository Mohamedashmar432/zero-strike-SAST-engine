package rules

import "embed"

//go:embed data/python/*.yaml data/js/*.yaml data/ts/*.yaml
var EmbeddedFS embed.FS
