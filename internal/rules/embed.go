package rules

import "embed"

//go:embed data/python/*.yaml
var EmbeddedFS embed.FS
