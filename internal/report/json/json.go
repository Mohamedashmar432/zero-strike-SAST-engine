package jsonreport

import (
	"encoding/json"
	"io"

	"github.com/zerostrike/scanner/internal/report"
)

type jsonReporter struct{}

// New returns a Reporter that writes indented JSON.
func New() report.Reporter { return &jsonReporter{} }

func (r *jsonReporter) Format() string { return "json" }

func (r *jsonReporter) Render(rep *report.Report, dest io.Writer) error {
	enc := json.NewEncoder(dest)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
