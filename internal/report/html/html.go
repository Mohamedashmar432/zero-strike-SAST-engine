package html

import (
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/report"
)

type htmlReporter struct{}

// New returns a Reporter that writes a self-contained HTML page.
func New() report.Reporter { return &htmlReporter{} }

func (r *htmlReporter) Format() string { return "html" }

func (r *htmlReporter) Render(rep *report.Report, dest io.Writer) error {
	return tmpl.Execute(dest, buildTemplateData(rep))
}

type templateData struct {
	Report *report.Report
	Groups []severityGroup
}

type severityGroup struct {
	Label    string
	Class    string
	Findings []core.Finding
}

func buildTemplateData(rep *report.Report) templateData {
	by := make(map[core.Severity][]core.Finding)
	for _, f := range rep.Findings {
		by[f.Severity] = append(by[f.Severity], f)
	}
	var groups []severityGroup
	for _, sev := range report.SeverityOrder {
		if fs := by[sev]; len(fs) > 0 {
			s := string(sev)
			groups = append(groups, severityGroup{
				Label:    strings.ToUpper(s[:1]) + s[1:],
				Class:    s,
				Findings: fs,
			})
		}
	}
	return templateData{Report: rep, Groups: groups}
}

var tmpl = template.Must(
	template.New("report").
		Funcs(template.FuncMap{
			"fmtTime":     func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") },
			"fmtDuration": func(d time.Duration) string { return d.Round(time.Millisecond).String() },
		}).
		Parse(htmlTmpl),
)

const htmlTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ZeroStrike Scan Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f8f9fa;color:#212529;padding:2rem}
h1{font-size:1.5rem;margin-bottom:1.5rem}
h2{font-size:1.1rem;margin:1.5rem 0 .75rem}
.meta{background:#fff;border:1px solid #dee2e6;border-radius:6px;padding:1rem 1.25rem;margin-bottom:1.5rem;display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:.5rem}
.meta dt{font-size:.75rem;color:#6c757d;text-transform:uppercase;letter-spacing:.04em}
.meta dd{font-size:.875rem;font-weight:500}
.stats{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1.5rem}
.stat-card{background:#fff;border:1px solid #dee2e6;border-radius:6px;padding:.75rem 1rem;min-width:120px}
.stat-card .n{font-size:1.5rem;font-weight:700}
.stat-card .l{font-size:.75rem;color:#6c757d}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #dee2e6;border-radius:6px;overflow:hidden;margin-bottom:1.5rem}
thead{background:#f1f3f5}
th{padding:.6rem .75rem;text-align:left;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;color:#495057}
td{padding:.6rem .75rem;font-size:.875rem;border-top:1px solid #dee2e6;vertical-align:top}
.badge{display:inline-block;padding:.2em .5em;border-radius:4px;font-size:.75rem;font-weight:600;text-transform:uppercase}
.critical .badge{background:#ffe0e0;color:#c0392b}
.high .badge{background:#fff3cd;color:#e65100}
.medium .badge{background:#fffde7;color:#795548}
.low .badge{background:#e3f2fd;color:#1565c0}
.info .badge{background:#f0f0f0;color:#555}
.loc{font-family:monospace;font-size:.8rem;color:#6c757d}
.empty{color:#6c757d;font-style:italic;padding:2rem;text-align:center}
</style>
</head>
<body>
<h1>ZeroStrike Scan Report</h1>
<dl class="meta">
  <div><dt>Scan ID</dt><dd>{{.Report.ScanID}}</dd></div>
  <div><dt>Version</dt><dd>{{.Report.ScannerVersion}}</dd></div>
  <div><dt>Root</dt><dd>{{.Report.RootPath}}</dd></div>
  <div><dt>Started</dt><dd>{{fmtTime .Report.StartedAt}}</dd></div>
  <div><dt>Duration</dt><dd>{{fmtDuration .Report.Duration}}</dd></div>{{if .Report.Branch}}
  <div><dt>Branch</dt><dd>{{.Report.Branch}}</dd></div>{{end}}{{if .Report.GitCommit}}
  <div><dt>Commit</dt><dd>{{.Report.GitCommit}}</dd></div>{{end}}
</dl>
<div class="stats">
  <div class="stat-card"><div class="n">{{.Report.Stats.FilesScanned}}</div><div class="l">Files Scanned</div></div>
  <div class="stat-card"><div class="n">{{.Report.Stats.TotalFindings}}</div><div class="l">Total Findings</div></div>
  <div class="stat-card"><div class="n">{{.Report.Stats.Suppressed}}</div><div class="l">Suppressed</div></div>
</div>
{{if .Groups}}{{range .Groups}}
<h2>{{.Label}} ({{len .Findings}})</h2>
<table class="{{.Class}}">
  <thead><tr><th>Rule ID</th><th>Severity</th><th>Message</th><th>Location</th></tr></thead>
  <tbody>{{range .Findings}}
  <tr>
    <td>{{.RuleID}}</td>
    <td><span class="badge">{{.Severity}}</span></td>
    <td>{{.Message}}</td>
    <td class="loc">{{.Location.File}}:{{.Location.StartLine}}</td>
  </tr>{{end}}
  </tbody>
</table>
{{end}}{{else}}
<p class="empty">No findings &#8212; clean scan.</p>
{{end}}
</body>
</html>`
