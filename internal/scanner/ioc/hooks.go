package ioc

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
)

// ZS-IOC-001: install-time hooks. A hook fires only on a shape that fetches or
// runs something from outside the repository, or on a credential harvester; a
// local build step (tsc, node-gyp rebuild, husky install, patch-package) has
// none of these shapes. The matcher is shared by package.json, setup.py and
// composer.json.

var (
	hookDownloader = regexp.MustCompile("(?i)(?:^|[\\s;&|(`\"'])(curl|wget|invoke-webrequest|iwr|invoke-restmethod|irm)(?:\\.exe)?(?:\\s|$)|\\.(?:downloadstring|downloadfile)\\s*\\(")
	hookURL        = regexp.MustCompile(`(?i)(?:https?|ftp)://[^\s"'<>]+`)
	hookPipeShell  = regexp.MustCompile(`\|\s*(?:sudo\s+)?(?:/[\w./-]*/)?(?:sh|bash|zsh|dash|powershell(?:\.exe)?|pwsh|iex|invoke-expression)(?:\s|$|;|\)|")`)
	hookEvalFlag   = regexp.MustCompile(`(?i)\b(?:node|nodejs|python3?|py|perl|ruby|php)(?:\.exe)?\s+(?:--eval|-e|-c|-r)\b(.*)$`)
	hookEncoded    = regexp.MustCompile(`(?i)base64|\batob\s*\(|b64decode|fromcharcode|Buffer\.from|(?:\\x[0-9a-f]{2}){4,}|[A-Za-z0-9+/]{60,}={0,2}`)
	hookPSEncoded  = regexp.MustCompile(`(?i)\b(?:powershell|pwsh)(?:\.exe)?\b.*\s-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}`)
	hookHarvester  = regexp.MustCompile(`(?i)(?:^|[\s;&|(/\\"'])(trufflehog|gitleaks)(?:\.exe)?(?:\s|$|["'])`)
)

// hookShape reports why a shell command line, taken from an install hook, is
// an indicator, or "" when it is an ordinary local step.
func hookShape(cmd string) string {
	if hookPipeShell.MatchString(cmd) {
		return "pipes output into a shell"
	}
	if m := hookDownloader.FindStringSubmatch(cmd); m != nil && hookURL.MatchString(cmd) {
		name := strings.ToLower(m[1])
		if name == "" {
			name = "a download call"
		}
		return "downloads remote content with " + name
	}
	if m := hookEvalFlag.FindStringSubmatch(cmd); m != nil && hookEncoded.MatchString(m[1]) {
		return "runs an inline script with an encoded argument"
	}
	if hookPSEncoded.MatchString(cmd) {
		return "runs an encoded PowerShell command"
	}
	if m := hookHarvester.FindStringSubmatch(cmd); m != nil {
		return "invokes the credential scanner " + strings.ToLower(m[1])
	}
	return ""
}

func (s *Scanner) installHooks(f *file) []core.Finding {
	switch f.base {
	case "package.json":
		return s.npmHooks(f)
	case "composer.json":
		return s.composerHooks(f)
	case "setup.py":
		return s.setupPyHooks(f)
	}
	return nil
}

var npmHookNames = []string{"preinstall", "install", "postinstall", "prepare"}

func (s *Scanner) npmHooks(f *file) []core.Finding {
	var doc struct {
		Scripts map[string]any `json:"scripts"`
	}
	if json.Unmarshal([]byte(f.text), &doc) != nil {
		return nil
	}
	var out []core.Finding
	for _, name := range npmHookNames {
		cmd, ok := doc.Scripts[name].(string)
		if !ok {
			continue
		}
		if why := hookShape(cmd); why != "" {
			out = append(out, f.finding(hit{
				rule: "ZS-IOC-001", offset: -1, line: keyLine(f, "scripts", name),
				snippet:   fmt.Sprintf("%q: %q", name, cmd),
				message:   fmt.Sprintf("package.json %s hook %s", name, why),
				indicator: name,
				extra:     map[string]string{"hook": name, "manifest": "package.json"},
			}))
		}
	}
	return out
}

var composerHookNames = []string{"post-install-cmd", "post-update-cmd"}

func (s *Scanner) composerHooks(f *file) []core.Finding {
	var doc struct {
		Scripts map[string]any `json:"scripts"`
	}
	if json.Unmarshal([]byte(f.text), &doc) != nil {
		return nil
	}
	var out []core.Finding
	for _, name := range composerHookNames {
		var cmds []string
		switch v := doc.Scripts[name].(type) {
		case string:
			cmds = []string{v}
		case []any:
			for _, c := range v {
				if str, ok := c.(string); ok {
					cmds = append(cmds, str)
				}
			}
		}
		for _, cmd := range cmds {
			if why := hookShape(cmd); why != "" {
				out = append(out, f.finding(hit{
					rule: "ZS-IOC-001", offset: -1, line: keyLine(f, "scripts", name),
					snippet:   fmt.Sprintf("%q: %q", name, cmd),
					message:   fmt.Sprintf("composer.json %s hook %s", name, why),
					indicator: name,
					extra:     map[string]string{"hook": name, "manifest": "composer.json"},
				}))
				break
			}
		}
	}
	return out
}

// keyLine finds the line of "key" after the "section" key in a JSON file, or
// of the first "key" when the section cannot be located.
func keyLine(f *file, section, key string) int {
	start := 0
	if m := regexp.MustCompile(`"` + regexp.QuoteMeta(section) + `"\s*:`).FindStringIndex(f.text); m != nil {
		start = m[0]
	}
	if m := regexp.MustCompile(`"` + regexp.QuoteMeta(key) + `"\s*:`).FindStringIndex(f.text[start:]); m != nil {
		return f.lineAt(start + m[0])
	}
	return 1
}

var (
	pyExecCall   = regexp.MustCompile(`\b(?:os\.system|os\.popen|subprocess\.\w+|Popen|check_call|check_output|exec|eval)\s*\(`)
	pyFetchCall  = regexp.MustCompile(`\b(?:urlopen|urlretrieve|requests\.(?:get|post)|urllib\.request|http\.client)\b`)
	pyDecodeCall = regexp.MustCompile(`\bb64decode\s*\(`)
	pyExecOnly   = regexp.MustCompile(`\b(?:exec|eval)\s*\(`)
)

// setupPyHooks looks for the same shapes in setup.py, where install commands
// run arbitrary code at pip install time. Only a statement that launches a
// process or executes code is considered, and for exec/eval only when its
// argument fetches or decodes content.
func (s *Scanner) setupPyHooks(f *file) []core.Finding {
	var out []core.Finding
	for i, line := range f.lines {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || !pyExecCall.MatchString(t) {
			continue
		}
		why := ""
		switch {
		case hookShape(t) != "":
			why = hookShape(t)
		case pyExecOnly.MatchString(t) && pyFetchCall.MatchString(t):
			why = "executes content fetched over the network"
		case pyExecCall.MatchString(t) && pyDecodeCall.MatchString(t):
			why = "executes base64-decoded content"
		}
		if why == "" {
			continue
		}
		out = append(out, f.finding(hit{
			rule: "ZS-IOC-001", offset: -1, line: i + 1,
			snippet:   t,
			message:   "setup.py " + why,
			indicator: "setup.py",
			lang:      core.LangPython,
			extra:     map[string]string{"hook": "setup.py", "manifest": "setup.py"},
		}))
	}
	return out
}
