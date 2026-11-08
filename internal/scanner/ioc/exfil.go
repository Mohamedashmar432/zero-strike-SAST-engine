package ioc

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
)

// ZS-IOC-006: a request-capture or bot endpoint written as a URL literal in
// shipped source. Configuration and markup files are not source, and test,
// fixture, documentation and comment-only lines never fire.

var exfilCodeExts = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".jsx": true, ".ts": true, ".tsx": true,
	".py": true, ".php": true, ".java": true, ".kt": true, ".cs": true, ".go": true,
	".rb": true, ".rs": true, ".swift": true, ".pl": true, ".lua": true, ".groovy": true,
	".scala": true, ".vb": true, ".sh": true, ".bash": true, ".ps1": true, ".bat": true,
	".cmd": true, ".jsp": true, ".aspx": true, ".ashx": true,
}

// Shell-like files take a bare URL as a request target (curl https://...);
// elsewhere the URL must sit inside a string literal.
var exfilBareOK = map[string]bool{".sh": true, ".bash": true, ".ps1": true, ".bat": true, ".cmd": true}

var (
	exfilURL    = regexp.MustCompile("(?i)https?://[^\\s\"'`)\\]>,;]+")
	redactDisc  = regexp.MustCompile(`(?i)(/webhooks/\d+/)[\w-]+`)
	redactTelBt = regexp.MustCompile(`(?i)(/bot)[\w:-]+`)
)

func redactEndpoint(s string) string {
	s = redactDisc.ReplaceAllString(s, "${1}****")
	return redactTelBt.ReplaceAllString(s, "${1}****")
}

// insideLiteral reports whether position pos of line is inside a quoted
// string, judged by an odd number of the same quote character before it.
func insideLiteral(line string, pos int) bool {
	for _, q := range []byte{'"', '\'', '`'} {
		if strings.Count(line[:pos], string(q))%2 == 1 {
			return true
		}
	}
	return false
}

func hostMatches(host, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func (s *Scanner) exfil(f *file) []core.Finding {
	if f.nonShipped || !exfilCodeExts[f.ext] {
		return nil
	}
	var out []core.Finding
	for i, line := range f.lines {
		if len(line) > 2000 || isCommentLine(line) {
			continue
		}
		low := strings.ToLower(line)
		if !strings.Contains(low, "http") {
			continue
		}
		reported := map[string]bool{}
		for _, loc := range exfilURL.FindAllStringIndex(line, -1) {
			if !exfilBareOK[f.ext] && !insideLiteral(line, loc[0]) {
				continue
			}
			raw := line[loc[0]:loc[1]]
			indicator := ""
			for _, p := range s.m.data.Exfil.URLPatterns {
				if p.re.MatchString(raw) {
					indicator = p.Name
					break
				}
			}
			if indicator == "" {
				u, err := url.Parse(raw)
				if err != nil {
					continue
				}
				host := strings.ToLower(u.Hostname())
				for _, d := range s.m.exfilHosts {
					if hostMatches(host, d) {
						indicator = d
						break
					}
				}
			}
			if indicator == "" || reported[indicator] {
				continue
			}
			reported[indicator] = true
			out = append(out, f.finding(hit{
				rule: "ZS-IOC-006", offset: f.lineStarts[i] + loc[0],
				snippet:   redactEndpoint(line),
				message:   "Request target " + indicator + " is an exfiltration or request-capture endpoint",
				indicator: indicator, lang: langForExt(f.ext),
			}))
		}
	}
	return out
}
