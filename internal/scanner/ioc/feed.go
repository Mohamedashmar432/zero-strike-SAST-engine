package ioc

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
)

// ZS-IOC-007: the organisation's own indicator feed.
//
// File format, one indicator per line:
//
//	domain:evil.example
//	ip:203.0.113.7
//	url:https://evil.example/payload.sh
//	sha256:<64 hex digits>
//	# comment
//
// Blank lines and lines starting with # are ignored. Any other line is an
// error: a typo must not silently drop an indicator.

type feed struct {
	abs     string
	domains []string
	ips     []string
	urls    []string
	hashes  map[string]string // sha256 -> original line
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

func loadFeed(path string) (*feed, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("ioc: open feed: %w", err)
	}
	defer fh.Close()
	abs, _ := filepath.Abs(path)
	fd := &feed{abs: abs, hashes: map[string]string{}}
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\ufeff"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kind, val, ok := strings.Cut(line, ":")
		val = strings.TrimSpace(val)
		if !ok || val == "" {
			return nil, fmt.Errorf("ioc: feed %s line %d: want domain:, ip:, url: or sha256:", path, n)
		}
		switch strings.ToLower(strings.TrimSpace(kind)) {
		case "domain":
			fd.domains = append(fd.domains, strings.ToLower(strings.TrimPrefix(val, ".")))
		case "ip":
			fd.ips = append(fd.ips, val)
		case "url":
			fd.urls = append(fd.urls, strings.ToLower(val))
		case "sha256":
			h := strings.ToLower(val)
			if !sha256Hex.MatchString(h) {
				return nil, fmt.Errorf("ioc: feed %s line %d: sha256 must be 64 hex digits", path, n)
			}
			fd.hashes[h] = line
		default:
			return nil, fmt.Errorf("ioc: feed %s line %d: unknown indicator type %q", path, n, kind)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("ioc: read feed: %w", err)
	}
	return fd, nil
}

func isLabelChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_'
}

// findToken finds needle in hay (both lower-case) where the characters on
// either side are not part of a host label (for a domain) or a number (for an
// IP), so evil.com does not match notevil.com or evil.company.
func findToken(hay, needle string, ip bool) int {
	for from := 0; ; {
		i := strings.Index(hay[from:], needle)
		if i < 0 {
			return -1
		}
		i += from
		end := i + len(needle)
		okBefore := i == 0
		if !okBefore {
			b := hay[i-1]
			if ip {
				okBefore = !(b >= '0' && b <= '9') && b != '.'
			} else {
				okBefore = !isLabelChar(b)
			}
		}
		okAfter := end == len(hay)
		if !okAfter {
			b := hay[end]
			if ip {
				okAfter = !(b >= '0' && b <= '9') && !(b == '.' && end+1 < len(hay) && hay[end+1] >= '0' && hay[end+1] <= '9')
			} else {
				// evil.com.example.org is another host: a dot followed by a
				// label character continues the name.
				okAfter = !isLabelChar(b) && !(b == '.' && end+1 < len(hay) && isLabelChar(hay[end+1]))
			}
		}
		if okBefore && okAfter {
			return i
		}
		from = i + 1
	}
}

// inLiteralOrValue reports whether the match at pos of line is a string
// literal, a URL, or a configuration value rather than a bare identifier.
func inLiteralOrValue(line string, pos int, needleLen int) bool {
	if insideLiteral(line, pos) {
		return true
	}
	before := line[:pos]
	if strings.HasSuffix(before, "://") || strings.Contains(before[max(0, len(before)-12):], "://") {
		return true
	}
	t := strings.TrimRight(before, " \t")
	return strings.HasSuffix(t, "=") || strings.HasSuffix(t, ":") || strings.HasSuffix(t, "=>")
}

func (s *Scanner) feedMatches(f *file, data []byte) []core.Finding {
	fd := s.feed
	if abs, err := filepath.Abs(f.path); err == nil && abs == fd.abs {
		return nil
	}
	var out []core.Finding
	if len(fd.hashes) > 0 {
		sum := sha256.Sum256(data)
		h := hex.EncodeToString(sum[:])
		if orig, ok := fd.hashes[h]; ok {
			out = append(out, f.finding(hit{
				rule: "ZS-IOC-007", offset: -1, line: 1, snippet: orig,
				message:   "File SHA-256 " + h[:16] + "... is in the IOC feed",
				indicator: "sha256:" + h, extra: map[string]string{"feed_type": "sha256"},
			}))
		}
	}
	if f.lines == nil || (len(fd.domains)+len(fd.ips)+len(fd.urls)) == 0 {
		return out
	}
	for i, line := range f.lines {
		if len(line) > 4000 {
			continue
		}
		low := strings.ToLower(line)
		check := func(kind, needle string, ip bool) {
			pos := findToken(low, needle, ip)
			if kind == "url" {
				pos = strings.Index(low, needle)
			}
			if pos < 0 || !inLiteralOrValue(line, pos, len(needle)) {
				return
			}
			out = append(out, f.finding(hit{
				rule: "ZS-IOC-007", offset: f.lineStarts[i] + pos, snippet: line,
				message:   "Feed " + kind + " " + needle + " appears in this file",
				indicator: kind + ":" + needle, extra: map[string]string{"feed_type": kind},
			}))
		}
		for _, d := range fd.domains {
			check("domain", d, false)
		}
		for _, ip := range fd.ips {
			check("ip", ip, true)
		}
		for _, u := range fd.urls {
			check("url", u, false)
		}
	}
	return out
}
