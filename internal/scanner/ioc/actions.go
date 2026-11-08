package ioc

import (
	"regexp"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
)

// ZS-IOC-008: a workflow `uses:` line for an action with a published
// compromise whose ref is not a full commit SHA. A SHA cannot be repointed;
// a tag or branch can.

var (
	usesLine = regexp.MustCompile(`^\s*(?:-\s*)?uses:\s*['"]?([^'"\s#]+)`)
	fullSHA  = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
)

func isWorkflowFile(rel string) bool {
	r := strings.ToLower(strings.ReplaceAll(rel, "\\", "/"))
	if !(strings.HasSuffix(r, ".yml") || strings.HasSuffix(r, ".yaml")) {
		return false
	}
	return strings.HasPrefix(r, ".github/workflows/") || strings.Contains(r, "/.github/workflows/")
}

func (s *Scanner) workflowActions(f *file) []core.Finding {
	if !isWorkflowFile(f.rel) {
		return nil
	}
	var out []core.Finding
	for i, line := range f.lines {
		m := usesLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		spec := m[1]
		at := strings.LastIndex(spec, "@")
		if at < 0 || strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "docker://") {
			continue
		}
		name, ref := spec[:at], spec[at+1:]
		parts := strings.Split(strings.ToLower(name), "/")
		if len(parts) < 2 {
			continue
		}
		adv, ok := s.m.actions[parts[0]+"/"+parts[1]]
		if !ok || fullSHA.MatchString(ref) {
			continue
		}
		out = append(out, f.finding(hit{
			rule: "ZS-IOC-008", offset: -1, line: i + 1,
			snippet:   strings.TrimSpace(line),
			message:   adv.Action + "@" + ref + " has a published compromise (" + adv.Advisory + "): " + adv.Summary + "; the ref is not a commit SHA",
			indicator: adv.Action,
			extra:     map[string]string{"advisory": adv.Advisory, "action": adv.Action, "ref": ref},
		}))
	}
	return out
}
