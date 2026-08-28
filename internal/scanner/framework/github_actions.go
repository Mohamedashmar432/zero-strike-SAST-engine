package framework

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/findings"
)

var (
	actionUsesRe = regexp.MustCompile(`(?i)^\s*(?:-\s*)?uses:\s*["']?([^@\s"']+)(?:@([^\s#"']+))?["']?`)
	sha40Re      = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
)

// githubActionsUnpinnedCheck detects unpinned GitHub Actions (uses: ...@vX instead of a full commit SHA).
// Mutable tags can be moved or compromised by attackers to execute malicious code in CI workflows.
var githubActionsUnpinnedCheck = check{
	ruleID:  "ZS-CFG-012",
	accepts: isGitHubWorkflowFile,
	detect:  detectGitHubActionsUnpinned,
}

func isGitHubWorkflowFile(path string) bool {
	norm := strings.ReplaceAll(strings.ToLower(path), "\\", "/")
	return (strings.Contains(norm, ".github/workflows/") || strings.Contains(norm, ".github/actions/")) &&
		(strings.HasSuffix(norm, ".yml") || strings.HasSuffix(norm, ".yaml"))
}

func detectGitHubActionsUnpinned(path string, data []byte) []core.Finding {
	var out []core.Finding
	lines := bytes.Split(data, []byte("\n"))
	for i, line := range lines {
		m := actionUsesRe.FindSubmatch(line)
		if m == nil {
			continue
		}
		action := string(m[1])
		if strings.HasPrefix(action, "./") || strings.HasPrefix(action, "docker://") {
			continue // local or docker container actions
		}
		if len(m) < 3 || len(m[2]) == 0 {
			// No version specified at all
			out = append(out, buildUnpinnedActionFinding(path, action, "missing", i+1))
			continue
		}
		ref := string(m[2])
		if !sha40Re.MatchString(ref) {
			out = append(out, buildUnpinnedActionFinding(path, action, ref, i+1))
		}
	}
	return out
}

func buildUnpinnedActionFinding(path, action, ref string, line int) core.Finding {
	loc := core.Location{File: path, StartLine: line, EndLine: line}
	return findings.BuildConfigFinding(
		"ZS-CFG-012",
		"GitHub Action Not Pinned to SHA",
		"Action "+action+"@"+ref+" is not pinned to a full commit SHA in "+path+" — mutable tags present supply chain risks",
		"security-misconfiguration",
		findings.ConfigInput{Framework: "github-actions", ConfigFile: path, Key: action, Value: ref},
		loc,
		core.SeverityMedium,
		core.ConfidenceHigh,
		[]string{"CWE-829"},
		[]string{"A03:2025"},
	)
}
