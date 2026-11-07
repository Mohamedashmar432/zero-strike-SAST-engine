package framework

import (
	"regexp"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/findings"
)

// dockerfileCheck reads a Dockerfile once and reports four conditions, each
// under its own rule ID so a team can suppress one without the others:
//
//	ZS-CFG-021  the final stage runs as root (no USER, or USER root/0)
//	ZS-CFG-022  a base image is untagged or tagged :latest
//	ZS-CFG-023  ADD fetches a remote URL (use curl with a checksum, or COPY)
//	ZS-CFG-024  ENV/ARG bakes a credential-named variable into the image
//
// The first three are hardening tier: they widen the blast radius of some
// other flaw and have no exploit path alone, so default output leaves them
// out (see core.Tier). A literal secret in an image layer is recoverable by
// anyone who can pull the image, so ZS-CFG-024 is a security finding.
var dockerfileCheck = check{
	ruleID:  "ZS-CFG-021",
	accepts: isDockerfile,
	detect:  detectDockerfile,
}

func isDockerfile(path string) bool {
	base := strings.ToLower(baseName(path))
	return base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile")
}

// dockerInstr is one logical instruction: continuation lines are joined and
// Line is the 1-based line where the instruction starts.
type dockerInstr struct {
	Line int
	Op   string
	Args string
}

func parseDockerfile(data []byte) []dockerInstr {
	var out []dockerInstr
	var cur strings.Builder
	start := 0
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if cur.Len() == 0 && (trimmed == "" || strings.HasPrefix(trimmed, "#")) {
			continue
		}
		if cur.Len() > 0 && strings.HasPrefix(trimmed, "#") {
			continue // comment line inside a continued instruction
		}
		if cur.Len() == 0 {
			start = i + 1
		}
		if strings.HasSuffix(trimmed, "\\") {
			cur.WriteString(strings.TrimSuffix(trimmed, "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(trimmed)
		text := strings.TrimSpace(cur.String())
		cur.Reset()
		op, args, _ := strings.Cut(text, " ")
		out = append(out, dockerInstr{Line: start, Op: strings.ToUpper(op), Args: strings.TrimSpace(args)})
	}
	return out
}

var (
	dockerCredNameRe  = regexp.MustCompile(`(?i)(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL)`)
	dockerNonValueRe  = regexp.MustCompile(`(?i)_(FILE|PATH|DIR|URL|URI|HOST|PORT|NAME|USER|ID|TYPE|ENABLED|LENGTH|TTL|EXPIRY|EXPIRES|ALGORITHM)$`)
	dockerPlaceholdRe = regexp.MustCompile(`(?i)(changeme|change_me|example|placeholder|dummy|sample|your[_-]|redacted|replace[_-]?me|<[^>]*>|^x+$|^\*+$)`)
)

func detectDockerfile(path string, data []byte) []core.Finding {
	instrs := parseDockerfile(data)
	var out []core.Finding

	finalFrom, finalUser := -1, ""
	stages := map[string]bool{} // FROM ... AS name, so "FROM name" is not an image
	for i, in := range instrs {
		switch in.Op {
		case "FROM":
			finalFrom, finalUser = i, "" // a new stage resets the user
			if f, ok := dockerLatestFinding(path, in, stages); ok {
				out = append(out, f)
			}
			if fields := strings.Fields(in.Args); len(fields) >= 3 && strings.EqualFold(fields[len(fields)-2], "as") {
				stages[strings.ToLower(fields[len(fields)-1])] = true
			}
		case "USER":
			finalUser = strings.ToLower(strings.TrimSpace(strings.SplitN(in.Args, ":", 2)[0]))
		case "ADD":
			if f, ok := dockerAddURLFinding(path, in); ok {
				out = append(out, f)
			}
		case "ENV", "ARG":
			out = append(out, dockerSecretFindings(path, in)...)
		}
	}
	if finalFrom >= 0 && (finalUser == "" || finalUser == "root" || finalUser == "0") {
		out = append(out, dockerRootFinding(path, instrs[finalFrom], finalUser))
	}
	return out
}

func dockerRootFinding(path string, from dockerInstr, user string) core.Finding {
	msg := "final stage of " + path + " has no USER instruction, so the container runs as root"
	if user != "" {
		msg = "final stage of " + path + " ends with USER " + user + ", so the container runs as root"
	}
	f := findings.BuildConfigFinding(
		"ZS-CFG-021",
		"Dockerfile Runs As Root",
		msg,
		"security-misconfiguration",
		findings.ConfigInput{Framework: "docker", ConfigFile: path, Key: "USER"},
		core.Location{File: path, StartLine: from.Line, EndLine: from.Line},
		core.SeverityLow,
		core.ConfidenceMedium,
		[]string{"CWE-250"},
		[]string{"A02:2025"},
	)
	f.Tier = core.TierHardening
	return f
}

func dockerLatestFinding(path string, from dockerInstr, stages map[string]bool) (core.Finding, bool) {
	fields := strings.Fields(from.Args)
	for len(fields) > 0 && strings.HasPrefix(fields[0], "--") {
		fields = fields[1:] // --platform=...
	}
	if len(fields) == 0 {
		return core.Finding{}, false
	}
	image := fields[0]
	if strings.EqualFold(image, "scratch") || stages[strings.ToLower(image)] || strings.Contains(image, "@") || strings.Contains(image, "$") {
		return core.Finding{}, false // pinned by digest, or resolved from a build arg
	}
	// Strip a registry port before looking for the tag colon.
	name := image[strings.LastIndex(image, "/")+1:]
	tag := ""
	if i := strings.Index(name, ":"); i >= 0 {
		tag = name[i+1:]
	}
	if tag != "" && !strings.EqualFold(tag, "latest") {
		return core.Finding{}, false
	}
	shown := "untagged"
	if tag != "" {
		shown = "tagged :latest"
	}
	f := findings.BuildConfigFinding(
		"ZS-CFG-022",
		"Dockerfile Unpinned Base Image",
		"FROM "+image+" in "+path+" is "+shown+" — builds are not reproducible and pick up unreviewed upstream changes",
		"security-misconfiguration",
		findings.ConfigInput{Framework: "docker", ConfigFile: path, Key: "FROM " + image, Value: image},
		core.Location{File: path, StartLine: from.Line, EndLine: from.Line},
		core.SeverityLow,
		core.ConfidenceHigh,
		[]string{"CWE-1104"},
		[]string{"A03:2025"},
	)
	f.Tier = core.TierHardening
	return f, true
}

func dockerAddURLFinding(path string, add dockerInstr) (core.Finding, bool) {
	for _, tok := range strings.Fields(add.Args) {
		if strings.HasPrefix(tok, "--") {
			continue
		}
		lower := strings.ToLower(tok)
		if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
			return core.Finding{}, false // sources come first; a local source means no URL ADD
		}
		f := findings.BuildConfigFinding(
			"ZS-CFG-023",
			"Dockerfile ADD From Remote URL",
			"ADD "+tok+" in "+path+" downloads unverified content at build time — fetch with a pinned checksum or vendor the file and COPY it",
			"security-misconfiguration",
			findings.ConfigInput{Framework: "docker", ConfigFile: path, Key: "ADD " + tok},
			core.Location{File: path, StartLine: add.Line, EndLine: add.Line},
			core.SeverityLow,
			core.ConfidenceHigh,
			[]string{"CWE-494"},
			[]string{"A08:2025"},
		)
		f.Tier = core.TierHardening
		return f, true
	}
	return core.Finding{}, false
}

// dockerEnvPairs splits ENV/ARG arguments into name/value pairs. ENV accepts
// the legacy "ENV NAME value" form as well as "ENV A=1 B=2".
func dockerEnvPairs(in dockerInstr) [][2]string {
	var pairs [][2]string
	fields := strings.Fields(in.Args)
	if len(fields) == 0 {
		return nil
	}
	if !strings.Contains(fields[0], "=") {
		name, value, found := strings.Cut(in.Args, " ")
		if in.Op == "ARG" || !found {
			return nil // ARG without a default carries no value
		}
		return [][2]string{{name, strings.TrimSpace(value)}}
	}
	for _, tok := range fields {
		if name, value, ok := strings.Cut(tok, "="); ok {
			pairs = append(pairs, [2]string{name, value})
		}
	}
	return pairs
}

func dockerSecretFindings(path string, in dockerInstr) []core.Finding {
	var out []core.Finding
	for _, p := range dockerEnvPairs(in) {
		name, value := p[0], strings.Trim(p[1], "\"'")
		if !dockerCredNameRe.MatchString(name) || dockerNonValueRe.MatchString(name) {
			continue
		}
		if len(value) < 4 || strings.Contains(value, "$") || dockerPlaceholdRe.MatchString(value) {
			continue
		}
		out = append(out, findings.BuildConfigFinding(
			"ZS-CFG-024",
			"Dockerfile Credential In ENV/ARG",
			in.Op+" "+name+" in "+path+" stores a literal credential in an image layer — anyone who can pull the image can read it; pass it at run time or use a build secret",
			"authentication",
			findings.ConfigInput{Framework: "docker", ConfigFile: path, Key: in.Op + " " + name},
			core.Location{File: path, StartLine: in.Line, EndLine: in.Line},
			core.SeverityHigh,
			core.ConfidenceMedium,
			[]string{"CWE-798"},
			[]string{"A07:2025"},
		))
	}
	return out
}
