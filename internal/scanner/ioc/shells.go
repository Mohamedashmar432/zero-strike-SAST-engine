package ioc

import (
	"regexp"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
)

// ZS-IOC-004 (reverse shell) and ZS-IOC-005 (crypto mining). Both are tight
// textual shapes over any non-binary file outside test, vendor and
// documentation paths.

var (
	// /dev/tcp is also how shell scripts wait for a port, so the redirection
	// alone never matches: an interactive shell or its descriptor plumbing
	// has to be on the same line.
	revDevTCP = regexp.MustCompile(`(?i)/dev/(?:tcp|udp)/\S+` )
	revDevTCPPlumbing = regexp.MustCompile(`(?i)\b(?:ba|z|k|da)?sh\s+-i\b|\b0>&1|\b0<&\d|<&\d+\s*>&\d+|>&\s*/dev/(?:tcp|udp)/|\bcat\s+<&\d`)
	revFifoShell      = regexp.MustCompile(`(?i)\b(?:ba|z|k|da)?sh\s+-i\s*<&\d+\s*>&\d+`)
	revNetcat         = regexp.MustCompile(`(?i)\b(?:nc|ncat|netcat|nc\.traditional)\b[^|;&\n]*\s-[a-z]*[ec]\s+\S*(?:sh|bash|zsh|dash|cmd(?:\.exe)?|powershell)\b`)
	revMkfifo         = regexp.MustCompile(`(?i)\bmkfifo\b.*\|\s*(?:/bin/)?(?:ba)?sh\b.*\|\s*(?:nc|ncat|netcat)\b`)
	revSocat          = regexp.MustCompile(`(?i)\bsocat\b`)
	revSocatExec      = regexp.MustCompile(`(?i)\bexec:\S*(?:sh|bash|cmd)\b`)
	revSocatNet       = regexp.MustCompile(`(?i)\b(?:tcp|tcp4|tcp6|openssl)(?:-connect)?:`)
	revPyOneLine      = regexp.MustCompile(`(?i)socket\.socket\s*\(.*dup2\s*\(.*(?:/bin/(?:ba)?sh|pty\.spawn|subprocess)`)
	revPySocket       = regexp.MustCompile(`(?m)^\s*(?:import\s+[\w, ]*\bsocket\b|from\s+socket\s+import)`)
	revPtySpawn       = regexp.MustCompile(`pty\.spawn\s*\(\s*['"](?:/bin/)?(?:ba)?sh['"]`)
	revDup2           = regexp.MustCompile(`os\.dup2\s*\(`)
	revPyShellExec    = regexp.MustCompile(`/bin/(?:ba)?sh|subprocess\.call|os\.execve|os\.system`)
	revPSClient       = regexp.MustCompile(`(?i)Net\.Sockets\.TCPClient`)
	revPSStream       = regexp.MustCompile(`(?i)\.GetStream\s*\(`)
	revPSExec         = regexp.MustCompile(`(?i)\b(?:iex|invoke-expression)\b`)
)

func isCommentLine(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "*") ||
		strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "<!--") || strings.HasPrefix(t, "--") || strings.HasPrefix(t, "REM ")
}

func (s *Scanner) reverseShell(f *file) []core.Finding {
	if f.nonShipped {
		return nil
	}
	var out []core.Finding
	add := func(line int, why string) {
		out = append(out, f.finding(hit{
			rule: "ZS-IOC-004", offset: -1, line: line,
			snippet: f.lines[line-1], message: "Reverse shell: " + why,
			indicator: why, lang: langForExt(f.ext),
		}))
	}
	for i, line := range f.lines {
		if len(line) > 2000 || isCommentLine(line) {
			continue
		}
		switch {
		case revDevTCP.MatchString(line) && revDevTCPPlumbing.MatchString(line):
			add(i+1, "interactive shell redirected to /dev/tcp")
		case revFifoShell.MatchString(line):
			add(i+1, "interactive shell wired to a socket descriptor")
		case revNetcat.MatchString(line):
			add(i+1, "netcat executes a shell")
		case revMkfifo.MatchString(line):
			add(i+1, "mkfifo and netcat pipe a shell")
		case revSocat.MatchString(line) && revSocatExec.MatchString(line) && revSocatNet.MatchString(line):
			add(i+1, "socat connects a socket to a shell")
		case revPyOneLine.MatchString(line):
			add(i+1, "Python socket duplicated onto a shell's descriptors")
		}
	}
	// File-level shapes. Python: a socket plus pty.spawn of a shell, or two
	// dup2 calls onto a socket with a shell launch.
	if f.ext == ".py" && revPySocket.MatchString(f.text) {
		if loc := revPtySpawn.FindStringIndex(f.text); loc != nil {
			out = append(out, f.finding(hit{
				rule: "ZS-IOC-004", offset: loc[0], snippet: f.lines[f.lineAt(loc[0])-1],
				message: "Reverse shell: Python socket with pty.spawn of a shell", indicator: "python-pty", lang: core.LangPython,
			}))
		} else if d := revDup2.FindAllStringIndex(f.text, -1); len(d) >= 2 && revPyShellExec.MatchString(f.text) {
			out = append(out, f.finding(hit{
				rule: "ZS-IOC-004", offset: d[0][0], snippet: f.lines[f.lineAt(d[0][0])-1],
				message: "Reverse shell: Python socket dup2'd onto stdin/stdout with a shell launch", indicator: "python-dup2", lang: core.LangPython,
			}))
		}
	}
	// PowerShell: TCPClient, its stream, and execution of what it reads.
	if loc := revPSClient.FindStringIndex(f.text); loc != nil && revPSStream.MatchString(f.text) && revPSExec.MatchString(f.text) {
		out = append(out, f.finding(hit{
			rule: "ZS-IOC-004", offset: loc[0], snippet: f.lines[f.lineAt(loc[0])-1],
			message: "Reverse shell: PowerShell TCPClient stream executed with Invoke-Expression", indicator: "powershell-tcpclient",
		}))
	}
	return out
}

var (
	minerCfgDonate = regexp.MustCompile(`(?i)"donate-level"\s*:`)
	minerCfgPools  = regexp.MustCompile(`(?i)"pools"\s*:`)
	minerRelease   = regexp.MustCompile(`(?i)github\.com/xmrig/xmrig/releases`)
	minerChmod     = regexp.MustCompile(`(?i)\bchmod\s+\+x\s+\S*(?:xmrig|minerd|cpuminer)`)
)

func (s *Scanner) miner(f *file) []core.Finding {
	if f.nonShipped {
		return nil
	}
	var out []core.Finding
	add := func(line int, why string) {
		out = append(out, f.finding(hit{
			rule: "ZS-IOC-005", offset: -1, line: line,
			snippet: f.lines[line-1], message: "Crypto mining indicator: " + why,
			indicator: why, lang: langForExt(f.ext),
		}))
	}
	for i, line := range f.lines {
		if len(line) > 2000 {
			continue
		}
		switch {
		case s.m.poolURL.MatchString(line):
			add(i+1, "stratum pool URL")
		case s.m.minerCmd.MatchString(line):
			add(i+1, "miner binary run with pool arguments")
		case minerRelease.MatchString(line):
			add(i+1, "xmrig release download")
		case minerChmod.MatchString(line):
			add(i+1, "miner binary made executable")
		}
	}
	if minerCfgDonate.MatchString(f.text) && minerCfgPools.MatchString(f.text) {
		loc := minerCfgDonate.FindStringIndex(f.text)
		out = append(out, f.finding(hit{
			rule: "ZS-IOC-005", offset: loc[0], snippet: f.lines[f.lineAt(loc[0])-1],
			message: "Crypto mining indicator: miner config with donate-level and pools", indicator: "miner-config",
		}))
	}
	return out
}
