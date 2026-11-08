package ioc

import "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"

// Category is the finding category of every IOC finding.
const Category = "indicator-of-compromise"

// RuleInfo is the metadata of one IOC rule. It is copied onto every finding
// (RuleName, Description, Rationale, Remediation, CWE) the way SAST findings
// carry their YAML rule's text, and Rules() lists it for tooling.
type RuleInfo struct {
	ID          string
	Name        string
	Short       string // value of Metadata["ioc"]
	Severity    core.Severity
	CWE         string
	Description string
	Rationale   string
	Remediation string
}

var rules = []RuleInfo{
	{
		ID: "ZS-IOC-001", Name: "Install-time hook downloads or runs remote code", Short: "install-hook",
		Severity: core.SeverityCritical, CWE: "CWE-506",
		Description: "An install hook (package.json preinstall/install/postinstall/prepare, a setup.py install command, composer.json post-install-cmd/post-update-cmd) downloads content, pipes into a shell, runs an encoded one-liner, or invokes a credential harvester (trufflehog, gitleaks). Local build steps (tsc, node-gyp rebuild, husky install) do not match. A hook that runs a script file is not followed into that file.",
		Rationale:   "Install hooks run automatically on every developer machine and CI runner that installs the package, with that user's credentials. Fetching and running code from there is the standard delivery path of supply-chain malware.",
		Remediation: "Remove the hook or replace it with a local build step. If the repository is not yours, treat it as compromised: do not install it, rotate any credentials present on machines that did, and report the package to its registry.",
	},
	{
		ID: "ZS-IOC-002", Name: "Encoded payload passed to an executor", Short: "encoded-payload",
		Severity: core.SeverityHigh, CWE: "CWE-506",
		Description: "eval, exec, Function, assert, create_function or vm.runIn*Context is applied to a decoder (atob, Buffer.from base64/hex, base64_decode, gzinflate, gzuncompress, str_rot13, b64decode, zlib.decompress, marshal.loads) with a string literal of 200 or more characters, or to a chain of two or more decoders. Applies to JS, TS, PHP and Python outside test, vendor and documentation paths.",
		Rationale:   "Legitimate code seldom hides its own logic in an encoded blob that it decodes and runs; obfuscated loaders, droppers and backdoors almost always do.",
		Remediation: "Decode the blob offline and review what it runs. If it is not code you recognise, treat the file as compromised, find how it was introduced (git blame, the commit's author), and remove it.",
	},
	{
		ID: "ZS-IOC-003", Name: "Web shell", Short: "web-shell",
		Severity: core.SeverityCritical, CWE: "CWE-912",
		Description: "Request data (PHP superglobals, ASP Request, JSP request.getParameter) passed directly to eval, assert, system, passthru, shell_exec, exec or a preg_replace /e pattern in a PHP, ASP/ASPX or JSP file that is under 60 lines or declares no functions. Shells hidden inside a large file with many functions are out of scope.",
		Rationale:   "A file whose whole job is to run what the request says is a remote command interface left for an attacker, not application logic.",
		Remediation: "Delete the file, then find how it was written (upload handler, compromised credentials, vulnerable plugin), rotate credentials reachable from the web server and review web server logs for use of the file.",
	},
	{
		ID: "ZS-IOC-004", Name: "Reverse shell", Short: "reverse-shell",
		Severity: core.SeverityCritical, CWE: "CWE-912",
		Description: "An interactive shell wired to a network socket: /dev/tcp redirection with bash -i, nc/ncat -e or -c, mkfifo with nc, socat with exec:, a Python socket with pty.spawn or dup2, or a PowerShell Net.Sockets.TCPClient stream loop that executes received text. Plain /dev/tcp port checks do not match. Test and documentation paths are excluded.",
		Rationale:   "A reverse shell hands an attacker an interactive session from inside the network. It has no place in shipped source, build scripts or container images.",
		Remediation: "Remove it and treat the host or image that ran it as compromised. Identify who added it and how.",
	},
	{
		ID: "ZS-IOC-005", Name: "Crypto mining indicator", Short: "crypto-miner",
		Severity: core.SeverityHigh, CWE: "CWE-506",
		Description: "A stratum pool URL (stratum+tcp, stratum+ssl, stratum2+tcp), a miner binary invoked with pool arguments (xmrig, minerd, cpuminer), an xmrig release download, or a miner config with donate-level and pools. Test and documentation paths are excluded.",
		Rationale:   "Unauthorised mining is a frequent payload of compromised CI pipelines, containers and dependencies, and it spends the owner's compute.",
		Remediation: "Remove the miner and the code that fetches or launches it, then review how it entered the repository and what else the same change touched.",
	},
	{
		ID: "ZS-IOC-006", Name: "Exfiltration endpoint in shipped code", Short: "exfil-endpoint",
		Severity: core.SeverityMedium, CWE: "CWE-912",
		Description: "A request-capture or out-of-band service (webhook.site, ngrok, pipedream, requestbin, interact.sh, oast, burpcollaborator) or a Discord or Telegram bot endpoint written as a URL literal in source code. Test, fixture, documentation and comment-only lines are excluded.",
		Rationale:   "These services exist to receive data from a client the operator does not control. Production code that posts to one is a common way to ship stolen data out, and is a leak even when the intent was a forgotten debug call.",
		Remediation: "Confirm the destination is intended. If not, remove the call and rotate any secret the request could have carried. A legitimate bot notification belongs in configuration, not source.",
	},
	{
		ID: "ZS-IOC-007", Name: "Match against the organisation IOC feed", Short: "feed-match",
		Severity: core.SeverityCritical, CWE: "CWE-506",
		Description: "A domain, IP address or URL from the --ioc-feed file appears in a string literal, URL or config value, or a scanned file's SHA-256 equals a hash in the feed.",
		Rationale:   "The feed lists indicators the organisation has already tied to an incident or threat report, so a hit is a known indicator rather than a heuristic.",
		Remediation: "Follow your incident procedure for the feed entry that matched: isolate the repository, determine the introducing change and rotate reachable credentials.",
	},
	{
		ID: "ZS-IOC-008", Name: "GitHub Action with a published compromise, not pinned to a commit", Short: "compromised-action",
		Severity: core.SeverityHigh, CWE: "CWE-506",
		Description: "A workflow `uses:` line names an action in the compromised-action list (see data/ioc.yaml; every entry cites an advisory) with a ref that is not a 40-character commit SHA.",
		Rationale:   "A tag or branch can be repointed after the fact, which is how these actions were compromised. A full commit SHA cannot be.",
		Remediation: "Pin the action to a full commit SHA that predates the advisory window and is on the fixed release, or remove the action. Rotate secrets exposed to workflow runs that used the affected ref.",
	},
}

func ruleByID(id string) RuleInfo {
	for _, r := range rules {
		if r.ID == id {
			return r
		}
	}
	return RuleInfo{ID: id}
}

// Rules returns the metadata of every IOC rule, in rule-ID order.
func Rules() []RuleInfo { return append([]RuleInfo(nil), rules...) }
