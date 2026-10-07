package secrets

import (
	"bytes"
	"context"
	"math"
	"os"
	"regexp"
	"strings"
	"unicode"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/findings"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/suppress"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"
)

type detector struct {
	ruleID     string
	detectorID string
	pattern    *regexp.Regexp
	severity   core.Severity
	minEntropy float64 // 0 = no entropy filter

	// generic marks a detector that matches by surrounding syntax
	// (password = "...", "token": "...", a URI with credentials) rather than
	// by a provider's own key shape.
	//
	// Only generic detectors get the placeholder and example-host filters
	// below. The split is the whole point: AKIA-prefixed strings, ghp_ tokens
	// and PEM blocks are worth reporting whatever words they contain -- AWS's
	// own documentation key is literally AKIAIOSFODNN7EXAMPLE, and rejecting
	// it for containing "EXAMPLE" would drop a real detector. A generic
	// `password = "test-pw"` carries no such signal and is almost always a
	// fixture.
	generic bool

	// cwe is the weakness this detector's hit represents, carried onto the
	// finding so SARIF consumers and CWE-keyed policy see secret findings at
	// all (they used to ship with no CWE). CWE-798 for credentials, tokens
	// and API keys -- something that authenticates a caller. CWE-321 for key
	// material -- something that signs or encrypts, where the harm is forged
	// or decrypted data rather than a borrowed identity.
	cwe string

	// comparison marks a detector whose whole shape is a value compared
	// against a literal (password === 'x'). The "==" / "!=" entries of
	// assertionContext exist to drop test assertions about credentials;
	// for this detector the comparison IS the hardcoded credential, so only
	// the assertion-call words still apply.
	comparison bool
}

const (
	cweHardcodedCredential = "CWE-798"
	cweHardcodedKey        = "CWE-321"
)

var detectors = []detector{
	{
		ruleID:     "ZS-SEC-001",
		detectorID: "aws-access-key",
		pattern:    regexp.MustCompile(`(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)`),
		severity:   core.SeverityCritical,
	},
	{
		ruleID:     "ZS-SEC-002",
		detectorID: "github-token",
		pattern:    regexp.MustCompile(`(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36})`),
		severity:   core.SeverityCritical,
	},
	{
		ruleID:     "ZS-SEC-003",
		detectorID: "generic-api-key",
		pattern:    regexp.MustCompile(`(?i)api[_\-]?key\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,64})["']?`),
		severity:   core.SeverityHigh,
		minEntropy: 3.0,
		generic:    true,
	},
	{
		ruleID:     "ZS-SEC-004",
		detectorID: "hardcoded-password",
		pattern:    regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{8,})["']`),
		severity:   core.SeverityHigh,
		minEntropy: 3.0,
		generic:    true,
	},
	{
		ruleID:     "ZS-SEC-005",
		detectorID: "private-key-pem",
		pattern:    regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`),
		severity:   core.SeverityCritical,
		cwe:        cweHardcodedKey,
	},
	{
		ruleID:     "ZS-SEC-006",
		detectorID: "sendgrid-api-key",
		pattern:    regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})(?:[^A-Za-z0-9_-]|$)`),
		severity:   core.SeverityCritical,
	},
	{
		ruleID:     "ZS-SEC-007",
		detectorID: "slack-token",
		pattern:    regexp.MustCompile(`(xox[baprs]-[0-9a-zA-Z]{10,48})`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-008",
		detectorID: "stripe-api-key",
		pattern:    regexp.MustCompile(`((?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24})`),
		severity:   core.SeverityCritical,
	},
	{
		ruleID:     "ZS-SEC-009",
		detectorID: "google-cloud-api-key",
		pattern:    regexp.MustCompile(`(AIza[0-9A-Za-z\-_]{35})`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-010",
		detectorID: "azure-secret",
		pattern:    regexp.MustCompile(`(?i)(?:azure[_\-]?secret|azure[_\-]?key)\s*[:=]\s*["']?([a-zA-Z0-9~_.-]{34})["']?`),
		severity:   core.SeverityHigh,
		minEntropy: 3.0,
	},
	{
		ruleID:     "ZS-SEC-011",
		detectorID: "jwt-token",
		pattern:    regexp.MustCompile(`(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`),
		severity:   core.SeverityMedium,
	},
	{
		ruleID:     "ZS-SEC-012",
		detectorID: "mongodb-uri",
		pattern:    regexp.MustCompile(`(mongodb(?:\+srv)?:\/\/[^:\s"']+:[^@\s"']+@[^\s"']+)`),
		severity:   core.SeverityHigh,
		generic:    true,
	},
	{
		ruleID:     "ZS-SEC-013",
		detectorID: "postgresql-uri",
		pattern:    regexp.MustCompile(`(postgres(?:ql)?:\/\/[^:\s"']+:[^@\s"']+@[^\s"']+)`),
		severity:   core.SeverityHigh,
		generic:    true,
	},
	{
		ruleID:     "ZS-SEC-014",
		detectorID: "mysql-uri",
		pattern:    regexp.MustCompile(`(mysql:\/\/[^:\s"']+:[^@\s"']+@[^\s"']+)`),
		severity:   core.SeverityHigh,
		generic:    true,
	},
	{
		ruleID:     "ZS-SEC-015",
		detectorID: "redis-uri",
		pattern:    regexp.MustCompile(`(redis:\/\/(?:[^:\s"']*:[^@\s"']+@)[^\s"']+)`),
		severity:   core.SeverityHigh,
		generic:    true,
	},
	{
		ruleID:     "ZS-SEC-016",
		detectorID: "json-yaml-secret",
		// Deliberately excludes api_key and password/passwd/pwd: ZS-SEC-003 and
		// ZS-SEC-004 already match those keywords on every file type, so keeping
		// them here reported the same line twice. Only the keywords no other
		// detector covers belong in this alternation.
		pattern:    regexp.MustCompile(`(?i)"?(?:secret|access_key|token)"?\s*[:=]\s*"([^"]{6,})"`),
		severity:   core.SeverityMedium,
		minEntropy: 3.0,
		generic:    true,
	},
	{
		ruleID:     "ZS-SEC-017",
		detectorID: "twilio-api-key",
		pattern:    regexp.MustCompile(`(SK[0-9a-fA-F]{32})`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-018",
		detectorID: "mailgun-api-key",
		pattern:    regexp.MustCompile(`(key-[0-9a-zA-Z]{32})`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-019",
		detectorID: "square-access-token",
		pattern:    regexp.MustCompile(`(sq0atp-[0-9A-Za-z\-_]{22})`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-020",
		detectorID: "pypi-token",
		pattern:    regexp.MustCompile(`(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,})`),
		severity:   core.SeverityCritical,
	},
	{
		ruleID:     "ZS-SEC-021",
		detectorID: "npm-token",
		pattern:    regexp.MustCompile(`(npm_[A-Za-z0-9]{32,36})`),
		severity:   core.SeverityCritical,
	},
	{
		ruleID:     "ZS-SEC-022",
		detectorID: "heroku-api-key",
		pattern:    regexp.MustCompile(`(?i)heroku[_\-]?api[_\-]?key\s*[:=]\s*["']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["']?`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-023",
		detectorID: "vault-token",
		pattern:    regexp.MustCompile(`(?:^|[^a-zA-Z0-9])(hvs\.[a-zA-Z0-9_-]{90,}|s\.[a-zA-Z0-9]{24})(?:[^a-zA-Z0-9]|$)`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-024",
		detectorID: "discord-bot-token",
		pattern:    regexp.MustCompile(`([MNO][a-zA-Z\d_-]{23,25}\.[a-zA-Z\d_-]{6}\.[a-zA-Z\d_-]{27})`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-025",
		detectorID: "shopify-token",
		pattern:    regexp.MustCompile(`(shpat_[a-fA-F0-9]{32}|shpca_[a-fA-F0-9]{32})`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-026",
		detectorID: "openai-api-key",
		pattern:    regexp.MustCompile(`(sk-(?:proj-)?[a-zA-Z0-9\-_]{32,})`),
		severity:   core.SeverityHigh,
	},
	{
		// A credential checked against a literal: if (password === 'admin123').
		// ZS-SEC-004 only knows the assignment shape ([:=] then a quote), so
		// the comparison form -- the most common way a backdoor or default
		// login is written -- was invisible. The key may be a subscript or
		// property (req.body.password, request.form['password']), hence the
		// optional closing quote/bracket before the operator.
		ruleID:     "ZS-SEC-027",
		detectorID: "hardcoded-password-comparison",
		pattern:    regexp.MustCompile(`(?i)(?:password|passwd|pwd)['"\]]*\s*(?:===?|!==?)\s*["']([^"']{4,})["']`),
		severity:   core.SeverityHigh,
		generic:    true,
		comparison: true,
	},
	{
		// XML credential elements: <password>...</password> in config.xml,
		// web.config-style files and Maven settings. The key=value detectors
		// never see these because the value sits between tags.
		ruleID:     "ZS-SEC-028",
		detectorID: "xml-credential",
		pattern:    regexp.MustCompile(`(?i)<(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)>\s*([^<\s][^<]{3,}?)\s*</`),
		severity:   core.SeverityHigh,
		generic:    true,
	},
	{
		// Node-provider API keys embedded in the RPC URL path rather than in
		// a key= parameter: wss://eth-mainnet.g.alchemy.com/v2/<key> and
		// https://mainnet.infura.io/v3/<project-id>. The path segment is the
		// whole credential, so the provider's own URL shape is the signal.
		ruleID:     "ZS-SEC-029",
		detectorID: "rpc-url-api-key",
		pattern:    regexp.MustCompile(`(?:alchemy\.com/v2/|alchemyapi\.io/v2/|infura\.io/v3/)([A-Za-z0-9_-]{20,})`),
		severity:   core.SeverityHigh,
	},
	{
		// A base32 TOTP/MFA seed. Anyone holding it generates valid one-time
		// codes forever, so it is key material (CWE-321), not a password.
		ruleID:     "ZS-SEC-030",
		detectorID: "totp-seed",
		pattern:    regexp.MustCompile(`(?i:totp|otp|mfa|2fa)[_-]?(?i:secret|seed|key)['"]?\s*[:=]\s*['"]?([A-Z2-7]{16,})(?:['"\s,;]|$)`),
		severity:   core.SeverityHigh,
		minEntropy: 3.0,
		generic:    true,
		cwe:        cweHardcodedKey,
	},
}

// weakness returns the CWE a detector's findings carry. Every detector not
// explicitly marked as key material is a credential or token.
func (d detector) weakness() string {
	if d.cwe != "" {
		return d.cwe
	}
	return cweHardcodedCredential
}

// SecretsScanner detects hardcoded secrets via regex patterns.
// Pure Go — no CGo, testable on Windows without gcc.
type SecretsScanner struct{}

// New returns a SecretsScanner.
func New() *SecretsScanner { return &SecretsScanner{} }

func (s *SecretsScanner) Name() string { return "secrets" }

func (s *SecretsScanner) Accepts(entry walker.FileEntry) bool {
	return !entry.IsBinary
}

func (s *SecretsScanner) Scan(_ context.Context, files []walker.FileEntry) ([]core.Finding, []analyzer.Diagnostic, error) {
	var out []core.Finding
	for _, entry := range files {
		data, err := os.ReadFile(entry.Path)
		if err != nil {
			continue
		}
		out = append(out, scanContent(entry.Path, data)...)
	}
	return out, nil, nil
}

func scanContent(path string, data []byte) []core.Finding {
	var out []core.Finding

	// Structured passes first. A dotenv or compose line they already judged
	// (reported or deliberately rejected) is not re-judged by the line
	// regexes below, which would otherwise report the same credential twice
	// under a second rule ID, or report the `${VAR}` reference the structured
	// pass correctly recognised as indirection.
	handled := map[int]bool{}
	if isDotenvFile(path) {
		fs, lines := scanDotenv(path, data)
		out = append(out, fs...)
		for l := range lines {
			handled[l] = true
		}
	}
	if isComposeFile(path) {
		fs, lines := scanCompose(path, data)
		out = append(out, fs...)
		for l := range lines {
			handled[l] = true
		}
	}

	lines := bytes.Split(data, []byte("\n"))
	for lineNum, line := range lines {
		for _, d := range detectors {
			if d.generic && handled[lineNum+1] {
				continue
			}
			match := d.pattern.FindSubmatch(line)
			if match == nil {
				continue
			}
			// Use captured group (index 1) if present, else full match.
			captured := match[0]
			if len(match) > 1 {
				captured = match[1]
			}
			if d.minEntropy > 0 && shannonEntropy(string(captured)) < d.minEntropy {
				continue
			}
			if suppress.Suppressed(data, lineNum+1, lineNum+1, d.ruleID) {
				continue
			}
			if d.generic && !plausibleSecret(captured, line, d.comparison) {
				continue
			}
			out = append(out, newFinding(d.detectorID, d.ruleID, d.weakness(), path, lineNum+1, captured, d.severity))
		}
	}
	return out
}

// newFinding builds a secret finding with its CWE attached.
func newFinding(detectorID, ruleID, cwe, path string, line int, captured []byte, sev core.Severity) core.Finding {
	return findings.BuildSecretFinding(
		detectorID,
		ruleID,
		detectorID,
		"Potential "+detectorID+" detected",
		path,
		line,
		captured,
		shannonEntropy(string(captured)),
		sev,
		[]string{cwe},
	)
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, c := range freq {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// placeholderTokens are substrings that mark a value as a stand-in rather than
// a live credential. Applied only to generic detectors -- see detector.generic.
var placeholderTokens = []string{
	"canary", "example", "dummy", "sample", "placeholder",
	"dev-only", "dev_only", "test-", "test_", "fake", "changeme",
	"change-me", "xxx", "your-", "your_", "redacted", "notreal",
	"todo", "insecure", "dontuse",
}

// exampleHosts are reserved or non-routable hosts. A URI pointing at one is
// documentation or a fixture: RFC 2606 reserves example.com/.net/.org and the
// .test/.invalid TLDs precisely so they can never be a real endpoint.
// Restricted to the domains RFC 2606 and RFC 6761 reserve so they can never
// resolve to a real endpoint. Deliberately NOT localhost/127.0.0.1: a
// committed mongodb://admin:secretpass123@localhost is a real hardcoded
// credential, and the host being local says nothing about whether the
// password is. The canary case that motivated this filter is caught by the
// placeholder vocabulary and the assertion context instead.
var exampleHosts = []string{
	"example.com", "example.net", "example.org",
	".invalid", ".test",
}

// assertionContext marks a line where the value is being compared rather than
// used -- a test asserting that a credential does NOT appear in output is the
// control, not the vulnerability. The report that motivated this flagged a
// credential-redaction canary test as a leaked mongodb URI.
var assertionContext = []string{
	"assert", "expect(", "should", "assertequal", "assertnotin",
	"tobe(", "toequal(", "!=", "==",
}

// plausibleSecret reports whether a generic-detector hit looks like a live
// credential rather than a placeholder, an example endpoint, or an assertion
// operand. line is the full source line, which carries the context the
// captured value alone cannot show.
func plausibleSecret(captured, line []byte, comparison bool) bool {
	if !plausibleValue(string(captured)) {
		return false
	}
	l := strings.ToLower(string(line))
	for _, a := range assertionContext {
		if comparison && (a == "==" || a == "!=") {
			continue
		}
		if strings.Contains(l, a) {
			return false
		}
	}
	return true
}

// interpolationMarkers are the openers of a template or shell expansion. A
// captured "value" containing one is a reference to a secret resolved at run
// time -- password = '${security.hash(req.body.password)}' inside a SQL
// template, TOKEN="$(cat $TOKEN_FILE)" in a shell script, {{ .Values.pw }} in
// a Helm chart -- never the literal secret itself.
var interpolationMarkers = []string{"${", "$(", "{{", "<%", "#{", "%("}

// htmlTagRe matches an HTML/XML tag inside a captured value. Documentation
// pages that show an injection payload (password='<b>anything' OR '1'='1</b>')
// match the password='...' shape, but markup inside the value marks it as
// rendered prose rather than a credential.
var htmlTagRe = regexp.MustCompile(`<[a-zA-Z/!][^>]*>`)

// plausibleValue reports whether a captured generic value looks like a live
// credential rather than a placeholder, an example endpoint, a run-time
// reference, or prose. It looks at the value only; plausibleSecret adds the
// line-context checks.
func plausibleValue(captured string) bool {
	raw := strings.TrimSpace(captured)
	if raw == "" {
		return false
	}

	// A value wrapped in angle brackets is a documentation placeholder, never
	// a live credential: <your-password>, <dev sentinel value>,
	// SEED_ADMIN_PASSWORD='<a real password>'. Checked before the vocabulary
	// list because the give-away is the shape, not the words inside -- the
	// words are usually a description of the secret rather than any of the
	// tokens below. This is what kept a deployment guide and two triage
	// documents in the report.
	if strings.HasPrefix(raw, "<") && strings.HasSuffix(raw, ">") {
		return false
	}
	for _, m := range interpolationMarkers {
		if strings.Contains(raw, m) {
			return false
		}
	}
	// $NAME / %NAME% are shell and batch variable references.
	if raw[0] == '$' || (raw[0] == '%' && strings.HasSuffix(raw, "%")) {
		return false
	}
	if htmlTagRe.MatchString(raw) {
		return false
	}
	// Whitespace inside the value means a sentence, not a secret: a UI
	// string ("no_secret": "Only admin can access, ..."), an i18n label
	// ("INVALID_TOKEN": "Invalid token"), a log message. Generated secrets
	// and real-world passwords practically never contain spaces, and the
	// cost of missing the rare passphrase is far below the cost of
	// reporting every translated label that mentions a token.
	if strings.IndexFunc(raw, unicode.IsSpace) >= 0 {
		return false
	}

	v := strings.ToLower(raw)
	// A credential variable compared to or set to a language sentinel
	// (newPassword === 'undefined', <password>null</password>) is a check for
	// absence, not a secret.
	switch v {
	case "null", "none", "nil", "undefined", "true", "false", "empty":
		return false
	}
	for _, t := range placeholderTokens {
		if strings.Contains(v, t) {
			return false
		}
	}
	for _, h := range exampleHosts {
		if strings.Contains(v, h) {
			return false
		}
	}
	return true
}
