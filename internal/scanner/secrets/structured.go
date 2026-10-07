package secrets

import (
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/scanner/framework"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/suppress"
)

// Structured secret passes: file formats whose values are unquoted, so the
// line regexes (which anchor on a quote after [:=]) never see them.
//
//   - dotenv:          SQL_PASSWORD=mysecretpassword
//   - compose:         environment: { MYSQL_ROOT_PASSWORD: mysecretpassword }
//
// Both are judged by KEY NAME rather than by entropy. A committed .env with
// JWT_SECRET=access is a real hardcoded signing key precisely because the
// value is guessable; an entropy gate would keep only the strong secrets and
// drop the weak ones, which are the worse finding.

const (
	ruleDotenvSecret  = "ZS-SEC-031"
	ruleComposeSecret = "ZS-SEC-032"
)

// credentialKeyRe matches a configuration key that names a credential.
var credentialKeyRe = regexp.MustCompile(`(?i)(PASSWORD|PASSWD|PWD|PASSPHRASE|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|AUTH_?KEY|CLIENT_?KEY|SIGNING_?KEY|ENCRYPTION_?KEY|APP_?KEY|MASTER_?KEY)`)

// nonValueKeyRe matches keys that mention a credential but configure
// something about it rather than holding it: TOKEN_EXPIRES_IN=3600,
// PASSWORD_MIN_LENGTH=8, JWT_SECRET_FILE=/run/secrets/jwt. The suffix is what
// separates the setting from the secret.
var nonValueKeyRe = regexp.MustCompile(`(?i)_(URL|URI|HOST|PORT|PATH|FILE|DIR|EXPIRY|EXPIRES|EXPIRES_IN|EXPIRATION|TTL|LIFETIME|AGE|LENGTH|LEN|ALGORITHM|ALG|NAME|USER|USERNAME|HEADER|ISSUER|AUDIENCE|TYPE|ENABLED|DISABLED|TIMEOUT|REGION|ID|PREFIX|FIELD|ROUNDS|COST|VERSION|ENDPOINT)$`)

// keyMaterialKeyRe marks a credential-named key whose value signs or encrypts
// (CWE-321) rather than authenticates a caller (CWE-798): JWT_SECRET,
// SESSION_SECRET, SECRET_KEY_BASE, ENCRYPTION_KEY, APP_KEY.
var keyMaterialKeyRe = regexp.MustCompile(`(?i)(JWT|SIGNING|SIGN_|HMAC|ENCRYPT|CIPHER|AES|CRYPT|SESSION_?SECRET|COOKIE_?SECRET|SECRET_?KEY_?BASE|^SECRET_?KEY$|APP_?KEY|MASTER_?KEY|PRIVATE_?KEY)`)

// numericOrBoolRe matches values that cannot be a secret: a bare number or a
// boolean flag (SECRET_ROTATION=true).
var numericOrBoolRe = regexp.MustCompile(`(?i)^([0-9]+|true|false|yes|no|on|off|null|none|nil|undefined)$`)

// credentialKeyCWE classifies a credential-named key, or returns "" when the
// key does not name a stored secret at all.
func credentialKeyCWE(key string) string {
	if !credentialKeyRe.MatchString(key) || nonValueKeyRe.MatchString(key) {
		return ""
	}
	if keyMaterialKeyRe.MatchString(key) {
		return cweHardcodedKey
	}
	return cweHardcodedCredential
}

// credentialValueOK reports whether a structured value is a literal secret
// worth reporting: non-trivial, not a ${VAR} reference, not a placeholder.
func credentialValueOK(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < 3 || numericOrBoolRe.MatchString(v) {
		return false
	}
	return plausibleValue(v)
}

// isDotenvFile reports whether path is a dotenv file that holds real values.
// Template files (.env.example, .env.sample, .env.template, .env.dist) exist
// precisely to be committed with stand-in values, so they are excluded.
func isDotenvFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base != ".env" && !strings.HasPrefix(base, ".env.") && !strings.HasSuffix(base, ".env") {
		return false
	}
	for _, t := range []string{"example", "sample", "template", "tmpl", "dist", "schema", "defaults"} {
		if strings.Contains(base, t) {
			return false
		}
	}
	return true
}

// scanDotenv reports credential-named keys with literal values in a dotenv
// file, and returns every line it judged (reported or rejected) so the line
// regexes do not re-judge them.
func scanDotenv(path string, data []byte) ([]core.Finding, map[int]bool) {
	var out []core.Finding
	judged := map[int]bool{}
	for _, e := range framework.ParseEnvFile(data) {
		cwe := credentialKeyCWE(e.Key)
		if cwe == "" {
			continue
		}
		judged[e.Line] = true
		if !credentialValueOK(e.Value) || suppress.Suppressed(data, e.Line, e.Line, ruleDotenvSecret) {
			continue
		}
		out = append(out, newFinding("dotenv-secret", ruleDotenvSecret, cwe, path, e.Line, []byte(e.Value), core.SeverityHigh))
	}
	return out, judged
}

// isComposeFile mirrors framework.isDockerComposeFile: docker-compose.yml,
// compose.yaml and their docker-compose.<env>.yml variants.
func isComposeFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if !strings.HasSuffix(base, ".yml") && !strings.HasSuffix(base, ".yaml") {
		return false
	}
	return strings.HasPrefix(base, "docker-compose.") || strings.HasPrefix(base, "compose.") ||
		base == "docker-compose.yml" || base == "docker-compose.yaml"
}

// scanCompose reports literal credential values under services.*.environment
// in a compose file. Both environment forms are handled:
//
//	environment:                 environment:
//	  DB_PASSWORD: hunter2         - DB_PASSWORD=hunter2
//
// A ${VAR} or ${VAR:-default} value is the compose idiom for "read it from the
// host environment" and is skipped; that is the fix for this finding.
func scanCompose(path string, data []byte) ([]core.Finding, map[int]bool) {
	var out []core.Finding
	judged := map[int]bool{}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return nil, judged
	}
	services := mappingValue(doc.Content[0], "services")
	if services == nil || services.Kind != yaml.MappingNode {
		return nil, judged
	}
	report := func(key, value string, line int) {
		cwe := credentialKeyCWE(key)
		if cwe == "" {
			return
		}
		judged[line] = true
		if !credentialValueOK(value) || suppress.Suppressed(data, line, line, ruleComposeSecret) {
			return
		}
		out = append(out, newFinding("compose-env-secret", ruleComposeSecret, cwe, path, line, []byte(value), core.SeverityMedium))
	}
	for i := 1; i < len(services.Content); i += 2 {
		env := mappingValue(services.Content[i], "environment")
		if env == nil {
			continue
		}
		switch env.Kind {
		case yaml.MappingNode:
			for j := 0; j+1 < len(env.Content); j += 2 {
				k, v := env.Content[j], env.Content[j+1]
				if v.Kind == yaml.ScalarNode {
					report(k.Value, v.Value, k.Line)
				}
			}
		case yaml.SequenceNode:
			for _, item := range env.Content {
				if item.Kind != yaml.ScalarNode {
					continue
				}
				if k, v, ok := strings.Cut(item.Value, "="); ok {
					report(strings.TrimSpace(k), v, item.Line)
				}
			}
		}
	}
	return out, judged
}

// mappingValue returns the value node for key in a YAML mapping node, or nil.
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}
