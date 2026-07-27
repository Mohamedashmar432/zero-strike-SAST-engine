Goal

Close security coverage gaps by strengthening rule semantics, source/sink modeling, and framework-specific detections while keeping the current parser and language support unchanged.

What Needs to Be Built

1) Stronger taint-aware detection for injection classes

Improve detection when tainted data reaches risky sinks, including indirect construction patterns.

Cover:

SQL injection
command injection
SSRF
XSS / DOM XSS
template injection
NoSQL injection
LDAP injection
XPath injection
JNDI injection
format string injection
prototype pollution
Required rule-engine improvements:

recognize direct calls, wrapper/helper functions, chained calls, string concatenation/interpolation, object property writes, and assignment-based sinks
propagate taint through function arguments, return values, local reassignments, object fields where applicable, and common helper wrappers
detect tainted input in query strings, shell commands, URL constructors, template render calls, DOM sinks, regex constructors, and dynamic reflection/code execution APIs
2) Expand framework and configuration misconfiguration checks

Add rules for insecure framework settings and security posture issues.

Cover:

disabled or weak CSP
insecure cookie flags
insecure TLS settings
HSTS misconfiguration
debug mode enabled
verbose error exposure
permissive CORS policies
exposed administrative endpoints
insecure CSRF exclusions or bypasses
missing helmet/security middleware patterns where relevant
Required work:

detect misconfigurations in both code and config files
support multi-file context where needed
identify security posture issues even without explicit taint flow
3) Strengthen file and archive safety checks

Improve rules for unsafe file operations and archive handling.

Cover:

path traversal
arbitrary file read/write
unsafe file download helpers
unsafe sendFile / readFile / open patterns
zip slip / tar slip
unsafe archive extraction
symlink traversal
temp-file race conditions
unsafe upload-to-path logic
Required work:

track user-controlled path input into file APIs
flag file operations without normalization, allowlisting, or path confinement
detect unsafe extraction patterns in archive APIs
4) Improve authentication and token handling rules

Expand coverage for insecure auth and token logic.

Cover:

JWT parsing or decoding without verification
alg:none usage
weak JWT secrets
missing token validation steps such as expiry or audience checks
insecure password encoder usage
insecure session handling
insecure cookie construction
Required work:

model auth APIs and common auth helper patterns as sinks
recognize insecure options in token verification libraries
detect dangerous defaults and insecure configuration flags
5) Improve cryptography rules

Catch insecure primitives and dangerous options.

Cover:

weak hashes: MD5, SHA-1
weak ciphers: DES, RC4, 3DES where applicable
insecure crypto modes
fixed or weak IV usage
hardcoded keys, salts, or secrets
predictable random number generation
deprecated TLS / SSL protocol versions
Required work:

detect unsafe algorithm names and insecure parameter values
catch hardcoded values passed into crypto setup
identify weak randomness used for tokens, passwords, or secrets
6) Improve logging and sensitive data exposure rules

Detect accidental disclosure and log injection risks.

Cover:

secrets or credentials logged directly
request/response data logged unsafely
sensitive values inside exception messages
stack traces exposed in production-sensitive paths
log injection / CRLF injection patterns
telemetry or debug output leaking secrets
Required work:

add heuristics for sensitive variable names and credential-shaped values
detect logging sinks across common logger APIs
flag message construction that includes tainted or secret-like content
7) Improve DOM and client-side browser security rules

Expand browser-side vulnerability detection.

Cover:

DOM XSS via unsafe HTML sinks
unsafe innerHTML, outerHTML, insertAdjacentHTML
document.write
location.href / redirect assignment from untrusted data
unsafe javascript: URI usage
insecure iframe / script attributes
missing SRI on external scripts
insecure form submission over HTTP
tabnabbing-related patterns
Required work:

handle inline script extraction from HTML
track user-controlled values into browser sinks
detect insecure attributes and tag patterns in HTML templates
Architecture Changes Needed

A. Rule model enhancements

Update rules so they can express:

multiple sinks per rule
sink families instead of exact APIs
taint-sensitive conditions
configuration-value matching
negation / exclusions for safe variants
framework-specific variants of the same issue
B. Analyzer improvements

Strengthen analysis so it can:

track taint through assignments and returns more accurately
understand common wrapper/helper functions
reduce false negatives for indirect flows
reduce false positives with safe/validated patterns
C. IR and matching improvements

Improve matching so rules can recognize:

method calls
property assignments
chained expressions
nested calls
config object literals
framework-specific constructs
HTML attributes and embedded script patterns
D. Test and benchmark expansion

Add or update fixtures for:

vulnerable and clean examples
positive and negative cases
framework configs
HTML/browser cases
multi-file or indirect-flow cases
Constraints

Do not add new language support
Reuse the existing parser / IR / rule architecture
Focus on rule coverage, sink modeling, taint flow, and framework misconfiguration detection
Preserve current scanner behavior for already passing rules unless intentionally tightening a vulnerable pattern
Avoid noisy rules that create high false positives
Acceptance Criteria

This is complete when:

the engine detects more security issues from the existing benchmark corpus
indirect and wrapper-based vulnerable patterns are detected reliably
framework misconfigurations are covered more consistently
rules distinguish safe and unsafe variants with fewer false positives
benchmark tests pass for both vulnerable and clean cases
new or updated rules are documented and validated by the rule loader
Suggested Implementation Order

Extend rule definitions and sink/source modeling
Improve taint propagation and wrapper handling
Add or refine misconfiguration rules
Expand file/archive/auth/crypto/logging/browser rule coverage
Add regression tests and benchmark fixtures
Validate against clean samples to control false positives