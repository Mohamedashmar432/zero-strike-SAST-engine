"""Regenerate dvwa/ground-truth.json from a DVWA clone at the pinned commit.
Usage: python -I gen_ground_truth.py <dvwa-clone> > ground-truth.json
Line numbers are located by regex per file, so the output is exact for the pinned SHA."""
import json, re, sys
ROOT = sys.argv[1]
V = "vulnerabilities"
SQL = ("sql_injection", "CWE-89", ["CWE-89", "CWE-564"])
XSS = ("xss", "CWE-79", ["CWE-79", "CWE-80", "CWE-83", "CWE-116"])
CMD = ("command_injection", "CWE-78", ["CWE-78", "CWE-77", "CWE-88"])
FI = ("file_inclusion", "CWE-98", ["CWE-98", "CWE-22", "CWE-73", "CWE-829", "CWE-94"])
UP = ("file_upload", "CWE-434", ["CWE-434", "CWE-22", "CWE-73"])
CSRF = ("csrf", "CWE-352", ["CWE-352"])
RED = ("open_redirect", "CWE-601", ["CWE-601", "CWE-113"])
WID = ("weak_session_id", "CWE-330", ["CWE-330", "CWE-331", "CWE-338", "CWE-341", "CWE-340", "CWE-614", "CWE-1004", "CWE-1275"])
HASH = ("weak_hash", "CWE-328", ["CWE-328", "CWE-327", "CWE-916", "CWE-759"])
SEC = ("hardcoded_secret", "CWE-798", ["CWE-798", "CWE-321", "CWE-259", "CWE-547"])
ECB = ("weak_crypto", "CWE-327", ["CWE-327", "CWE-326", "CWE-329", "CWE-780"])
items = []; n = {}
def add(module, level, file, rx, cls, vuln, only=None, note=""):
    lines = open(f"{ROOT}/{file}", encoding="utf-8", errors="replace").read().split("\n")
    hits = [i + 1 for i, l in enumerate(lines) if re.search(rx, l)]
    if only is not None: hits = [hits[i] for i in only if i < len(hits)]
    assert hits, (file, rx)
    for h in hits:
        k = f"dvwa-{module}-{level}-{cls[0]}"; n[k] = n.get(k, 0) + 1
        items.append(dict(id=f"{k}-{n[k]}", repo_file=file, is_vulnerable=vuln, vulnerability_class=cls[0], primary_cwe=cls[1],
                          acceptable_cwes=cls[2], file=file, location=dict(start_line=h, end_line=h),
                          description=(note or f"{module}/{level}: {'vulnerable' if vuln else 'safe'} {cls[0]} sink")))
def src(m, l): return f"{V}/{m}/source/{l}.php"
for l in ("low", "medium", "high"):
    add("sqli", l, src("sqli", l), r'\$query\s*=.*user_id', SQL, True)
    add("sqli_blind", l, src("sqli_blind", l), r'\$query\s*=.*user_id', SQL, True)
    add("brute", l, src("brute", l), r'\$query\s*=.*FROM `users`', SQL, True)
    add("brute", l, src("brute", l), r'md5\(', HASH, True)
    add("csrf", l, src("csrf", l), r'mysqli_query.*\$insert', CSRF, True)
    add("csrf", l, src("csrf", l), r'md5\(', HASH, True)
    add("captcha", l, src("captcha", l), r'mysqli_query.*\$insert', CSRF, True)
    add("captcha", l, src("captcha", l), r'md5\(', HASH, True)
    add("exec", l, src("exec", l), r'shell_exec', CMD, True)
    add("fi", l, src("fi", l), r"\$file = \$_GET", FI, True)
    add("upload", l, src("upload", l), r'move_uploaded_file\(', UP, True)
    add("xss_s", l, src("xss_s", l), r'INSERT INTO guestbook', XSS, True)
    add("xss_s", l, src("xss_s", l), r'INSERT INTO guestbook', SQL, False, note="inputs pass mysqli_real_escape_string before the INSERT (safe look-alike for SQLi)")
add("xss_r", "low", src("xss_r", "low"), r"Hello", XSS, True)
add("xss_r", "medium", src("xss_r", "medium"), r"Hello", XSS, True)
add("xss_r", "high", src("xss_r", "high"), r"Hello", XSS, True)
add("open_redirect", "low", src("open_redirect", "low"), r"header \(", RED, True)
add("open_redirect", "medium", src("open_redirect", "medium"), r"header \(", RED, True)
add("open_redirect", "high", src("open_redirect", "high"), r"header \(", RED, True)
add("weak_id", "low", src("weak_id", "low"), r"setcookie", WID, True)
add("weak_id", "medium", src("weak_id", "medium"), r"setcookie", WID, True)
add("weak_id", "high", src("weak_id", "high"), r"setcookie", WID, True)
add("csp", "low", src("csp", "low"), r"\$_POST\['include'\]", XSS, True)
add("csp", "medium", src("csp", "medium"), r"\$_POST\['include'\]", XSS, True)
add("csp", "high", src("csp", "high"), r"\$_POST\['include'\]", XSS, True)
add("csp", "jsonp", f"{V}/csp/source/jsonp.php", r"echo \$callback", XSS, True)
add("xss_d", "all", f"{V}/xss_d/index.php", r"document\.write\(\"<option value='\" \+ lang", XSS, True)
add("fi", "all", f"{V}/fi/index.php", r"include\( \$file \)", FI, True)
add("cryptography", "low", src("cryptography", "low"), r'^\$key = ', SEC, True)
add("cryptography", "medium", src("cryptography", "medium"), r'aes-128-ecb', ECB, True)
add("cryptography", "medium", src("cryptography", "medium"), r'^\$key = ', SEC, True)
add("cryptography", "high", src("cryptography", "token_library_high"), r'define \("KEY"', SEC, True)
add("cryptography", "high", src("cryptography", "token_library_high"), r'define \("IV"', ECB, True, note="static IV for CBC")
# impossible: safe traps at the corresponding sinks
for m, rx, cls in [("sqli", r"prepare\(", SQL), ("sqli_blind", r"prepare\(", SQL), ("brute", r"prepare\( 'SELECT \* FROM users", SQL),
                   ("csrf", r"prepare\( 'UPDATE users", CSRF), ("captcha", r"prepare\( 'UPDATE users", CSRF),
                   ("exec", r"shell_exec", CMD), ("upload", r"rename\(", UP), ("xss_r", r"Hello", XSS), ("xss_s", r"prepare\(", XSS),
                   ("open_redirect", r"header \(", RED), ("weak_id", r"setcookie", WID)]:
    add(m, "impossible", src(m, "impossible"), rx, cls, False)
add("fi", "impossible", src("fi", "impossible"), r"\$file = \$_GET", FI, False)
add("cryptography", "impossible", src("cryptography", "token_library_impossible"), r"aes-256-gcm", ECB, False, note="AES-GCM with random IV")
gt = dict(repo_url="https://github.com/digininja/DVWA", commit_sha=open(__file__.replace("gen_ground_truth.py", "SOURCE.txt")).read().split("commit:")[1].split()[0],
          findings=items)
print(json.dumps(gt, indent=1))
