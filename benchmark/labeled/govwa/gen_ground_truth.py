"""Regenerate govwa/ground-truth.json from a govwa clone at the pinned commit.
Usage: python -I gen_ground_truth.py <govwa-clone> > ground-truth.json
Labels are located by regex in files that were read at the pinned SHA; the run fails if an anchor no longer matches."""
import json, re, sys
ROOT = sys.argv[1]
SQL = ("sql_injection", "CWE-89", ["CWE-89", "CWE-564", "CWE-943"])
XSS = ("xss", "CWE-79", ["CWE-79", "CWE-80", "CWE-83", "CWE-116"])
IDOR = ("idor", "CWE-639", ["CWE-639", "CWE-284", "CWE-285", "CWE-345", "CWE-566", "CWE-863"])
HASH = ("weak_hash", "CWE-328", ["CWE-328", "CWE-327", "CWE-916", "CWE-759"])
SEC = ("hardcoded_secret", "CWE-798", ["CWE-798", "CWE-259", "CWE-321", "CWE-547", "CWE-615"])
ERR = ("information_exposure", "CWE-209", ["CWE-209", "CWE-200", "CWE-210", "CWE-497"])
COOK = ("insecure_cookie", "CWE-1004", ["CWE-1004", "CWE-614", "CWE-732"])
CORS = ("permissive_cors", "CWE-942", ["CWE-942", "CWE-346", "CWE-1385"])
AUTH = ("missing_authentication", "CWE-306", ["CWE-306", "CWE-862", "CWE-284", "CWE-285"])
items = []; n = {}
def add(mod, file, rx, cls, vuln, occ=0, span=1, note=""):
    lines = open(f"{ROOT}/{file}", encoding="utf-8-sig", errors="replace").read().split("\n")
    hits = [i + 1 for i, l in enumerate(lines) if re.search(rx, l)]
    assert len(hits) > occ, (file, rx, hits)
    s = hits[occ]
    k = f"govwa-{mod}-{cls[0]}"; n[k] = n.get(k, 0) + 1
    items.append(dict(id=f"{k}-{n[k]}" + ("" if vuln else "-safe"), repo_file=file, is_vulnerable=vuln, vulnerability_class=cls[0],
        primary_cwe=cls[1], acceptable_cwes=cls[2], file=file, location=dict(start_line=s, end_line=s + span - 1),
        description=note or f"{mod}: {'vulnerable' if vuln else 'safe'} {cls[0]} sink"))
V = "vulnerability"
# SQL injection lesson (levels low = unsafe, high = prepared)
add("sqli", f"{V}/sqli/function.go", r"getProfileSql := fmt\.Sprintf\(", SQL, True, span=5, note="UnsafeQueryGetData: uid formatted into the query, then DB.Query (comment: here is the vulnerable query)")
add("sqli", f"{V}/sqli/function.go", r"stmt, err := DB\.Prepare\(getProfileSql\)", SQL, False, span=7, note="SafeQueryGetData: prepared statement (high level)")
add("sqli", f"{V}/sqli/sqli.go", r'data\["error"\] = err\.Error\(\)', ERR, True, note="raw SQL error returned to the client (comment: this will return error query to client)")
add("idor", f"{V}/idor/function.go", r"stmt, err := DB\.Prepare\(getProfileSql\)", SQL, False, span=7, note="GetData: prepared statement")
add("idor", f"{V}/idor/function.go", r"stmt, err := DB\.Prepare\(sql\)", SQL, False, span=5, note="UpdateProfile: prepared statement")
add("login", "user/user.go", r"stmt, err := db\.Prepare\(sql\)", SQL, False, span=6, note="login query is prepared")
# XSS lesson (template.HTML is the documented vulnerable function)
add("xss1", f"{V}/xss/xss.go", r"data\[\"value\"\] = template\.HTML\(value\)", XSS, True, occ=0, note="term converted to template.HTML after a bypassable script-tag filter")
add("xss1", f"{V}/xss/xss.go", r"data\[\"term\"\] = template\.HTML\(notFound\)", XSS, True, note="comment: vulnerable function")
add("xss1", f"{V}/xss/xss.go", r"data\[\"value\"\] = template\.HTML\(value\)", XSS, True, occ=1)
add("xss1", f"{V}/xss/xss.go", r"data\[\"term\"\] = template\.HTML\(vuln\)", XSS, True)
add("xss2", f"{V}/xss/xss.go", r"inlineJS := fmt\.Sprintf\(js,uid", XSS, True, span=5, note="request uid written into an inline script and rendered as template.HTML (comment: here is the mistake)")
add("xss1", f"{V}/xss/xss.go", r"term = HTMLEscapeString\(term\)", XSS, False, note="high level escapes the term")
add("xss2", f"{V}/xss/xss.go", r"uid = HTMLEscapeString\(uid\)", XSS, False, note="high level escapes the uid")
# IDOR lesson
add("idor1", f"{V}/idor/idor.go", r"if uid != cid \|\| uid == \"\" \|\| cid == \"\"", IDOR, True, span=13, note="level low: the uid and the Uid cookie both come from the client, so any user id can be updated")
add("idor2", f"{V}/idor/idor.go", r"if sign != signature", IDOR, True, span=13, note="level low: the signature is MD5 of the client-supplied uid, so it can be forged")
add("idor2", f"{V}/idor/idor.go", r"hasher := md5\.New\(\)", HASH, True, note="MD5 used as the IDOR integrity signature")
# client side authentication lesson
add("csa", f"{V}/csa/csa.go", r'sotp := "a587cd6bf1e49d2c3928d1f8b86f248b"', SEC, True, note="hardcoded OTP digest")
add("csa", f"{V}/csa/csa.go", r"hasher := md5\.New\(\)", HASH, True, note="OTP compared as unsalted MD5")
# authentication, session, cookies, configuration
add("login", "user/user.go", r"pass := Md5Sum\(r\.FormValue\(\"password\"\)\)", HASH, True, note="passwords stored as unsalted MD5")
add("login", "user/user.go", r"^uname : admin", SEC, True, span=5, note="default credentials documented in a source comment")
add("setup", "setup/function.go", r"InsertUsers = ", SEC, True, note="default users with MD5 password digests seeded by setup")
add("session", "user/session/session.go", r"HttpOnly: false, //set to false for xss", COOK, True, occ=0, note="session cookie HttpOnly deliberately false, no Secure flag")
add("session", "user/session/session.go", r"HttpOnly: false, //set to false for xss", COOK, True, occ=1, note="delete-session options, HttpOnly false")
add("cookie", "util/cookie.go", r"cookie := http\.Cookie\{", COOK, True, span=6, note="Level and Uid cookies set without HttpOnly or Secure")
add("config", "config/config.json", r'"password": "govwaP@ss"', SEC, True, note="database password in the shipped config")
add("config", "config/config.json", r'"sessionkey:": "G0Vw444"', SEC, True, note="session cookie signing key in the shipped config")
add("cors", "util/template.go", r'Access-Control-Allow-Origin", "\*"', CORS, True, span=2, note="wildcard origin together with Allow-Credentials true")
add("setup", "setup/setup.go", r'r\.GET\("/setup"', AUTH, True, span=2, note="setup and database reset routes are registered without AuthCheck")
add("middleware", "util/middleware/middleware.go", r"http\.Error\(w, err\.Error\(\), http\.StatusInternalServerError\)", ERR, True, note="recovered panic message returned to the client")
gt = dict(repo_url="https://github.com/0c34/govwa", commit_sha=open(__file__.replace("gen_ground_truth.py", "SOURCE.txt")).read().split("commit:")[1].split()[0], findings=items)
print(json.dumps(gt, indent=1))
