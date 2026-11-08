"""Regenerate xvwa/ground-truth.json from an XVWA clone at the pinned commit.
Usage: python -I gen_ground_truth.py <xvwa-clone> > ground-truth.json
Each label is located by regex in a file that was read at the pinned SHA; the run fails if an anchor no longer matches."""
import json, re, sys
ROOT = sys.argv[1]
V = "vulnerabilities"
SQL = ("sql_injection", "CWE-89", ["CWE-89", "CWE-564", "CWE-943"])
XSS = ("xss", "CWE-79", ["CWE-79", "CWE-80", "CWE-83", "CWE-116"])
CMD = ("command_injection", "CWE-78", ["CWE-78", "CWE-77", "CWE-88"])
FI = ("file_inclusion", "CWE-98", ["CWE-98", "CWE-22", "CWE-73", "CWE-829", "CWE-94"])
UP = ("file_upload", "CWE-434", ["CWE-434", "CWE-22", "CWE-73"])
CSRF = ("csrf", "CWE-352", ["CWE-352"])
RED = ("open_redirect", "CWE-601", ["CWE-601", "CWE-113"])
SSRF = ("ssrf", "CWE-918", ["CWE-918"])
XPATH = ("xpath_injection", "CWE-643", ["CWE-643", "CWE-91", "CWE-74", "CWE-943"])
CSV = ("formula_injection", "CWE-1236", ["CWE-1236", "CWE-74"])
DESER = ("deserialization", "CWE-502", ["CWE-502", "CWE-915", "CWE-94"])
EVAL = ("code_injection", "CWE-95", ["CWE-95", "CWE-94", "CWE-502"])
SSTI = ("template_injection", "CWE-1336", ["CWE-1336", "CWE-94", "CWE-95", "CWE-74", "CWE-79"])
IDOR = ("idor", "CWE-639", ["CWE-639", "CWE-284", "CWE-285", "CWE-862", "CWE-863", "CWE-566"])
BAC = ("missing_function_access_control", "CWE-862", ["CWE-862", "CWE-285", "CWE-284", "CWE-863", "CWE-306"])
SESS = ("session_fixation", "CWE-384", ["CWE-384", "CWE-613", "CWE-330", "CWE-1275"])
HASH = ("weak_hash", "CWE-328", ["CWE-328", "CWE-327", "CWE-916", "CWE-759"])
SEC = ("hardcoded_secret", "CWE-798", ["CWE-798", "CWE-321", "CWE-259", "CWE-547"])
RNG = ("weak_random", "CWE-338", ["CWE-338", "CWE-330", "CWE-331", "CWE-329", "CWE-340"])
items = []; n = {}
def add(mod, file, rx, cls, vuln, occ=0, span=1, note=""):
    lines = open(f"{ROOT}/{file}", encoding="utf-8", errors="replace").read().split("\n")
    hits = [i + 1 for i, l in enumerate(lines) if re.search(rx, l)]
    assert len(hits) > occ, (file, rx, hits)
    s = hits[occ]
    k = f"xvwa-{mod}-{cls[0]}"; n[k] = n.get(k, 0) + 1
    items.append(dict(id=f"{k}-{n[k]}" + ("" if vuln else "-safe"), repo_file=file, is_vulnerable=vuln, vulnerability_class=cls[0],
        primary_cwe=cls[1], acceptable_cwes=cls[2], file=file, location=dict(start_line=s, end_line=s + span - 1),
        description=note or f"{mod}: {'vulnerable' if vuln else 'safe'} {cls[0]} sink"))
H = lambda m: f"{V}/{m}/home.php"
add("sqli", H("sqli"), r'select \* from caffaine where itemid = "\.\$item', SQL, True, span=2, note="item id concatenated into query")
add("sqli", H("sqli"), r"SELECT \* FROM caffaine WHERE itemname LIKE", SQL, True, span=2, note="search term concatenated into LIKE query")
add("sqli_blind", H("sqli_blind"), r'select \* from caffaine where itemid = "\.\$item', SQL, True, span=2)
add("sqli_blind", H("sqli_blind"), r"SELECT \* FROM caffaine WHERE itemname LIKE", SQL, True, span=2)
add("cmdi", H("cmdi"), r"shell_exec\( 'ping  ' \.", CMD, True, note="Windows branch")
add("cmdi", H("cmdi"), r"shell_exec\( 'ping  -c 3 ' \.", CMD, True, note="non-Windows branch")
add("xpath", H("xpath"), r"\$query = ", XPATH, True, span=3)
add("formula_injection", f"{V}/formula_injection/export.php", r"fputcsv\(\$output, \$row\)", CSV, True, note="stored item fields written to CSV without neutralizing = + - @")
add("php_object_injection", H("php_object_injection"), r"\$var1=unserialize\(", DESER, True)
add("php_object_injection", H("php_object_injection"), r"eval\(\$this->inject\)", EVAL, True, note="gadget reachable from unserialize via __wakeup")
add("fileupload", H("fileupload"), r"move_uploaded_file", UP, True, note="client file name, no type check")
add("reflected_xss", H("reflected_xss"), r"echo \$_GET\['item'\]", XSS, True)
add("stored_xss", H("stored_xss"), r"echo ucfirst\(\$rows\[0\]\)", XSS, True, note="stored name echoed unescaped")
add("stored_xss", H("stored_xss"), r'echo "<p>"\.\$rows\[1\]', XSS, True, note="stored comment echoed unescaped")
add("dom_xss", H("dom_xss"), r'document\.write\("<OPTION value=1>"\+document\.location', XSS, True, note="URL fragment written with document.write")
add("ssrf_xspa", H("ssrf_xspa"), r"file_get_contents\(\$_POST\['img_url'\]\)", SSRF, True)
add("fi", H("fi"), r"include\(\$file\)", FI, True)
add("redirect", H("redirect"), r'header\("Location: "\.\$forward\)', RED, True)
add("redirect", f"{V}/redirect/redirect.php", r'header\("Location: "\.\$forward\)', RED, True)
add("ssti", H("ssti"), r"\$twig->render\(\$name\)", SSTI, True, note="user input is the template (Twig_Loader_String)")
add("ssti", f"{V}/ssti/ssti.php", r"\$twig->render\(\$name\)", SSTI, True, note="standalone copy of the SSTI sink")
add("idor", H("idor"), r"\$stmt->bindParam\(':itemid',\$item\)", IDOR, True, span=2, note="record fetched by client-supplied id with no ownership check")
add("missfunc", H("missfunc"), r'\$sql="delete from caffaine', BAC, True, span=4, note="delete action is only hidden in the UI, server does not check the role")
add("csrf", H("csrf"), r'prepare\("UPDATE users set password', CSRF, True, span=4, note="password change over GET with no token")
add("sessionflaws", "login.php", r"\$_SESSION\['user'\] = \$ActiveUser", SESS, True, note="no session_regenerate_id after login")
add("crypto", H("crypto"), r"\$key = pack\('H\*'", SEC, True, note="hardcoded AES key")
add("crypto", H("crypto"), r"mcrypt_create_iv\(\$iv_size, MCRYPT_RAND\)", RNG, True, note="IV from MCRYPT_RAND")
add("crypto", H("crypto"), r"md5\(\$str\)", HASH, True, note="MD5 without salt")
add("login", "login.php", r"md5\(\$_POST\['password'\]\)", HASH, True, note="password stored and compared as unsalted MD5")
add("csrf", H("csrf"), r"md5\(\$password\)", HASH, True, note="password stored as unsalted MD5")
# safe look-alikes shipped by the app itself
add("crypto", H("crypto"), r"create_hash\(\$str\)", HASH, False, note="PBKDF2 with salt, the app's own correct example")
add("login", "login.php", r"\$stmt = \$conn1->prepare\(\$sql\)", SQL, False, span=4, note="parameterized login query")
add("stored_xss", H("stored_xss"), r'\$stmt->bindParam\(":comment"', SQL, False, note="parameterized insert")
add("idor", H("idor"), r"htmlspecialchars\(\$rows\[0\]\)", XSS, False, note="output escaped")
add("fileupload", H("fileupload"), r"htmlspecialchars\(\$itemcode\)", XSS, False, note="output escaped")
add("formula_injection", H("formula_injection"), r"htmlspecialchars\(\$rows\[0\]\)", XSS, False, note="output escaped")
add("sessionflaws", "logout.php", r"session_destroy\(\)", SESS, False, note="logout destroys the session")
gt = dict(repo_url="https://github.com/s4n7h0/xvwa", commit_sha=open(__file__.replace("gen_ground_truth.py", "SOURCE.txt")).read().split("commit:")[1].split()[0], findings=items)
print(json.dumps(gt, indent=1))
