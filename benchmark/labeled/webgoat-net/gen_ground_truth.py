"""Regenerate webgoat-net/ground-truth.json from a WebGoat.NET clone at the pinned commit.
Usage: python -I gen_ground_truth.py <webgoat-net-clone> > ground-truth.json
Labels are located by regex in files that were read at the pinned SHA; the run fails if an anchor no longer matches.
Paths are repo-relative (the application lives under WebGoat/)."""
import json, re, sys
ROOT = sys.argv[1]
SQL = ("sql_injection", "CWE-89", ["CWE-89", "CWE-564", "CWE-943"])
XSS = ("xss", "CWE-79", ["CWE-79", "CWE-80", "CWE-83", "CWE-116"])
PATH = ("path_traversal", "CWE-22", ["CWE-22", "CWE-23", "CWE-73", "CWE-36"])
UP = ("file_upload", "CWE-434", ["CWE-434", "CWE-22", "CWE-73"])
RED = ("open_redirect", "CWE-601", ["CWE-601"])
HASH = ("weak_hash", "CWE-328", ["CWE-328", "CWE-327", "CWE-916", "CWE-759"])
PWD = ("weak_password_storage", "CWE-261", ["CWE-261", "CWE-256", "CWE-257", "CWE-327", "CWE-328", "CWE-916", "CWE-759"])
SEC = ("hardcoded_secret", "CWE-798", ["CWE-798", "CWE-321", "CWE-259", "CWE-547", "CWE-760", "CWE-329"])
RNG = ("weak_random", "CWE-338", ["CWE-338", "CWE-330", "CWE-331", "CWE-335", "CWE-337", "CWE-340"])
ERR = ("information_exposure", "CWE-209", ["CWE-209", "CWE-200", "CWE-215", "CWE-497", "CWE-11"])
LOGP = ("password_logged", "CWE-532", ["CWE-532", "CWE-117", "CWE-312"])
COOK = ("insecure_cookie", "CWE-1004", ["CWE-1004", "CWE-614", "CWE-732"])
COOKDATA = ("sensitive_data_in_cookie", "CWE-261", ["CWE-261", "CWE-311", "CWE-315", "CWE-602", "CWE-327", "CWE-200"])
MEM = ("unsafe_memory_write", "CWE-787", ["CWE-787", "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-805"])
items = []; n = {}
def add(mod, file, rx, cls, vuln, occ=0, span=1, note=""):
    lines = open(f"{ROOT}/{file}", encoding="utf-8-sig", errors="replace").read().split("\n")
    hits = [i + 1 for i, l in enumerate(lines) if re.search(rx, l)]
    assert len(hits) > occ, (file, rx, hits)
    s = hits[occ]
    k = f"webgoat-{mod}-{cls[0]}"; n[k] = n.get(k, 0) + 1
    items.append(dict(id=f"{k}-{n[k]}" + ("" if vuln else "-safe"), repo_file=file, is_vulnerable=vuln, vulnerability_class=cls[0],
        primary_cwe=cls[1], acceptable_cwes=cls[2], file=file, location=dict(start_line=s, end_line=s + span - 1),
        description=note or f"{mod}: {'vulnerable' if vuln else 'safe'} {cls[0]} sink"))
W = "WebGoat"
for prov, file in (("sqlite", f"{W}/App_Code/DB/SqliteDbProvider.cs"), ("mysql", f"{W}/App_Code/DB/MySqlDbProvider.cs")):
    q = r'string sql = "select \* from CustomerLogin where email = \'" \+ email'
    add(prov, file, q, SQL, True, occ=0, span=2, note="customer login query concatenates email and encoded password (portal login)")
    add(prov, file, q, SQL, True, occ=1, note="CustomCustomerLogin concatenates email")
    add(prov, file, q, SQL, True, occ=2, note="GetPasswordByEmail concatenates email (forgot-password lesson)")
    add(prov, file, r'"select email from CustomerLogin where customerNumber = " \+ customerNumber', SQL, True, note="customer number from the customerNumber cookie")
    add(prov, file, r'Customers\.customerNumber = " \+ customerNumber', SQL, True, note="customer number from the customerNumber cookie (portal main page)")
    add(prov, file, r'insert into Comments\(productCode, email, comment\)', SQL, True, note="comment insert concatenates all three values")
    add(prov, file, r"where productCode = '\" \+ productCode", SQL, True, occ=0, note="product lookup by productNumber request value")
    add(prov, file, r"where productCode = '\" \+ productCode", SQL, True, occ=1, note="comments lookup by productNumber request value")
    add(prov, file, r"firstName like '\" \+ name", SQL, True, note="Exploiting SQL Injection lesson")
    add(prov, file, r"select email from CustomerLogin where customerNumber = \" \+ num", SQL, True, note="SQL Error Messages lesson (num from page input)")
    add(prov, file, r"email like '\" \+ email", SQL, True, note="autocomplete handler query")
    add(prov, file, r"CustomerLogin\.email = '\" \+ email", SQL, True, note="security question lookup concatenates email")
    add(prov, file, r'"select \* from Offices where city = @city"', SQL, False, note="parameterized city query (used by the reflected XSS lesson)")
    add(prov, file, r'"select \* from Comments where productCode = @productCode"', SQL, False, note="parameterized comments query")
    add(prov, file, r"string encoded_password = Encoder\.Encode\(password\)", PWD, True, note="Base64 'encoding' used as password storage")
C = f"{W}/Content"
add("pathmanip", f"{C}/PathManipulation.aspx.cs", r'string filename = Request\.QueryString\["filename"\]', PATH, True, span=21, note="filename from query string reaches FileStream via MapPath(~/Downloads/ + filename)")
add("uploadpath", f"{C}/UploadPathManipulation.aspx.cs", r"FileUpload1\.SaveAs", UP, True, note="no extension or content check, saved under a web-served directory")
add("uploadpath", f"{C}/UploadPathManipulation.aspx.cs", r'"<div class=\'success\'', XSS, True, note="uploaded file name reflected unencoded")
add("reflectedxss", f"{C}/ReflectedXSS.aspx.cs", r'lblOutput\.Text = "Here are the details for our " \+ city', XSS, True)
add("reflectedxss", f"{C}/ReflectedXSS.aspx.cs", r"Server\.HtmlEncode\(city\)", XSS, False, note="FixedLoadCity, the app's own fix")
add("storedxss", f"{C}/StoredXSS.aspx.cs", r'comments \+= "<strong>Email:</strong>" \+ row\["email"\]', XSS, True)
add("storedxss", f"{C}/StoredXSS.aspx.cs", r'comments \+= "<strong>Comment:</strong><br/>" \+ row\["comment"\]', XSS, True)
add("storedxss", f"{C}/StoredXSS.aspx.cs", r'Server\.HtmlEncode\(row\["email"\]', XSS, False, note="FixedLoadComments, the app's own fix")
add("storedxss", f"{C}/StoredXSS.aspx.cs", r'Server\.HtmlEncode\(row\["comment"\]', XSS, False, note="FixedLoadComments, the app's own fix")
P = f"{W}/WebGoatCoins"
add("productdetails", f"{P}/ProductDetails.aspx.cs", r'comments \+= "<strong>Email:</strong>" \+ commentRow\["email"\]', XSS, True, note="stored comment email rendered unencoded")
add("productdetails", f"{P}/ProductDetails.aspx.cs", r'comments \+= "<strong>Comment:</strong><br/>" \+ commentRow\["comment"\]', XSS, True, note="stored comment rendered unencoded")
add("customerlogin", f"{P}/CustomerLogin.aspx.cs", r"Response\.Redirect\(returnUrl\)", RED, True, note="ReturnUrl query value, not validated")
add("customerlogin", f"{P}/CustomerLogin.aspx.cs", r'log\.Info\("User " \+ email \+ " attempted to log in with password " \+ pwd\)', LOGP, True)
add("forgotpassword", f"{C}/ForgotPassword.aspx.cs", r"cookie\.Value = Encoder\.Encode\(Encoder\.Encode\(result\[1\]\)\)", COOKDATA, True, note="security answer in a cookie, double Base64 'for more security'")
add("forgotpassword", f"{P}/ForgotPassword.aspx.cs", r"cookie\.Value = Encoder\.Encode\(Encoder\.Encode\(result\[1\]\)\)", COOKDATA, True, note="security answer in a cookie, double Base64")
add("sqldiscovery", f"{C}/SQLInjectionDiscovery.aspx.cs", r"lblOutput\.Text = ex\.Message", ERR, True, note="raw database exception shown (SQL Error Messages lesson)")
add("exploitdebug", f"{C}/ExploitDebug.aspx.cs", r"throw new Exception\(strBuilder\.ToString\(\)\)", ERR, True, note="environment details thrown into an unhandled exception page")
add("encryption", f"{C}/EncryptVSEncode.aspx.cs", r'private string hardCodedKey = "key"', SEC, True)
add("encryption", f"{C}/EncryptVSEncode.aspx.cs", r"sha = new SHA1Managed\(\)", HASH, True, note="SHA1 shown as a hashing option in the Encryption vs Encoding lesson")
add("encryption", f"{W}/App_Code/Encoder.cs", r'private static byte\[\] _salt = Encoding\.ASCII\.GetBytes', SEC, True, note="static hardcoded salt for key derivation")
add("digest", f"{W}/App_Code/WeakMessageDigest.cs", r"foreach\(char c in word\)", HASH, True, span=5, note="Insecure Message Digest lesson: byte-sum digest")
add("random", f"{W}/App_Code/WeakRandom.cs", r"_seed = _seed \* _seed \+ _seed", RNG, True, note="Weak Random Number Generators lesson")
add("unsafe", f"{C}/Unsafe.aspx.cs", r"for \(int i = 0; i < lineLen; i\+\+\)", MEM, True, span=2, note="Unsafe blocks lesson: unbounded write into a 256 char fixed buffer")
add("config", f"{W}/Web.config", r'<user name="admin" password="admin" />', SEC, True, span=3, note="clear-text forms credentials")
add("config", f"{W}/Web.config", r'<httpCookies httpOnlyCookies="false"', COOK, True, note="HttpOnly disabled, requireSSL off")
add("config", f"{W}/Web.config", r'<customErrors mode="Off" />', ERR, True, note="detailed errors returned to clients (Exploiting Debug Page lesson)")
gt = dict(repo_url="https://github.com/jerryhoff/WebGoat.NET", commit_sha=open(__file__.replace("gen_ground_truth.py", "SOURCE.txt")).read().split("commit:")[1].split()[0], findings=items)
print(json.dumps(gt, indent=1))
