"""Authoring helper: turns a self-built app's marked sources into ground-truth.json and README.md.
Sources are written with a trailing marker on each labeled line: `@@V:<class>` (vulnerable) or `@@S:<class>` (safe).
Running this strips the markers in place (so the committed code is clean) and records the exact line numbers.
Usage: python -I build_labels.py <app-dir>
Idempotent: if no markers remain it only re-reads the existing ground-truth.json to refresh README.md."""
import json, os, re, sys

CLASSES = {  # class: (long name, primary CWE, acceptable)
    "sqli": ("SQL injection", "CWE-89", ["CWE-89", "CWE-564"]),
    "cmdi": ("OS command injection", "CWE-78", ["CWE-78", "CWE-77", "CWE-88"]),
    "nosqli": ("NoSQL injection", "CWE-943", ["CWE-943", "CWE-89", "CWE-74"]),
    "xss": ("cross-site scripting", "CWE-79", ["CWE-79", "CWE-80", "CWE-83", "CWE-116"]),
    "path": ("path traversal", "CWE-22", ["CWE-22", "CWE-23", "CWE-36", "CWE-73"]),
    "lfi": ("file inclusion", "CWE-98", ["CWE-98", "CWE-22", "CWE-73", "CWE-829"]),
    "ssrf": ("server-side request forgery", "CWE-918", ["CWE-918", "CWE-441"]),
    "redirect": ("open redirect", "CWE-601", ["CWE-601", "CWE-113"]),
    "deser": ("insecure deserialization", "CWE-502", ["CWE-502", "CWE-915"]),
    "weakcrypto": ("weak cryptographic algorithm", "CWE-327", ["CWE-327", "CWE-326", "CWE-328", "CWE-780", "CWE-329"]),
    "weakhash": ("weak password hashing", "CWE-328", ["CWE-328", "CWE-327", "CWE-916", "CWE-759"]),
    "weakrand": ("insecure randomness", "CWE-330", ["CWE-330", "CWE-338", "CWE-331", "CWE-334"]),
    "secret": ("hardcoded secret", "CWE-798", ["CWE-798", "CWE-259", "CWE-321", "CWE-547"]),
    "debug": ("debug mode enabled", "CWE-489", ["CWE-489", "CWE-215", "CWE-11", "CWE-209", "CWE-200"]),
    "cors": ("permissive CORS", "CWE-942", ["CWE-942", "CWE-346", "CWE-1275"]),
    "cookieflag": ("cookie without security flags", "CWE-614", ["CWE-614", "CWE-1004", "CWE-1275", "CWE-319"]),
    "csrf": ("missing CSRF protection", "CWE-352", ["CWE-352"]),
    "xxe": ("XML external entity", "CWE-611", ["CWE-611", "CWE-776"]),
    "upload": ("unrestricted file upload", "CWE-434", ["CWE-434", "CWE-22", "CWE-73"]),
}
app = sys.argv[1].rstrip("/\\")
name = os.path.basename(app)
SKIP = {"ground-truth.json", "README.md"}
MARK = re.compile(r"[ \t]*@@([VS]):(\w+)[ \t]*$")
items, n = [], 0
for dp, dn, fn in os.walk(app):
    dn.sort()
    for f in sorted(fn):
        if f in SKIP: continue
        p = os.path.join(dp, f); rel = os.path.relpath(p, app).replace("\\", "/")
        raw = open(p, encoding="utf-8", newline="").read()
        nl = "\r\n" if "\r\n" in raw else "\n"
        lines = raw.split(nl); out = []
        for i, l in enumerate(lines):
            m = MARK.search(l)
            if m:
                kind, cls = m.groups(); l = l[:m.start()]
                long, cwe, acc = CLASSES[cls]; n += 1
                items.append(dict(id=f"{name}-{n:02d}", is_vulnerable=kind == "V", vulnerability_class=cls, primary_cwe=cwe,
                                  acceptable_cwes=acc, file=rel, location=dict(start_line=i + 1, end_line=i + 1),
                                  description=("Vulnerable: " if kind == "V" else "Safe look-alike: ") + long))
            out.append(l)
        new = nl.join(out)
        if new != raw: open(p, "w", encoding="utf-8", newline="").write(new)
gt_path = os.path.join(app, "ground-truth.json")
if items:
    json.dump(dict(repo_url="local:benchmark/labeled/" + name, commit_sha="local", findings=items), open(gt_path, "w"), indent=1)
else:
    items = json.load(open(gt_path))["findings"]
v = [e for e in items if e["is_vulnerable"]]; s = [e for e in items if not e["is_vulnerable"]]
rows = "\n".join(f"| {e['id']} | `{e['file']}` | {e['location']['start_line']} | {e['vulnerability_class']} ({e['primary_cwe']}) | {'vulnerable' if e['is_vulnerable'] else 'safe'} |" for e in items)
open(os.path.join(app, "README.md"), "w", encoding="utf-8").write(
    f"# {name}\n\nSynthetic application written from OWASP weakness classes for scanner measurement. "
    f"It is not meant to run. Secrets are obvious placeholders.\n\n"
    f"Labels: {len(v)} vulnerable, {len(s)} safe look-alikes. Line numbers refer to the files as committed; "
    f"ground truth is in `ground-truth.json`.\n\n| id | file | line | class | label |\n|---|---|---|---|---|\n{rows}\n")
print(name, "vulnerable", len(v), "safe", len(s))
