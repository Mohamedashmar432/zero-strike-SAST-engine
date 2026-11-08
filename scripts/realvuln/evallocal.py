"""Score the in-repo labeled applications (benchmark/labeled) without cloning anything but DVWA.
Usage: python -I evallocal.py <zerostrike-binary> <work-dir> <labeled-root> [--dvwa-src <path>] [--only app1,app2]
Matching rules are exactly those of runset.py: same file relative to the app root, CWE in acceptable_cwes, line within 10 of the
label, one finding per label, a finding that matches a safe label is a false positive, unmatched findings are false positives.
Writes <work-dir>/out/<app>.json, <work-dir>/rules.json and <work-dir>/fps.json; prints per-app, per-language and TOTAL lines.
apps.json in <labeled-root> maps app -> "tune" | "verify"; totals are also printed per split."""
import collections, json, os, re, subprocess, sys

args = sys.argv[1:]
if len(args) < 3:
    sys.exit(__doc__)
BIN, WORK, ROOT = args[:3]
opts = args[3:]
DVWA = None; ONLY = None
i = 0
while i < len(opts):
    if opts[i] == "--dvwa-src": DVWA = opts[i + 1]; i += 2
    elif opts[i] == "--only": ONLY = opts[i + 1].split(","); i += 2
    else: sys.exit("unknown option " + opts[i])
os.makedirs(f"{WORK}/out", exist_ok=True)
SPLIT = json.load(open(f"{ROOT}/apps.json", encoding="utf-8")) if os.path.exists(f"{ROOT}/apps.json") else {}


def norm(p):
    p = p.replace("\\", "/")
    while p.startswith("./"): p = p[2:]
    return p.lstrip("/")


def inr(l, s, e): return s is None or s - 10 <= l <= (e if e is not None else s) + 10


def where(f, g):
    L = g["location"]
    if f["file"] == g["file"] and inr(f["line"], L.get("start_line"), L.get("end_line")): return True
    return any(f["file"] == norm(a.get("file", "")) and inr(f["line"], a.get("start_line"), a.get("end_line")) for a in g.get("acceptable_locations", []))


TEMPLATE_EXT = (".blade.php", ".cshtml", ".razor", ".html", ".htm", ".ejs", ".hbs", ".handlebars", ".aspx", ".ascx", ".master", ".vue")
def lang(path):
    p = path.lower()
    if p.endswith(TEMPLATE_EXT): return "HTML templates"
    if p.endswith(".php"): return "PHP"
    if p.endswith(".cs"): return "C#"
    if p.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")): return "TypeScript/JavaScript"
    return "Config/other"


class Tally:
    def __init__(self): self.tp = self.fp = self.fn = 0
    def line(self):
        P = 100 * self.tp / max(1, self.tp + self.fp); R = 100 * self.tp / max(1, self.tp + self.fn)
        return "tp=%d fp=%d fn=%d precision=%.1f recall=%.1f" % (self.tp, self.fp, self.fn, P, R)


rules = collections.defaultdict(collections.Counter); FPS = []
by_lang = collections.defaultdict(Tally); by_split = collections.defaultdict(Tally); split_lang = collections.defaultdict(Tally); total = Tally()
def bump(kind, language, split):
    for t in (total, by_lang[language], by_split[split], split_lang[(split, language)]): setattr(t, kind, getattr(t, kind) + 1)

apps = sorted(d for d in os.listdir(ROOT) if os.path.isfile(f"{ROOT}/{d}/ground-truth.json"))
for app in apps:
    if ONLY and app not in ONLY: continue
    split = SPLIT.get(app, "tune")
    if app == "dvwa":
        if not DVWA: print(app, "SKIPPED (no --dvwa-src)"); continue
        d = DVWA
    else:
        d = f"{ROOT}/{app}"
    d = os.path.abspath(d)  # the scanner reports paths as given, so an absolute root keeps RootPath stripping exact
    out = f"{WORK}/out/{app}.json"
    subprocess.run([BIN, "scan", d, "--format", "json", "--enable-secrets", "--enable-framework-checks", "--no-cache", "-o", out],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    g = json.load(open(f"{ROOT}/{app}/ground-truth.json", encoding="utf-8"))
    ents = g["findings"]
    for e in ents: e["file"] = norm(e["file"])
    sc = [e for e in ents if e.get("scoring") != "non_scoring"]; ns = [e for e in ents if e.get("scoring") == "non_scoring"]
    if not os.path.exists(out): print(app, "NO REPORT"); continue
    rep = json.load(open(out, encoding="utf-8")); root = (rep.get("RootPath") or "").replace("\\", "/").rstrip("/")
    used = set(); tp = fp = 0
    for x in rep.get("Findings") or []:
        fl = x["Location"]["File"].replace("\\", "/")
        p = norm(fl[len(root) + 1:] if root and fl.startswith(root + "/") else fl)
        for c in x.get("CWE") or []:
            m = re.match(r"(CWE-\d+)", str(c))
            if not m: continue
            f = dict(file=p, line=x["Location"]["StartLine"], cwe=m.group(1)); rid = x["RuleID"]
            cs = [e for e in sc if e["id"] not in used and f["cwe"] in e["acceptable_cwes"] and where(f, e)]
            if cs:
                cs.sort(key=lambda e: not e["is_vulnerable"]); b = cs[0]; used.add(b["id"])
                if b["is_vulnerable"]: tp += 1; rules[rid]["tp"] += 1; bump("tp", lang(p), split)
                else:
                    fp += 1; rules[rid]["fp"] += 1; bump("fp", lang(p), split)
                    FPS.append(dict(repo=app, rule=rid, file=p, line=f["line"], label=b["id"], snippet=((x.get("Evidence") or [{}])[0].get("Snippet") or "")[:160].strip()))
                continue
            if f["line"] is not None and any(where(f, e) for e in ns): continue
            fp += 1; rules[rid]["fp"] += 1; bump("fp", lang(p), split)
            FPS.append(dict(repo=app, rule=rid, file=p, line=f["line"], label=None, snippet=((x.get("Evidence") or [{}])[0].get("Snippet") or "")[:160].strip()))
    fn = 0
    for e in sc:
        if e["is_vulnerable"] and e["id"] not in used: fn += 1; bump("fn", lang(e["file"]), split)
    print(app, f"[{split}]", dict(vulnerable_labels=sum(1 for e in sc if e["is_vulnerable"]), safe_labels=sum(1 for e in sc if not e["is_vulnerable"]), tp=tp, fp=fp, fn=fn))

json.dump({k: dict(v) for k, v in rules.items()}, open(f"{WORK}/rules.json", "w"), indent=0)
json.dump(FPS, open(f"{WORK}/fps.json", "w"), indent=0)
for s in sorted(by_split):
    print(f"SPLIT {s}: " + by_split[s].line())
    for l in ("PHP", "C#", "TypeScript/JavaScript", "HTML templates", "Config/other"):
        if (s, l) in split_lang: print(f"  {s} {l}: " + split_lang[(s, l)].line())
for l in ("PHP", "C#", "TypeScript/JavaScript", "HTML templates", "Config/other"):
    if l in by_lang: print(f"LANG {l}: " + by_lang[l].line())
print("TOTAL " + total.line())
