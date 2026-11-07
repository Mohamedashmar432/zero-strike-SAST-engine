"""Clone, scan, score and attribute per rule for any set of RealVuln repos.
Usage: python -I runset.py <ground-truth-dir> <work-dir> <zerostrike-binary> slug=gtdir [slug=gtdir ...]
Writes <work-dir>/out/<slug>.json, <work-dir>/rules.json ({rule: {tp, fp}}) and prints per-repo and total counts."""
import json, os, re, subprocess, sys, collections
GT, WORK, BIN = sys.argv[1:4]; SET = dict(a.split("=") for a in sys.argv[4:])
os.makedirs(f"{WORK}/repos", exist_ok=True); os.makedirs(f"{WORK}/out", exist_ok=True)
def norm(p):
    p = p.replace("\\", "/")
    while p.startswith("./"): p = p[2:]
    return p.lstrip("/")
def inr(l, s, e): return s is None or s - 10 <= l <= (e if e is not None else s) + 10
def where(f, g):
    L = g["location"]
    if f["file"] == g["file"] and inr(f["line"], L.get("start_line"), L.get("end_line")): return True
    return any(f["file"] == norm(a.get("file", "")) and inr(f["line"], a.get("start_line"), a.get("end_line")) for a in g.get("acceptable_locations", []))
rules = collections.defaultdict(collections.Counter); T = [0, 0, 0]; FPS = []
for slug, gt in SET.items():
    g = json.load(open(f"{GT}/{gt}/ground-truth.json", encoding="utf-8")); d = f"{WORK}/repos/{slug}"
    if not os.path.isdir(d):
        subprocess.run(["git", "-c", "core.longpaths=true", "clone", "-q", g["repo_url"], d])
        subprocess.run(["git", "-C", d, "checkout", "-q", g["commit_sha"]])
    out = f"{WORK}/out/{slug}.json"
    subprocess.run([BIN, "scan", d, "--format", "json", "--enable-secrets", "--enable-framework-checks", "--no-cache", "-o", out], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ents = g["findings"]
    for e in ents: e["file"] = norm(e["file"])
    sc = [e for e in ents if e.get("scoring") != "non_scoring"]; ns = [e for e in ents if e.get("scoring") == "non_scoring"]
    rep = json.load(open(out, encoding="utf-8")); root = (rep.get("RootPath") or "").replace("\\", "/").rstrip("/"); used = set(); tp = fp = 0
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
                if b["is_vulnerable"]: tp += 1; rules[rid]["tp"] += 1
                else: fp += 1; rules[rid]["fp"] += 1; FPS.append(dict(repo=slug, rule=rid, file=p, line=f["line"], snippet=((x.get("Evidence") or [{}])[0].get("Snippet") or "")[:160].strip()))
                continue
            if f["line"] is not None and any(where(f, e) for e in ns): continue
            fp += 1; rules[rid]["fp"] += 1; FPS.append(dict(repo=slug, rule=rid, file=p, line=f["line"], snippet=((x.get("Evidence") or [{}])[0].get("Snippet") or "")[:160].strip()))
    fn = sum(1 for e in sc if e["is_vulnerable"] and e["id"] not in used)
    print(slug, dict(labels=sum(1 for e in sc if e["is_vulnerable"]), tp=tp, fp=fp, fn=fn)); T[0] += tp; T[1] += fp; T[2] += fn
json.dump({k: dict(v) for k, v in rules.items()}, open(f"{WORK}/rules.json", "w"), indent=0); json.dump(FPS, open(f"{WORK}/fps.json", "w"), indent=0)
print("TOTAL tp=%d fp=%d fn=%d precision=%.1f recall=%.1f" % (T[0], T[1], T[2], 100 * T[0] / max(1, T[0] + T[1]), 100 * T[0] / max(1, T[0] + T[2])))
