"""Sealed held-out run: clone at pinned SHA, scan, score, print aggregates only.
Usage: python -I heldout.py <ground-truth-dir> <work-dir> <zerostrike-binary>
Per-finding output is written under <work-dir>/out but must not be opened until the final unsealing."""
import json, os, subprocess, sys
GT, WORK, BIN = sys.argv[1:4]
HERE = os.path.dirname(os.path.abspath(__file__))
SET = {  # slug -> ground-truth dir (plan section 7.1)
 "javavulnerablelab":"realvuln-javavulnerablelab","eladmin":"realvuln-eladmin",
 "springboot-payments":"vc-sonnet-5-claude-code-seeded-v4-corp-payments-springboot",
 "evfa":"realvuln-extremely-vulnerable-flask-app","threatbyte":"realvuln-threatbyte",
 "vfapi":"realvuln-vfapi","python-insecure-app":"realvuln-python-insecure-app",
 "fastapi-supportdesk":"vc-claude-code-seeded-v2-support-desk-fastapi",
 "nodejs-goof":"realvuln-nodejs-goof","vuln-node-express-swagger":"realvuln-vuln-node-express-swagger",
 "nextjs-vulnerable-app":"realvuln-nextjs-vulnerable-app","nextjs-lms":"vc-codex-high-seeded-v3-education-lms-nextjs",
 "lets-be-bad-guys":"realvuln-lets-be-bad-guys"}
os.makedirs(f"{WORK}/repos", exist_ok=True); os.makedirs(f"{WORK}/out", exist_ok=True)
for slug, gt in SET.items():
    g = json.load(open(f"{GT}/{gt}/ground-truth.json", encoding="utf-8")); d = f"{WORK}/repos/{slug}"
    if not os.path.isdir(d):
        subprocess.run(["git","-c","core.longpaths=true","clone","-q",g["repo_url"],d],check=False)
        subprocess.run(["git","-C",d,"checkout","-q",g["commit_sha"]],check=False)
    subprocess.run([BIN,"scan",d,"--format","json","--enable-secrets","--enable-framework-checks",
                    "-o",f"{WORK}/out/{slug}.json"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
# score.py strips a leading repos/<name>/ prefix; scan paths here are absolute, so rewrite them.
for slug in SET:
    p = f"{WORK}/out/{slug}.json"
    if os.path.exists(p):
        r = json.load(open(p, encoding="utf-8")); root = (r.get("RootPath") or "").replace("\\","/").rstrip("/")
        for f in r.get("Findings") or []:
            fp = f["Location"]["File"].replace("\\","/")
            if root and fp.startswith(root+"/"): f["Location"]["File"] = "repos/x/" + fp[len(root)+1:]
        json.dump(r, open(p,"w",encoding="utf-8"))
res = subprocess.run([sys.executable,"-I",f"{HERE}/score.py",GT,f"{WORK}/out"]+[f"{s}={g}" for s,g in SET.items()],capture_output=True,text=True)
print(res.stdout or res.stderr)
