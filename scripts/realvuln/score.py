# Re-implementation of RealVuln's file + CWE + line(+-10) matcher (scorer/matcher.py semantics).
import json,sys,re,os,collections
GT,OUT,SLUGS=sys.argv[1],sys.argv[2],sys.argv[3:]
def norm(p):
    p=p.replace("\\","/")
    while p.startswith("./"): p=p[2:]
    return p.lstrip("/")
def inr(line,s,e):
    if line is None or s is None: return True
    return s-10<=line<=(e if e is not None else s)+10
def where(f,g):
    l=g["location"]
    if f["file"]==g["file"] and inr(f["line"],l.get("start_line"),l.get("end_line")): return True
    for a in g.get("acceptable_locations",[]):
        if f["file"]==norm(a.get("file","")) and inr(f["line"],a.get("start_line"),a.get("end_line")): return True
    return False
res={}
for slug,gtname in [x.split("=") for x in SLUGS]:
    g=json.load(open(f"{GT}/{gtname}/ground-truth.json",encoding="utf-8"))
    for e in g["findings"]: e["file"]=norm(e["file"])
    ents=g["findings"]; scored=[e for e in ents if e.get("scoring")!="non_scoring"]; ns=[e for e in ents if e.get("scoring")=="non_scoring"]
    rep=json.load(open(f"{OUT}/{slug}.json",encoding="utf-8"))
    fs=[]
    for x in rep.get("Findings") or []:
        p=norm(x["Location"]["File"]); p=re.sub(r"^repos/[^/]+/","",p)
        for c in x.get("CWE") or []:
            m=re.match(r"(CWE-\d+)",str(c))
            if m: fs.append(dict(file=p,line=x["Location"]["StartLine"],cwe=m.group(1),rule=x["RuleID"],cat=x.get("Category")))
    used=set(); tp=fp=0; fpr=collections.Counter(); tpr=collections.Counter()
    for f in fs:
        c=[e for e in scored if e["id"] not in used and f["cwe"] in e["acceptable_cwes"] and where(f,e)]
        if c:
            c.sort(key=lambda e:not e["is_vulnerable"]); b=c[0]; used.add(b["id"])
            if b["is_vulnerable"]: tp+=1; tpr[f["rule"]]+=1
            else: fp+=1; fpr[f["rule"]]+=1
            continue
        if f["line"] is not None and any(where(f,e) for e in ns): continue
        fp+=1; fpr[f["rule"]]+=1
    fn=sum(1 for e in scored if e["is_vulnerable"] and e["id"] not in used)
    res[slug]=dict(labels=sum(1 for e in scored if e["is_vulnerable"]),traps=sum(1 for e in scored if not e["is_vulnerable"]),tp=tp,fp=fp,fn=fn,fpr=fpr.most_common(8),tpr=tpr.most_common(8),findings=len(fs))
    r=res[slug]; P=tp/(tp+fp) if tp+fp else 0; R=tp/(tp+fn) if tp+fn else 0
    r["precision"]=round(100*P,1); r["recall"]=round(100*R,1); r["f3"]=round(100*(10*P*R/(9*P+R)),1) if P+R else 0
json.dump(res,open(f"{OUT}/results.json","w"),indent=1)
for k,r in res.items(): print(k,{x:r[x] for x in ("labels","traps","tp","fp","fn","precision","recall","f3")})
