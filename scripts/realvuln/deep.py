import json,re,sys,collections
GT=sys.argv[1]; OUT="out"
M={"pygoat":"realvuln-pygoat","vulpy":"realvuln-vulpy","juice-shop":"realvuln-juice-shop","dvws-node":"realvuln-dvws-node","healthcare-clinic-nextjs":"vc-claude-code-seeded-v3-healthcare-clinic-nextjs","djangoat":"realvuln-djangoat","nodegoat":"realvuln-nodegoat","vampi":"realvuln-vampi","vulnnodeapp":"realvuln-vulnnodeapp"}
def norm(p):
    p=p.replace("\\","/")
    while p.startswith("./"): p=p[2:]
    return p.lstrip("/")
def inr(l,s,e): return s is None or s-10<=l<=(e if e is not None else s)+10
def where(f,g):
    L=g["location"]
    if f["file"]==g["file"] and inr(f["line"],L.get("start_line"),L.get("end_line")): return True
    return any(f["file"]==norm(a.get("file","")) and inr(f["line"],a.get("start_line"),a.get("end_line")) for a in g.get("acceptable_locations",[]))
rule=collections.defaultdict(lambda:collections.Counter()); rcat={}; rlang={}
fns=[]; fps=[]; fnclass=collections.Counter(); hitclass=collections.Counter()
for slug,gt in M.items():
    g=json.load(open(f"{GT}/{gt}/ground-truth.json",encoding="utf-8")); ents=g["findings"]
    for e in ents: e["file"]=norm(e["file"])
    sc=[e for e in ents if e.get("scoring")!="non_scoring"]; ns=[e for e in ents if e.get("scoring")=="non_scoring"]
    rep=json.load(open(f"{OUT}/{slug}.json",encoding="utf-8")); used=set()
    for x in rep["Findings"]:
        p=re.sub(r"^repos/[^/]+/","",norm(x["Location"]["File"])); 
        for c in x.get("CWE") or []:
            m=re.match(r"(CWE-\d+)",str(c))
            if not m: continue
            f=dict(file=p,line=x["Location"]["StartLine"],cwe=m.group(1)); rid=x["RuleID"]; rcat[rid]=x.get("Category"); rlang[rid]=x.get("Language")
            cs=[e for e in sc if e["id"] not in used and f["cwe"] in e["acceptable_cwes"] and where(f,e)]
            if cs:
                cs.sort(key=lambda e:not e["is_vulnerable"]); b=cs[0]; used.add(b["id"])
                if b["is_vulnerable"]: rule[rid]["tp"]+=1; hitclass[b["vulnerability_class"]]+=1
                else: rule[rid]["fp_trap"]+=1; fps.append(dict(repo=slug,rule=rid,file=p,line=f["line"],why="trap",cls=b["vulnerability_class"]))
                break
            if any(where(f,e) for e in ns): break
            rule[rid]["fp"]+=1; fps.append(dict(repo=slug,rule=rid,file=p,line=f["line"],why="unlabeled",cwe=f["cwe"],sev=x["Severity"],msg=x["Message"][:80])); break
    for e in sc:
        if e["is_vulnerable"] and e["id"] not in used:
            fnclass[e["vulnerability_class"]]+=1
            fns.append(dict(repo=slug,id=e["id"],cls=e["vulnerability_class"],cwe=e["primary_cwe"],file=e["file"],line=e["location"].get("start_line"),lang=g["language"],desc=e["evidence"]["description"][:140]))
        elif e["is_vulnerable"]: pass
json.dump(dict(rule={k:dict(v) for k,v in rule.items()},rcat=rcat,rlang=rlang,fns=fns,fps=fps),open("deep.json","w"),indent=0)
print("RULES (tp,fp) sorted by fp:")
rows=sorted(rule.items(),key=lambda kv:-(kv[1]["fp"]+kv[1]["fp_trap"]))
for rid,c in rows[:25]: print(f" {rid:12} {rcat[rid]:24} {rlang[rid]:10} tp={c['tp']:3} fp={c['fp']+c['fp_trap']:3} prec={100*c['tp']/max(1,c['tp']+c['fp']+c['fp_trap']):.0f}%")
tot=sum(c['fp']+c['fp_trap'] for c in rule.values()); print("total fp",tot,"rules with fp",sum(1 for c in rule.values() if c['fp']+c['fp_trap']),"rules with tp",sum(1 for c in rule.values() if c['tp']),"rules fired",len(rule))
fc=collections.Counter(); 
for r,c in rule.items(): fc[rcat[r]]+=c['fp']+c['fp_trap']
print("FP by category",fc.most_common(12))
tc=collections.Counter()
for r,c in rule.items(): tc[rcat[r]]+=c['tp']
print("TP by category",tc.most_common(12))
print("FN by class",fnclass.most_common(25)); print("HIT by class",hitclass.most_common(12))
print("FN by repo",collections.Counter(f['repo'] for f in fns).most_common())
