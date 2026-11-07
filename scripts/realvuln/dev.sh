#!/bin/sh
# Dev-set run: scan the nine open repos and print per-repo and total TP/FP/FN.
# Usage: dev.sh <zerostrike-binary> <out-dir> <bench-dir>   (bench-dir holds repos/ and the rv/ benchmark clone's parent: see below)
BIN="$1"; OUT="$2"; BENCH="$3"; GT="${GT:-$BENCH/../rv/Real-Vuln-Benchmark/ground-truth}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"; cd "$BENCH" || exit 1
for r in pygoat vulpy juice-shop dvws-node healthcare-clinic-nextjs djangoat nodegoat vampi vulnnodeapp; do
  "$BIN" scan "repos/$r" --format json --enable-secrets --enable-framework-checks -o "$OUT/$r.json" >/dev/null 2>&1
done
python -I "$HERE/score.py" "$GT" "$OUT" pygoat=realvuln-pygoat vulpy=realvuln-vulpy juice-shop=realvuln-juice-shop \
 dvws-node=realvuln-dvws-node healthcare-clinic-nextjs=vc-claude-code-seeded-v3-healthcare-clinic-nextjs \
 djangoat=realvuln-djangoat nodegoat=realvuln-nodegoat vampi=realvuln-vampi vulnnodeapp=realvuln-vulnnodeapp |
python -I -c "
import sys,re,ast
t=[0,0,0]
for l in sys.stdin:
    print(l.rstrip()); m=re.search(r'(\{.*\})',l)
    if m: d=ast.literal_eval(m.group(1)); t[0]+=d['tp'];t[1]+=d['fp'];t[2]+=d['fn']
print('DEV TOTAL tp=%d fp=%d fn=%d precision=%.1f recall=%.1f'%(t[0],t[1],t[2],100*t[0]/max(1,t[0]+t[1]),100*t[0]/max(1,t[0]+t[2])))"
