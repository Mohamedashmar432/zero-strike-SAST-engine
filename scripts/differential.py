#!/usr/bin/env python3
"""Differential coverage harness: ZeroStrike vs Semgrep OSS on the same targets.

The in-repo benchmark corpus is self-authored -- fixtures are copied from
testdata/ and expectations are written by whoever wrote the rule -- so FN=0 is
structural there and 100% recall says "no regressions", not "competitive".
This measures the other thing: run both scanners over the same real vulnerable
application and bucket the findings.

    both            -- agreement, highest-confidence true positives
    semgrep-only    -- the actual gap list, ranked by CWE x language
    zerostrike-only -- our edge, or our false positives; needs review either way

Matching is (file, CWE) with a line tolerance, deliberately loose: two engines
flag the same defect at slightly different AST nodes, and demanding exact line
agreement would inflate the gap with pairs that are really the same finding.
Semgrep's output is another tool's opinion, not ground truth -- this ranks work,
it does not grade correctness.

Usage:
    python scripts/differential.py <targets_root> <zerostrike_exe> <out_dir>
                                   [--label pre|post] [target ...]
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict

# Line tolerance for calling two findings "the same defect".
LINE_SLOP = 3

EXT_LANG = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".go": "go",
    ".php": "php", ".java": "java", ".cs": "csharp",
    ".html": "html", ".htm": "html",
}

CWE_RE = re.compile(r"CWE-(\d+)")

# CWE ids the two tools use interchangeably for the same defect. Without this
# the same finding scores as a miss purely on taxonomy granularity: we report
# md5 as CWE-327 (broken crypto algorithm), semgrep as CWE-328 (weak hash);
# both are correct and both describe the same line. Each frozenset is one
# equivalence class -- ids inside a class are treated as matching.
CWE_ALIASES = [
    frozenset({"326", "327", "328", "916"}),   # weak crypto / weak hash / weak key
    frozenset({"77", "78", "88"}),             # command / argument injection
    frozenset({"94", "95", "96"}),             # code / expression injection
    frozenset({"22", "23", "36", "73"}),       # path traversal family
    frozenset({"79", "80"}),                   # XSS
    frozenset({"89", "564"}),                  # SQL / HQL injection
    frozenset({"330", "338"}),                 # weak randomness
    # information exposure. 489 (active debug code) belongs here: semgrep tags
    # printStackTrace as CWE-489 while we tag it CWE-209, on byte-identical
    # sites, and without this the differential reported all 8 as misses.
    frozenset({"200", "209", "489", "532"}),
]


def cwe_match(a, b):
    """True when two CWE id sets describe the same defect class."""
    if a & b:
        return True
    for klass in CWE_ALIASES:
        if (a & klass) and (b & klass):
            return True
    return False


def cwes(values):
    """Pull the numeric CWE ids out of either tool's assorted CWE spellings."""
    out = set()
    for v in values or []:
        out.update(CWE_RE.findall(str(v)))
    return out


def norm_path(p, target):
    """Normalize to a target-relative posix path so both tools' paths align."""
    p = str(p).replace("\\", "/").lstrip("./")
    # Both tools are invoked from targets_root with the same relative target
    # dir, but zerostrike reports paths relative to its own scan root.
    if p.startswith(target + "/"):
        p = p[len(target) + 1:]
    return p.lower()


def lang_of(path):
    return EXT_LANG.get(os.path.splitext(path)[1].lower(), "other")


def run_zerostrike(exe, targets_root, target, out_json):
    cmd = [exe, "scan", "--no-cache", "--enable-secrets", "--enable-framework-checks",
           "--format", "json", "--output", out_json, target]
    # exit 1 just means "findings found"; only >1 is a real failure.
    r = subprocess.run(cmd, cwd=targets_root, capture_output=True, text=True)
    if r.returncode > 1:
        print(f"  ! zerostrike exit {r.returncode}: {r.stderr.strip()[:300]}", file=sys.stderr)
        return []
    # Both tools embed raw source snippets, which in targets like DVWA are not
    # valid UTF-8. Replace rather than abort: we only read paths/lines/CWEs.
    with open(out_json, encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    out = []
    for f in data.get("Findings") or []:
        loc = f.get("Location") or {}
        path = norm_path(loc.get("File", ""), target)
        out.append({
            "path": path, "line": int(loc.get("StartLine") or 0),
            "cwe": cwes(f.get("CWE")), "rule": f.get("RuleID", ""),
            "lang": lang_of(path), "sev": (f.get("Severity") or "").lower(),
        })
    return out


def run_semgrep(targets_root, target, out_json):
    cmd = ["semgrep", "scan", "--config=auto", "--json", "--quiet",
           "--no-git-ignore", "--timeout", "20", target, "-o", out_json]
    r = subprocess.run(cmd, cwd=targets_root, capture_output=True, text=True)
    if not os.path.exists(out_json):
        print(f"  ! semgrep produced no output (exit {r.returncode}): "
              f"{r.stderr.strip()[:300]}", file=sys.stderr)
        return []
    # Both tools embed raw source snippets, which in targets like DVWA are not
    # valid UTF-8. Replace rather than abort: we only read paths/lines/CWEs.
    with open(out_json, encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    out = []
    for f in data.get("results") or []:
        meta = (f.get("extra") or {}).get("metadata") or {}
        path = norm_path(f.get("path", ""), target)
        out.append({
            "path": path, "line": int((f.get("start") or {}).get("line") or 0),
            "cwe": cwes(meta.get("cwe")), "rule": f.get("check_id", ""),
            "lang": lang_of(path),
            "sev": ((f.get("extra") or {}).get("severity") or "").lower(),
        })
    return out


def collapse(findings):
    """Collapse findings to one entry per (file, line) vulnerability site.

    Without this the gap is systematically overstated, because the two tools
    have very different rule granularity. Semgrep reports a single
    `exec("ping " . $target)` under four separate rule ids
    (tainted-exec, exec-use, tainted-command-injection,
    laravel-command-injection); pair_up can only spend one of our findings on
    one of theirs, so detecting that line correctly still scored as three
    misses. Measured on DVWA, that alone accounted for most of the apparent
    PHP gap on lines we already flag.

    One source line is one vulnerability site. That is the unit worth
    counting on both sides.
    """
    by_site = {}
    for f in findings:
        key = (f["path"], f["line"])
        if key in by_site:
            by_site[key]["cwe"] |= f["cwe"]
            by_site[key]["rules"].add(f["rule"])
        else:
            e = dict(f)
            e["rules"] = {f["rule"]}
            by_site[key] = e
    return list(by_site.values())


def pair_up(zs, sg):
    """Bucket into both / semgrep-only / zerostrike-only.

    A semgrep finding is matched if some unconsumed zerostrike finding sits in
    the same file, shares a CWE, and lands within LINE_SLOP lines. Each
    zerostrike finding can only satisfy one semgrep finding, so N duplicate
    semgrep rules on one line cannot all be credited to a single detection.
    """
    by_file = defaultdict(list)
    for i, f in enumerate(zs):
        by_file[f["path"]].append(i)
    consumed, both = set(), []
    sg_only = []
    for s in sg:
        hit = None
        for i in by_file.get(s["path"], []):
            if i in consumed:
                continue
            z = zs[i]
            if s["cwe"] and z["cwe"] and not cwe_match(s["cwe"], z["cwe"]):
                continue
            # Location tolerance applies whether or not CWEs are present. An
            # earlier version demanded an exact line when either side had no
            # CWE metadata, which manufactured misses: semgrep tags
            # string-to-int-signedness-cast with no CWE at all and reports it
            # one line above where we report ours, so a real detection scored
            # as a gap. Many semgrep rules carry no CWE, so this was not rare.
            if abs(s["line"] - z["line"]) > LINE_SLOP:
                continue
            hit = i
            break
        if hit is None:
            sg_only.append(s)
        else:
            consumed.add(hit)
            both.append((s, zs[hit]))
    zs_only = [z for i, z in enumerate(zs) if i not in consumed]
    return both, sg_only, zs_only


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("targets_root")
    ap.add_argument("zerostrike_exe")
    ap.add_argument("out_dir")
    ap.add_argument("--label", default="run")
    ap.add_argument("targets", nargs="*")
    a = ap.parse_args()

    os.makedirs(a.out_dir, exist_ok=True)
    targets = a.targets or sorted(
        d for d in os.listdir(a.targets_root)
        if os.path.isdir(os.path.join(a.targets_root, d)) and not d.startswith("."))

    summary = {}
    for t in targets:
        # flush: a semgrep pass over a large target (WebGoat) runs for many
        # minutes, and Python's block buffering makes a working run look hung.
        print(f"[{a.label}] {t}", flush=True)
        zs = collapse(run_zerostrike(a.zerostrike_exe, a.targets_root, t,
                                     os.path.join(a.out_dir, f"{t}-zs-{a.label}.json")))
        sg = collapse(run_semgrep(a.targets_root, t,
                                  os.path.join(a.out_dir, f"{t}-sg.json")))
        both, sg_only, zs_only = pair_up(zs, sg)
        gaps = defaultdict(int)
        for s in sg_only:
            for c in (s["cwe"] or {"none"}):
                gaps[f"{s['lang']}/CWE-{c}"] += 1
        summary[t] = {
            "zerostrike_total": len(zs), "semgrep_total": len(sg),
            "both": len(both), "semgrep_only": len(sg_only),
            "zerostrike_only": len(zs_only),
            "overlap_pct": round(100.0 * len(both) / len(sg), 1) if sg else None,
            "top_gaps": dict(sorted(gaps.items(), key=lambda kv: -kv[1])[:12]),
        }
        print(f"    zerostrike={len(zs)} semgrep={len(sg)} both={len(both)} "
              f"sg_only={len(sg_only)} zs_only={len(zs_only)}", flush=True)

    path = os.path.join(a.out_dir, f"summary-{a.label}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print(f"\nwrote {path}")


if __name__ == "__main__":
    main()
