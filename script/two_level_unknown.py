#!/usr/bin/env python3
"""What ARE the crashes whose signature matches no catalogued bug?

Two possibilities the class counts cannot separate: an uncatalogued bug of the
target, or a catalogued bug the top-frame matcher missed.  This asks each
unmatched class what evidence it carries, using the whole stored stack rather
than the top frame alone:

  bug-on-stack       a catalogued bug's exact (function, file, line) appears
                     DEEPER in the stack -- the crash ran through that bug's
                     recorded site and faulted further in.  Strongest signal
                     that this is that bug on a different path.
  same-function      the top frame's function is some catalogued bug's
                     crash_function, at a different line.
  same-file          the top frame's file holds a catalogued bug's site, but
                     a different function.
  graft-file         (graft-triggered only) the top frame is in a file the
                     required graft patches, so the crash is downstream of the
                     graft even though it matches nothing.
  no-evidence        none of the above: nothing in the stack touches any
                     catalogued bug or any patched file.
  no-stack           no usable frames, or no line number anywhere.

Usage: python3 script/two_level_unknown.py --data DIR --logs WORKDIR --out FILE
"""
import argparse
import csv
import glob
import gzip
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from two_level_triage import parse_frames_all              # noqa: E402
from two_level_full import BENCH, BD, path_suffix, top_project_frame  # noqa: E402
from two_level_unattributed import parse_patch, suffix     # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--logs", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    rows = []
    for f in sorted(glob.glob(os.path.join(a.data, "*_classes.csv"))):
        n = os.path.basename(f).replace("_classes.csv", "")
        logs = Path(a.logs) / n / "logs"
        if not logs.is_dir():
            continue
        meta = json.load(open(f"{BD}/{BENCH[n]}/bug_metadata.json"))["bugs"]
        sites = {b: (str(v.get("crash_file") or ""), v.get("crash_line"),
                     str(v.get("crash_function") or ""))
                 for b, v in meta.items() if v.get("crash_line") is not None}
        byfunc = defaultdict(list)
        byfile = defaultdict(list)
        for b, (cf, cl, fn) in sites.items():
            if fn:
                byfunc[fn].append(b)
            byfile[os.path.basename(cf)].append(b)
        patch = parse_patch(BENCH[n])
        for r in csv.DictReader(open(f)):
            if r["contaminated"] == "True" or r["matched_bug"]:
                continue
            if r["level1"] not in ("graft-triggered", "graft-independent",
                                   "composition-dependent"):
                continue
            p = logs / f"{r['testcase']}.log.gz"
            fr = parse_frames_all(gzip.open(p, "rt").read()) if p.is_file() else []
            top = top_project_frame(fr) or ("", "", "")
            # a catalogued bug's exact site, anywhere in the stack
            deep = sorted({b for (fn_, fl_, ln_) in fr
                           for b, (cf, cl, cfn) in sites.items()
                           if ln_ and int(ln_) == int(cl)
                           and path_suffix(fl_, cf)
                           and (not cfn or fn_ == cfn)})
            same_fn = sorted(set(byfunc.get(top[0], [])))
            same_fl = sorted(set(byfile.get(os.path.basename(top[1] or ""), [])))
            in_patch = any(suffix(top[1], pf) for pf in patch)
            if not fr or not top[0]:
                ev = "no-stack"
            elif deep:
                ev = "bug-on-stack"
            elif same_fn:
                ev = "same-function"
            elif same_fl:
                ev = "same-file"
            elif in_patch:
                ev = "graft-file"
            else:
                ev = "no-evidence"
            rows.append({
                "benchmark": n, "level1": r["level1"], "evidence": ev,
                "top_function": top[0], "top_file": top[1], "top_line": top[2],
                "class_crashes": r["class_crashes"],
                "sanitizer": r["sanitizer"],
                "candidates": r["candidates"],
                "bug_on_stack": "|".join(deep),
                "same_function_as": "|".join(same_fn),
                "same_file_as": "|".join(same_fl),
                "frames": len(fr),
                "testcase": r["testcase"],
            })
        print(f"{n:13s} {sum(1 for x in rows if x['benchmark']==n):6d} unmatched")

    with open(a.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    print(f"\nwrote {a.out}  ({len(rows)} classes)\n")
    for l1 in ("graft-triggered", "graft-independent", "composition-dependent"):
        sub = [x for x in rows if x["level1"] == l1]
        if not sub:
            continue
        c = Counter(x["evidence"] for x in sub)
        k = Counter((x["evidence"], x["benchmark"], x["top_function"],
                     x["top_file"], x["top_line"]) for x in sub)
        print(f"{l1}  ({len(sub)} classes, {len(k)} sites)")
        for e, v in c.most_common():
            ks = len({x for x in k if x[0] == e})
            print(f"    {e:16s} {v:6d} classes  {ks:4d} sites")


if __name__ == "__main__":
    main()
