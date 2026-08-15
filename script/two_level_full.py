#!/usr/bin/env python3
"""Full two-level attribution result set, in one pass over the replay logs.

Supersedes two_level_rematch.py (level 2 only) and two_level_summary.py
(tables only).  Reads the level-1 verdicts produced by two_level_triage.py plus
the stored per-class replay logs, recomputes level 2 on the top project frame,
and writes every result table the evaluation needs.

Level 1 -- causal, from the dispatch-bit counterfactual -- is NOT recomputed;
it is copied through.  Level 2 -- semantic, which catalogued bug is this --
is recomputed here.

Outputs (into --out):
  <target>_classes.csv      per-class verdicts, authoritative (supersedes
                            <target>_two_level{,_topframe}.csv)
  bug_attribution.csv       one row per catalogued bug: how it was attributed
  composition_dependent.csv every composition-dependent class, in full
  native_unmatched_sites.csv unmatched graft-independent crash sites, grouped
  per_fuzzer_bugs.csv       bugs credited per fuzzer per target (feeds RQ5)
  FULL_RESULTS.md           the tables

Usage:
  python3 script/two_level_full.py --data DIR --logs WORKDIR --out DIR
"""
import argparse
import csv
import glob
import gzip
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from two_level_triage import parse_frames_all  # noqa: E402

BD = "/home/user/oss-fuzz-build/fuzzbench/benchmarks"
BENCH = {
    "libavc": "libavc_transplant_svc_dec_fuzzer",
    "opensc": "opensc_transplant_fuzz_pkcs15_reader",
    "htslib": "htslib_transplant_hts_open_fuzzer",
    "ndpi_process": "ndpi_transplant_fuzz_process_packet",
    "c-blosc2": "c-blosc2_transplant_decompress_frame_fuzzer",
    "libredwg": "libredwg_transplant_llvmfuzz",
    "ntopng": "ntopng_transplant_fuzz_dissect_packet",
    "gs_pdfwrite": "ghostscript_transplant_gs_device_pdfwrite_fuzzer",
    "ndpi_reader": "ndpi_transplant_fuzz_ndpi_reader",
    "gstoraster": "ghostscript_transplant_gstoraster_fuzzer",
}

# ndpi_process dispatch bit 256 gates five live sites in combined.diff that no
# bug_metadata entry claims.  Crashes found with it set may be caused by a graft
# the catalogue does not record, so they are flagged and excluded from every
# aggregate.  See notes/results/ndpi_unowned_dispatch_bit.md.
CONTAMINATED = {"ndpi_process": 256}

# FuzzBench crash types that UBSan, not ASan, produces.  Replay runs with
# halt_on_error=0, so a UB report is not a crash and these classes legitimately
# never reproduce -- a policy exclusion, not a replay failure.
UBSAN_TYPES = ("Undefined-shift", "Integer-overflow", "Index-out-of-bounds",
               "Float-cast", "Divide-by-zero", "Invalid-bool",
               "Misaligned-address", "Object-size", "Non-positive-vla",
               "Pointer-overflow", "Invalid-shift")

# Frames that are not program code.  A fault inside an intercepted libc call
# reports ASan's interposer on top and the faulting application code beneath,
# so frame #0 taken literally rejects most heap overflows (measured: 3,106 of
# 3,117 dropped matches had an interceptor on top).  Skip these, then match the
# first remaining frame.
INFRA_PATH = re.compile(r"^(/src/llvm-project/|/lib/x86_64-linux-gnu/|"
                        r"/usr/lib/|/usr/include/|/build/glibc)")
# Sanitizer namespaces are matched as PREFIXES; libc functions must match the
# WHOLE name.  Matching those as prefixes too silently ate project functions
# that merely start with one -- libredwg's `free_preR13_object` was skipped as
# if it were libc `free`, which is why 1,632 classes of its double-free bug
# (OSV-2023-440, recorded at exactly that function) matched nothing.
INFRA_FUNC = re.compile(
    r"^(__asan|__ubsan|__msan|__tsan|__interceptor|__sanitizer|_asan|asan_|"
    r"AddressIsPoisoned|printf_common|atomic_)")
INFRA_LIBC = re.compile(
    r"^(malloc|free|calloc|realloc|memcpy|memmove|memset|strlen|strnlen|"
    r"strcpy|strncpy|strcat|strncat|strdup|strndup|"
    r"operator new(\[\])?|operator delete(\[\])?)$")


# A frame the symbolizer could not resolve to source keeps the module in the
# function field: `fseek (/lib/x86_64-linux-gnu/libc.so.6+0x8b327)`.  Those are
# not program code either, and one of them (libc `fseek`) sits on top of 51
# c-blosc2 classes.
INFRA_MODULE = re.compile(r"\((/lib/|/usr/lib/|/lib64/|<unknown module>)")


def is_infra(func, path):
    return (bool(INFRA_PATH.match(path or ""))
            or bool(INFRA_FUNC.match(func or ""))
            or bool(INFRA_LIBC.match(func or ""))
            or (not path and bool(INFRA_MODULE.search(func or ""))))


def top_project_frame(frames):
    for fr in frames:
        if not is_infra(fr[0], fr[1]):
            return fr
    return None


def path_suffix(a, e):
    """One path is a /-aligned suffix of the other."""
    if not a or not e:
        return False
    a, e = a.replace("\\", "/"), e.replace("\\", "/")
    return a == e or a.endswith("/" + e.lstrip("/")) or e.endswith("/" + a.lstrip("/"))


def match_top(frames, targets):
    """(strict, basename_only) -- bugs whose recorded site IS the crash site.

    strict requires the paths to agree as suffixes; basename_only holds bugs
    that agree on file basename and line and function but NOT on path, i.e.
    the matches the old basename fallback added.
    """
    top = top_project_frame(frames)
    if not top:
        return [], [], None
    func, path, line = top
    if not line:
        return [], [], top
    strict, loose = [], []
    for bug, (cf, cl, fn) in targets.items():
        if int(line) != int(cl):
            continue
        if fn and func != fn:
            continue
        if path_suffix(path, cf):
            strict.append(bug)
        elif os.path.basename(path or "") == os.path.basename(cf):
            loose.append(bug)
    return sorted(strict), sorted(loose), top


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="dir with level-1 verdict CSVs")
    ap.add_argument("--logs", required=True, help="workdir holding <name>/logs")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    outdir = Path(a.out)
    outdir.mkdir(parents=True, exist_ok=True)

    src = sorted(glob.glob(os.path.join(a.data, "*_two_level.csv")))
    if not src:
        src = sorted(glob.glob(os.path.join(a.data, "*_classes.csv")))
    ALL = {}
    META = {}
    for f in src:
        n = (os.path.basename(f).replace("_two_level.csv", "")
             .replace("_classes.csv", ""))
        logs = Path(a.logs) / n / "logs"
        if not logs.is_dir():
            print(f"!! {n}: no logs at {logs}, skipped")
            continue
        meta = json.load(open(f"{BD}/{BENCH[n]}/bug_metadata.json"))["bugs"]
        META[n] = meta
        tg = {k: (str(v.get("crash_file", "")), v.get("crash_line"),
                  str(v.get("crash_function", "") or ""))
              for k, v in meta.items()
              if v.get("crash_file") and v.get("crash_line") is not None}
        bit = CONTAMINATED.get(n, 0)
        rows = []
        for r in csv.DictReader(open(f)):
            p = logs / f"{r['testcase']}.log.gz"
            fr = parse_frames_all(gzip.open(p, "rt").read()) if p.is_file() else []
            strict, loose, top = match_top(fr, tg)
            cands = [b for b in (r.get("candidates") or "").split("|") if b]
            lvl1 = r["level1"]
            # Level 1 vetoes level 2.  A GATED bug's grafted code only runs
            # when its bit is set, so if the crash reproduces with that bit
            # CLEAR the bug cannot be the cause -- whatever the stack says.
            # The site is real but shared: the fault is at a location that
            # exists in the target regardless of the graft.  Measured over the
            # ten targets this vetoes a bug in 24% of matched classes, and
            # every named bug in 394 of them.
            masks = [int(x) for x in (r.get("repro_masks") or "").split()]
            minm = min(masks) if masks else None
            vetoed = []
            if minm is not None:
                dv = {b: meta.get(b, {}).get("dispatch_value") for b in strict}
                vetoed = [b for b in strict if dv[b] and not (minm & dv[b])]
                strict = [b for b in strict if b not in vetoed]
            if not strict:
                lvl2 = "no-match"
            elif not cands or set(strict) & set(cands):
                lvl2 = "match"
            else:
                lvl2 = "match-other-bug"
            # Credit: level 1 is authoritative when it has a verdict (the crash
            # provably needs those bits); level 2 names the bug when level 1
            # cannot (no bits involved).
            if lvl1 in ("graft-triggered", "composition-dependent"):
                credited = cands
            elif lvl1 == "graft-independent":
                credited = strict
            else:
                credited = []
            rows.append({
                "benchmark": n,
                "crash_key": r["crash_key"],
                "canon_mask": r["canon_mask"],
                "recorded_mask": r["recorded_mask"],
                "class_crashes": r["class_crashes"],
                "testcase": r["testcase"],
                "fuzzer": r["fuzzer"], "trial": r["trial"], "time": r["time"],
                "sanitizer": r["sanitizer"],
                "level1": lvl1,
                "candidates": "|".join(cands),
                "repro_masks": r["repro_masks"],
                "masks_tested": r["masks_tested"],
                "top_function": (top or ("", "", ""))[0],
                "top_file": (top or ("", "", ""))[1],
                "top_line": (top or ("", "", ""))[2] or "",
                "level2": lvl2,
                "matched_bug": "|".join(strict),
                "matched_vetoed_bit_off": "|".join(vetoed),
                "matched_basename_only": "|".join(loose),
                "ambiguous": len(strict) > 1,
                "credited_bug": "|".join(credited),
                "ubsan_only": (lvl1 == "non-reproducing"
                               and r["crash_key"].startswith(UBSAN_TYPES)),
                "contaminated": bool(bit and int(r["recorded_mask"]) & bit),
            })
        with open(outdir / f"{n}_classes.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        ALL[n] = rows
        print(f"{n:13s} {len(rows):6d} classes")

    clean = {n: [r for r in rs if not r["contaminated"]] for n, rs in ALL.items()}
    L = []          # report lines
    P = L.append

    def cat(r):
        return "ubsan-only" if r["ubsan_only"] else r["level1"]

    # ---------------------------------------------------------------- table 1
    P("## 1. Level 1 -- causal attribution by dispatch-bit counterfactual\n")
    P("| target | classes | crashes | native | graft-triggered | composition | "
      "ubsan-only | no-repro |")
    P("|---|--:|--:|--:|--:|--:|--:|--:|")
    T = Counter()
    for n, rows in sorted(clean.items()):
        c = Counter(cat(r) for r in rows)
        cr = sum(int(r["class_crashes"]) for r in rows)
        t = len(rows) or 1
        T.update(c)
        T["classes"] += len(rows)
        T["crashes"] += cr
        f = lambda k: f"{c[k]} ({100*c[k]/t:.1f}%)"
        P(f"| {n} | {len(rows)} | {cr} | {f('graft-independent')} | "
          f"{f('graft-triggered')} | {f('composition-dependent')} | "
          f"{c['ubsan-only']} | {c['non-reproducing']} |")
    t = T["classes"] or 1
    f = lambda k: f"**{T[k]} ({100*T[k]/t:.1f}%)**"
    P(f"| **total** | **{T['classes']}** | **{T['crashes']}** | "
      f"{f('graft-independent')} | {f('graft-triggered')} | "
      f"{f('composition-dependent')} | **{T['ubsan-only']}** | "
      f"**{T['non-reproducing']}** |")
    drop = {n: sum(1 for r in rs if r["contaminated"]) for n, rs in ALL.items()}
    drop = {k: v for k, v in drop.items() if v}
    if drop:
        P("\nExcluded as contaminated (unowned dispatch bit): "
          + ", ".join(f"{k} {v} classes" for k, v in drop.items()) + ".")

    # ---------------------------------------------------------------- table 2
    P("\n## 2. Level 2 -- semantic match on the top project frame\n")
    P("Restricted to classes where level 2 is the attribution that matters: "
      "`graft-independent` (no bits involved, so level 1 has nothing to say).\n")
    P("| target | native | matched | unmatched | ambiguous | distinct bugs | "
      "ungated | gated |")
    P("|---|--:|--:|--:|--:|--:|--:|--:|")
    N = Counter()
    for n, rows in sorted(clean.items()):
        nat = [r for r in rows if r["level1"] == "graft-independent"]
        m = [r for r in nat if r["matched_bug"]]
        amb = [r for r in m if r["ambiguous"]]
        bugs = set()
        for r in m:
            bugs.update(r["matched_bug"].split("|"))
        gated = {b for b, v in META[n].items() if v.get("dispatch_value")}
        N["nat"] += len(nat)
        N["m"] += len(m)
        N["amb"] += len(amb)
        P(f"| {n} | {len(nat)} | {len(m)} ({100*len(m)/max(1,len(nat)):.0f}%) | "
          f"{len(nat)-len(m)} | {len(amb)} | {len(bugs)} | "
          f"{len(bugs - gated)} | {len(bugs & gated)} |")
    P(f"| **total** | **{N['nat']}** | **{N['m']} "
      f"({100*N['m']/max(1,N['nat']):.0f}%)** | **{N['nat']-N['m']}** | "
      f"**{N['amb']}** | | | |")
    P("\nAmbiguous = the top frame is the recorded crash site of more than one "
      "catalogued bug; every candidate is credited (see "
      "`notes/results/level2_top_project_frame.md`).")

    bo = sum(1 for rs in clean.values() for r in rs
             if r["matched_basename_only"] and not r["matched_bug"])
    P(f"\nPath rule: a bug's file must be a /-aligned suffix of the crash "
      f"frame's path. A looser basename-only comparison would add {bo} further "
      f"matched classes suite-wide; they are recorded in "
      f"`matched_basename_only` and are NOT counted above.")

    # ---------------------------------------------------------------- table 3
    P("\n## 3. Bugs surfaced, and how\n")
    P("| target | catalogue | gated | ungated | seen | by bit (causal) | "
      "by signature | by both |")
    P("|---|--:|--:|--:|--:|--:|--:|--:|")
    G = Counter()
    bugrows = []
    for n, rows in sorted(clean.items()):
        meta = META[n]
        gated = {b for b, v in meta.items() if v.get("dispatch_value")}
        bybit, bysig = Counter(), Counter()
        bysig_nat, bysig_uniq, bybit_cd = Counter(), Counter(), Counter()
        for r in rows:
            cands = [b for b in r["candidates"].split("|") if b]
            mm = [b for b in r["matched_bug"].split("|") if b]
            if r["level1"] == "graft-triggered":
                bybit.update(cands)
            elif r["level1"] == "composition-dependent":
                bybit_cd.update(cands)
            for b in mm:
                bysig[b] += 1
                if r["level1"] == "graft-independent":
                    bysig_nat[b] += 1
                if len(mm) == 1:
                    bysig_uniq[b] += 1
        seen = set(bybit) | set(bysig) | set(bybit_cd)
        G["cat"] += len(meta)
        G["gated"] += len(gated)
        G["seen"] += len(seen)
        G["bit"] += len(set(bybit) | set(bybit_cd))
        G["sig"] += len(bysig)
        G["both"] += len((set(bybit) | set(bybit_cd)) & set(bysig))
        P(f"| {n} | {len(meta)} | {len(gated)} | {len(meta)-len(gated)} | "
          f"{len(seen)} | {len(set(bybit) | set(bybit_cd))} | {len(bysig)} | "
          f"{len((set(bybit) | set(bybit_cd)) & set(bysig))} |")
        for b, v in sorted(meta.items()):
            bugrows.append({
                "benchmark": n, "bug_id": b,
                "gated": b in gated,
                "dispatch_value": v.get("dispatch_value", 0),
                "crash_file": v.get("crash_file", ""),
                "crash_line": v.get("crash_line", ""),
                "crash_function": v.get("crash_function", ""),
                "seen": b in seen,
                "classes_by_bit": bybit[b],
                "classes_by_bit_composition": bybit_cd[b],
                "classes_by_signature": bysig[b],
                "classes_by_signature_native": bysig_nat[b],
                "classes_signature_unambiguous": bysig_uniq[b],
            })
    P(f"| **total** | **{G['cat']}** | **{G['gated']}** | "
      f"**{G['cat']-G['gated']}** | **{G['seen']}** | **{G['bit']}** | "
      f"**{G['sig']}** | **{G['both']}** |")
    P("\n`by bit` = a crash provably needs that bug's dispatch bit (level 1). "
      "`by signature` = a crash faults at that bug's recorded site (level 2). "
      "The two overlap; `seen` is their union.")
    BUGROWS = bugrows

    # ---------------------------------------------------------------- table 4
    P("\n## 4. Composition-dependent crashes\n")
    P("| target | classes | crashes | bugs involved | matches a catalogued bug "
      "| matches nothing |")
    P("|---|--:|--:|--:|--:|--:|")
    C = Counter()
    cdrows = []
    for n, rows in sorted(clean.items()):
        cd = [r for r in rows if r["level1"] == "composition-dependent"]
        if not cd:
            continue
        m = sum(1 for r in cd if r["matched_bug"])
        cr = sum(int(r["class_crashes"]) for r in cd)
        inv = set()
        for r in cd:
            inv.update(b for b in r["candidates"].split("|") if b)
        C["cd"] += len(cd)
        C["m"] += m
        C["cr"] += cr
        P(f"| {n} | {len(cd)} | {cr} | {len(inv)} | {m} | {len(cd)-m} |")
        cdrows += cd
    P(f"| **total** | **{C['cd']}** | **{C['cr']}** | | **{C['m']}** | "
      f"**{C['cd']-C['m']}** |")
    if C["cd"]:
        P(f"\nComposition-dependent classes are {100*C['cd']/t:.2f}% of all "
          f"classes and {100*C['cr']/max(1,T['crashes']):.2f}% of all crashes; "
          f"{100*C['m']/C['cd']:.0f}% fault at a catalogued bug's site.")
    if cdrows:
        with open(outdir / "composition_dependent.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(cdrows[0]))
            w.writeheader()
            w.writerows(cdrows)

    # ---------------------------------------------------------------- table 5
    P("\n## 5. Unmatched graft-independent crashes, by site\n")
    sites = Counter()
    why = Counter()
    for n, rows in sorted(clean.items()):
        files = {str(v["crash_file"]) for v in META[n].values() if v.get("crash_file")}
        for r in rows:
            if r["level1"] != "graft-independent" or r["matched_bug"]:
                continue
            sites[(n, r["top_function"], r["top_file"], r["top_line"])] += 1
            if not r["top_function"] and not r["top_file"]:
                why["no usable stack in the replay log"] += 1
            elif not r["top_line"]:
                why["top frame carries no line number"] += 1
            elif any(path_suffix(r["top_file"], f) for f in files):
                why["faults in a bug's file, at a different line"] += 1
            else:
                why["faults in a file no catalogued bug touches"] += 1
    P("Why each unmatched class is unmatched:\n")
    P("| reason | classes |")
    P("|---|--:|")
    for k, v in why.most_common():
        P(f"| {k} | {v} |")
    P("")
    P(f"{len(sites)} distinct crash sites over "
      f"{sum(sites.values())} classes. Top 20:\n")
    P("| target | function | file:line | classes |")
    P("|---|---|---|--:|")
    for (n, fn, fi, li), c in sites.most_common(20):
        P(f"| {n} | `{fn or '?'}` | `{fi or '?'}:{li or '?'}` | {c} |")
    with open(outdir / "native_unmatched_sites.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["benchmark", "top_function", "top_file", "top_line", "classes"])
        for (n, fn, fi, li), c in sorted(sites.items(), key=lambda kv: -kv[1]):
            w.writerow([n, fn, fi, li, c])

    # ---------------------------------------------------------------- table 6
    # Credit is split by which level established it, because the two are not
    # equally strong evidence.  A GATED bug is credited causally: the crash
    # provably needs its dispatch bit.  An UNGATED bug has no bit to toggle, so
    # its credit rests entirely on the crash site matching -- that is the
    # category to look at when asking how much of the fuzzer comparison stands
    # on signature matching.
    P("\n## 6. Bugs credited per fuzzer, per target\n")
    tf = defaultdict(lambda: defaultdict(set))      # (target, fuzzer) -> kind
    tft = defaultdict(lambda: defaultdict(set))     # (target, fuzzer, trial)
    trials_seen = defaultdict(set)                  # (target, fuzzer) -> trials
    seen_any = defaultdict(set)
    bug_fz = defaultdict(set)                       # (target, bug) -> fuzzers
    for n, rows in sorted(clean.items()):
        idx = Path(a.data) / f"{n}_crash_index.csv"
        if not idx.is_file():
            continue
        gated = {b for b, v in META[n].items() if v.get("dispatch_value")}
        verdict = {(r["crash_key"], r["canon_mask"]): r for r in rows}
        for r in csv.DictReader(open(idx)):
            trials_seen[(n, r["fuzzer"])].add(r["trial"])
            v = verdict.get((r["crash_key"], r["canon_mask"]))
            if not v:
                continue
            causal = {b for b in v["candidates"].split("|") if b}
            bysig = {b for b in v["matched_bug"].split("|") if b}
            for b in causal & gated:
                tf[(n, r["fuzzer"])]["gated"].add(b)
                tft[(n, r["fuzzer"], r["trial"])]["gated"].add(b)
                seen_any["gated"].add((n, b))
                bug_fz[(n, b)].add(r["fuzzer"])
            for b in bysig - gated:
                tf[(n, r["fuzzer"])]["ungated"].add(b)
                tft[(n, r["fuzzer"], r["trial"])]["ungated"].add(b)
                seen_any["ungated"].add((n, b))
                bug_fz[(n, b)].add(r["fuzzer"])
    FZ = sorted({f for _, f in trials_seen})
    # A campaign that archived no crash at all leaves no row in the index, and
    # a 0 there means "no data", not "found nothing".  c-blosc2 x libafl is the
    # clear case (0 trials); gstoraster x aflplusplus has 2 of 10.
    P("Trials that produced any archived crash, out of 10:\n")
    P("| target | " + " | ".join(FZ) + " |")
    P("|---|" + "--:|" * len(FZ))
    for n in sorted(clean):
        P(f"| {n} | " + " | ".join(
            (f"**{len(trials_seen[(n, f)])}**" if len(trials_seen[(n, f)]) < 10
             else "10") for f in FZ) + " |")
    P("\nBold marks incomplete coverage; those cells are `n/a` below, not zero.")
    for kind, why in (("ungated", "credit rests on crash-site matching alone"),
                      ("gated", "credit is causal -- the crash requires that bit")):
        P(f"\n### {kind} bugs ({why})\n")
        P("| target | in catalogue | " + " | ".join(FZ) + " | union |")
        P("|---|--:|" + "--:|" * (len(FZ) + 1))
        for n in sorted(clean):
            gset = {b for b, v in META[n].items() if v.get("dispatch_value")}
            pool = len(gset) if kind == "gated" else len(META[n]) - len(gset)
            cells = [len(tf[(n, f)][kind]) for f in FZ]
            uni = set().union(*[tf[(n, f)][kind] for f in FZ]) if FZ else set()
            hi = max(cells) if cells else 0
            out = []
            for f, c in zip(FZ, cells):
                if not trials_seen[(n, f)]:
                    out.append("n/a")
                else:
                    out.append(f"**{c}**" if c == hi and hi else str(c))
            P(f"| {n} | {pool} | " + " | ".join(out) + f" | {len(uni)} |")
        tot = [sum(len(tf[(n, f)][kind]) for n in clean) for f in FZ]
        pool = sum(sum(1 for v in META[n].values()
                       if bool(v.get("dispatch_value")) == (kind == "gated"))
                   for n in clean)
        P(f"| **total** | **{pool}** | "
          + " | ".join(f"**{c}**" for c in tot)
          + f" | **{len(seen_any[kind])}** |")
        if tot:
            P(f"\nSpread {min(tot)}--{max(tot)} bugs "
              f"({max(tot)/max(1,min(tot)):.2f}x).")
    P("\nBold marks the best fuzzer on that target. A bug counts once per "
      "target no matter how often it was hit, and the per-trial figures below "
      "say how much of that is one lucky trial.\n")

    # Trial ids are FuzzBench's, not 1..10, and a trial that produced no crash
    # at all leaves no row in the crash index.  Take the trials that appear and
    # say how many they were, rather than assuming ten.
    P("\n### Mean per trial, ungated bugs\n")
    P("| target | " + " | ".join(FZ) + " |")
    P("|---|" + "--:|" * len(FZ))
    for n in sorted(clean):
        cells = []
        for f in FZ:
            trs = trials_seen[(n, f)]
            if not trs:
                cells.append("n/a")
                continue
            per = [len(tft[(n, f, tr)]["ungated"]) for tr in trs]
            cells.append(f"{sum(per)/len(per):.1f}")
        P(f"| {n} | " + " | ".join(cells) + " |")
    P("\nMean distinct ungated bugs a single 24 h trial surfaces, averaged over "
      "the trials that produced crashes. The gap between this and the union "
      "above is how much of a fuzzer's score comes from repetition rather than "
      "from a single run.")

    P("\n### Detection rate: share of the target's catalogue each fuzzer "
      "surfaces\n")
    det = []
    for kind in ("gated", "ungated"):
        P(f"\n**{kind} bugs**\n")
        P("| target | pool | " + " | ".join(FZ) + " | union |")
        P("|---|--:|" + "--:|" * (len(FZ) + 1))
        for n in sorted(clean):
            gset = {b for b, v in META[n].items() if v.get("dispatch_value")}
            pool = len(gset) if kind == "gated" else len(META[n]) - len(gset)
            cells, uni = [], set()
            for f in FZ:
                got = tf[(n, f)][kind]
                uni |= got
                cells.append("n/a" if not trials_seen[(n, f)] else
                             (f"{100*len(got)/pool:.0f}%" if pool else "—"))
                det.append({
                    "benchmark": n, "fuzzer": f, "gating": kind,
                    "found": len(got), "pool": pool,
                    "pct": f"{100*len(got)/pool:.1f}" if pool else "",
                    "trials_with_crashes": len(trials_seen[(n, f)]),
                })
            P(f"| {n} | {pool} | " + " | ".join(cells) + " | "
              + (f"{100*len(uni)/pool:.0f}%" if pool else "—") + " |")
        tot_pool = sum(sum(1 for v in META[n].values()
                           if bool(v.get("dispatch_value")) == (kind == "gated"))
                       for n in clean)
        tot = [sum(len(tf[(n, f)][kind]) for n in clean) for f in FZ]
        P(f"| **suite** | **{tot_pool}** | "
          + " | ".join(f"**{100*c/tot_pool:.0f}%**" for c in tot)
          + f" | **{100*len(seen_any[kind])/tot_pool:.0f}%** |")
    with open(outdir / "per_fuzzer_detection.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(det[0]))
        w.writeheader()
        w.writerows(det)
    P("\nA percentage is of that target's own pool, so it is comparable across "
      "fuzzers but not across targets. `n/a` marks a fuzzer that archived no "
      "crash on that target at all.")

    with open(outdir / "per_fuzzer_bugs.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["benchmark", "fuzzer", "trial", "bug_id", "gating",
                    "attributed_by"])
        for (n, f, tr), kinds in sorted(tft.items()):
            for kind, bugs in sorted(kinds.items()):
                for b in sorted(bugs):
                    w.writerow([n, f, tr, b, kind,
                                "dispatch bit" if kind == "gated"
                                else "crash site"])

    # ------------------------------------------------------------ per target
    PT = ["# Two-level attribution, per fuzz target\n",
          "One section per target. Generated by `script/two_level_full.py`; "
          "see `FULL_RESULTS.md` for the suite-wide tables and `README.md` for "
          "what each column means.\n"]
    for n in sorted(clean):
        rows = clean[n]
        meta = META[n]
        gset = {b for b, v in meta.items() if v.get("dispatch_value")}
        c = Counter(cat(r) for r in rows)
        nat = [r for r in rows if r["level1"] == "graft-independent"]
        m = [r for r in nat if r["matched_bug"]]
        cd = [r for r in rows if r["level1"] == "composition-dependent"]
        cdsites = {(r["top_function"], r["top_file"], r["top_line"]) for r in cd}
        gseen = {b for f in FZ for b in tf[(n, f)]["gated"]}
        useen = {b for f in FZ for b in tf[(n, f)]["ungated"]}
        drop = sum(1 for r in ALL[n] if r["contaminated"])
        PT.append(f"\n## {n}\n")
        PT.append(f"{len(meta)} catalogued bugs — {len(gset)} gated, "
                  f"{len(meta)-len(gset)} ungated. {len(rows)} replay classes "
                  f"over {sum(int(r['class_crashes']) for r in rows)} crashes"
                  + (f" ({drop} further classes excluded as contaminated)"
                     if drop else "") + ".\n")
        PT.append("| level 1 | classes | share |")
        PT.append("|---|--:|--:|")
        for k in ("graft-triggered", "graft-independent",
                  "composition-dependent", "non-reproducing", "ubsan-only"):
            PT.append(f"| {k} | {c[k]} | {100*c[k]/max(1,len(rows)):.1f}% |")
        PT.append(f"\n**Bugs seen: {len(gseen | useen)} of {len(meta)}** — "
                  f"{len(gseen)}/{len(gset)} gated (causally, by dispatch bit) "
                  f"and {len(useen)}/{len(meta)-len(gset)} ungated (by crash "
                  f"site).\n")
        PT.append("| fuzzer | ungated bugs | gated bugs | trials with crashes |")
        PT.append("|---|--:|--:|--:|")
        for f in FZ:
            k = len(trials_seen[(n, f)])
            PT.append(f"| {f} | "
                      + (f"{len(tf[(n, f)]['ungated'])} | "
                         f"{len(tf[(n, f)]['gated'])}" if k else "n/a | n/a")
                      + f" | {k} |")
        PT.append(f"\nGraft-independent classes: {len(nat)}, of which "
                  f"{len(m)} match a catalogued bug "
                  f"({100*len(m)/max(1,len(nat)):.0f}%) and "
                  f"{sum(1 for r in m if r['ambiguous'])} match more than one.")
        if cd:
            PT.append(f"\nComposition-dependent: {len(cd)} classes at "
                      f"{len(cdsites)} distinct fault sites, involving "
                      + str(len({b for r in cd for b in r["candidates"].split("|") if b}))
                      + " bugs.")
        else:
            PT.append("\nComposition-dependent: none.")
        PT.append("")
    (outdir / "PER_TARGET.md").write_text("\n".join(PT) + "\n")

    for r in BUGROWS:
        fz = sorted(bug_fz.get((r["benchmark"], r["bug_id"]), ()))
        r["found_by"] = "|".join(fz)
        r["n_fuzzers"] = len(fz)
    with open(outdir / "bug_attribution.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(BUGROWS[0]))
        w.writeheader()
        w.writerows(BUGROWS)

    (outdir / "FULL_RESULTS.md").write_text(
        "# Two-level attribution: full results\n\n"
        "Generated by `script/two_level_full.py` (BugTransplant repo) from the "
        "replay logs. Level 1 is the dispatch-bit counterfactual; level 2 is "
        "the top-project-frame match against `bug_metadata.json`.\n\n"
        + "\n".join(L) + "\n")
    print("\n".join(L))
    print(f"\nwrote {outdir}/FULL_RESULTS.md")


if __name__ == "__main__":
    main()
