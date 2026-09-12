#!/usr/bin/env python3
"""Causal attribution result set, from the level-1 verdicts.

Reads the per-class verdicts produced by two_level_triage.py and writes every
result table the evaluation needs.  The verdict itself is NOT recomputed; it is
copied through, annotated with the two policy flags (contaminated dispatch bit,
UBSan-only crash type) and aggregated.

Crash frames are not read.  The semantic second level -- matching a replayed
stack against each bug's recorded crash_file/crash_line -- was removed
2026-08-19 (user decision), together with every table that rested on it:
per-class bug identity, the unmatched-site breakdown, and ungated-bug credit.
What remains is causal: which graft a crash requires.  Only the gated bugs have
a bit to toggle, so only they can be credited at all; a crash from an ungated
(`dispatch_value == 0`) bug reproduces at mask 0 and is indistinguishable from
a pre-existing target bug.

Outputs (into --out):
  <target>_classes.csv       per-class verdicts, authoritative
  composition_dependent.csv  every composition-dependent class, in full
  bug_attribution.csv        one row per GATED bug: seen by its bit or not
  per_fuzzer_bugs.csv        (target, fuzzer, trial, bug) credited causally
  per_fuzzer_detection.csv   (target, fuzzer) -> found / pool / %
  FULL_RESULTS.md            the suite-wide tables
  PER_TARGET.md              the same, one section per target

Usage:
  python3 script/two_level_full.py --data DIR --out DIR
"""
import argparse
import csv
import glob
import json
import os
from collections import Counter, defaultdict
from pathlib import Path

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

FIELDS = ["benchmark", "crash_key", "canon_mask", "recorded_mask",
          "class_crashes", "testcase", "fuzzer", "trial", "time", "sanitizer",
          "level1", "candidates", "repro_masks", "masks_tested",
          "sufficiency", "ubsan_only", "contaminated"]


def single_bits(masks):
    return [m for m in masks if m and not (m & (m - 1))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="dir with level-1 verdict CSVs")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    outdir = Path(a.out)
    outdir.mkdir(parents=True, exist_ok=True)

    src = sorted(glob.glob(os.path.join(a.data, "*_two_level.csv")))
    if not src:
        src = sorted(glob.glob(os.path.join(a.data, "*_classes.csv")))
    ALL, META = {}, {}
    for f in src:
        n = (os.path.basename(f).replace("_two_level.csv", "")
             .replace("_classes.csv", ""))
        meta = json.load(open(f"{BD}/{BENCH[n]}/bug_metadata.json"))["bugs"]
        META[n] = meta
        bit = CONTAMINATED.get(n, 0)
        rows = []
        for r in csv.DictReader(open(f)):
            cands = [b for b in (r.get("candidates") or "").split("|") if b]
            lvl1 = r["level1"]
            sb = single_bits(int(x) for x in (r["repro_masks"] or "").split())
            if lvl1 != "graft-triggered":
                suff = ""
            else:
                suff = "one-bit" if len(sb) == 1 else "either-of-n"
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
                "sufficiency": suff,
                "ubsan_only": (lvl1 == "non-reproducing"
                               and r["crash_key"].startswith(UBSAN_TYPES)),
                "contaminated": bool(bit and int(r["recorded_mask"]) & bit),
            })
        with open(outdir / f"{n}_classes.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=FIELDS)
            w.writeheader()
            w.writerows(rows)
        ALL[n] = rows
        print(f"{n:13s} {len(rows):6d} classes")

    clean = {n: [r for r in rs if not r["contaminated"]] for n, rs in ALL.items()}
    L = []
    P = L.append

    def cat(r):
        return "ubsan-only" if r["ubsan_only"] else r["level1"]

    P("# Causal attribution: full results\n")
    P("Generated by `script/two_level_full.py` from the level-1 verdicts. The "
      "verdict is the dispatch-bit counterfactual; crash frames are not "
      "examined. Only gated bugs can be credited.\n")

    # ---------------------------------------------------------------- table 1
    P("## 1. Verdicts by dispatch-bit counterfactual\n")
    P("| target | classes | crashes | native | graft-triggered | composition | "
      "ubsan-only | no-repro |")
    P("|---|--:|--:|--:|--:|--:|--:|--:|")
    T = Counter()
    for n, rows in sorted(clean.items()):
        c = Counter(cat(r) for r in rows)
        cr = sum(int(r["class_crashes"]) for r in rows)
        t = len(rows) or 1
        P(f"| {n} | {len(rows)} | {cr} | "
          f"{c['graft-independent']} ({100*c['graft-independent']/t:.1f}%) | "
          f"{c['graft-triggered']} ({100*c['graft-triggered']/t:.1f}%) | "
          f"{c['composition-dependent']} ({100*c['composition-dependent']/t:.1f}%) | "
          f"{c['ubsan-only']} | {c['non-reproducing']} |")
        for k, v in c.items():
            T[k] += v
        T["classes"] += len(rows)
        T["crashes"] += cr
    t = T["classes"] or 1
    P(f"| **total** | **{T['classes']}** | **{T['crashes']}** | "
      f"**{T['graft-independent']} ({100*T['graft-independent']/t:.1f}%)** | "
      f"**{T['graft-triggered']} ({100*T['graft-triggered']/t:.1f}%)** | "
      f"**{T['composition-dependent']} ({100*T['composition-dependent']/t:.1f}%)** | "
      f"**{T['ubsan-only']}** | **{T['non-reproducing']}** |")
    drop = {n: sum(1 for r in rs if r["contaminated"]) for n, rs in ALL.items()}
    drop = {k: v for k, v in drop.items() if v}
    if drop:
        P("\nExcluded as contaminated (unowned dispatch bit): "
          + ", ".join(f"{k} {v} classes" for k, v in drop.items()) + ".")

    # ---------------------------------------------------------------- table 2
    # `non-reproducing` is a replay failure and `ubsan-only` a policy
    # exclusion; neither is an attribution verdict, so the four real categories
    # are reported on their own denominator.
    P("\n## 2. The four verdicts that carry attribution\n")
    P("`graft-triggered` splits by how many single bits reproduce the crash: "
      "the sweep replays every bit the benchmark defines, so a class can have "
      "more than one independently sufficient graft.\n")
    P("| category | classes | % | crashes | % | distinct crash signatures |")
    P("|---|--:|--:|--:|--:|--:|")
    keys = [("one-bit", "exactly one bit"),
            ("either-of-n", "either of N bits"),
            ("composition-dependent", "composition-dependent"),
            ("graft-independent", "graft-independent")]
    cc, xx, sig = Counter(), Counter(), defaultdict(set)
    for n, rows in clean.items():
        for r in rows:
            if r["ubsan_only"] or r["level1"] == "non-reproducing":
                continue
            k = r["sufficiency"] or r["level1"]
            cc[k] += 1
            xx[k] += int(r["class_crashes"])
            sig[k].add((n, r["crash_key"]))
    tc = sum(cc[k] for k, _ in keys) or 1
    tx = sum(xx[k] for k, _ in keys) or 1
    for k, label in keys:
        P(f"| {label} | {cc[k]} | {100*cc[k]/tc:.1f}% | {xx[k]} | "
          f"{100*xx[k]/tx:.1f}% | {len(sig[k])} |")
    P(f"| **total** | **{tc}** | | **{tx}** | | |")

    P("\n| target | one bit | either of N | composition | graft-independent |")
    P("|---|--:|--:|--:|--:|")
    for n, rows in sorted(clean.items()):
        c = Counter(r["sufficiency"] or r["level1"] for r in rows
                    if not r["ubsan_only"] and r["level1"] != "non-reproducing")
        P(f"| {n} | {c['one-bit']} | {c['either-of-n']} | "
          f"{c['composition-dependent']} | {c['graft-independent']} |")

    # ---------------------------------------------------------------- table 3
    P("\n## 3. Gated bugs surfaced, by their dispatch bit\n")
    P("Ungated bugs (`dispatch_value == 0`) have no bit to toggle and cannot "
      "be credited; they are listed as the part of the catalogue this method "
      "does not reach.\n")
    P("| target | catalogue | gated | ungated (unreachable) | gated seen |")
    P("|---|--:|--:|--:|--:|")
    seen_bit = defaultdict(set)
    for n, rows in clean.items():
        for r in rows:
            if r["level1"] in ("graft-triggered", "composition-dependent"):
                for b in r["candidates"].split("|"):
                    if b:
                        seen_bit[n].add(b)
    G = Counter()
    for n in sorted(clean):
        gated = {b for b, v in META[n].items() if v.get("dispatch_value")}
        s = seen_bit[n] & gated
        P(f"| {n} | {len(META[n])} | {len(gated)} | {len(META[n])-len(gated)} "
          f"| {len(s)} |")
        G["cat"] += len(META[n]); G["gated"] += len(gated); G["seen"] += len(s)
    P(f"| **total** | **{G['cat']}** | **{G['gated']}** | "
      f"**{G['cat']-G['gated']}** | **{G['seen']}** |")

    with open(outdir / "bug_attribution.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["benchmark", "bug", "dispatch_value", "seen_by_bit"])
        for n in sorted(clean):
            for b, v in sorted(META[n].items()):
                if v.get("dispatch_value"):
                    w.writerow([n, b, v["dispatch_value"],
                                int(b in seen_bit[n])])

    # ---------------------------------------------------------------- table 4
    P("\n## 4. Composition-dependent classes\n")
    P("No subset search is run, so the smallest reproducing mask known is the "
      "recorded one and `candidates` lists every bug whose bit it sets -- an "
      "upper bound on what is involved.\n")
    P("| target | classes | crashes | bugs involved (upper bound) |")
    P("|---|--:|--:|--:|")
    with open(outdir / "composition_dependent.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        for n, rows in sorted(clean.items()):
            cd = [r for r in rows if r["level1"] == "composition-dependent"]
            if not cd:
                continue
            w.writerows(cd)
            bugs = {b for r in cd for b in r["candidates"].split("|") if b}
            P(f"| {n} | {len(cd)} | "
              f"{sum(int(r['class_crashes']) for r in cd)} | {len(bugs)} |")

    # ---------------------------------------------------------------- table 5
    P("\n## 5. Gated bugs credited per fuzzer\n")
    tf = defaultdict(set)
    tft = defaultdict(set)
    trials_seen = defaultdict(set)
    for n, rows in sorted(clean.items()):
        idx = Path(a.data) / f"{n}_crash_index.csv"
        if not idx.is_file():
            continue
        gated = {b for b, v in META[n].items() if v.get("dispatch_value")}
        verdict = {(r["crash_key"], r["canon_mask"]): r for r in rows}
        for r in csv.DictReader(open(idx)):
            trials_seen[(n, r["fuzzer"])].add(r["trial"])
            v = verdict.get((r["crash_key"], r["canon_mask"]))
            if not v or v["level1"] not in ("graft-triggered",
                                            "composition-dependent"):
                continue
            for b in {x for x in v["candidates"].split("|") if x} & gated:
                tf[(n, r["fuzzer"])].add(b)
                tft[(n, r["fuzzer"], r["trial"])].add(b)
    fuzzers = sorted({f for _, f in tf})
    P("| target | " + " | ".join(fuzzers) + " | union |")
    P("|---" * (len(fuzzers) + 2) + "|")
    for n in sorted(clean):
        u = set()
        cells = []
        for f in fuzzers:
            s = tf[(n, f)]
            u |= s
            cells.append(str(len(s)) if trials_seen[(n, f)] else "n/a")
        P(f"| {n} | " + " | ".join(cells) + f" | {len(u)} |")
    tot = {f: set() for f in fuzzers}
    for (n, f), s in tf.items():
        tot[f] |= {(n, b) for b in s}
    P("| **total** | "
      + " | ".join(f"**{len(tot[f])}**" for f in fuzzers)
      + f" | **{len(set().union(*tot.values())) if tot else 0}** |")

    with open(outdir / "per_fuzzer_bugs.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["benchmark", "fuzzer", "trial", "bug"])
        for (n, f, tr), s in sorted(tft.items()):
            for b in sorted(s):
                w.writerow([n, f, tr, b])
    with open(outdir / "per_fuzzer_detection.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["benchmark", "fuzzer", "found", "pool", "pct"])
        for n in sorted(clean):
            pool = len({b for b, v in META[n].items() if v.get("dispatch_value")})
            for f in fuzzers:
                if not trials_seen[(n, f)]:
                    continue
                w.writerow([n, f, len(tf[(n, f)]), pool,
                            f"{100*len(tf[(n, f)])/pool:.1f}" if pool else ""])

    (outdir / "FULL_RESULTS.md").write_text("\n".join(L) + "\n")

    # ------------------------------------------------------------ per target
    PT = ["# Causal attribution, per fuzz target\n"]
    for n, rows in sorted(clean.items()):
        gated = {b for b, v in META[n].items() if v.get("dispatch_value")}
        c = Counter(cat(r) for r in rows)
        PT.append(f"\n## {n}\n")
        PT.append(f"{len(META[n])} catalogued bugs, {len(gated)} gated / "
                  f"{len(META[n])-len(gated)} ungated. {len(rows)} classes "
                  f"over {sum(int(r['class_crashes']) for r in rows)} crashes.\n")
        PT.append("| verdict | classes | share |")
        PT.append("|---|--:|--:|")
        t = len(rows) or 1
        for k, v in c.most_common():
            PT.append(f"| {k} | {v} | {100*v/t:.1f}% |")
        PT.append(f"\nGated bugs seen by their bit: "
                  f"{len(seen_bit[n] & gated)} of {len(gated)}.")
    (outdir / "PER_TARGET.md").write_text("\n".join(PT) + "\n")
    print(f"\nwrote {outdir}/FULL_RESULTS.md and PER_TARGET.md")


if __name__ == "__main__":
    main()
