#!/usr/bin/env python3
"""Enumerate every class the two-level attribution leaves open, with evidence.

Four populations, one file each.  The unit is a KIND -- (target, crash site,
candidate bugs) -- not a class, because the same fault reached under different
dispatch masks forms many classes and one question.  8,088 classes collapse to
a few hundred kinds, which is small enough to read one by one.

  1 graft-triggered, no catalogued bug matches   -> the causal/semantic gap
  2 graft-independent, no catalogued bug matches -> uncatalogued native bugs
  3 graft-triggered, matches a DIFFERENT bug     -> unmasking, or a bad credit
  4 composition-dependent                        -> needs >=2 grafts together

The discriminating evidence is whether the crash site is code the transplant
patch wrote.  For each kind we locate the top project frame in
`patches/combined.diff`:

  graft-code        the crash line is a line the patch ADDED, inside a block
                    gated by one of the bugs the crash causally needs.  A
                    crash here is inside the graft itself -- the strongest
                    signal that the transplant, not the target, is at fault.
  graft-code-other  an added line, but gated by some other bug (or ungated
                    patch code).
  patched-file      the file is patched, the crash line is not an added line.
  candidate-file    the crash is in the same file as a candidate bug's
                    recorded site, and the patch does not touch that file.
  unpatched         neither.

Hunk ranges include context, so `in_hunk` is coarse; `graft-code` uses exact
added-line numbers in new-file coordinates and is not.

Usage: python3 script/two_level_unattributed.py --data DIR --out DIR
"""
import argparse
import csv
import json
import os
import re
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
GUARD = re.compile(r"__bug_dispatch\s*\[\s*(\d+)\s*\]\s*&\s*\(\s*1\s*<<\s*(\d+)\s*\)")
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def branch_states(lines):
    """new_line -> ('graft'|'original'|'plain', bits) for one hunk.

    A graft is written `if (__bug_dispatch[B] & (1<<N)) { new } else { orig }`,
    so the ELSE branch is the target's original code, merely re-indented -- and
    the diff shows it as added.  Taking every added line as graft code labels
    that original code as ours, which is how 229 libredwg classes that
    reproduce with EVERY BIT CLEAR came out as crashing "inside the graft".
    Track the branch by brace depth instead.

    `lines` is [(new_line_no, text), ...] for the lines that exist after the
    patch (added + context), in order.
    """
    st = {}
    txt = [t for _, t in lines]

    def block_end(i):
        """Index of the line closing the brace block that starts at/after i."""
        depth, seen = 0, False
        while i < len(lines):
            depth += txt[i].count("{") - txt[i].count("}")
            if "{" in txt[i]:
                seen = True
            if seen and depth <= 0:
                return i
            i += 1
        return None

    for idx, (no, t) in enumerate(lines):
        g = GUARD.findall(t)
        if not g:
            continue
        bits = {1 << (8 * int(b) + int(n)) for b, n in g}
        if "?" in t and ":" in t:              # ternary guard, all on one line
            st[no] = ("graft", bits)
            continue
        end = block_end(idx)
        if end is None or "{" not in "".join(txt[idx:idx + 3]):
            st[no] = ("graft", bits)           # single-statement guard
            continue
        for k in range(idx, end + 1):
            st[lines[k][0]] = ("graft", bits)
        # the else branch, if any, holds the target's ORIGINAL code
        e = next((c for c in (end, end + 1)
                  if c < len(lines) and re.search(r"\belse\b", txt[c])), None)
        if e is None:
            continue
        eend = block_end(e)
        for k in range(e, (eend if eend is not None else e) + 1):
            st[lines[k][0]] = ("original", bits)
    for no, _ in lines:
        st.setdefault(no, ("plain", set()))
    return st


def parse_patch(bench):
    """file -> (hunks, added).

    hunks: list of (start, end, {dispatch_value, ...}) in new-file lines.
    added: {new_line_number: (state, {dispatch_value, ...})} for lines that
    exist after the patch, state as in branch_states().
    """
    p = Path(BD) / bench / "patches" / "combined.diff"
    if not p.is_file():
        return {}
    files = {}
    cur = None
    hunks, added = [], {}
    ln = hstart = 0
    hbits = set()
    hlines = []          # (new_line_no, text) for lines present after the patch
    was_added = set()

    def flush():
        if not hlines:
            return
        hunks.append((hstart, ln, set(hbits)))
        for no, (state, bits) in branch_states(hlines).items():
            if no in was_added:
                added[no] = (state, bits)

    for line in p.read_text(errors="replace").splitlines():
        if line.startswith("+++ "):
            flush()
            if cur:
                files[cur] = (hunks, added)
            cur = line[4:].strip()
            cur = cur[2:] if cur.startswith("b/") else cur
            hunks, added, hlines, was_added = [], {}, [], set()
            continue
        m = HUNK.match(line)
        if m:
            flush()
            hstart = int(m.group(1))
            ln = hstart - 1
            hbits, hlines, was_added = set(), [], set()
            continue
        if cur is None:
            continue
        if line.startswith(("+", " ")):
            ln += 1
            hlines.append((ln, line[1:]))
            if line.startswith("+"):
                was_added.add(ln)
                for b, n in GUARD.findall(line):
                    hbits.add(1 << (8 * int(b) + int(n)))
    flush()
    if cur:
        files[cur] = (hunks, added)
    return files


def suffix(a, e):
    if not a or not e:
        return False
    a, e = a.replace("\\", "/"), e.replace("\\", "/")
    return a == e or a.endswith("/" + e.lstrip("/")) or e.endswith("/" + a.lstrip("/"))


def locate(patch, path, line):
    """(state, bits, in_hunk, hunk_bits) for a frame.

    state is 'graft' (inside a dispatch-gated then-branch), 'original' (inside
    its else-branch -- the target's own code, re-indented by the graft),
    'plain' (a line the patch added outside any guard) or '' (not an added
    line).
    """
    if not path or not line:
        return "", set(), False, set()
    line = int(line)
    for f, (hunks, added) in patch.items():
        if not suffix(path, f):
            continue
        if line in added:
            state, bits = added[line]
            return state, set(bits), True, set(bits)
        for s, e, bits in hunks:
            if s <= line <= e:
                return "", set(), True, set(bits)
    return "", set(), False, set()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    POPS = {
        "graft_triggered_unmatched": [],
        "native_unmatched": [],
        "graft_triggered_other_bug": [],
        "composition_dependent": [],
    }
    META, PATCH, OWNER = {}, {}, {}
    for n, b in BENCH.items():
        META[n] = json.load(open(f"{BD}/{b}/bug_metadata.json"))["bugs"]
        PATCH[n] = parse_patch(b)
        OWNER[n] = {v["dispatch_value"]: k for k, v in META[n].items()
                    if v.get("dispatch_value")}

    kinds = defaultdict(lambda: defaultdict(lambda: {
        "classes": 0, "crashes": 0, "fuzzers": set(), "examples": [],
        "sanitizers": Counter(), "masks": set()}))
    for n in sorted(BENCH):
        f = Path(a.data) / f"{n}_classes.csv"
        if not f.is_file():
            continue
        for r in csv.DictReader(open(f)):
            if r["contaminated"] == "True":
                continue
            l1, mm, l2 = r["level1"], r["matched_bug"], r["level2"]
            if l1 == "graft-triggered" and not mm:
                p = "graft_triggered_unmatched"
            elif l1 == "graft-independent" and not mm:
                p = "native_unmatched"
            elif l1 == "graft-triggered" and l2 == "match-other-bug":
                p = "graft_triggered_other_bug"
            elif l1 == "composition-dependent":
                p = "composition_dependent"
            else:
                continue
            key = (n, r["top_function"], r["top_file"], r["top_line"],
                   r["candidates"], mm)
            k = kinds[p][key]
            k["classes"] += 1
            k["crashes"] += int(r["class_crashes"])
            k["fuzzers"].add(r["fuzzer"])
            k["sanitizers"][r["sanitizer"]] += 1
            k["masks"].add(r["repro_masks"])
            if len(k["examples"]) < 3:
                k["examples"].append(r["testcase"])

    SUMMARY = []
    for p, ks in kinds.items():
        rows = []
        for (n, fn, fi, li, cands, mm), k in ks.items():
            cl = [b for b in cands.split("|") if b]
            ml = [b for b in mm.split("|") if b]
            state, abits, in_hunk, hbits = locate(PATCH[n], fi, li)
            cand_vals = {META[n][b].get("dispatch_value") for b in cl
                         if b in META[n]}
            owners = sorted(OWNER[n].get(v, f"unowned:{v}")
                            for v in (abits or hbits))
            if state == "graft" and (abits & cand_vals):
                verdict = "graft-code"
            elif state == "graft":
                verdict = "graft-code-other"
            elif state == "original":
                verdict = "graft-else-original"
            elif state == "plain":
                verdict = "patch-added-ungated"
            elif in_hunk:
                verdict = "patched-file"
            elif any(suffix(fi, str(META[n][b].get("crash_file") or ""))
                     for b in cl if b in META[n]):
                verdict = "candidate-file"
            else:
                verdict = "unpatched"
            # distance to the nearest candidate's recorded site in this file
            dist = ""
            for b in cl:
                v = META[n].get(b, {})
                if v.get("crash_line") and suffix(fi, str(v.get("crash_file"))):
                    d = abs(int(li or 0) - int(v["crash_line"])) if li else ""
                    dist = d if dist == "" else min(dist, d)
            rows.append({
                "benchmark": n, "verdict": verdict,
                "classes": k["classes"], "crashes": k["crashes"],
                "top_function": fn, "top_file": fi, "top_line": li,
                "candidates": cands, "matched_bug": mm,
                "matched_gating": "|".join(
                    "gated" if META[n].get(b, {}).get("dispatch_value")
                    else "ungated" for b in ml),
                "patch_owners_at_site": "|".join(owners),
                "lines_from_candidate_site": dist,
                "sanitizer": k["sanitizers"].most_common(1)[0][0],
                "fuzzers": "|".join(sorted(k["fuzzers"])),
                "distinct_masks": len(k["masks"]),
                "example_testcase": k["examples"][0] if k["examples"] else "",
            })
        rows.sort(key=lambda r: (-r["classes"], r["benchmark"]))
        with open(out / f"{p}.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        SUMMARY.append((p, rows))
        print(f"{p:30s} {sum(r['classes'] for r in rows):6d} classes  "
              f"{len(rows):4d} kinds  " +
              " ".join(f"{k}={v}" for k, v in
                       Counter(r["verdict"] for r in rows).most_common()))

        # ------------------------------------------------------------ report
        M = [f"# {HEAD[p][0]}\n", HEAD[p][1], ""]
        nsite = len({(r["benchmark"], r["top_function"], r["top_file"],
                      r["top_line"]) for r in rows})
        M.append(f"**{sum(r['classes'] for r in rows)} classes / "
                 f"{sum(r['crashes'] for r in rows)} crashes, "
                 f"{len(rows)} kinds, {nsite} distinct crash sites.** A *kind* "
                 "is one (target, crash site, causally required bugs) — the "
                 "same fault reached under different dispatch masks forms many "
                 "classes but one question, and the same site reached with "
                 "different bug sets is listed once per set. Full data: `"
                 + p + ".csv`.\n")
        M.append("## Where the crash site sits relative to the transplant\n")
        M.append("| verdict | kinds | classes | meaning |")
        M.append("|---|--:|--:|---|")
        vc = Counter(r["verdict"] for r in rows)
        vcl = Counter()
        for r in rows:
            vcl[r["verdict"]] += r["classes"]
        for v, k in vc.most_common():
            M.append(f"| `{v}` | {k} | {vcl[v]} | {VERDICT[v]} |")
        M.append("\n" + PATCH_NOTE + "\n")
        M.append("## Every kind\n")
        M.append("| target | classes | crashes | verdict | crash site | "
                 "needs bits of | matches | fuzzers |")
        M.append("|---|--:|--:|---|---|---|---|--:|")
        for r in rows:
            site = (f"`{r['top_function'] or '?'}` "
                    f"{(r['top_file'] or '?').split('/')[-1]}:"
                    f"{r['top_line'] or '?'}")
            M.append(f"| {r['benchmark']} | {r['classes']} | {r['crashes']} | "
                     f"{r['verdict']} | {site} | "
                     f"{r['candidates'].replace('|', ' ') or '—'} | "
                     f"{r['matched_bug'].replace('|', ' ') or '—'} | "
                     f"{len(r['fuzzers'].split('|'))} |")
        (out / f"{p}.md").write_text("\n".join(M) + "\n")
    return SUMMARY, out


VERDICT = {
    "graft-code": "the crash line is inside the dispatch-gated block of a bug "
                  "the crash causally needs — the fault is in the "
                  "transplanted code itself",
    "graft-code-other": "inside a gated block, but of a bug the crash does "
                        "not need",
    "graft-else-original": "inside the `else` branch of a graft — the "
                           "target's own code, merely re-indented by the patch",
    "patch-added-ungated": "a line the patch added outside any dispatch "
                           "guard (a renamed/cloned function body, or an "
                           "unconditional layout change)",
    "patched-file": "the file is patched, the crash line is not",
    "candidate-file": "same file as a causally required bug's recorded site, "
                      "different line; the patch does not touch that file",
    "unpatched": "the transplant does not touch this file at all",
}
PATCH_NOTE = (
    "Sites are located in `patches/combined.diff` by new-file line number. "
    "`graft-code` vs `graft-else-original` matters: a graft is written "
    "`if (bit) { new } else { original }`, so the else branch is the target's "
    "own code re-indented, and the diff shows it as added. Counting every "
    "added line as ours labelled 229 libredwg classes that reproduce with "
    "**every bit clear** as crashing inside the graft; they are in the else "
    "branch of `OSV-2022-387`, at libredwg's own `memcpy` in "
    "`decode_preR13_entities`. Block boundaries are found by brace matching "
    "over the diff, which is exact for the `if/else` form every graft uses "
    "and approximate for macro-heavy code.")
HEAD = {
    "graft_triggered_unmatched": (
        "Graft-triggered crashes that match no catalogued bug",
        "Level 1 proves these need one bug's dispatch bit — clear it and the "
        "crash goes away, set it alone and it returns. Level 2 finds no "
        "catalogued bug at that crash site. This is the gap between causal "
        "and semantic attribution: the bit says which graft a crash needs, "
        "not which historical bug it is."),
    "native_unmatched": (
        "Graft-independent crashes that match no catalogued bug",
        "These reproduce with every graft switched off, so no transplant is "
        "involved, and they fault where no catalogued bug is recorded. They "
        "are the target's own uncatalogued bugs — the largest unattributed "
        "population in the analysis."),
    "graft_triggered_other_bug": (
        "Graft-triggered crashes whose site belongs to a different bug",
        "The crash causally needs bug A's bit, but faults at bug B's recorded "
        "site. Where B is gated and its bit is off, the match is already "
        "vetoed by level 1 and never reaches this file; what remains is "
        "mostly B ungated — unmasking, where A makes B reachable."),
    "composition_dependent": (
        "Composition-dependent crashes",
        "No single dispatch bit reproduces these; two or more grafts must be "
        "enabled together. This is the population that would contain a bug "
        "introduced by composition itself, if there were one."),
}


if __name__ == "__main__":
    main()
