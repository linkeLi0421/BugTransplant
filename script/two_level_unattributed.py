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
# Some transplants clone the whole function instead of gating inside it: the
# patch adds `f_original()` (the target's behaviour) and `f_osv_2020_1715()`
# (the bug's), and the dispatch guard sits at the call site.  A crash inside
# such a clone is attributable by NAME, which the guard-tracking alone cannot
# see -- the body carries no guard.
CLONE = re.compile(r"^\s*(?:static\s+|inline\s+|const\s+|unsigned\s+|struct\s+|"
                   r"[\w:]+\s+|\*\s*)*?(\w+)\s*\(")
CLONE_ORIG = re.compile(r"_original$")
CLONE_BUG = re.compile(r"_osv[_-](\d{4})[_-](\d+)$", re.I)


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

    def block_end(i, pos=0):
        """(line index, column) where the block opening at/after (i, pos) closes.

        Character-wise, because `} else {` closes the then-block and opens the
        else-block on ONE line: counting braces per line leaves depth at 0 and
        the scan runs past the `else` into the target's original code.  That
        put a graft-independent ndpi crash inside a gated block, which cannot
        happen by construction.
        """
        depth, seen = 0, False
        while i < len(lines):
            for c in range(pos, len(txt[i])):
                ch = txt[i][c]
                if ch == "{":
                    depth += 1
                    seen = True
                elif ch == "}":
                    depth -= 1
                    if seen and depth <= 0:
                        return i, c
            pos = 0
            i += 1
        return None, None

    for idx, (no, t) in enumerate(lines):
        g = GUARD.findall(t)
        if not g:
            continue
        bits = {1 << (8 * int(b) + int(n)) for b, n in g}
        if "?" in t and ":" in t:              # ternary guard, all on one line
            st[no] = ("graft", bits)
            continue
        end, col = block_end(idx)
        if end is None or "{" not in "".join(txt[idx:idx + 3]):
            st[no] = ("graft", bits)           # single-statement guard
            continue
        for k in range(idx, end + 1):
            st[lines[k][0]] = ("graft", bits)
        # the else branch, if any, holds the target's ORIGINAL code
        if re.search(r"\belse\b", txt[end][col + 1:]):
            e, epos = end, col + 1
        elif end + 1 < len(lines) and re.search(r"\belse\b", txt[end + 1]):
            e, epos = end + 1, 0
        else:
            continue
        eend, _ = block_end(e, epos)
        for k in range(e, (eend if eend is not None else e) + 1):
            st[lines[k][0]] = ("original", bits)
    # Cloned functions: whatever the guards did not claim inside a clone body
    # belongs to that clone -- `_original` is the target's own code, and
    # `_osv_YYYY_N` is the named bug's.
    for idx, (no, t) in enumerate(lines):
        m = CLONE.match(t)
        if not m or "(" not in t:
            continue
        name = m.group(1)
        if CLONE_ORIG.search(name):
            tag = ("clone-original", None)
        else:
            b = CLONE_BUG.search(name)
            if not b:
                continue
            tag = ("clone-graft", f"OSV-{b.group(1)}-{b.group(2)}")
        end, _ = block_end(idx)
        if end is None:
            continue
        for k in range(idx, end + 1):
            if st.get(lines[k][0], ("plain", set()))[0] == "plain":
                st[lines[k][0]] = tag
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
            return state, bits, True, (set(bits) if isinstance(bits, set)
                                       else set())
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
    # Every fault site in the campaign, by level-1 verdict.  Needed to ask
    # whether a composition-dependent site is EVER reached without
    # composition -- if single grafts reach it too, composition did not create
    # it.
    site_l1 = defaultdict(Counter)
    for n in sorted(BENCH):
        f = Path(a.data) / f"{n}_classes.csv"
        if not f.is_file():
            continue
        for r in csv.DictReader(open(f)):
            if r["contaminated"] == "True":
                continue
            l1, mm, l2 = r["level1"], r["matched_bug"], r["level2"]
            site_l1[(n, r["top_function"], r["top_file"], r["top_line"])][l1] += 1
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
            state, payload, in_hunk, hbits = locate(PATCH[n], fi, li)
            cand_vals = {META[n][b].get("dispatch_value") for b in cl
                         if b in META[n]}
            abits = payload if isinstance(payload, set) else set()
            owners = sorted(OWNER[n].get(v, f"unowned:{v}")
                            for v in (abits or hbits))
            resolved = []
            if state == "clone-graft":
                owners = [payload]
                if payload in cl:
                    verdict, resolved = "graft-clone", [payload]
                else:
                    verdict = "graft-clone-other"
            elif state == "clone-original":
                owners, verdict = [], "graft-clone-original"
            elif state == "graft" and (abits & cand_vals):
                verdict = "graft-code"
                resolved = sorted(b for b in cl
                                  if META[n].get(b, {}).get("dispatch_value")
                                  in abits)
            elif state == "graft":
                verdict = "graft-code-other"
            elif state == "original":
                verdict = "graft-else-original"
            elif state == "plain":
                verdict = "patch-added-ungated"
            elif in_hunk:
                verdict = "graft-hunk-context"
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
            # Is this a bug we already know about?  Three ways to say yes,
            # strongest first; the crash site's relation to the patch is a
            # separate question and does not settle identity.
            if ml and set(ml) & set(cl):
                ident, ibug = "matches a bug it needs", sorted(set(ml) & set(cl))
            elif resolved:
                ident, ibug = "inside the graft of a bug it needs", resolved
            elif ml:
                ident, ibug = "matches a bug it does not need", ml
            else:
                ident, ibug = "not a catalogued bug", []
            rows.append({
                "benchmark": n, "verdict": verdict,
                "identified": ident, "identified_bug": "|".join(ibug),
                "classes": k["classes"], "crashes": k["crashes"],
                "top_function": fn, "top_file": fi, "top_line": li,
                "candidates": cands, "matched_bug": mm,
                "matched_gating": "|".join(
                    "gated" if META[n].get(b, {}).get("dispatch_value")
                    else "ungated" for b in ml),
                "patch_owners_at_site": "|".join(owners),
                "resolved_bug": "|".join(resolved),
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
        # Which catalogued bug is this?  Asked first, because it is the
        # question; where the crash sits in the patch is evidence for it.
        M.append("## Is it a bug we already know about?\n")
        M.append("| | kinds | classes | |")
        M.append("|---|--:|--:|---|")
        idc, idcl = Counter(), Counter()
        for r in rows:
            idc[r["identified"]] += 1
            idcl[r["identified"]] += r["classes"]
        allbugs = {b for r in rows for b in r["identified_bug"].split("|") if b}
        for k in ("matches a bug it needs", "inside the graft of a bug it needs",
                  "matches a bug it does not need", "not a catalogued bug"):
            if not idc[k]:
                continue
            M.append(f"| {k} | {idc[k]} | {idcl[k]} | "
                     f"{100*idcl[k]/sum(idcl.values()):.0f}% |")
        known = sum(idcl.values()) - idcl["not a catalogued bug"]
        M.append(f"| **catalogued bug identified** | | **{known}** | "
                 f"**{100*known/sum(idcl.values()):.0f}%** |")
        M.append(f"\n{len(allbugs)} distinct catalogued bugs are named. "
                 "*Matches a bug it needs* is both signals agreeing: the crash "
                 "requires that bug's dispatch bit and faults at the site its "
                 "reference crash records. *Matches a bug it does not need* is "
                 "unmasking in the other direction — the required grafts made "
                 "a different catalogued bug reachable.\n")
        if idc["not a catalogued bug"]:
            M.append("### The ones that are not\n")
            for r in rows:
                if r["identified"] != "not a catalogued bug":
                    continue
                key = (r["benchmark"], r["top_function"], r["top_file"],
                       r["top_line"])
                o = site_l1[key]
                alt = o["graft-triggered"] + o["graft-independent"]
                M.append(f"- **{r['benchmark']}** `{r['top_function']}` "
                         f"{(r['top_file'] or '?').split('/')[-1]}:"
                         f"{r['top_line'] or '?'} — {r['classes']} class(es), "
                         f"{r['crashes']} crash(es), {r['sanitizer']}. Needs "
                         f"{len(r['candidates'].split('|'))} bits. "
                         + (f"The same fault site is reached by {alt} classes "
                            "that need no composition at all, so the site is "
                            "not new." if alt else
                            "**No other class reaches this site.**")
                         + f" `{r['example_testcase']}`")
            M.append("")
        cdsites = {(r["benchmark"], r["top_function"], r["top_file"],
                    r["top_line"]) for r in rows}
        uniq = [s for s in cdsites
                if not (site_l1[s]["graft-triggered"]
                        + site_l1[s]["graft-independent"])]
        M.append(f"**{len(cdsites)-len(uniq)} of the {len(cdsites)} distinct "
                 "fault sites are also reached without composition** — by a "
                 "single graft or by no graft at all. A site that only a "
                 "multi-bit mask can reach is the shape a composition-created "
                 "fault would have.\n")
        for s in uniq:
            b = {r["identified_bug"] for r in rows
                 if (r["benchmark"], r["top_function"], r["top_file"],
                     r["top_line"]) == s and r["identified_bug"]}
            M.append(f"- Only under composition: **{s[0]}** `{s[1]}` "
                     f"{(s[2] or '?').split('/')[-1]}:{s[3] or '?'}"
                     + (f" — but it is {'/'.join(sorted(b))}'s own recorded "
                        "crash site, reached only once another graft is on."
                        if b else " — no catalogued bug."))
        M.append("")
        rc = sum(r["classes"] for r in rows if r["resolved_bug"])
        if rc:
            rb = {b for r in rows if r["resolved_bug"]
                  for b in r["resolved_bug"].split("|")}
            M.append(f"**{rc} of these classes ({100*rc/sum(r['classes'] for r in rows):.0f}%) "
                     f"are resolved by where they crash**: the fault is inside "
                     f"the grafted code of a bug the crash causally needs "
                     f"({len(rb)} distinct bugs), a few lines from where that "
                     f"bug's reference crash was recorded. Level 2 missed them "
                     f"on the exact line, not on the identity. Column "
                     f"`resolved_bug`.\n")
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
        M.append("## By fault site\n")
        M.append("The same fault reached under different bug sets is one site, "
                 "many kinds; libredwg in particular reaches a handful of "
                 "sites under dozens of masks. Read this table, not the kind "
                 "count.\n")
        M.append("| target | crash site | kinds | classes | crashes | "
                 "identified as | also reached without composition |")
        M.append("|---|---|--:|--:|--:|---|---|")
        bysite = defaultdict(lambda: {"k": 0, "c": 0, "cr": 0, "b": set(),
                                      "i": set()})
        for r in rows:
            s = bysite[(r["benchmark"], r["top_function"], r["top_file"],
                        r["top_line"])]
            s["k"] += 1
            s["c"] += r["classes"]
            s["cr"] += r["crashes"]
            s["i"].add(r["identified"])
            s["b"].update(b for b in r["identified_bug"].split("|") if b)
        for key, s in sorted(bysite.items(), key=lambda kv: -kv[1]["c"]):
            o = site_l1[key]
            alt = o["graft-triggered"] + o["graft-independent"]
            M.append(f"| {key[0]} | `{key[1] or '?'}` "
                     f"{(key[2] or '?').split('/')[-1]}:{key[3] or '?'} | "
                     f"{s['k']} | {s['c']} | {s['cr']} | "
                     f"{'/'.join(sorted(s['b'])) or '—'} | "
                     f"{'yes, ' + str(alt) + ' classes' if alt else '**no**'} |")
        M.append("\n## Every kind\n")
        M.append("| target | classes | crashes | identified as | crash site | "
                 "needs bits of | where in the patch | fuzzers |")
        M.append("|---|--:|--:|---|---|---|---|--:|")
        for r in rows:
            site = (f"`{r['top_function'] or '?'}` "
                    f"{(r['top_file'] or '?').split('/')[-1]}:"
                    f"{r['top_line'] or '?'}")
            nb = len([b for b in r["candidates"].split("|") if b])
            cand = (r["candidates"].replace("|", " ") if nb <= 4
                    else f"{nb} bugs")
            M.append(f"| {r['benchmark']} | {r['classes']} | {r['crashes']} | "
                     f"{r['identified_bug'].replace('|', ' ') or '—'} | {site} | "
                     f"{cand or '—'} | {r['verdict']} | "
                     f"{len(r['fuzzers'].split('|'))} |")
        (out / f"{p}.md").write_text("\n".join(M) + "\n")
    return SUMMARY, out


VERDICT = {
    "graft-code": "**resolved** — the crash line is inside the dispatch-gated "
                  "block of a bug the crash causally needs, so the fault is "
                  "in that bug's transplanted code, a few lines from where "
                  "its reference crash was recorded",
    "graft-clone": "**resolved** — inside a cloned function carrying a bug's "
                   "name (`f_osv_2020_1715`), and that bug is one the crash "
                   "causally needs",
    "graft-clone-other": "inside a bug-named clone, but not one this crash "
                         "needs",
    "graft-clone-original": "inside an `_original` clone — the target's own "
                            "code, kept beside the grafted copy",
    "graft-code-other": "inside a gated block, but of a bug the crash does "
                        "not need",
    "graft-else-original": "inside the `else` branch of a graft — the "
                           "target's own code, merely re-indented by the patch",
    "patch-added-ungated": "a line the patch added outside any dispatch "
                           "guard (a renamed/cloned function body, or an "
                           "unconditional layout change)",
    "graft-hunk-context": "an unchanged line inside a hunk the patch touches "
                          "— next to a graft, not part of one",
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
