#!/usr/bin/env python3
"""Per-benchmark two-level triage notes, deduplicated into distinct bug KINDS.

The question these notes answer is "how many distinct kinds of bug can fuzzing
this benchmark surface", not "how many crashes were seen".  A campaign emits
the same fault thousands of times; counting crashes measures fuzzer luck and
sampling, not the benchmark.  So crashes are collapsed on

    (level-1 category, required dispatch bits, sanitizer class,
     top frame's (function, file, line) -- i.e. the fault site)

Two crashes needing the same grafts and faulting at the same place are one
kind, however many times they were found.  Each kind is reported once, with a
representative testcase, the fuzzers that found it, and the earliest time.

Reads only the results CSV plus the stored replay logs -- no replays.

Usage: python3 script/two_level_report.py <csv> <benchmark-dir> <cov-tar> \
           <workdir> <out-dir> <name>
"""
import csv
import gzip
import json
import sys
import collections
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fuzzbench_triage import parse_stacktrace_frames  # noqa: E402
from two_level_triage import parse_frames_all  # noqa: E402

csv_path, bench_dir, cov_tar, workdir, out_dir, name = sys.argv[1:7]
BD, WORK, OUT = Path(bench_dir), Path(workdir), Path(out_dir)
LOGS = WORK / "logs"
meta = json.loads((BD / "bug_metadata.json").read_text())["bugs"]
gated = {b for b, v in meta.items() if v.get("dispatch_value")}
always = sorted(b for b in meta if b not in gated)
refs = {}
for b in meta:
    f = BD / "crashes" / f"{b}.txt"
    if f.is_file():
        refs[b] = parse_stacktrace_frames(f.read_text(errors="replace"))[:3]
rows = list(csv.DictReader(open(csv_path)))


def frames(r):
    p = LOGS / f"{r['testcase']}.log.gz"
    if not p.is_file():
        return []
    return parse_frames_all(gzip.open(p, "rt").read())


def kind_key(r, fr):
    """What makes two crashes the same KIND: same cause, same fault site."""
    return (r["level1"], r["candidates"], r["sanitizer"] or "?", sig_key(r, fr))


def sig_key(r, fr):
    """The FAULT SITE alone: sanitizer class + the top frame's (func, file, line).

    Deliberately the top frame only, not the top 3.  The question these notes
    answer is how many distinct kinds of BUG the benchmark can surface, and the
    same bug is commonly reached by several call paths -- libavc OSV-2025-589
    faults at isvcd_process_epslice.c:1564 via both a cabac and a non-cabac
    path, which a top-3 key split into two kinds.  Keying on the fault site
    merges them, and matches how RQ5's own matcher identifies a bug
    (crash_file + crash_line).

    Also used to spot the same fault appearing in more than one level-1
    category: a fault seen both with grafts required and with none required is
    a pre-existing fault the graft opened a *new path* to, not a new bug.
    """
    top = fr[0] if fr else ("", "", "")
    return (r["sanitizer"] or "?", top[0], top[1], top[2])


def bug_kind(b):
    """How a matched bug relates to the dispatch mechanism."""
    if not b:
        return ""
    kinds = set()
    for x in b.split("|"):
        kinds.add("always-active" if x in always else "gated")
    if kinds == {"always-active"}:
        return "always-active (no bit; indistinguishable from a pre-existing bug by the causal test)"
    if kinds == {"gated"}:
        return "gated (has its own dispatch bit)"
    return "mixed gated / always-active"


def group(subset):
    """Collapse rows into kinds, keeping a representative and provenance."""
    kinds = collections.OrderedDict()
    for r in subset:
        fr = frames(r)
        k = kind_key(r, fr)
        e = kinds.setdefault(k, {"rep": r, "frames": fr, "n": 0, "sig": sig_key(r, fr),
                                 "fuzzers": collections.Counter(),
                                 "first": None, "matched": set()})
        e["n"] += 1
        e["fuzzers"][r["fuzzer"]] += 1
        t = int(r["time"] or 0)
        e["first"] = t if e["first"] is None else min(e["first"], t)
        if r["matched_bug"]:
            e["matched"].add(r["matched_bug"])
    return kinds


def cell(x):
    """Escape a value for a markdown table cell.

    Bug lists are pipe-joined (`OSV-2023-68|OSV-2023-75`), and a raw `|`
    silently splits the row into extra columns -- the table then renders
    broken in any strict markdown viewer.
    """
    return str(x or "").replace("|", r"\|")


def bug_sites(bug_ids):
    out = {}
    for b in (bug_ids or "").split("|"):
        info = meta.get(b)
        if info and info.get("crash_file") and info.get("crash_line") is not None:
            out[b] = (info["crash_file"], int(info["crash_line"]))
    return out


def render_stack(e, o):
    """Full replayed stack of the representative, marking the matched frame.

    The matching frame is often not the fault site: RQ5's matcher accepts a
    bug's crash_file:crash_line appearing ANYWHERE on the stack, so a bug can
    be credited from a caller several frames below the crash.  Printing the
    whole stack with the depth marked makes that visible.
    """
    fr = e["frames"]
    if not fr:
        o.append("- (no frames in the replay log)")
        return
    sites = bug_sites(e["rep"]["matched_bug"])
    o.append(f"- replayed stack ({len(fr)} frames):\n")
    o.append("```")
    for i, (f, fl, l) in enumerate(fr):
        mark = ""
        for bug, (cf, cl) in sites.items():
            if l and int(l) == cl and fl.split("/")[-1] == cf.split("/")[-1]:
                mark = f"   <-- matched {bug} here (frame #{i})"
        loc = f"{fl}:{l}" if l else (fl or "(no source location)")
        o.append(f"#{i:<2d} {f} @ {loc}{mark}")
    o.append("```")


def section(o, kinds, show_masks=True):
    for n, (k, e) in enumerate(kinds.items(), 1):
        r = e["rep"]
        o.append(f"### kind {n} — {r['level2']}"
                 + (f" vs `{cell(r['matched_bug'])}`" if r["matched_bug"] else ""))
        o.append(f"- **{e['n']} crash(es)** collapse here; first seen "
                 f"{e['first'] // 3600}h by "
                 f"{', '.join(f'{f}×{c}' for f, c in e['fuzzers'].most_common())}")
        o.append(f"- representative: `{r['testcase'][:46]}`")
        if show_masks and r["candidates"]:
            o.append(f"- needs graft **{cell(r['candidates'])}**; reproduced at "
                     f"[{r['repro_masks']}] of [{r['masks_tested']}] "
                     f"(recorded {r['recorded_mask']})")
        elif show_masks:
            o.append(f"- reproduced at [{r['repro_masks']}] of "
                     f"[{r['masks_tested']}] (recorded {r['recorded_mask']})")
        o.append(f"- replayed crash: **{r['sanitizer'] or '?'}**")
        if r["matched_bug"]:
            o.append(f"- matched bug is **{bug_kind(r['matched_bug'])}**")
        for c, i, x in elsewhere(e, r["level1"]):
            o.append(f"- **same fault signature also appears as {c} kind {i}** "
                     f"({x['n']} crash(es), needs `{cell(x['rep']['candidates']) or 'no graft'}`)"
                     + ("  <- the graft opens a NEW PATH to a fault that also"
                        " occurs with no graft at all"
                        if c == "graft-independent" else ""))
        render_stack(e, o)
        o.append("")


CROSS_NOTE = [
    "A fault signature that appears in **more than one level-1 category** is",
    "reachable under more than one dispatch condition. When a graft-dependent",
    "kind shares its signature with a graft-independent one, the graft did not",
    "*create* that fault -- the fault occurs with no graft enabled at all -- it",
    "opened a **new path** to it. That is the strongest evidence available",
    "without rebuilding that such a kind is not an agent-introduced defect.\n",
]


def analysis_sections(o, kinds, cat):
    """The two cross-cutting checks, emitted for every category.

    1. what the matched bug IS -- gated, or always-active and therefore
       indistinguishable from a pre-existing bug by the causal test;
    2. whether this fault signature also occurs under a different dispatch
       condition, which tells us a graft opened a new path rather than
       creating a bug.
    """
    matched = [(n, e) for n, (k, e) in enumerate(kinds.items(), 1)
               if e["rep"]["matched_bug"]]
    o.append("## What the matched bugs are\n")
    if matched:
        o += ["Always-active bugs are still *transplanted* bugs -- they simply",
              "have no dispatch bit, so the causal test cannot separate them",
              "from a pre-existing bug of the target.\n",
              "| kind | verdict | matched | the matched bug is |",
              "|--:|---|---|---|"]
        for n, e in matched:
            o.append(f"| {n} | {e['rep']['level2']} | `{cell(e['rep']['matched_bug'])}` "
                     f"| {bug_kind(e['rep']['matched_bug'])} |")
        o.append("")
    else:
        o.append("No kind in this category matched a catalogued bug.\n")

    o.append("## Fault signatures shared with another category\n")
    o += CROSS_NOTE
    shared = [(n, e) for n, (k, e) in enumerate(kinds.items(), 1)
              if elsewhere(e, cat)]
    if shared:
        o += ["| kind | verdict | needs graft | top frame | also seen as |",
              "|--:|---|---|---|---|"]
        for n, e in shared:
            also = ", ".join(f"{c} kind {i}" for c, i, _ in elsewhere(e, cat))
            top = e["frames"][0][0] if e["frames"] else "(none)"
            o.append(f"| {n} | {e['rep']['level2']} | "
                     f"{cell(e['rep']['candidates']) or 'no graft'} | `{top}` | {also} |")
        o.append("")
    else:
        o.append("None: every fault signature in this category is unique to it "
                 "in this campaign.\n")


HEAD = [
    "## How kinds are counted\n",
    "Crashes are collapsed into **kinds**. Two crashes are the same kind when",
    "they need the same grafts and fault at the same place -- same sanitizer",
    "class and same **top frame** (function, file, line) -- however often they",
    "were found and *whatever call path reached the fault*.\n",
    "Counting raw crashes instead would measure fuzzer luck and per-signature",
    "sampling rather than what the benchmark can surface: one fault can be",
    "emitted thousands of times in a campaign, and we sample up to 3 testcases",
    "per FuzzBench signature.\n",
    "**Why the top frame only, and not the top 3.** The question is how many",
    "distinct kinds of *bug* the benchmark surfaces, and one bug is commonly",
    "reached by several call paths. libavc `OSV-2025-589` faults at",
    "`isvcd_process_epslice.c:1564` via both a cabac and a non-cabac parse path;",
    "a top-3 key split that single bug into two kinds. Keying on the fault site",
    "merges them, and matches how RQ5's own matcher identifies a bug",
    "(`crash_file` + `crash_line`).\n",
    "**What the key still separates.** The required dispatch bits are part of",
    "the key, so the same fault site reachable under different graft conditions",
    "stays separate -- that is a difference in *cause*, not in call path.\n",
    "**Nothing is lost.** `data/two-level/<bench>_two_level.csv` keeps every",
    "crash with its full replayed stack, so a call-path-level count can be",
    "re-derived without re-running anything.\n",
]

# Signature index across ALL categories, built before any note is written.
# If a fault site appears both where a graft is required and where none is,
# the graft opened a NEW PATH to a bug that is reachable anyway -- it did not
# create the bug.
ALLK = {}
for _cat in ("graft-triggered", "graft-independent", "composition-dependent"):
    ALLK[_cat] = group([r for r in rows if r["level1"] == _cat])
SIG_INDEX = collections.defaultdict(list)
for _cat, _kinds in ALLK.items():
    for _i, (_k, _e) in enumerate(_kinds.items(), 1):
        SIG_INDEX[_e["sig"]].append((_cat, _i, _e))


def elsewhere(e, cat):
    """Other categories whose kinds share this exact fault signature."""
    return [(c, i, x) for c, i, x in SIG_INDEX.get(e["sig"], []) if c != cat]


# ------------------------------------------------------------ graft-triggered
gt = [r for r in rows if r["level1"] == "graft-triggered"]
kgt = ALLK["graft-triggered"]
unmask = {k: e for k, e in kgt.items() if e["rep"]["level2"] == "match-other-bug"}
o = [f"# {name}: {len(kgt)} distinct graft-triggered kinds "
     f"(from {len(gt)} crashes)\n"] + HEAD + [
    "**Level 1 (causal).** Each crash is silent with every dispatch bit clear",
    "and reproduces with one bug's bit alone, so a graft is *necessary*. Masks",
    "tested are one-hot -- mask 0, each bug's own bit, plus the recorded mask.\n",
    "**Level 2 (semantic).** Matched against every bug in the catalogue with",
    "`fuzzbench_triage._match_bug_ids_in_stacktrace` -- the same matcher RQ5",
    "uses. A frame must hit the bug's recorded `crash_file` and `crash_line`",
    "(and `crash_function` when known). Replays run against the COVERAGE build,",
    "which carries the line tables the fuzzing binary lacks.\n",
    "`no-match` is strict by design: a transplanted bug faulting on a shifted",
    "line will not match, so it mixes genuinely unexplained crashes with",
    "near-misses on line drift.\n",
    "## Kinds\n",
    "| kind | crashes | needs graft | verdict | matched | top frame |",
    "|--:|--:|---|---|---|---|"]
for n, (k, e) in enumerate(kgt.items(), 1):
    r = e["rep"]
    top = e["frames"][0][0] if e["frames"] else "(none)"
    o.append(f"| {n} | {e['n']} | {cell(r['candidates']) or '-'} | {r['level2']} | "
             f"`{cell(r['matched_bug']) or 'none'}` | `{top}` |")
o += [f"\n**{len(unmask)} of {len(kgt)} kinds** match a bug *other* than the",
      "graft they depend on -- unmasking: the graft makes a different bug",
      "reachable rather than causing the crash itself.\n"]
analysis_sections(o, kgt, "graft-triggered")
o.append("## Every kind\n")
section(o, kgt)
(OUT / f"{name}_graft_triggered.md").write_text("\n".join(o))

# --------------------------------------------------------- graft-independent
gi = [r for r in rows if r["level1"] == "graft-independent"]
kgi = ALLK["graft-independent"]
mt = {k: e for k, e in kgi.items() if e["rep"]["matched_bug"]}
rj = {k: e for k, e in kgi.items() if not e["rep"]["matched_bug"]}
o = [f"# {name}: {len(kgi)} distinct graft-independent kinds "
     f"(from {len(gi)} crashes)\n"] + HEAD + [
    "These reproduce with **every dispatch bit clear**, so no *gated* graft is",
    f"required. That does not make them foreign: {len(always)} of this",
    f"benchmark's {len(meta)} transplanted bugs are always-active",
    "(`dispatch_value == 0`) and have no bit to switch, so their crashes are",
    "indistinguishable from a pre-existing bug by the causal test alone. Level",
    "2 is the only instrument that separates them.\n",
    f"Always-active bugs ({len(always)}): " + ", ".join(always) + "\n",
    f"- kinds matching a catalogued bug: **{len(mt)}**",
    f"- kinds matching nothing: **{len(rj)}**\n",
    "## Kinds matching a catalogued bug\n",
    "| kind | crashes | bug | always-active? | top frame |", "|--:|--:|---|---|---|"]
for n, (k, e) in enumerate(kgi.items(), 1):
    if not e["rep"]["matched_bug"]:
        continue
    b = e["rep"]["matched_bug"]
    kinds_ = {"yes" if x in always else "**no — gated**" for x in b.split("|")}
    top = e["frames"][0][0] if e["frames"] else "(none)"
    o.append(f"| {n} | {e['n']} | `{cell(b)}` | {'/'.join(sorted(kinds_))} | `{top}` |")
o += ["\n## Kinds matching nothing\n",
      "Reproduce without any graft and resemble no catalogued bug: most likely",
      "pre-existing bugs of the target that the fuzzers found on their own.\n",
      "| kind | crashes | sanitizer | top frame |", "|--:|--:|---|---|"]
for n, (k, e) in enumerate(kgi.items(), 1):
    if e["rep"]["matched_bug"]:
        continue
    top = e["frames"][0][0] if e["frames"] else "(no frames)"
    o.append(f"| {n} | {e['n']} | {e['rep']['sanitizer'] or '?'} | `{top}` |")
o.append("")
analysis_sections(o, kgi, "graft-independent")
o.append("## Every kind\n")
section(o, kgi)
o.append("\n## Reference crashes of the always-active bugs\n")
for b in always:
    if b in refs and refs[b]:
        o.append(f"- **{b}** — crash_line {meta[b].get('crash_line')} in "
                 f"`{str(meta[b].get('crash_file','?')).split('/')[-1]}`")
        for f, p, l in refs[b]:
            o.append(f"    - `{f}` @ {p}:{l}")
    else:
        o.append(f"- **{b}** — no reference crash on file")
(OUT / f"{name}_graft_independent.md").write_text("\n".join(o))

# ------------------------------------------------------ composition-dependent
cd_ = [r for r in rows if r["level1"] == "composition-dependent"]
kcd = ALLK["composition-dependent"]
o = [f"# {name}: {len(kcd)} distinct composition-dependent kinds "
     f"(from {len(cd_)} crashes)\n"] + HEAD + [
    "The narrowest category, and the only one that is a property of the",
    "*composition* rather than of any single bug.\n",
    "**Level 1.** Silent with every dispatch bit clear, and silent with each",
    "bug's bit set on its own -- but reproduces at the mask the fuzzer actually",
    "found it with. So no transplanted bug alone accounts for it; several must",
    "be enabled together.\n",
    "**What it is not.** This is *not* a count of bugs the pipeline introduced.",
    "A crash needing two grafts can still be a documented bug that only becomes",
    "*reachable* once another graft is enabled -- the same unmasking effect seen",
    "elsewhere. It is an upper bound on composition side effects, measured",
    "causally, and level 2 says whether it resembles a known bug at all.\n"]
if not kcd:
    o.append("None in this campaign.\n")
analysis_sections(o, kcd, "composition-dependent")
o.append("## Every kind\n")
section(o, kcd)
o += ["## Reading these\n",
      "`needs graft` lists every bug whose bit is set in the recorded mask, not",
      "a claim that all are involved -- the causal test only establishes that no",
      "single one suffices. Narrowing further would need pairwise masks, which",
      "are not one-hot configurations and so are not swept here.\n"]
(OUT / f"{name}_composition_dependent.md").write_text("\n".join(o))

# ------------------------------------------------------------------- kinds CSV
dest = Path("/home/user/paper1/data/two-level") / f"{name}_kinds.csv"
with open(dest, "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["benchmark", "kind", "level1", "candidates", "sanitizer",
                "level2", "matched_bug", "crashes", "fuzzers", "first_seen_s",
                "top_func", "top_file", "top_line", "representative"])
    i = 0
    for kinds in (kgt, kgi, kcd):
        for k, e in kinds.items():
            i += 1
            r = e["rep"]
            tf = e["frames"][0] if e["frames"] else ("", "", "")
            w.writerow([name, i, r["level1"], r["candidates"], r["sanitizer"],
                        r["level2"], r["matched_bug"], e["n"],
                        "|".join(sorted(e["fuzzers"])), e["first"],
                        tf[0], tf[1], tf[2], r["testcase"]])
print(f"kinds: graft-triggered {len(kgt)} (unmasking {len(unmask)}) from {len(gt)} crashes; "
      f"graft-independent {len(kgi)} ({len(mt)} matched, {len(rj)} none) from {len(gi)}; "
      f"composition-dependent {len(kcd)} from {len(cd_)}")
print("wrote", dest)
