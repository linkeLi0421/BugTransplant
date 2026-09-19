#!/usr/bin/env python3
"""Classify transplanted-bug validity for RQ3.

For each (benchmark, bug) pair, compare the canonical OSV crash log in
``original-crashes/<bug>.txt`` against the post-transplant crash log in
``crashes/<bug>.txt``. Produce a three-tier verdict matching the
``ndss2027_paper_structure_plan.md`` RQ3 definition:

* ``exact``    — same sanitizer class + the innermost non-harness *site*
                 matches (shared function name and same file).
* ``partial``  — the innermost site matches but the sanitizer class
                 differs, OR same sanitizer class plus a shared
                 *discriminating* frame in both top-3 sites.
* ``rejected`` — neither. Likely an agent-introduced confounder rather
                 than the historical bug.
* ``no_data``  — one or both crash logs missing a usable stack /
                 sanitizer SUMMARY. Excluded from rate denominators.
* ``native``   — the agent modified nothing for this bug (it already
                 triggers at c*). No patch exists, so it cannot have
                 introduced a different bug: validity is not applicable.
                 Excluded from rate denominators. Classifying these
                 measures the fidelity of our reference collection, not
                 the agent, and conflates the two.

Frames sharing a program counter are grouped into one "site", carrying every
function name and file reported at that address, so a small static helper
inlined at the fault site cannot displace either the name or the location of
the function that actually holds the bug. Frames without ``:<line>`` are
kept -- dropping them mistakes a caller for the fault site.

**Specificity is measured, not assumed.** Negative control: classify every
same-benchmark mismatched ``(reference_i, post_j)`` pair, which is wrong by
construction. Over the 132 agent-modified bugs (2,348 pairs) this rule
accepts **4.6%**, against **65.0%** for the rule it replaced on the same
pairs. Over all 355 shipped bugs (17,518 pairs) it accepts 3.8%. See
``notes/methodology/rq3_oracle_specificity.md`` in the paper repo.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys
from collections import Counter
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from bug_verify import extract_sanitizer_class  # noqa: E402
# Inlined from the retired script/sideeffect/duplication_report.py, which went
# with the bitmask-dispatch attribution family; this is the only piece of it
# RQ3 validity classification needs.
_FRAME_RE = re.compile(
    r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s+(/src/[^:\n]+)(?::(\d+))?",
    re.MULTILINE,
)
_PROJECT_FILE_PREFIX = "/src/"


def extract_frames(stacktrace: str) -> list[tuple[str, str, int | None]]:
    """Return list of (function, file, line) from ASAN frames, project source only."""
    frames: list[tuple[str, str, int | None]] = []
    for m in _FRAME_RE.finditer(stacktrace or ""):
        func = m.group(1).strip()
        filepath = m.group(2).strip()
        line = int(m.group(3)) if m.group(3) else None
        if not filepath.startswith(_PROJECT_FILE_PREFIX):
            continue
        rel = "/".join(filepath.split("/")[3:])  # strip "/src/<proj>/"
        frames.append((func, rel, line))
    return frames


logger = logging.getLogger(__name__)

VERDICTS = ("exact", "partial", "rejected", "no_data", "native")

# Verdicts that are *not* evidence about the agent and are excluded from
# rate denominators.
_NON_RATED = ("no_data", "native")


# Frames whose function name OR file path looks like sanitizer / libFuzzer /
# libc infrastructure rather than project code. Stack traces in
# UBSAN/ASAN/libFuzzer paths can stack 5-10 of these on top of the real
# project frame, fooling top-frame comparison.
_INFRA_FUNC_RE = re.compile(
    r"^("
    r"__asan_|__msan_|__tsan_|__sanitizer|__interceptor_|__ubsan_"
    r"|fuzzer::|asan_thread_start|_start$|start_thread$|__clone$"
    r"|__libc_|raise$|abort$|__assert_fail$|__GI___|sigsetjmp"
    r")"
)
_INFRA_PATH_RE = re.compile(
    r"^(/src/llvm-project/|/lib/x86_64-linux-gnu/|/usr/lib/)"
)
# Dispatch wrapping renames bug-gated functions like
# `ndpi_search_kerberos_osv_2020_1715` (the wrapped/gated variant) and
# `ndpi_search_kerberos_original` (the unwrapped fallback when the dispatch
# bit is 0). Strip both so the cleaned name matches the original's
# `ndpi_search_kerberos`.
_DISPATCH_SUFFIX_RE = re.compile(r"(_osv_\d+_\d+|_original)(?=$|\W)")

# Harness entry-point frames that appear in /src/<proj>/fuzz/* and so are
# not filtered by _INFRA_PATH_RE; treat as non-vulnerability code for the
# drift tier's overlap count.
_HARNESS_FUNCS = {"LLVMFuzzerTestOneInput"}


def _clean_func(name: str) -> str:
    """Strip dispatch-wrapping bug-ID suffix from a function name."""
    return _DISPATCH_SUFFIX_RE.sub("", name)


def _is_infra(func: str, path: str) -> bool:
    return bool(_INFRA_FUNC_RE.match(func)) or bool(_INFRA_PATH_RE.match(path))


# A stack frame: leading "#N  0xADDR in <func> <path>[:line[:col]]".
# The line/column suffix is OPTIONAL on purpose: translation units built
# without line info emit "<func> /src/proj/file.c" with no ":<line>", and
# dropping those frames silently mistakes a *caller* for the fault site.
# (Same defect the retired fuzzbench_triage.parse_stacktrace_frames had; see
# two_level_attribution_plan.md threat T5.)
_FRAME_RE = re.compile(
    r"^\s*#\d+\s+(0x[0-9a-fA-F]+)\s+in\s+(.+?)\s+(\S+?)(?::(\d+))?(?::\d+)?\s*$",
    re.MULTILINE,
)

# One "site" = one program counter. Inlining makes a single PC report several
# nested function names; they are the same fault site, so they are grouped.
# A site therefore carries *all* the names and *all* the files reported at
# that address -- both innermost-first. Keeping the whole file list matters:
# an inlined helper often lives in a header (`sw32_` in blosc-private.h
# inlined into blosc_d in blosc2.c), so recording only the innermost frame's
# file would let the helper displace the location of the function that
# actually holds the bug, exactly the artifact the grouping exists to remove.
Site = tuple  # (funcs: tuple[str, ...], files: tuple[str, ...], line: int | None)


def _sites(text: str) -> list[Site]:
    """Project frames grouped into inline-sites, innermost first.

    Grouping by PC is what removes the small-static-helper artifacts: a
    `sw32_` or `_blosc_getitem` inlined at the fault site otherwise displaces
    the real function name and makes two reports of the same bug disagree.
    """
    out: list[list] = []
    prev_addr = None
    for m in _FRAME_RE.finditer(text or ""):
        addr, func, path, line = m.group(1), m.group(2).strip(), m.group(3), m.group(4)
        func = _clean_func(func.split("(")[0].strip())
        if _is_infra(func, path) or "/src/" not in path:
            continue
        rel = path.split("/src/", 1)[1]
        rel = rel.split("/", 1)[1] if "/" in rel else rel
        li = int(line) if line else None
        if prev_addr is not None and addr == prev_addr and out:
            if func not in out[-1][0]:
                out[-1][0].append(func)
            if rel not in out[-1][1]:
                out[-1][1].append(rel)
            if out[-1][2] is None:
                out[-1][2] = li
        else:
            out.append([[func], [rel], li])
        prev_addr = addr
    return [(tuple(f), tuple(p), l) for f, p, l in out]


def _top_site(sites: list[Site]) -> Site:
    """Innermost site that is not purely harness code."""
    for funcs, files, line in sites:
        if set(funcs) - _HARNESS_FUNCS:
            return (funcs, files, line)
    return ((), (), None)


def _first_top(sites: list[Site]) -> str:
    funcs, _, _ = _top_site(sites)
    return funcs[0] if funcs else ""


def _top3_fingerprint(sites: list[Site]) -> tuple:
    """Top-3 (functions, files) tuples; ignores line numbers (drift across commits)."""
    return tuple((f, p) for f, p, _ in sites[:3])


def _top3_funcs(sites: list[Site]) -> set[str]:
    return {f for funcs, _, _ in sites[:3] for f in funcs} - _HARNESS_FUNCS


def _basenames(files) -> set[str]:
    return {p.split("/")[-1] for p in files}


def _file_set(sites: list[Site]) -> set[str]:
    return {p.split("/")[-1] for _, files, _ in sites for p in files}


def _func_set(sites: list[Site]) -> set[str]:
    return {f for funcs, _, _ in sites for f in funcs}


def rare_predicate(df: Counter | None, n_bugs: int):
    """Return f(name) -> bool: is this function *discriminating* in this benchmark?

    A frame shared by most of a benchmark's bugs (the common call funnel, e.g.
    `ndpi_workflow_process_packet`) carries no evidence that two reports are the
    same bug. Only frames appearing in <=25% of the benchmark's reference logs
    count toward the partial tier.

    With df=None there is no benchmark context and every frame is treated as
    discriminating -- a strictly weaker rule, used only for one-off calls.
    """
    if df is None:
        return lambda _f: True
    threshold = max(1, 0.25 * n_bugs)
    return lambda f: df.get(f, 0) <= threshold


def classify(orig_text: str, post_text: str,
             df: Counter | None = None, n_bugs: int = 0) -> tuple[str, dict]:
    """Apply the 3-tier RQ3 rule over inline-grouped project sites.

    Cleaning steps (both sides):
      * Drop sanitizer / libFuzzer / libc infrastructure frames.
      * Strip dispatch-wrapping `_osv_\\d+_\\d+` suffix from function names.
      * Group frames sharing a program counter into one inline-site.

    Verdict:
      * **exact**    — same sanitizer class AND the innermost non-harness
                       site matches (shared function name *and* same file).
      * **partial**  — the innermost site matches but the sanitizer class
                       differs (a stale pointer surfaces as heap-UAF or as
                       SEGV depending on allocator state; an out-of-bounds
                       read lands in a redzone or an unmapped page). This
                       is a *narrow* allowance: it requires the same
                       function in the same file, not merely overlap.
                       OR: same sanitizer class and a shared
                       **discriminating** frame (see `rare_predicate`)
                       present in both top-3 sites.
      * **rejected** — none of the above.
      * **no_data**  — at least one log lacks a sanitizer SUMMARY.

    `df` / `n_bugs` supply the benchmark's function document-frequency so
    the partial tier can ignore the common call funnel. Specificity was
    measured by negative control over all same-benchmark mismatched
    (reference_i, post_j) pairs: this rule accepts 4.8% of them, versus
    80.2% for the pre-2026-08 rule it replaces.
    """
    orig_class, orig_dir = extract_sanitizer_class(orig_text)
    post_class, post_dir = extract_sanitizer_class(post_text)
    orig_sites = _sites(orig_text)
    post_sites = _sites(post_text)
    o_funcs, o_files, _ = _top_site(orig_sites)
    p_funcs, p_files, _ = _top_site(post_sites)
    orig_fp = _top3_fingerprint(orig_sites)
    post_fp = _top3_fingerprint(post_sites)

    details = {
        "orig_class": orig_class or "",
        "orig_dir": orig_dir or "",
        "orig_top": o_funcs[0] if o_funcs else "",
        "orig_top3": "|".join(f"{'/'.join(f)}@{'/'.join(p)}" for f, p in orig_fp),
        "post_class": post_class or "",
        "post_dir": post_dir or "",
        "post_top": p_funcs[0] if p_funcs else "",
        "post_top3": "|".join(f"{'/'.join(f)}@{'/'.join(p)}" for f, p in post_fp),
        "shared_funcs": len(_func_set(orig_sites) & _func_set(post_sites)),
        "shared_files": len(_file_set(orig_sites) & _file_set(post_sites)),
    }

    if not orig_class or not post_class:
        return "no_data", details

    # Both sides must agree on a function name AND on a file. Comparing the
    # whole file list, not just the innermost frame's, keeps an inlined
    # helper declared in a header from breaking a match that the function
    # names already agree on.
    same_site = (bool(set(o_funcs) & set(p_funcs))
                 and bool(set(o_files) & set(p_files)))
    if same_site:
        if orig_class == post_class:
            return "exact", details
        details["note"] = (
            f"sanitizer-class drift at an identical fault site: "
            f"{orig_class} -> {post_class}"
        )
        return "partial", details

    if orig_class == post_class:
        is_rare = rare_predicate(df, n_bugs)
        shared = {f for f in _top3_funcs(orig_sites) & _top3_funcs(post_sites)
                  if is_rare(f)}
        if shared:
            details["note"] = (
                "shared discriminating frame(s): " + ",".join(sorted(shared))
            )
            return "partial", details

    return "rejected", details


def find_benchmark_dirs(root: Path) -> list[Path]:
    """All ``*_transplant_*`` benchmark dirs under ``root``."""
    out = []
    for d in sorted(root.iterdir()):
        if d.is_dir() and "_transplant_" in d.name and (d / "bug_metadata.json").is_file():
            out.append(d)
    return out


def _benchmark_df(bench_dir: Path, bug_ids) -> tuple[Counter, int]:
    """Document frequency of each function across this benchmark's reference logs.

    Used to tell a discriminating frame from the benchmark's common call
    funnel; see `rare_predicate`.
    """
    df: Counter = Counter()
    n = 0
    for bug_id in bug_ids:
        orig = bench_dir / "original-crashes" / f"{bug_id}.txt"
        if not orig.is_file():
            continue
        n += 1
        df.update(_func_set(_sites(orig.read_text(errors="replace"))) - _HARNESS_FUNCS)
    return df, n


def _agent_modified(bug_id: str, info: dict, categories: dict | None) -> bool:
    """Did the agent change anything for this bug?

    Validity asks whether *the agent* introduced a different bug, so it is
    only meaningful where the agent touched something. Bugs that already
    trigger at c* carry no patch: nothing could have been corrupted, and
    classifying them measures the fidelity of our reference collection, not
    the agent. They are reported as ``native`` and excluded from the rates.

    With ``categories`` (data/bug_categories.csv) we use ``transplant_outcome``
    directly, which also keeps the 8 testcase-only bugs in scope -- the agent
    edited their PoC, so it could in principle have retargeted the crash.
    Without it we fall back to ``dispatch_value != 0``; on the shipped set the
    two agree for all 355 bugs, but the fallback cannot see testcase-only
    edits, so pass --categories when the file is available.
    """
    if categories is not None and bug_id in categories:
        return categories[bug_id] != "already-triggering"
    return bool(info.get("dispatch_value"))


def load_categories(path: Path | None) -> dict | None:
    """bug_id -> transplant_outcome, from data/bug_categories.csv."""
    if path is None:
        return None
    if not path.is_file():
        logger.warning("categories file not found: %s (falling back to dispatch_value)", path)
        return None
    with path.open() as f:
        return {r["bug_id"]: r.get("transplant_outcome", "")
                for r in csv.DictReader(f) if r.get("shipped", "yes") == "yes"}


def analyze_benchmark(bench_dir: Path, categories: dict | None = None) -> list[dict]:
    """One row per bug. Skips bugs lacking either crash log."""
    meta = json.loads((bench_dir / "bug_metadata.json").read_text())
    df, n_bugs = _benchmark_df(bench_dir, meta["bugs"].keys())
    rows = []
    for bug_id, info in meta["bugs"].items():
        orig = bench_dir / "original-crashes" / f"{bug_id}.txt"
        post = bench_dir / "crashes" / f"{bug_id}.txt"
        if not _agent_modified(bug_id, info, categories):
            verdict, details = "native", {
                "note": "already-triggering at c*; agent changed nothing",
            }
        elif not orig.is_file() or not post.is_file():
            verdict, details = "no_data", {}
            details["note"] = "missing_log"
        else:
            verdict, details = classify(
                orig.read_text(errors="replace"),
                post.read_text(errors="replace"),
                df=df, n_bugs=n_bugs,
            )
        rows.append({
            "benchmark": bench_dir.name,
            "bug_id": bug_id,
            "dispatch_value": info.get("dispatch_value"),
            "triggered": info.get("triggered"),
            "verdict": verdict,
            **details,
        })
    return rows


def summarize(rows: list[dict]) -> dict[str, Counter]:
    by_bench: dict[str, Counter] = {}
    for r in rows:
        by_bench.setdefault(r["benchmark"], Counter())[r["verdict"]] += 1
    by_bench["__overall__"] = Counter(r["verdict"] for r in rows)
    return by_bench


def render_markdown(summary: dict[str, Counter]) -> str:
    overall = summary["__overall__"]
    benches = sorted(k for k in summary if k != "__overall__")

    def _pct(num: int, den: int) -> str:
        return f"{num/den*100:.1f}%" if den else "—"

    lines = ["# RQ3: Transplanted-bug validity", ""]
    lines.append(
        "For each transplanted bug, compare `original-crashes/<bug>.txt` "
        "(canonical OSV reference, collected at the buggy commit / native "
        "target commit) against `crashes/<bug>.txt` (post-transplant log "
        "from the merged benchmark binary). Verdicts follow the "
        "`ndss2027_paper_structure_plan.md` definition:"
    )
    lines.append("")
    lines.append("- **exact** — same sanitizer class + the innermost non-harness *site* matches (shared function name and same file). Frames sharing a program counter are grouped, so inlining does not split a match.")
    lines.append("- **partial** — the innermost site matches but the sanitizer class differs (allocator state decides whether a stale pointer reads as heap-UAF or SEGV), OR same sanitizer class plus a shared **discriminating** frame (one appearing in <=25% of this benchmark's reference logs) in both top-3 sites.")
    lines.append("- **rejected** — neither: the fault sites differ and no discriminating frame is shared.")
    lines.append("- **no_data** — at least one log lacks a usable sanitizer SUMMARY; excluded from rate denominators.")
    lines.append("- **native** — the agent modified nothing (bug already triggers at $c^*$). No patch exists, so it cannot have introduced a different bug and validity is not applicable. Excluded from rate denominators: classifying these would measure our reference collection, not the agent.")
    lines.append("")
    lines.append("## Overall")
    lines.append("")
    classified = sum(overall[v] for v in ("exact", "partial", "rejected"))
    total = sum(overall.values())
    lines.append(
        f"- Bugs the agent modified: **{classified}** classified "
        f"({overall['native']} native bugs excluded -- no patch exists, so "
        f"validity is not applicable; {overall['no_data']} no_data)"
    )
    for v in ("exact", "partial", "rejected"):
        lines.append(f"- **{v}**: {overall[v]} ({_pct(overall[v], classified)} of classified)")
    lines.append("")
    lines.append("## Per benchmark")
    lines.append("")
    lines.append("| benchmark | modified | exact | partial | rejected | native (n/a) |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for b in benches:
        c = summary[b]
        mod = c['exact'] + c['partial'] + c['rejected']
        lines.append(
            f"| {b} | {mod} | {c['exact']} | {c['partial']} | {c['rejected']} | {c['native']} |"
        )
    lines.append("")
    return "\n".join(lines) + "\n"


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    # Stable field order regardless of dict insertion order.
    fields = [
        "benchmark", "bug_id", "dispatch_value", "triggered", "verdict",
        "orig_class", "orig_dir", "orig_top", "orig_top3",
        "post_class", "post_dir", "post_top", "post_top3",
        "shared_funcs", "shared_files", "note",
    ]
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="RQ3 transplant validity classifier (uses existing primitives).",
    )
    parser.add_argument(
        "--benchmarks-root", default=str(PROJECT_ROOT / "fuzzbench" / "benchmarks"),
        help="Root containing <project>_transplant_<target>/ benchmark dirs.",
    )
    parser.add_argument(
        "--benchmark", action="append", default=None,
        help="Restrict to specific benchmark dir name(s); can be repeated.",
    )
    parser.add_argument(
        "--output-dir", default=str(PROJECT_ROOT / "data"),
        help="Where to write rq3_validity.csv and rq3_validity_summary.md.",
    )
    parser.add_argument(
        "--categories", default=None,
        help="Path to bug_categories.csv; uses transplant_outcome to decide "
             "which bugs the agent modified. Without it, falls back to "
             "dispatch_value != 0 (cannot see testcase-only edits).",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    benchmarks_root = Path(args.benchmarks_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    categories = load_categories(Path(args.categories) if args.categories else None)

    dirs = find_benchmark_dirs(benchmarks_root)
    if args.benchmark:
        wanted = set(args.benchmark)
        dirs = [d for d in dirs if d.name in wanted]
    if not dirs:
        logger.error("No benchmark directories found under %s", benchmarks_root)
        return 2

    all_rows: list[dict] = []
    for d in dirs:
        logger.info("Analyzing %s ...", d.name)
        all_rows.extend(analyze_benchmark(d, categories))

    summary = summarize(all_rows)

    csv_path = output_dir / "rq3_validity.csv"
    md_path = output_dir / "rq3_validity_summary.md"
    write_csv(csv_path, all_rows)
    md_path.write_text(render_markdown(summary))

    overall = summary["__overall__"]
    classified = sum(overall[v] for v in ("exact", "partial", "rejected"))
    logger.info("")
    logger.info("=== RQ3 validity summary ===")
    logger.info("benchmarks: %d   shipped: %d   agent-modified (classified): %d   "
                "native (excluded): %d   no_data: %d",
                len(dirs), sum(overall.values()), classified,
                overall["native"], overall["no_data"])
    for v in ("exact", "partial", "rejected"):
        pct = (overall[v] / classified * 100) if classified else 0.0
        logger.info("  %-10s %3d  (%.1f%% of classified)", v, overall[v], pct)
    logger.info("")
    logger.info("CSV:      %s", csv_path)
    logger.info("Markdown: %s", md_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
