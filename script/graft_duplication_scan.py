#!/usr/bin/env python3
"""Find transplanted bugs whose gated code is identical or near-identical.

Attribution credits bug i when a crash needs dispatch bit i.  If two bugs guard
the same statements, that one condition credits two bugs and no dispatch-based
method can separate them -- discovery counts are then inflated by construction.
libavc OSV-2023-68 and OSV-2023-75 are byte-identical this way.

Scans every benchmark's combined.diff, extracts the added lines inside each
`if (__bug_dispatch[B] & (1 << N))` block, and compares blocks pairwise.

Usage: python3 script/graft_duplication_scan.py [--benchmarks-dir DIR]
"""
import argparse
import difflib
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

GUARD = re.compile(r"__bug_dispatch\[(\d+)\]\s*&\s*\(1\s*<<\s*(\d+)\)")


def norm(line):
    """Added source line, stripped of diff marker and whitespace."""
    return re.sub(r"\s+", " ", line[1:]).strip()


def blocks(diff_path):
    """(byte, bit) -> list of (file, block-text) guarded by that bit.

    Compared PER SITE, not per bug.  A bug's total gated code can differ while
    one of its blocks is byte-identical to another bug's -- libavc OSV-2023-68
    and OSV-2023-75 share an identical relaxed check in isvcd_api.c but differ
    in isvcd_parse_epslice.c.  It is the shared site that makes the two bits
    indistinguishable for any crash that depends only on it, so the site is the
    right unit.

    Brace-counts from the guard so nested code is captured, and stops when the
    block closes.  Lines that are themselves guards are skipped so an
    `else if` chain does not swallow its neighbours.
    """
    out = defaultdict(list)
    cur, depth, started, buf, cfile = None, 0, False, [], "?"
    for raw in Path(diff_path).read_text(errors="replace").splitlines():
        if raw.startswith("diff --git"):
            parts = raw.split()
            if len(parts) >= 3:
                cfile = parts[2][2:] if parts[2].startswith("a/") else parts[2]
        if not raw.startswith("+"):
            if cur and started and depth <= 0:
                if buf:
                    out[cur].append((cfile, "\n".join(buf)))
                cur, buf = None, []
            continue
        text = norm(raw)
        m = GUARD.search(text)
        if m and cur is None:
            cur = (int(m.group(1)), int(m.group(2)))
            depth, started, buf = 0, False, []
            continue
        if cur is None:
            continue
        if GUARD.search(text):        # next guard begins; close this one
            if buf:
                out[cur].append((cfile, "\n".join(buf)))
            mm = GUARD.search(text)
            cur = (int(mm.group(1)), int(mm.group(2)))
            depth, started, buf = 0, False, []
            continue
        depth += text.count("{") - text.count("}")
        if text.strip("{} "):
            buf.append(text)
        if text.count("{"):
            started = True
        if started and depth <= 0:
            if buf:
                out[cur].append((cfile, "\n".join(buf)))
            cur, buf = None, []
    if cur and buf:
        out[cur].append((cfile, "\n".join(buf)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benchmarks-dir",
                    default="/home/user/oss-fuzz-build/fuzzbench/benchmarks")
    a = ap.parse_args()

    rows = []
    for bench in sorted(Path(a.benchmarks_dir).glob("*_transplant_*")):
        diff = bench / "patches" / "combined.diff"
        meta_p = bench / "bug_metadata.json"
        if not diff.is_file() or not meta_p.is_file():
            continue
        meta = json.loads(meta_p.read_text())["bugs"]
        bit_of = {}
        for bug, info in meta.items():
            dv = info.get("dispatch_value") or 0
            if dv:
                bit_of[(dv.bit_length() - 1) // 8, (dv.bit_length() - 1) % 8] = bug
        blks = blocks(diff)
        sites = []          # (bug, file, text)
        for (byte, bit), lst in blks.items():
            bug = bit_of.get((byte, bit))
            if not bug:
                continue
            for cfile, text in lst:
                if text.strip():
                    sites.append((bug, cfile, text))
        dupes, near = [], []
        for i in range(len(sites)):
            for j in range(i + 1, len(sites)):
                bx, fx, tx = sites[i]
                by, fy, ty = sites[j]
                if bx == by:
                    continue
                if hashlib.md5(tx.encode()).hexdigest() == \
                   hashlib.md5(ty.encode()).hexdigest():
                    # NB no automatic bug-vs-setup label.  "Is the shared
                    # block in the bug's crash_file" looks like a proxy and is
                    # not: libavc OSV-2023-68/-75 share their relaxed error
                    # check in isvcd_api.c while both fault in other files --
                    # the shared block is the cause, not the crash site.
                    # Print the code and let a human classify.
                    dupes.append((bx, by, fx, len(tx.splitlines()), tx))
                else:
                    r = difflib.SequenceMatcher(None, tx.splitlines(),
                                                ty.splitlines()).ratio()
                    if r >= 0.85:
                        near.append((bx, by, fx, round(r, 3)))
        rows.append((bench.name, len(bit_of), len(sites), dupes, near))

    print(f"{'benchmark':46s} {'gated':>5s} {'sites':>6s} {'identical':>9s} "
          f"{'>=85% similar':>13s}")
    td = tn = tc = 0
    for name, ngated, nblocks, dupes, near in rows:
        td += len(dupes); tn += len(near)
        print(f"{name[:44]:46s} {ngated:5d} {nblocks:6d} {len(dupes):9d} "
              f"{len(near):13d}")
    print(f"{'TOTAL':46s} {'':5s} {'':6s} {td:9d} {tn:13d}")

    for name, _, _, dupes, near in rows:
        if not dupes and not near:
            continue
        print(f"\n=== {name}")
        for x, y, f, n, code in dupes:
            print(f"  IDENTICAL  {x} == {y}   in {f}  ({n} lines)")
            for line in code.splitlines()[:6]:
                print(f"      | {line[:88]}")
        for x, y, f, r in near:
            print(f"  similar     {x} ~ {y}   in {f}  ratio {r}")


if __name__ == "__main__":
    main()
