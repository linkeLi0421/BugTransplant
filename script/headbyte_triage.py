#!/usr/bin/env python3
"""Bug triage from the dispatch head byte alone, with discovery times.

Attribution here is purely the selector byte a crashing input carries: the
harness reads it to pick which grafted bug is live, so a crash whose head byte
maps to slot N is a candidate for the bug in slot N.  Nothing is inferred from
stack frames, the way the retired fuzzbench_triage.py did -- on the htslib graft
campaign its frame matching credited 3 bugs where necessity replay proved 7.

Time comes from the archive index: FuzzBench writes ``crashes-<cycle>.tar.gz``
each measurement cycle and the archives are cumulative, so the first archive an
input appears in is the cycle it was found in, and
``cycle * snapshot_period`` is its discovery time.  Note ``snapshot_period``
differs per campaign (900s for htslib and c-blosc2, 1800s for libavc).

This says a crash *selected* a bug, not that the bug caused it -- pair it with
``dispatch_zero_replay.py``, which zeroes the head byte and keeps only crashes
that actually need it.

Usage:
  python3 script/headbyte_triage.py \\
      --experiment-dir <experiment>/experiment-folders \\
      --bug-metadata <benchmark>/bug_metadata.json \\
      --snapshot-period 1800 --output libavc_headbyte.csv
"""
from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import logging
import os
import re
import statistics
import sys
import tarfile
from pathlib import Path

logger = logging.getLogger(__name__)
CYCLE_RE = re.compile(r"crashes-(\d+)\.tar\.gz$")

# Crash types UndefinedBehaviorSanitizer produces.  The benchmarks are ASan-only,
# so these can never reproduce and are not this suite's bugs.
UBSAN_CRASH_TYPES = frozenset({
    "Integer-overflow", "Divide-by-zero", "Undefined-shift",
    "Float-cast-overflow", "Pointer-overflow", "Object-size",
    "Misaligned-address", "Invalid-bool-value", "Invalid-enum-value",
    "Non-positive-vla-size", "Implicit-integer-sign-change",
    "Implicit-unsigned-integer-truncation",
    "Implicit-signed-integer-truncation",
})


def load_crash_types(db_path):
    """crash artifact name -> the crash_type FuzzBench recorded for it."""
    import sqlite3
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    out = {}
    for name, ctype in con.execute(
            "select crash_testcase, crash_type from crash"):
        if name and name not in out:
            out[name] = (ctype or "").splitlines()[0].strip()
    con.close()
    logger.info("Loaded %d confirmed crashes from %s", len(out), db_path)
    return out


def slot_of(head: int, slice_: int, slots: int) -> int:
    """Head byte -> dispatch slot, mirroring __bug_dispatch_slot() in C."""
    s = head // slice_
    return s if s < slots else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--experiment-dir", required=True, type=Path,
                   help="FuzzBench experiment-folders directory")
    p.add_argument("--bug-metadata", required=True, type=Path)
    p.add_argument("--snapshot-period", type=int, default=900,
                   help="Seconds per measurement cycle (default: 900; the "
                        "libavc graft campaign used 1800)")
    p.add_argument("--db", type=Path, default=None,
                   help="FuzzBench local.db.  Without it every crash-* file the "
                        "fuzzers wrote is counted.  Fuzzers write one for any "
                        "finding, including leaks, and FuzzBench's own measurer "
                        "records only the ones that reproduce as a sanitizer "
                        "crash -- libredwg's fuzzers wrote 17,361 files where "
                        "the measurer confirmed 7,039, and the surplus is what "
                        "later shows up as 'cannot reproduce'.  With --db, only "
                        "crashes the measurer confirmed are counted, and "
                        "UBSan-typed ones are dropped as outside this "
                        "benchmark's ASAN-only oracle.")
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")

    meta = json.loads(args.bug_metadata.read_text())
    slice_, slots = meta["dispatch_slice"], meta["dispatch_slots"]
    slot2bug: dict[int, list[str]] = collections.defaultdict(list)
    for bug, m in meta["bugs"].items():
        slot2bug[slot_of(m["dispatch_value"], slice_, slots)].append(bug)
    gated = {s: b for s, b in slot2bug.items() if s > 0}
    logger.info("Dispatch: %d slots, slice %d, %d gated bugs",
                slots, slice_, len(gated))

    # (fuzzer, trial, bug) -> earliest cycle ; and the unique inputs behind it
    first: dict[tuple, int] = {}
    inputs: dict[tuple, set] = collections.defaultdict(set)
    crash_types = load_crash_types(args.db) if args.db else None
    dropped = collections.Counter()
    slot0 = 0            # occurrences, kept for continuity
    slot0_digests: set = set()   # unique inputs, comparable with the replay
    archives = unreadable = 0

    for root, _dirs, files in os.walk(args.experiment_dir):
        for fn in sorted(files):
            m = CYCLE_RE.search(fn)
            if not m:
                continue
            cycle = int(m.group(1))
            archives += 1
            parts = Path(root).parts
            fuzzer = next((p.split("-")[-1] for p in parts if "graft_" in p), "?")
            trial = next((p.split("trial-")[1] for p in parts
                          if p.startswith("trial-")), "?")
            try:
                with tarfile.open(os.path.join(root, fn), "r:gz") as tar:
                    for member in tar.getmembers():
                        if not member.isfile():
                            continue
                        base = os.path.basename(member.name)
                        if not base.startswith("crash-"):
                            continue      # oom-/timeout- artifacts are not bugs
                        if crash_types is not None:
                            ctype = crash_types.get(base)
                            if ctype is None:
                                # The fuzzer wrote it; FuzzBench's measurer never
                                # confirmed it as a sanitizer crash (leaks land
                                # here).  Not a crash by the campaign's own
                                # standard.
                                dropped["unconfirmed"] += 1
                                continue
                            if ctype in UBSAN_CRASH_TYPES:
                                dropped[f"ubsan:{ctype}"] += 1
                                continue
                        fh = tar.extractfile(member)
                        data = fh.read() if fh else b""
                        if not data:
                            continue
                        slot = slot_of(data[0], slice_, slots)
                        if slot == 0:
                            # Archives are cumulative, so one crash reappears in
                            # every later archive.  Count occurrences *and*
                            # unique contents: the latter is the number that is
                            # comparable with dispatch_zero_replay.py, which
                            # dedupes by digest.
                            slot0 += 1
                            slot0_digests.add(hashlib.sha256(data).hexdigest())
                            continue
                        bug = "/".join(slot2bug[slot])
                        key = (fuzzer, trial, bug)
                        digest = hashlib.sha256(data).hexdigest()
                        inputs[key].add(digest)
                        if key not in first or cycle < first[key]:
                            first[key] = cycle
            except (tarfile.TarError, OSError):
                unreadable += 1

    logger.info("Scanned %d crash archives (%d unreadable); slot-0 (ungated) "
                "crashes skipped: %d unique inputs, %d occurrences across the "
                "cumulative archives", archives, unreadable,
                len(slot0_digests), slot0)
    if dropped:
        logger.info("Dropped by --db: %s",
                    dict(sorted(dropped.items(), key=lambda kv: -kv[1])))

    rows = []
    for (fuzzer, trial, bug), cycle in sorted(first.items()):
        rows.append({"fuzzer": fuzzer, "trial": trial, "bug": bug,
                     "first_cycle": cycle,
                     "first_seen_seconds": cycle * args.snapshot_period,
                     "first_seen_hours": round(cycle * args.snapshot_period / 3600, 2),
                     "unique_inputs": len(inputs[(fuzzer, trial, bug)])})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]) if rows else
                           ["fuzzer", "trial", "bug", "first_cycle",
                            "first_seen_seconds", "first_seen_hours",
                            "unique_inputs"])
        w.writeheader()
        w.writerows(rows)

    # ---- per-bug summary -------------------------------------------------
    by_bug = collections.defaultdict(list)
    for r in rows:
        by_bug[r["bug"]].append(r)
    print(f"\n{'bug':16} {'fuzzers':>8} {'trials':>7} {'inputs':>8} "
          f"{'first(h)':>9} {'median(h)':>10}")
    for bug in sorted(gated.values(), key=lambda b: b[0]):
        name = "/".join(bug)
        rs = by_bug.get(name, [])
        if not rs:
            print(f"{name:16} {0:>8} {0:>7} {0:>8} {'-':>9} {'-':>10}")
            continue
        times = [r["first_seen_hours"] for r in rs]
        print(f"{name:16} {len({r['fuzzer'] for r in rs}):>8} {len(rs):>7} "
              f"{sum(r['unique_inputs'] for r in rs):>8} "
              f"{min(times):>9.2f} {statistics.median(times):>10.2f}")

    found = {r["bug"] for r in rows}
    print(f"\nbugs with >=1 head-byte crash: {len(found)} of {len(gated)}")
    print(f"{'fuzzer':14} {'bugs':>6} {'trials':>7} {'inputs':>8}")
    byf = collections.defaultdict(list)
    for r in rows:
        byf[r["fuzzer"]].append(r)
    for f in sorted(byf, key=lambda x: -len({r["bug"] for r in byf[x]})):
        rs = byf[f]
        print(f"{f:14} {len({r['bug'] for r in rs}):>6} "
              f"{len({r['trial'] for r in rs}):>7} "
              f"{sum(r['unique_inputs'] for r in rs):>8}")
    print(f"\nPer (fuzzer, trial, bug) rows: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
