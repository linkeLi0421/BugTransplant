#!/usr/bin/env python3
"""Necessity replay for campaign crashes: does the dispatch byte matter?

A crash input from a FuzzBench transplant campaign carries a dispatch byte in
its head that selects which transplanted bug is live.  Attributing the crash to
that bug assumes the gated code is what crashed -- but an input whose head byte
happens to land in slot *N* can just as easily have crashed in the project's
own ungated code, which is live in every slot.

This script settles that, per input, on the campaign binary itself:

    original input  (head byte -> slot N)   must crash   [control]
    zeroed  input   (head byte  = 0x00)     should not   [test]

If the zeroed variant still crashes, slot *N* was not the cause: the crash is
an **ungated** one that merely wore that bug's dispatch byte.  If it goes
quiet, the crash is consistent with the gated bug being the cause.

Repetition is asymmetric.  A
crash is proof and stops immediately; a quiet run proves nothing on its own, so
the zeroed variant is retried ``--attempts`` times before it is called gated.

Usage:
  python3 script/dispatch_zero_replay.py \\
    --experiment-dir /mnt/nas/linke/buggraft2609/c-blosc2/fuzzing_.../c-blosc2-graft-24h-6fuzzer-v3 \\
    --bug-metadata fuzzbench/benchmarks/c-blosc2_decompress_frame_fuzzer_graft_cf8d63c2/bug_metadata.json \\
    --image gcr.io/fuzzbench/runners/libfuzzer/c-blosc2_..._graft_cf8d63c2:latest \\
    --target /out/decompress_frame_fuzzer \\
    --out data/dispatch_zero_replay/c-blosc2_cf8d63c2
"""
from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sqlite3
import sys
import tarfile
from pathlib import Path

logger = logging.getLogger(__name__)


class _SkipGroup(Exception):
    """This fuzzer's crashes cannot be replayed on any available binary."""

DEFAULT_ASAN = "detect_leaks=0"

# Crash types UndefinedBehaviorSanitizer produces.  These are excluded from the
# replay entirely, not counted as failures: the transplant benchmarks are
# ASAN-only (every build pins SANITIZER=address, and the merge skips any bug
# whose OSV sanitizer is not "address"), and replay runs UBSan with
# halt_on_error=0, so a UBSan-typed campaign crash can never reproduce.
# Measured on c-blosc2: 1,163 of them, every one a non-reproducer, against
# zero UBSan-typed inputs among the 8,810 that did reproduce.  Leaving them in
# reported an 11% "unreproducible" rate that was policy, not tooling failure.
UBSAN_CRASH_TYPES = frozenset({
    "Integer-overflow", "Divide-by-zero", "Undefined-shift",
    "Float-cast-overflow", "Pointer-overflow", "Object-size",
    "Misaligned-address", "Invalid-bool-value", "Invalid-enum-value",
    "Non-positive-vla-size", "Implicit-integer-sign-change",
    "Implicit-unsigned-integer-truncation",
    "Implicit-signed-integer-truncation",
})
# libFuzzer's default, which is what the trial containers actually used.
# The benchmark Dockerfiles set ENV ADDITIONAL_ARGS="-rss_limit_mb=8192" and
# claim the runners splice it on, but that ENV is set in the *builder* image;
# FuzzBench's runner image is built from base-runner and only copies /out, so
# neither ADDITIONAL_ARGS nor ASAN_OPTIONS survives into the container the
# trials run in (`docker inspect` on the runner image shows neither, and
# scheduler's docker run passes a fixed -e list that includes neither).
# Measured: replaying htslib at 8192 vs 2048 gives byte-identical verdicts.
DEFAULT_RSS_LIMIT_MB = 2048
DEFAULT_JOBS = max(4, (os.cpu_count() or 8) // 2)


def load_crash_types(db_path: Path) -> dict[str, str]:
    """crash artifact name -> the crash_type FuzzBench recorded for it.

    The measurer dedupes by crash_key per trial, so most crash *files* have no
    row here; those come back unmapped and are replayed anyway.
    """
    if not db_path or not Path(db_path).exists():
        return {}
    con = sqlite3.connect(f"file:{Path(db_path).resolve()}?mode=ro", uri=True)
    out: dict[str, str] = {}
    for name, ctype in con.execute(
            "select crash_testcase, crash_type from crash"):
        if name and name not in out:
            out[name] = (ctype or "").splitlines()[0].strip()
    con.close()
    logger.info("Loaded %d recorded crash types from %s", len(out), db_path)
    return out


def slot_of(head: int, slice_: int, slots: int) -> int:
    """Head byte -> dispatch slot, mirroring __bug_dispatch_slot() in C."""
    s = head // slice_
    return s if s < slots else 0


def load_metadata(path: Path) -> tuple[dict, int, int, dict]:
    meta = json.loads(path.read_text())
    slice_ = meta["dispatch_slice"]
    slots = meta["dispatch_slots"]
    slot2bug: dict[int, list[str]] = collections.defaultdict(list)
    for bug, m in meta["bugs"].items():
        slot2bug[slot_of(m["dispatch_value"], slice_, slots)].append(bug)
    return meta, slice_, slots, slot2bug


def harvest(experiment_dir: Path, stage: Path, slice_: int, slots: int,
            crash_types: dict[str, str] | None = None) -> list[dict]:
    """Extract every unique gated crash input, deduplicated by content."""
    stage.mkdir(parents=True, exist_ok=True)
    by_digest: dict[str, dict] = {}
    skipped: collections.Counter = collections.Counter()
    archives = 0
    unreadable = 0
    for root, _dirs, files in os.walk(experiment_dir):
        for fn in sorted(files):
            if not (fn.startswith("crashes-") and fn.endswith(".tar.gz")):
                continue
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
                        fh = tar.extractfile(member)
                        if fh is None:
                            continue
                        data = fh.read()
                        if not data:
                            continue
                        # libFuzzer also files timeout-<sha> / oom-<sha>
                        # artifacts in the same crashes dir.  Those are not
                        # sanitizer crashes and can never pass a crash
                        # control, so they must not be replayed as if they
                        # were.
                        base = os.path.basename(member.name)
                        kind = base.split("-")[0]
                        if kind != "crash":
                            skipped[kind] += 1
                            continue
                        ctype = (crash_types or {}).get(base)
                        if ctype in UBSAN_CRASH_TYPES:
                            skipped[f"ubsan:{ctype}"] += 1
                            continue
                        slot = slot_of(data[0], slice_, slots)
                        if slot == 0:
                            continue          # ungated by construction
                        digest = hashlib.sha256(data).hexdigest()
                        if digest in by_digest:
                            by_digest[digest]["seen"] += 1
                            continue
                        (stage / digest).write_bytes(data)
                        (stage / f"{digest}.zero").write_bytes(b"\x00" + data[1:])
                        by_digest[digest] = {
                            "digest": digest, "slot": slot, "head": data[0],
                            "size": len(data), "fuzzer": fuzzer, "trial": trial,
                            "crash_type": ctype or "", "seen": 1,
                        }
            except (tarfile.TarError, OSError):
                unreadable += 1
    logger.info("Scanned %d crash archives (%d unreadable); %d unique gated "
                "inputs staged in %s", archives, unreadable, len(by_digest), stage)
    if skipped:
        logger.info("Skipped non-crash artifacts: %s", dict(skipped))
    return list(by_digest.values())


def probe_driver(container: str, target: str) -> str:
    """Which driver is linked into this build: libfuzzer, afl or libafl.

    Each FuzzBench runner builds the same benchmark against a different
    driver, and they do not share a command line:

    libfuzzer  understands -runs/-rss_limit_mb/-timeout and takes files.
    afl        (afl, aflplusplus, fairfuzz, honggfuzz) links afl_driver,
               which takes files only -- a libFuzzer flag is read as a
               filename.
    libafl     is a LibAFL Rust fuzzer with its own CLI ("-o corpus_dir
               -i seed_dir").  It has no one-shot "run this file" mode at
               all, so its crashes cannot be replayed on its own binary and
               need --fallback-image.

    The probe must not truncate: libFuzzer prints rss_limit_mb on about line
    71 of -help=1, so a `head -40` filter misreads libFuzzer as afl and the
    whole run silently loses -runs=10.
    """
    probe = subprocess.run(
        ["docker", "exec", container, "bash", "-c",
         f"{target} -help=1 2>&1 | head -200"],
        capture_output=True, encoding="utf-8", errors="replace", timeout=120)
    out = probe.stdout or ""
    if "LibAFL-based fuzzer" in out or "--tokens <tokens>" in out:
        return "libafl"
    if "rss_limit_mb" in out:
        return "libfuzzer"
    return "afl"


def run_batch(container: str, target: str, names: list[str], *,
              asan: str, rss_limit_mb: int, jobs: int, timeout: int,
              unit_timeout: int, chunk: int, libfuzzer: bool = True,
              runs: int = 10, label: str = "") -> dict[str, str]:
    """Run each staged input once inside the container.

    Returns name -> one of "crash" (a sanitizer report), "timeout" (libFuzzer
    gave up on a slow unit), "oom", or "clean".

    ``-timeout`` matters: libFuzzer's default is 1200s per unit, so a single
    slow c-blosc2 frame pins an xargs worker for twenty minutes.  A handful of
    those stalls the whole sweep.

    A libFuzzer timeout or OOM prints a SUMMARY line too, so matching bare
    "SUMMARY:" would score a hang as a crash and call the bug ungated.
    """
    results: dict[str, str] = {}
    total = len(names)
    for start in range(0, total, chunk):
        batch = names[start:start + chunk]
        listing = "\n".join(batch)
        # Always an ABSOLUTE input path.  afl_driver has a legacy call style
        # where a numeric argv[1] means "run N iterations", and it decides via
        # atoi() -- so a bare SHA-256 filename like "0254976e3f..." parses as
        # 254976 iterations, the file is never opened, and the run reports
        # "successfully executed 0 input(s)".  A leading "/" makes atoi()
        # return 0 and the argument is taken as a path.
        # ``runs`` is not a knob to taste: <bench>/crashes/<bug>.txt records
        # what the campaign used to capture the crash on this very binary
        # ("Running 1 inputs 10 time(s) each" for every c-blosc2 bug).  A bug
        # that needs the process to reuse its stack or heap across runs simply
        # does not reproduce at -runs=1, and gets written off as a crash that
        # "cannot be reproduced in the same environment".
        invoke = (
            f"{target} -rss_limit_mb={rss_limit_mb} -timeout={unit_timeout} "
            f"-runs={runs} /inputs/@"
            if libfuzzer else
            # afl_driver takes file arguments only, so repeat the process
            # instead, stopping at the first crash.
            f"for _ in $(seq {runs}); do "
            f"o=$(timeout -s KILL {unit_timeout} {target} /inputs/@ 2>&1); "
            f'case "$o" in *"SUMMARY: "*Sanitizer*|*"libFuzzer: deadly signal"*) echo "$o"; break;; esac; '
            f"done; echo \"$o\""
        )
        script = (
            f"export ASAN_OPTIONS={asan}; "
            f"cat /tmp/batch.txt | xargs -P {jobs} -I@ bash -c '"
            f"out=$({invoke} 2>&1); "
            # Order matters: libFuzzer's timeout and OOM paths are classified
            # first, since neither is a bug.
            #
            # A crash is NOT only a sanitizer report. The campaign oracle is
            # FuzzBench's measurer, which records crash_type from the stacktrace
            # and logs Abrt and ASSERT: htslib transplants abort or trip an
            # assertion rather than tripping ASan, and libFuzzer reports those as
            # "deadly signal". Matching only "SUMMARY: ...Sanitizer" scored 9,560
            # of 17,432 htslib inputs (55%) as unable to reproduce when in fact
            # they crash on every run.
            f'if echo "$out" | grep -q "ERROR: libFuzzer: timeout"; then echo "timeout @"; '
            f'elif echo "$out" | grep -q "ERROR: libFuzzer: out-of-memory"; then echo "oom @"; '
            f'elif echo "$out" | grep -qE "^SUMMARY: (Address|Leak|Memory|Thread|Undefined)Sanitizer"; '
            f'then echo "crash @"; '
            f'elif echo "$out" | grep -q "ERROR: libFuzzer: deadly signal"; then echo "crash @"; '
            f'else echo "clean @"; fi\''
        )
        subprocess.run(
            ["docker", "exec", "-i", container, "bash", "-c", "cat > /tmp/batch.txt"],
            input=listing, encoding="utf-8", check=True, timeout=120,
        )
        proc = subprocess.run(
            ["docker", "exec", container, "bash", "-c", script],
            capture_output=True, encoding="utf-8", errors="replace", timeout=timeout,
        )
        for line in (proc.stdout or "").splitlines():
            verdict, _, name = line.partition(" ")
            if verdict in ("crash", "timeout", "oom", "clean") and name:
                results[name] = verdict
        done = min(start + chunk, total)
        logger.info("  %s %d/%d done (%d crash, %d timeout, %d oom)",
                    label, done, total,
                    sum(1 for v in results.values() if v == "crash"),
                    sum(1 for v in results.values() if v == "timeout"),
                    sum(1 for v in results.values() if v == "oom"))
    return results


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--experiment-dir", required=True, type=Path,
                   help="FuzzBench experiment dir holding crashes-*.tar.gz")
    p.add_argument("--bug-metadata", required=True, type=Path)
    p.add_argument("--db", type=Path, default=None,
                   help="FuzzBench local.db. Used to drop UBSan-typed crashes, "
                        "which are outside this benchmark's ASAN-only oracle "
                        "and can never reproduce under halt_on_error=0.")
    p.add_argument("--image", default=None,
                   help="Single runner image for every fuzzer's crashes. "
                        "Prefer --image-template: a crash found by afl was "
                        "found on afl's own instrumented build, and replaying "
                        "it on libFuzzer's build is a different binary.")
    p.add_argument("--fallback-image", default=None,
                   help="Replay image for fuzzers whose own runner has no "
                        "one-shot mode (LibAFL). Same benchmark source, "
                        "different instrumentation -- note it in the writeup.")
    p.add_argument("--image-template", default=None,
                   help="Per-fuzzer image, with {fuzzer} substituted, e.g. "
                        "'gcr.io/fuzzbench/runners/{fuzzer}/<benchmark>:latest'")
    p.add_argument("--target", required=True, help="Fuzz target path inside the image")
    p.add_argument("--out", required=True, type=Path, help="Output directory")
    p.add_argument("--container-name", default="dispatch-zero-replay")
    p.add_argument("--control-attempts", type=int, default=5,
                   help="Retries for an original that did not crash. A control "
                        "that goes quiet once is not proof it cannot "
                        "reproduce (default: 5)")
    p.add_argument("--attempts", type=int, default=5,
                   help="Retries for the quiet side before calling a crash gated "
                        "(a crash is proof and stops at once; default: 5)")
    p.add_argument("--runs", type=int, default=10,
                   help="Runs per attempt, matching what the campaign used to "
                        "capture the crash (default: 10)")
    p.add_argument("--asan", default=DEFAULT_ASAN)
    p.add_argument("--asan-uar",
                   default="detect_leaks=0:detect_stack_use_after_return=1"
                           ":max_uar_stack_size_log=16",
                   help="Second ASAN variant. UAR-on reveals some bugs and "
                        "masks others, so a control is tried under both and "
                        "the zeroed test then reuses whichever one worked.")
    p.add_argument("--rss-limit-mb", type=int, default=DEFAULT_RSS_LIMIT_MB)
    p.add_argument("--jobs", type=int, default=DEFAULT_JOBS)
    p.add_argument("--batch-timeout", type=int, default=7200,
                   help="Wall-clock cap for one chunk's docker exec")
    p.add_argument("--unit-timeout", type=int, default=25,
                   help="libFuzzer -timeout per input; its own default of "
                        "1200s lets one slow unit pin a worker (default: 25)")
    p.add_argument("--chunk", type=int, default=2000,
                   help="Inputs per docker exec, for progress reporting")
    p.add_argument("--limit", type=int, default=None,
                   help="Replay only the first N inputs (smoke test)")
    p.add_argument("--keep-container", action="store_true")
    p.add_argument("--reuse-stage", action="store_true",
                   help="Reuse an already-harvested staging dir")
    p.add_argument("--verbose", "-V", action="store_true")
    return p


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")

    meta, slice_, slots, slot2bug = load_metadata(args.bug_metadata)
    logger.info("Dispatch: %d byte(s), %d slots, slice %d",
                meta["dispatch_bytes"], slots, slice_)

    args.out.mkdir(parents=True, exist_ok=True)
    stage = args.out / "inputs"
    index_path = args.out / "inputs.json"
    if args.reuse_stage and index_path.exists():
        inputs = json.loads(index_path.read_text())
        logger.info("Reusing %d staged inputs", len(inputs))
    else:
        if stage.exists():
            shutil.rmtree(stage)
        inputs = harvest(args.experiment_dir, stage, slice_, slots,
                         load_crash_types(args.db))
        index_path.write_text(json.dumps(inputs, indent=1))
    if args.limit:
        inputs = inputs[:args.limit]
        logger.info("Limited to %d inputs", len(inputs))
    if not inputs:
        logger.error("No gated crash inputs found")
        return 1

    if not (args.image or args.image_template):
        logger.error("Pass --image or --image-template")
        return 1

    by_digest = {i["digest"]: i for i in inputs}
    groups = collections.defaultdict(list)
    for i in inputs:
        groups[i["fuzzer"] if args.image_template else "_all"].append(i)

    for group, members in sorted(groups.items()):
        image = (args.image_template.format(fuzzer=group)
                 if args.image_template else args.image)
        name = f"{args.container_name}-{group}"
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        logger.info("[%s] %d inputs -- starting %s", group, len(members), image)
        started = subprocess.run(
            ["docker", "run", "-d", "--name", name,
             "-v", f"{stage.resolve()}:/inputs:ro", "--entrypoint", "/bin/bash",
             image, "-c", "sleep infinity"],
            capture_output=True, encoding="utf-8")
        if started.returncode != 0:
            logger.error("[%s] could not start container: %s",
                         group, started.stderr.strip())
            for i in members:
                i["control"] = "no-image"
            continue
        try:
            # --- Control: the original input must crash on this binary ------
            driver = probe_driver(name, args.target)
            logger.info("[%s] driver: %s", group, driver)
            if driver == "libafl":
                if not args.fallback_image:
                    logger.error("[%s] LibAFL has no one-shot replay mode and "
                                 "no --fallback-image was given; skipping",
                                 group)
                    for i in members:
                        i["control"] = "no-replay-binary"
                    raise _SkipGroup
                logger.warning("[%s] LibAFL cannot replay a single input; "
                               "falling back to %s (same benchmark source, "
                               "different instrumentation)",
                               group, args.fallback_image)
                subprocess.run(["docker", "rm", "-f", name], capture_output=True)
                subprocess.run(
                    ["docker", "run", "-d", "--name", name,
                     "-v", f"{stage.resolve()}:/inputs:ro",
                     "--entrypoint", "/bin/bash", args.fallback_image,
                     "-c", "sleep infinity"], capture_output=True)
                driver = probe_driver(name, args.target)
                logger.info("[%s] fallback driver: %s", group, driver)
            lf = (driver == "libfuzzer")
            common = dict(rss_limit_mb=args.rss_limit_mb, jobs=args.jobs,
                          timeout=args.batch_timeout,
                          unit_timeout=args.unit_timeout, chunk=args.chunk,
                          libfuzzer=lf, runs=args.runs)
            variants = [("uar-off", args.asan), ("uar-on", args.asan_uar)]

            # --- Control: the original must crash, under some variant -------
            # Both directions are retried: a crash is proof and stops, a quiet
            # run proves nothing.  Whichever variant reproduces is recorded,
            # so the zeroed test is run against the same configuration rather
            # than a differently-configured binary.
            quiet = [i["digest"] for i in members]
            reproduced = []
            for attempt in range(1, args.control_attempts + 1):
                for vname, vopts in variants:
                    if not quiet:
                        break
                    res = run_batch(name, args.target, quiet, asan=vopts,
                                    label=f"{group} control a{attempt} {vname}",
                                    **common)
                    still = []
                    for d, verdict in res.items():
                        if verdict == "crash":
                            by_digest[d]["control"] = "crash"
                            by_digest[d]["asan"] = vopts
                            by_digest[d]["variant"] = vname
                            reproduced.append(d)
                        else:
                            by_digest[d].setdefault("control", verdict)
                            still.append(d)
                    quiet = still
                if not quiet:
                    break
            logger.info("[%s] control: %d/%d originals reproduce (%d still not)",
                        group, len(reproduced), len(members), len(quiet))

            # --- Test: zeroed head byte, same variant that reproduced -------
            for d in reproduced:
                by_digest[d]["zero_crash"] = False
            by_variant = collections.defaultdict(list)
            for d in reproduced:
                by_variant[by_digest[d]["asan"]].append(d)
            for vopts, digests in by_variant.items():
                pending = list(digests)
                for attempt in range(1, args.attempts + 1):
                    if not pending:
                        break
                    res = run_batch(name, args.target,
                                    [f"{d}.zero" for d in pending], asan=vopts,
                                    label=f"{group} zeroed p{attempt}", **common)
                    still = []
                    for nm, verdict in res.items():
                        d = nm[:-len(".zero")]
                        if verdict == "crash":
                            by_digest[d]["zero_crash"] = True
                            by_digest[d]["zero_attempt"] = attempt
                        else:
                            still.append(d)
                    logger.info("[%s] zeroed pass %d: %d crashed with the head "
                                "byte zeroed", group, attempt,
                                len(pending) - len(still))
                    pending = still
        except _SkipGroup:
            pass
        finally:
            if not args.keep_container:
                subprocess.run(["docker", "rm", "-f", name], capture_output=True)

    # --- Report -----------------------------------------------------------
    rows = []
    per_bug = collections.defaultdict(lambda: collections.Counter())
    for i in inputs:
        bug = "/".join(slot2bug.get(i["slot"], ["?"]))
        ctrl = i.get("control", "clean")
        verdict = ("ungated" if ctrl == "crash" and i.get("zero_crash")
                   else "gated" if ctrl == "crash"
                   else f"no-control-{ctrl}")
        per_bug[bug][verdict] += 1
        per_bug[bug]["inputs"] += 1
        rows.append({"bug": bug, "slot": i["slot"], "head": i["head"],
                     "fuzzer": i["fuzzer"], "trial": i["trial"],
                     "size": i["size"], "occurrences": i["seen"],
                     "digest": i["digest"], "crash_type": i.get("crash_type", ""),
                     "variant": i.get("variant", ""),
                     "verdict": verdict})
    csv_path = args.out / "replay_results.csv"
    with csv_path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    summary = {bug: dict(c) for bug, c in sorted(per_bug.items())}
    (args.out / "summary.json").write_text(json.dumps(summary, indent=1))

    def nc(c):
        return sum(v for k, v in c.items() if k.startswith("no-control-"))

    print(f"\n{'bug':16} {'inputs':>7} {'gated':>7} {'ungated':>8} "
          f"{'no-ctrl':>8}  {'ungated%':>8}")
    for bug, c in sorted(per_bug.items()):
        tested = c["gated"] + c["ungated"]
        pct = f"{100.0 * c['ungated'] / tested:.0f}%" if tested else "-"
        print(f"{bug:16} {c['inputs']:>7} {c['gated']:>7} "
              f"{c['ungated']:>8} {nc(c):>8}  {pct:>8}")
    tot = collections.Counter()
    for c in per_bug.values():
        tot.update(c)
    tested = tot["gated"] + tot["ungated"]
    pct = f"{100.0 * tot['ungated'] / tested:.0f}%" if tested else "-"
    print(f"\n{'TOTAL':16} {tot['inputs']:>7} {tot['gated']:>7} "
          f"{tot['ungated']:>8} {nc(tot):>8}  {pct:>8}")
    breakdown = {k: v for k, v in sorted(tot.items()) if k.startswith("no-control-")}
    if breakdown:
        print("no-control breakdown:", ", ".join(f"{k.split('-',2)[2]}={v}"
                                                 for k, v in breakdown.items()))
    print(f"\nPer-input results: {csv_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
