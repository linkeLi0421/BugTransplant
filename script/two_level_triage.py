#!/usr/bin/env python3
"""Two-level crash triage for bug-transplant benchmarks.

Every crash from a merged FuzzBench campaign is decided by two independent
signals, in this order:

  LEVEL 1 -- causal, by rewriting the dispatch prefix and replaying.  The
    payload is held byte-for-byte identical; only the N dispatch bytes change,
    so the sole variable is which grafted bugs exist in the run.

      mask 0 reproduces                     -> graft-independent
      mask 0 silent, bit i alone reproduces -> graft-triggered (every
                                               independently sufficient bit is
                                               a candidate)
      no single bit suffices, >=2 needed    -> composition-dependent
      own recorded mask does not reproduce  -> non-reproducing (excluded)

  LEVEL 2 -- semantic, using the SAME matcher RQ5 uses
    (fuzzbench_triage._match_bug_ids_in_stacktrace): a frame must hit the bug's
    recorded crash_file AND crash_line (and crash_function when known), with
    reference-frame overlap and sanitizer detail breaking ties.

    RQ3's classifier is deliberately NOT used here.  It exists to compare a
    bug's own PoC across two builds, where the stacks should coincide and a
    loose tier merely tolerates drift.  Applied to an arbitrary fuzzer-found
    crash its "same sanitizer class + any shared function or file" tier is
    near-vacuous: every libavc crash traverses LLVMFuzzerTestOneInput ->
    isvcd_api_function -> isvcd_video_decode, so unrelated heap-buffer-overflows
    matched each other on entry-path frames alone.

A bug is credited only when BOTH agree.  Level 1 alone cannot: a crash may
depend on graft i and still not BE historical bug i (libavc i35 crashes
identically under either of two bugs, at a site belonging to neither).  Level 2
alone cannot either: it is a stack comparison, and a native crash can share a
signature with a grafted bug.

Note on `graft-independent`: it does NOT mean "not ours".  231 of the 355
transplanted bugs are always-active (`dispatch_value == 0`) and have no bit to
switch, so a crash from one reproduces at mask 0 exactly like a pre-existing
target bug.  Level 2 is the only instrument that separates them, which is why
those crashes are matched too.

Replay details that matter:
  * Replays the COVERAGE build, not the fuzzing binary, inside `base-runner`.
    The fuzzing binary carries no line table -- every symbolizer returns
    `??:0:0` for it -- while the coverage build has full DWARF and still
    honours the dispatch prefix and ASan.  That yields native
    `#N 0x.. in <func> /src/path:line:col` frames, exactly the form
    fuzzbench_triage parses, so our replays are directly comparable with the
    campaign's own stacks and with the reference logs.
  * Every mask is retried until it crashes or the retry budget is spent.
    Crashes here are flaky: a libavc PoC reproduced 1 in 5 runs, so a single
    attempt is not evidence of absence.

Usage:
  python3 script/two_level_triage.py \
      --benchmark-dir fuzzbench/benchmarks/libavc_transplant_svc_dec_fuzzer \
      --db   /mnt/nas/.../local.db --experiment libavc-24h-6fuzzer \
      --folders /mnt/nas/.../experiment-folders \
      --runner-image gcr.io/fuzzbench/runners/libfuzzer/libavc_...:latest \
      --target svc_dec_fuzzer \
      --cov-tar /mnt/nas/.../coverage-build-libavc_....tar.gz \
      --workdir /home/user/abl_work/two_level \
      --out data/two-level
"""
import argparse
import csv
import gzip
import json
import re
import sqlite3
import subprocess
import sys
import tarfile
from collections import defaultdict
from glob import glob
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fuzzbench_triage import (  # noqa: E402
    load_bug_metadata, _bug_targets_from_metadata,
    _match_bug_ids_in_stacktrace)

BASE_RUNNER = "gcr.io/oss-fuzz-base/base-runner"
FRAME_RE = re.compile(r"^\s*#(\d+)\s+0x([0-9a-f]+)\s+in\s+(\S+)")

PROBE = r'''cd /tmp
while read -r f; do
  echo "@@@ $f"
  for i in $(seq 1 {tries}); do
    out=$(timeout {tmo} /out/{target} -runs={runs} "/inputs/$f" 2>&1)
    if printf "%s" "$out" | grep -q "ERROR: \|runtime error"; then
      # Keep the READ/WRITE-of-size and region lines: fuzzbench_triage's
      # parse_sanitizer_signature reads access type/size and region offset
      # from them to break ties between bugs sharing a frame.  Keep plenty of
      # frames -- the bug's crash_line may be several frames down.
      printf "%s" "$out" | grep -E "ERROR: |SUMMARY: |runtime error|(READ|WRITE) of size|is located|^ *#[0-9]+ 0x" | head -60
      break
    fi
  done
  echo "@@@END"
done < /list
'''


def load_meta(bench_dir):
    meta = json.loads((bench_dir / "bug_metadata.json").read_text())
    bits, always = {}, []
    for bug, info in meta["bugs"].items():
        dv = info.get("dispatch_value") or 0
        if dv:
            bits[bug] = dv.bit_length() - 1
        else:
            always.append(bug)
    return meta, meta.get("dispatch_bytes", 1), bits, always


def read_crashes(db, experiment, cap):
    """(crash_key -> [(testcase, fuzzer, trial, time)]) capped per signature."""
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    q = ("SELECT cr.crash_key, cr.crash_testcase, t.fuzzer, t.id, cr.time "
         "FROM crash cr JOIN trial t ON t.id = cr.trial_id "
         "WHERE cr.crash_testcase IS NOT NULL")
    args = ()
    if experiment:
        q += " AND t.experiment = ?"
        args = (experiment,)
    q += " ORDER BY cr.time"
    out, seen = defaultdict(list), set()
    for key, tc, fuzzer, trial, when in con.execute(q, args):
        if tc in seen:
            continue
        if len(out[key]) >= cap:
            continue
        seen.add(tc)
        out[key].append((tc, fuzzer, str(trial), int(when or 0)))
    return out


def extract(folders, wanted, dest):
    dest.mkdir(parents=True, exist_ok=True)
    todo = set(wanted) - {p.name for p in dest.iterdir()}
    for arch in sorted(glob(f"{folders}/*/trial-*/crashes/crashes-*.tar.gz")):
        if not todo:
            break
        try:
            with tarfile.open(arch, "r:gz") as tf:
                for mem in tf.getmembers():
                    n = mem.name.split("/")[-1]
                    if n in todo and mem.isfile():
                        fh = tf.extractfile(mem)
                        if fh:
                            (dest / n).write_bytes(fh.read())
                            todo.discard(n)
        except (tarfile.TarError, OSError, EOFError):
            continue


def mask_prefix(mask, nbytes):
    return bytes((mask >> (8 * i)) & 0xFF for i in range(nbytes))


def run_masks(image_out, target, vdir, names, tries, runs, tmo=60):
    lst = vdir.parent / "probe_list.txt"
    lst.write_text("\n".join(names) + "\n")
    cmd = ["docker", "run", "--rm", "--privileged", "--shm-size=2g",
           "-v", f"{image_out}:/out", "-v", f"{vdir}:/inputs:ro",
           "-v", f"{lst}:/list:ro",
           "-e", "ASAN_SYMBOLIZER_PATH=/usr/local/bin/llvm-symbolizer",
           "-e", "ASAN_OPTIONS=detect_leaks=0",
           "-e", "UBSAN_OPTIONS=print_stacktrace=0:halt_on_error=0",
           "--entrypoint", "bash", BASE_RUNNER, "-c",
           PROBE.format(target=target, tries=tries, runs=runs, tmo=tmo)]
    r = subprocess.run(cmd, capture_output=True, timeout=14400)
    if r.returncode != 0:
        raise SystemExit(f"replay container failed ({r.returncode}): "
                         f"{(r.stderr or b'').decode('latin-1')[:300]}")
    res, cur = {}, None
    for line in (r.stdout or b"").decode("latin-1").splitlines():
        if line.startswith("@@@END"):
            cur = None
        elif line.startswith("@@@ "):
            cur = line[4:].strip()
            res[cur] = []
        elif cur is not None:
            res[cur].append(line)
    return {k: "\n".join(v) for k, v in res.items()}


def sanitizer_class(text):
    m = re.search(r"ERROR:\s+\w+Sanitizer:\s+([a-zA-Z0-9_-]+)", text or "")
    if m:
        return m.group(1).lower()
    return "runtime-error" if "runtime error" in (text or "") else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benchmark-dir", required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--experiment", default=None)
    ap.add_argument("--folders", required=True)
    ap.add_argument("--runner-image", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--cov-tar", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--name", required=True, help="short benchmark name for output")
    ap.add_argument("--cap", type=int, default=3)
    ap.add_argument("--tries", type=int, default=3, help="container retries per mask")
    ap.add_argument("--runs", type=int, default=10, help="-runs= per attempt")
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()

    bench = Path(a.benchmark_dir)
    work = Path(a.workdir) / a.name
    work.mkdir(parents=True, exist_ok=True)
    meta, nbytes, bits, always = load_meta(bench)
    inv = {v: k for k, v in bits.items()}
    used = sorted(bits.values())
    print(f"{a.name}: {len(bits)} gated bugs, {len(always)} always-active, "
          f"{nbytes} dispatch byte(s)", flush=True)

    # Replay the COVERAGE build: it has line tables, honours the dispatch
    # prefix, and still reports under ASan.  The fuzzing binary has no line
    # info, and RQ5's matcher needs crash_line to match.
    out_dir = work / "covbin"
    if not out_dir.is_dir():
        out_dir.mkdir(parents=True, exist_ok=True)
        with tarfile.open(a.cov_tar, "r:gz") as tf:
            tf.extractall(out_dir)
    if not (out_dir / a.target).is_file():
        raise SystemExit(f"coverage build has no /{a.target}: {out_dir}")
    print(f"  coverage build extracted -> {out_dir/a.target}", flush=True)

    bug_meta = load_bug_metadata(bench / "bug_metadata.json")
    targets = _bug_targets_from_metadata(bug_meta)
    print(f"  {len(targets)} bugs have crash_file/crash_line for matching",
          flush=True)

    sigs = read_crashes(a.db, a.experiment, a.cap)
    inputs = [(k, tc, fz, tr, tm) for k, v in sigs.items() for tc, fz, tr, tm in v]
    if a.limit:
        inputs = inputs[:a.limit]
    print(f"  {len(sigs)} signatures, {len(inputs)} inputs", flush=True)

    raw = work / "raw"
    extract(a.folders, {tc for _, tc, _, _, _ in inputs}, raw)
    have = {p.name for p in raw.iterdir()}
    inputs = [x for x in inputs if x[1] in have]
    print(f"  {len(inputs)} inputs extracted", flush=True)

    # Dispatch values are one-hot -- one bit per bug -- so the meaningful
    # configurations are "nothing on" and "exactly one bug on", plus whatever
    # the fuzzer actually found the input at.  Arbitrary bit combinations are
    # not configurations the benchmark is run in, so sweeping all 2^N of them
    # tests states nobody uses and makes the arithmetic harder to read.
    base_masks = [0] + [1 << b for b in used]
    print(f"  masks per input: {len(base_masks)} one-hot + the recorded mask",
          flush=True)

    refs = {}
    for bug in list(bits) + always:
        f = bench / "crashes" / f"{bug}.txt"
        if f.is_file():
            refs[bug] = f.read_text(errors="replace")

    vdir = work / "variants"
    vdir.mkdir(exist_ok=True)
    rows = []
    logs = work / "logs"
    logs.mkdir(exist_ok=True)
    for n, (key, tc, fuzzer, trial, when) in enumerate(inputs, 1):
        blob = (raw / tc).read_bytes()
        payload = blob[nbytes:]
        recorded = int.from_bytes(blob[:nbytes], "little")
        masks = list(dict.fromkeys(base_masks + [recorded]))
        for p in vdir.iterdir():
            p.unlink()
        for m in masks:
            (vdir / f"m{m}").write_bytes(mask_prefix(m, nbytes) + payload)
        res = run_masks(out_dir, a.target, vdir, [f"m{m}" for m in masks],
                        a.tries, a.runs)
        crashed = {m for m in masks if sanitizer_class(res.get(f"m{m}", ""))}
        rec_text = None
        for m in masks:
            if m in crashed:
                rec_text = res[f"m{m}"]
                break
        if not crashed:
            level1, cands = "non-reproducing", []
        elif 0 in crashed:
            level1, cands = "graft-independent", []
            rec_text = res.get("m0")
        else:
            singles = [b for b in used if (1 << b) in crashed]
            if singles:
                level1 = "graft-triggered"
                cands = [inv[b] for b in singles]
                rec_text = res.get(f"m{1 << singles[0]}")
            else:
                # No single bug reproduces it, but the fuzzer's own mask does:
                # it needs more than one graft enabled together.
                mm = min(crashed, key=lambda x: bin(x).count("1"))
                level1 = "composition-dependent"
                cands = [inv[b] for b in used if mm >> b & 1]
                rec_text = res.get(f"m{mm}")

        # LEVEL 2 -- RQ5's matcher on the replayed crash.  Matched against the
        # WHOLE catalogue, not just the candidate grafts: a crash can require
        # graft i and still be, semantically, another bug that graft i merely
        # made reachable (unmasking).  Which bug matched, and whether it was a
        # candidate, is recorded separately.
        matched = sorted(_match_bug_ids_in_stacktrace(rec_text or "", targets))
        if not matched:
            best = "no-match"
        elif not cands:
            # No candidate set exists (graft-independent crashes have no
            # required bits), so "matched something other than its candidate"
            # is vacuous -- it would label every such crash match-other-bug.
            best = "match"
        elif set(matched) & set(cands):
            best = "match"
        else:
            best = "match-other-bug"
        best_bug = "|".join(matched)
        in_cands = [b for b in matched if b in cands]
        credited = "|".join(in_cands) if in_cands else (
            best_bug if level1 == "graft-independent" else "")
        matched_is_candidate = bool(in_cands)
        rows.append({
            "benchmark": a.name, "crash_key": (key or "").replace("\n", " "),
            "testcase": tc, "fuzzer": fuzzer, "trial": trial, "time": when,
            "level1": level1, "candidates": "|".join(cands),
            "recorded_mask": recorded,
            "repro_masks": " ".join(str(m) for m in sorted(crashed)),
            "masks_tested": " ".join(str(m) for m in sorted(masks)),
            "level2": best, "matched_bug": best_bug, "credited_bug": credited,
            "matched_is_candidate": matched_is_candidate,
            "sanitizer": sanitizer_class(rec_text or ""),
        })
        # Keep EVERY replay log, not just the unmatched ones: the per-case
        # notes show the stack for matched crashes too, and re-deriving one
        # means re-replaying the input.
        with gzip.open(logs / f"{tc}.log.gz", "wt") as fh:
            fh.write(rec_text or "")
        if n % 10 == 0 or n == len(inputs):
            print(f"  [{n}/{len(inputs)}] {level1:22s} {best}", flush=True)

    outdir = Path(a.out)
    outdir.mkdir(parents=True, exist_ok=True)
    dest = outdir / f"{a.name}_two_level.csv"
    with open(dest, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"\nwrote {dest} ({len(rows)} rows)")
    c1 = defaultdict(int)
    c2 = defaultdict(int)
    for r in rows:
        c1[r["level1"]] += 1
        if r["level1"] in ("graft-triggered", "composition-dependent"):
            c2[r["level2"]] += 1
    print("level 1:", dict(c1))
    print("level 2 (graft-dependent only):", dict(c2))


if __name__ == "__main__":
    main()
