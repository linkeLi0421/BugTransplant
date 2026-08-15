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
import threading
from concurrent.futures import ThreadPoolExecutor
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

_FRAME_HEAD = re.compile(r"^\s*#(\d+)\s+0x[0-9a-f]+\s+in\s+(.*)$")


def parse_frames_all(text):
    """(function, file, line) for EVERY frame, including ones with no line.

    fuzzbench_triage.parse_stacktrace_frames requires `/src/...:<line>` and
    silently drops anything else.  Some translation units are built without
    usable line info -- libavc's ih264d_inter_pred.c and ih264d_process_pslice.c
    among them -- so their frames vanish and the next frame down is mistaken for
    the fault site.  On libavc that hid a NULL dereference in
    ih264d_motion_compensate_mp behind three different callers and split one
    fault across three "kinds".

    `line` is "" when unknown.  That still cannot satisfy RQ5's matcher, which
    keys on crash_file + crash_line -- a bug whose crash site lies in a
    no-line-info unit is unmatchable by that rule either way.  What this fixes
    is knowing WHERE a crash actually faulted.
    """
    out = []
    for raw in (text or "").splitlines():
        m = _FRAME_HEAD.match(raw)
        if not m:
            continue
        rest = m.group(2).strip()
        func, path, line = rest, "", ""
        if " /" in rest:
            func, _, tail = rest.rpartition(" /")
            tail = "/" + tail
            loc = re.match(r"(/\S+?):(\d+)", tail)
            if loc:
                path, line = loc.group(1), loc.group(2)
            else:
                path = tail.split()[0].rstrip(")")
        out.append((func.strip(), path, line))
    return out
FRAME_RE = re.compile(r"^\s*#(\d+)\s+0x([0-9a-f]+)\s+in\s+(\S+)")

# Cheap first: one execution, and only escalate to -runs=N when that fails to
# reproduce.  Most crashes fire on the first try, so paying -runs=10 up front
# multiplies the cost of the common case for nothing.
PROBE = r'''cd /tmp
while read -r f; do
  echo "@@@ $f"
  for i in $(seq 1 {tries}); do
    if [ "$i" = "1" ]; then R=1; else R={runs}; fi
    out=$(timeout {tmo} /out/{target} -runs=$R "/inputs/$f" 2>&1)
    # Break only on a FATAL sanitizer report.  A bare UBSan "runtime error:"
    # line is not a crash under halt_on_error=0, and treating it as one stopped
    # the retry loop with only that text -- so a real ASan crash that needed a
    # second attempt was recorded as no-crash.  Must stay in step with
    # sanitizer_class().
    if printf "%s" "$out" | grep -q "ERROR: .*Sanitizer:"; then
      # Keep the READ/WRITE-of-size and region lines: fuzzbench_triage's
      # parse_sanitizer_signature reads access type/size and region offset
      # from them to break ties between bugs sharing a frame.  Keep plenty of
      # frames -- the bug's crash_line may be several frames down.
      # Drop UBSan chatter before truncating.  ghostscript emits dozens of
      # benign "runtime error" / "SUMMARY: UndefinedBehaviorSanitizer" lines
      # per run (gsiorom.c:94 fires at startup on every input), which pushed
      # the real ASan report past head -60 and made every gs_pdfwrite class
      # look like it never crashed.
      printf "%s" "$out" \
        | grep -E "ERROR: |SUMMARY: |(READ|WRITE) of size|is located|^ *#[0-9]+ 0x" \
        | grep -v "UndefinedBehaviorSanitizer" | head -60
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


def read_all_crashes(db, experiment):
    """Every crash row: (crash_key, testcase, fuzzer, trial, time)."""
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    q = ("SELECT cr.crash_key, cr.crash_testcase, t.fuzzer, t.id, cr.time "
         "FROM crash cr JOIN trial t ON t.id = cr.trial_id "
         "WHERE cr.crash_testcase IS NOT NULL")
    args = ()
    if experiment:
        q += " AND t.experiment = ?"
        args = (experiment,)
    return [(k, tc, fz, str(tr), int(w or 0))
            for k, tc, fz, tr, w in con.execute(q, args)]


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


def canon_mask(prefix_int, used_bits):
    """Mask reduced to the bits that actually exist.

    Fuzzers mutate the whole dispatch prefix, so libavc's 5 gated bugs showed
    145 distinct raw masks where only 32 combinations mean anything.  Two
    inputs whose masks differ only in unused bits are the same configuration.
    """
    keep = 0
    for b in used_bits:
        keep |= 1 << b
    return prefix_int & keep


def classes_for(db, experiment, folders, raw, nbytes, used_bits):
    """Group every crash into (signature, canonical mask) classes.

    This is the replay unit.  Content dedup is useless -- 217,662 of 250,851
    crash rows are distinct files, because fuzzers keep producing new inputs for
    the same fault -- but grouping on the pair the verdict is a function of
    collapses libavc's 5,234 unique inputs to 370 classes (14x).

    Each class gets its OWN replay, so no verdict is inferred from a sample;
    the class is only used to recognise the same fault when another fuzzer finds
    it again.
    """
    rows = read_all_crashes(db, experiment)
    extract(folders, {tc for _, tc, _, _, _ in rows}, raw)
    have = {p.name for p in raw.iterdir()}
    cls = defaultdict(list)
    for key, tc, fz, tr, when in rows:
        if tc not in have:
            continue
        blob = (raw / tc).read_bytes()
        if len(blob) < nbytes:
            continue
        m = canon_mask(int.from_bytes(blob[:nbytes], "little"), used_bits)
        cls[(key, m)].append((tc, fz, tr, when))
    return cls, len(rows)


def mask_prefix(mask, nbytes):
    return bytes((mask >> (8 * i)) & 0xFF for i in range(nbytes))


def run_masks(image_out, target, vdir, names, tries, runs, tmo=240):
    """Replay `names` in one container.

    tmo is deliberately generous.  With several containers running at once each
    execution slows down, and a per-execution timeout that is merely adequate
    when sequential starts firing on real crashes under load -- at 10 jobs and
    a 60 s limit, libavc lost 7 classes to spurious `non-reproducing` that the
    sequential run classified fine.
    """
    lst = vdir.parent / f"probe_list_{vdir.name}.txt"
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
    """The sanitizer class of a crash, or "" if the run did not crash.

    A bare UBSan `runtime error:` line does NOT count.  We run with
    `halt_on_error=0` (as regen_crashes.py does, so a pre-existing UB does not
    mask the ASan report we care about), which means the process prints the
    line and carries on -- it has not crashed.  Counting it was a real defect:
    ghostscript emits `base/gsiorom.c:94: left shift of 128 by 24 places` at
    startup on EVERY run, input-independent and mask-independent, so every
    gs_pdfwrite class looked like it "crashed with all bits clear" and the whole
    benchmark came out 100% graft-independent with 0 of 26 bugs surfaced.

    Only a fatal sanitizer report counts: ASan's `ERROR: AddressSanitizer:`, or
    UBSan's when it is configured to halt.
    """
    m = re.search(r"ERROR:\s+\w+Sanitizer:\s+([a-zA-Z0-9_-]+)", text or "")
    return m.group(1).lower() if m else ""


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
    ap.add_argument("--tries", type=int, default=3,
                    help="attempts per mask; the first uses -runs=1 and only "
                         "the rest use --runs")
    ap.add_argument("--runs", type=int, default=10, help="-runs= per attempt")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--jobs", type=int, default=10,
                    help="concurrent replay containers; replays are independent")
    ap.add_argument("--chunk", type=int, default=200,
                    help="inputs per container call in the mask-0 phase")
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

    raw = work / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    print("  enumerating (signature, mask) classes ...", flush=True)
    cls, n_rows = classes_for(a.db, a.experiment, a.folders, raw, nbytes, used)
    # one replay per class; the representative is the earliest-found member
    inputs = []
    for (key, m), members in cls.items():
        members.sort(key=lambda x: x[3])
        tc, fz, tr, when = members[0]
        inputs.append((key, tc, fz, tr, when, m, len(members)))
    inputs.sort(key=lambda x: x[4])
    if a.limit:
        inputs = inputs[:a.limit]
    print(f"  {n_rows} crash rows -> {len(cls)} classes "
          f"({n_rows / max(1, len(cls)):.1f}x collapse); replaying {len(inputs)}",
          flush=True)

    # index every crash to its class, so RQ5 can join per-fuzzer timings
    idx = Path(a.out) / f"{a.name}_crash_index.csv"
    idx.parent.mkdir(parents=True, exist_ok=True)
    with open(idx, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["benchmark", "crash_key", "canon_mask", "testcase",
                    "fuzzer", "trial", "time"])
        for (key, m), members in cls.items():
            for tc, fz, tr, when in members:
                w.writerow([a.name, (key or "").replace("\n", " "), m, tc,
                            fz, tr, when])
    print(f"  wrote {idx}", flush=True)

    # Dispatch values are one-hot -- one bit per bug -- so the meaningful
    # configurations are "nothing on" and "exactly one bug on", plus whatever
    # the fuzzer actually found the input at.  Arbitrary bit combinations are
    # not configurations the benchmark is run in, so sweeping all 2^N of them
    # tests states nobody uses and makes the arithmetic harder to read.
    print(f"  masks per class: 0, each of the {len(used)} single bits, and the "
          f"recorded mask", flush=True)

    refs = {}
    for bug in list(bits) + always:
        f = bench / "crashes" / f"{bug}.txt"
        if f.is_file():
            refs[bug] = f.read_text(errors="replace")

    # Append each verdict as it completes.  The whole-file write at the end
    # meant a timeout kill lost every replay done so far -- gstoraster lost
    # 3+ hours that way.
    dest = Path(a.out) / f"{a.name}_two_level.csv"
    FIELDS = ["benchmark", "crash_key", "canon_mask", "class_crashes",
              "testcase", "fuzzer", "trial", "time", "level1", "candidates",
              "recorded_mask", "repro_masks", "masks_tested", "level2",
              "matched_bug", "credited_bug", "matched_is_candidate",
              "sanitizer"]
    fh_out = open(dest, "w", newline="")
    wr_out = csv.DictWriter(fh_out, fieldnames=FIELDS)
    wr_out.writeheader()
    wr_lock = threading.Lock()

    vdir = work / "variants"
    vdir.mkdir(exist_ok=True)
    rows = []
    logs = work / "logs"
    logs.mkdir(exist_ok=True)
    # ---- PHASE A: mask 0 for everything, batched.
    # A crash that reproduces with every bit clear is graft-independent no
    # matter what the other masks do, so the rest of its sweep is wasted work.
    # That is about half of all crashes (100% on gs_pdfwrite, 95% on ntopng,
    # but only 17% on c-blosc2), and batching also amortises container startup.
    zero = {}
    zlock = threading.Lock()

    def mask0_chunk(i):
        chunk = inputs[i:i + a.chunk]
        wd = work / f"v0_{i}"
        wd.mkdir(exist_ok=True)
        for pth in wd.iterdir():
            pth.unlink()
        names = []
        for j, (_, tc, *_rest) in enumerate(chunk):
            payload = (raw / tc).read_bytes()[nbytes:]
            nm = f"z{i + j}"
            (wd / nm).write_bytes(mask_prefix(0, nbytes) + payload)
            names.append(nm)
        res = run_masks(out_dir, a.target, wd, names, a.tries, a.runs)
        with zlock:
            for j, nm in enumerate(names):
                zero[i + j] = res.get(nm, "")
            print(f"  [mask 0] {len(zero)}/{len(inputs)}", flush=True)
        for pth in wd.iterdir():
            pth.unlink()
        wd.rmdir()

    with ThreadPoolExecutor(max_workers=a.jobs) as ex:
        list(ex.map(mask0_chunk, range(0, len(inputs), a.chunk)))

    n_gi = sum(1 for t in zero.values() if sanitizer_class(t))
    print(f"  mask 0 reproduces for {n_gi}/{len(inputs)} classes "
          f"-- those skip the rest of the sweep", flush=True)

    # ---- PHASE B: the remaining masks, only where mask 0 was silent
    def one_class(item):
        n, (key, tc, fuzzer, trial, when, cmask, nmemb) = item
        vd = work / f"v{n % a.jobs}"
        vd.mkdir(exist_ok=True)
        blob = (raw / tc).read_bytes()
        payload = blob[nbytes:]
        recorded = int.from_bytes(blob[:nbytes], "little")
        z = zero.get(n - 1, "")
        if sanitizer_class(z):
            masks, res, crashed = [0], {"m0": z}, {0}
        else:
            # A crash found at mask M cannot depend on a bit that was OFF
            # when the fuzzer found it, so only the bits in M are worth
            # testing.  On wide dispatch spaces (libredwg 31 bits, gstoraster
            # 23) this is the difference between ~33 executions per class and
            # a handful.
            # Sweep EVERY single-bit mask, not just the bits set in the
            # recorded mask.  Restricting to the recorded bits looked sound --
            # a crash found at mask M cannot depend on a bit that was off --
            # and it is much cheaper on wide dispatch spaces, but it also cuts
            # the number of executions per class, and these crashes are flaky.
            # Measured on libavc: the restriction moved 2-9 classes per run
            # into `non-reproducing` that the full sweep classified, and the
            # composition-dependent count swung between 1 and 4.  Detection
            # sensitivity matters more here than replay cost, which
            # parallelism already covers.
            masks = [m for m in dict.fromkeys([1 << b for b in used] + [recorded]) if m]

            def sweep(ms):
                for pth in vd.iterdir():
                    pth.unlink()
                for m in ms:
                    (vd / f"m{m}").write_bytes(mask_prefix(m, nbytes) + payload)
                return run_masks(out_dir, a.target, vd, [f"m{m}" for m in ms],
                                 a.tries, a.runs)

            res = sweep(masks)
            res["m0"] = z
            masks = [0] + masks
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
        row = {
            "benchmark": a.name, "crash_key": (key or "").replace("\n", " "),
            "canon_mask": cmask, "class_crashes": nmemb,
            "testcase": tc, "fuzzer": fuzzer, "trial": trial, "time": when,
            "level1": level1, "candidates": "|".join(cands),
            "recorded_mask": recorded,
            "repro_masks": " ".join(str(m) for m in sorted(crashed)),
            "masks_tested": " ".join(str(m) for m in sorted(masks)),
            "level2": best, "matched_bug": best_bug, "credited_bug": credited,
            "matched_is_candidate": matched_is_candidate,
            "sanitizer": sanitizer_class(rec_text or ""),
        }
        with wr_lock:
            wr_out.writerow(row)
            fh_out.flush()
            rows.append(row)
        # Keep EVERY replay log, not just the unmatched ones: the per-case
        # notes show the stack for matched crashes too, and re-deriving one
        # means re-replaying the input.
        with gzip.open(logs / f"{tc}.log.gz", "wt") as fh:
            fh.write(rec_text or "")
        if n % 50 == 0 or n == len(inputs):
            print(f"  [{len(rows)}/{len(inputs)}] {level1:22s} {best}", flush=True)


    with ThreadPoolExecutor(max_workers=a.jobs) as ex:
        list(ex.map(one_class, enumerate(inputs, 1)))
    fh_out.close()

    outdir = Path(a.out)
    outdir.mkdir(parents=True, exist_ok=True)
    print(f"\nwrote {dest} ({len(rows)} rows, written incrementally)")
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
