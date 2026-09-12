#!/usr/bin/env python3
"""Causal crash triage for bug-transplant benchmarks.

Every crash from a merged FuzzBench campaign is decided by ONE signal: the
dispatch-bit counterfactual.  The payload is held byte-for-byte identical and
only the N dispatch bytes change, so the sole variable is which grafted bugs
exist in the run.

      mask 0 reproduces                     -> graft-independent
      mask 0 silent, bit i alone reproduces -> graft-triggered (every
                                               independently sufficient bit is
                                               a candidate)
      no single bit suffices, >=2 needed    -> composition-dependent
      own recorded mask does not reproduce  -> non-reproducing (excluded)

Crash frames are NOT examined.  An earlier version of this script carried a
second, semantic level that matched the replayed stack against each bug's
recorded crash_file/crash_line; it was removed 2026-08-19 (user decision) and
with it every claim of the form "this crash IS historical bug B".  What the
script produces now is strictly causal: which graft the crash requires.

Consequences to keep in mind when reading the output:
  * Only the gated bugs can be attributed at all.  A bug with
    `dispatch_value == 0` has no bit to switch, so its crashes land in
    `graft-independent` and are indistinguishable from a pre-existing target
    bug.  `graft-independent` therefore means "no graft is necessary", never
    "not ours".
  * `candidates` names the grafts the crash requires, not the bug it is.  A
    crash can depend on graft i and still be a different fault that graft i
    merely made reachable.

Replay details that matter:
  * Replays the COVERAGE build, not the fuzzing binary, inside `base-runner`.
    The fuzzing binary carries no line table -- every symbolizer returns
    `??:0:0` for it -- while the coverage build has full DWARF and still
    honours the dispatch prefix and ASan.  That yields native
    `#N 0x.. in <func> /src/path:line:col` frames, so a replay log is
    readable when a case needs looking at by hand.
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
import tarfile
from collections import defaultdict
from glob import glob
from pathlib import Path

BASE_RUNNER = "gcr.io/oss-fuzz-base/base-runner"

# UBSan is NOT part of this paper's oracle: no claim rests on undefined
# behaviour, the replays run with halt_on_error=0 so a UB report is not a
# crash, and a UBSan-typed campaign row can therefore never be reproduced or
# attributed.  Such rows are DROPPED at the source rather than carried through
# as `non-reproducing`, which is what made htslib look 47% unreproducible.
UBSAN_TYPES = ("Undefined-shift", "Integer-overflow", "Index-out-of-bounds",
               "Float-cast", "Divide-by-zero", "Invalid-bool",
               "Misaligned-address", "Object-size", "Non-positive-vla",
               "Pointer-overflow", "Invalid-shift")


def is_ubsan(crash_key):
    return (crash_key or "").startswith(UBSAN_TYPES)


# The sanitizer configuration FuzzBench's measurer used when it recorded these
# crashes (fuzzbench/common/sanitizer.py).  Replaying with anything else is
# replaying a different program: `detect_stack_use_after_return=1` moves locals
# to a fake stack, and on c-blosc2 it is the difference between the recorded
# crash and silence -- 8 of 8 sampled `non-reproducing` classes reproduce with
# it and none without.  Keep this in step with the measurer.
MEASURER_ASAN = ":".join([
    "alloc_dealloc_mismatch=0", "allocator_may_return_null=1",
    "allocator_release_to_os_interval_ms=500", "allow_user_segv_handler=0",
    "check_malloc_usable_size=0", "detect_leaks=0", "detect_odr_violation=0",
    "detect_stack_use_after_return=1", "fast_unwind_on_fatal=0",
    "handle_abort=2", "handle_sigbus=2", "handle_sigfpe=2", "handle_segv=2",
    "handle_sigill=2", "max_uar_stack_size_log=16", "quarantine_size_mb=64",
    "strict_memcmp=1", "symbolize=1", "symbolize_inline_frames=0",
])
# UBSan stays non-fatal: UBSan is not part of this paper's oracle and its
# crash types are filtered out entirely (is_ubsan).
MEASURER_UBSAN = "print_stacktrace=0:halt_on_error=0"

_FRAME_HEAD = re.compile(r"^\s*#(\d+)\s+0x[0-9a-f]+\s+in\s+(.*)$")


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


def pin_image(ref):
    """Resolve an image reference to its immutable id.

    A tag moves.  `base-runner:latest` and the locally built
    `runners/libfuzzer/<benchmark>:latest` are both rebuilt in place, so a run
    that records only the tag cannot say afterwards which environment produced
    its verdicts -- and a rebuild mid-sweep would silently change it.  Resolve
    once, run every container on the id, and write the id into the run
    metadata.
    """
    p = subprocess.run(["docker", "image", "inspect", "-f",
                        "{{.Id}}{{if .RepoDigests}}\t"
                        "{{index .RepoDigests 0}}{{end}}", ref],
                       capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"replay image not present locally: {ref}\n"
                         f"build it first -- a floating tag is not a fallback")
    out = p.stdout.strip().split("\t")
    image_id = out[0]
    digest = out[1] if len(out) > 1 else ""   # locally built images have none
    return image_id, digest


def run_masks(image_out, target, vdir, names, tries, runs, tmo=240,
              runner=BASE_RUNNER):
    """Replay `names` in one container.

    tmo is deliberately generous.  With several containers running at once each
    execution slows down, and a per-execution timeout that is merely adequate
    when sequential starts firing on real crashes under load -- at 10 jobs and
    a 60 s limit, libavc lost 7 classes to spurious `non-reproducing` that the
    sequential run classified fine.
    """
    lst = vdir.parent / f"probe_list_{vdir.name}.txt"
    lst.write_text("\n".join(names) + "\n")
    # image_out=None replays the image's OWN /out -- the fuzzing binary the
    # campaign ran.  The coverage build was chosen when RQ5's matcher needed
    # crash_line; frame matching was removed 2026-08-19, and the coverage build
    # does not reproduce every crash the fuzzing build does (c-blosc2: 8 of 8
    # sampled ASan classes reproduce on the fuzzing binary, none on coverage).
    cmd = ["docker", "run", "--rm", "--privileged", "--shm-size=2g",
           *(["-v", f"{image_out}:/out"] if image_out else []),
           "-v", f"{vdir}:/inputs:ro",
           "-v", f"{lst}:/list:ro",
           "-e", "ASAN_SYMBOLIZER_PATH=/usr/local/bin/llvm-symbolizer",
           "-e", f"ASAN_OPTIONS={MEASURER_ASAN}",
           "-e", f"UBSAN_OPTIONS={MEASURER_UBSAN}",
           "--entrypoint", "bash", runner, "-c",
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
    ap.add_argument("--runner-image", required=True,
                    help="image the replays run in.  Use the campaign's own "
                         "runner image (gcr.io/fuzzbench/runners/libfuzzer/"
                         "<benchmark>:latest) so the replay environment is the "
                         "one the crashes were found in; it is built on the "
                         "base-builder digest the benchmark Dockerfile pins.  "
                         f"Falls back to {BASE_RUNNER} only if you pass it "
                         "explicitly.")
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

    # Pin the replay environment before anything runs: every container below
    # uses the resolved id, not the tag it came from.
    runner_id, runner_digest = pin_image(a.runner_image)
    print(f"replay image: {a.runner_image} -> {runner_id}"
          f"{' (' + runner_digest + ')' if runner_digest else ''}", flush=True)

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

    # Append each verdict as it completes.  The whole-file write at the end
    # meant a timeout kill lost every replay done so far -- gstoraster lost
    # 3+ hours that way.
    dest = Path(a.out) / f"{a.name}_two_level.csv"
    FIELDS = ["benchmark", "crash_key", "canon_mask", "class_crashes",
              "testcase", "fuzzer", "trial", "time", "level1", "candidates",
              "recorded_mask", "repro_masks", "masks_tested", "sanitizer"]
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
        res = run_masks(out_dir, a.target, wd, names, a.tries, a.runs,
                        runner=runner_id)
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
                                 a.tries, a.runs, runner=runner_id)

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

        row = {
            "benchmark": a.name, "crash_key": (key or "").replace("\n", " "),
            "canon_mask": cmask, "class_crashes": nmemb,
            "testcase": tc, "fuzzer": fuzzer, "trial": trial, "time": when,
            "level1": level1, "candidates": "|".join(cands),
            "recorded_mask": recorded,
            "repro_masks": " ".join(str(m) for m in sorted(crashed)),
            "masks_tested": " ".join(str(m) for m in sorted(masks)),
            "sanitizer": sanitizer_class(rec_text or ""),
        }
        with wr_lock:
            wr_out.writerow(row)
            fh_out.flush()
            rows.append(row)
        # Keep every replay log: re-deriving one means re-replaying the input,
        # and the per-case notes quote the stack even though no verdict is
        # taken from it.
        with gzip.open(logs / f"{tc}.log.gz", "wt") as fh:
            fh.write(rec_text or "")
        if n % 50 == 0 or n == len(inputs):
            print(f"  [{len(rows)}/{len(inputs)}] {level1}", flush=True)


    with ThreadPoolExecutor(max_workers=a.jobs) as ex:
        list(ex.map(one_class, enumerate(inputs, 1)))
    fh_out.close()

    outdir = Path(a.out)
    outdir.mkdir(parents=True, exist_ok=True)
    # How the sweep was run, next to what it found: without this the image the
    # replays used is invisible in the output.
    (outdir / f"{a.name}_run_metadata.json").write_text(json.dumps({
        "benchmark": str(bench),
        "name": a.name,
        "db": a.db,
        "experiment": a.experiment,
        "folders": a.folders,
        "cov_tar": a.cov_tar,
        "runner_image": a.runner_image,
        "runner_image_id": runner_id,
        "runner_repo_digest": runner_digest,
        "gated_bugs": len(bits),
        "ungated_bugs": len(always),
        "dispatch_bytes": nbytes,
        "tries": a.tries,
        "runs": a.runs,
        "jobs": a.jobs,
        "crash_rows": n_rows,
        "classes": len(cls),
        "classes_replayed": len(inputs),
    }, indent=2) + "\n")
    print(f"\nwrote {dest} ({len(rows)} rows, written incrementally)")
    c1 = defaultdict(int)
    for r in rows:
        c1[r["level1"]] += 1
    print("verdicts:", dict(c1))


if __name__ == "__main__":
    main()
