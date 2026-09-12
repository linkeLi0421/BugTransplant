#!/usr/bin/env python3
"""Pass 1 by NECESSITY: leave one recorded bit out at a time.

The sufficiency sweep (`two_level_triage.py`) replays mask 0, every single bit
the benchmark defines, and the recorded mask, and calls a class
`graft-triggered` when some single bit reproduces "a crash".  Two things go
wrong with that:

  * it credits any graft that can crash the input ON ITS OWN, even one the
    campaign never had enabled -- c-blosc2's OSV-2022-486 is a use-after-free
    in the I/O callback registry that fires on nearly any input, so it appears
    as a co-sufficient candidate in 100% of that benchmark's `either-of-n`
    classes;
  * "a crash" is any fatal sanitizer report, so the replay need not be the
    fault the class is about.

This script asks the counterfactual the campaign actually poses.  Per class:

  1. mask 0            -- if the crash survives with every graft off it is
                          graft-independent, whatever else is true.
  2. the recorded mask  -- the control: does this input still crash in the
                          configuration the fuzzer found it in?
  3. recorded mask with ONE recorded bit cleared, for each bit that is on --
                          if the crash disappears, that graft is NECESSARY.

The PRIMARY verdict uses crash / no-crash only -- a bit is necessary when
clearing it leaves no fatal report at all.  That needs no crash signature, so
nothing about it can be wrong for signature reasons; in particular
`graft-independent` means "this input crashes the target with every graft off",
which is a fact about the binary, not about how two stacks are compared.

The signature-matched reading is kept alongside in the `*_sig` columns: there a
bit is necessary when clearing it stops producing THAT fault, whether the
program then runs clean or crashes with a different bug.  The two disagree on
~10% of classes; those are the ones worth reading by hand, and
`disagree`/`removal_effect` mark them.

Verdicts are the SAME vocabulary the sufficiency sweep used -- only the
evidence behind them changes:

  graft-independent                  crashes at mask 0
  non-reproducing                    the recorded mask does not crash
  graft-triggered, one-bit           exactly one recorded bit is necessary:
                                     clearing it removes the crash, and it is
                                     the only bit that does
  graft-triggered, either-of-n       the recorded mask crashes but no single
                                     removal stops it -- redundant causes, so
                                     the campaign's own mask cannot single one
                                     out
  composition-dependent              two or more bits are each necessary; the
                                     crash needs them together

Every replay is also compared against the CONTROL's signature (sanitizer class
+ faulting pc).  The binary is identical across masks -- only the dispatch
prefix changes -- so the pc is comparable.  Both readings are reported:
`*_raw` counts any fatal report (what the old sweep did) and the unsuffixed
columns require the same fault.  Where they disagree, the old sweep was
measuring a different crash.

Usage mirrors two_level_triage.py; see script/run_attribution_pass1.sh.
"""
import argparse
import csv
import gzip
import json
import re
import tarfile
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from pathlib import Path

import two_level_triage as t1

# Every frame as `module+offset`, e.g. (/out/decompress_frame_fuzzer+0x4d6050)
# or (/lib/x86_64-linux-gnu/libc.so.6+0x24082).
#
# The ABSOLUTE pc is useless as a signature -- a fault in a shared library gets
# a different pc every process because the mapping base is randomised, so every
# mask removal looked like it changed the fault.
#
# Frame 0 alone is not enough either: half of c-blosc2's classes fault inside an
# ASan interceptor (`__asan_memcpy`, `__interceptor_free`, ...), which sits at
# the SAME address for every memcpy overflow in the program, so two different
# faults collapse into one signature.  The fault is identified by the first
# frame that is not sanitizer runtime; which offsets those are is resolved once
# per run with addr2line, after the replays (see interceptor_offsets).
FRAME = re.compile(r"^ +#\d+ 0x[0-9a-f]+ +\((.+?)\+0x([0-9a-f]+)\)", re.M)
RUNTIME = ("__asan", "__lsan", "__ubsan", "__sanitizer", "__interceptor")


def frames(text, keep=6):
    """(sanitizer class, [(module, offset), ...]) for one replay."""
    if not text:
        return ("", [])
    fr = [(m.group(1).rsplit("/", 1)[-1], m.group(2))
          for m in FRAME.finditer(text)][:keep]
    return (t1.sanitizer_class(text), fr)


def interceptor_offsets(binary, offsets):
    """Offsets in *binary* that symbolize to sanitizer-runtime functions."""
    if not binary or not offsets:
        return set()
    offs = sorted(offsets)
    p = subprocess.run(["addr2line", "-f", "-C", "-e", str(binary)],
                       input="\n".join("0x" + o for o in offs),
                       capture_output=True, text=True)
    out = p.stdout.splitlines()
    bad = set()
    for i, o in enumerate(offs):
        name = out[2 * i].strip() if 2 * i < len(out) else ""
        if name.startswith(RUNTIME):
            bad.add(o)
    return bad


def make_sig(module, bad_offsets):
    """Signature = class + first frame that is not sanitizer runtime.

    Falls back to the top three frames when no binary was available to resolve
    interceptors, which still separates two faults that share frame 0.
    """
    def sig(entry):
        cls, fr = entry
        if not cls:
            return ""
        if bad_offsets is not None:
            for mod, off in fr:
                if mod == module and off in bad_offsets:
                    continue
                return f"{cls}:{mod}+0x{off}"
            return cls
        return cls + ":" + " ".join(f"{m}+0x{o}" for m, o in fr[:3])
    return sig


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
    ap.add_argument("--name", required=True)
    ap.add_argument("--tries", type=int, default=3)
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--chunk", type=int, default=200)
    ap.add_argument("--binary", choices=("fuzzing", "coverage"),
                    default="fuzzing",
                    help="which build to replay.  `fuzzing` (default) uses the "
                         "runner image's own /out -- the binary the campaign "
                         "ran.  `coverage` mounts the campaign's coverage "
                         "build, which has line tables but does NOT reproduce "
                         "every crash the fuzzing build does.")
    a = ap.parse_args()

    runner_id, runner_digest = t1.pin_image(a.runner_image)
    print(f"replay image: {a.runner_image} -> {runner_id}", flush=True)

    bench = Path(a.benchmark_dir)
    work = Path(a.workdir) / a.name
    work.mkdir(parents=True, exist_ok=True)
    meta, nbytes, bits, always = t1.load_meta(bench)
    inv = {v: k for k, v in bits.items()}
    used = sorted(bits.values())
    print(f"{a.name}: {len(bits)} gated bugs, {nbytes} dispatch byte(s)",
          flush=True)

    if a.binary == "coverage":
        out_dir = work / "covbin"
        if not out_dir.is_dir():
            out_dir.mkdir(parents=True, exist_ok=True)
            with tarfile.open(a.cov_tar, "r:gz") as tf:
                tf.extractall(out_dir)
        if not (out_dir / a.target).is_file():
            raise SystemExit(f"coverage build has no /{a.target}: {out_dir}")
    else:
        out_dir = None      # replay the runner image's own binary
    print(f"  replay binary: {a.binary}", flush=True)

    raw = work / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    cls, n_rows = t1.classes_for(a.db, a.experiment, a.folders, raw, nbytes,
                                 used)
    inputs = []
    for (key, m), members in cls.items():
        members.sort(key=lambda x: x[3])
        tc, fz, tr, when = members[0]
        inputs.append((key, tc, fz, tr, when, m, len(members)))
    n_ubsan = sum(1 for i in inputs if t1.is_ubsan(i[0]))
    inputs = [i for i in inputs if not t1.is_ubsan(i[0])]
    if n_ubsan:
        print(f"  dropped {n_ubsan} UBSan-typed class(es): UBSan is not part "
              f"of the oracle (replays run halt_on_error=0)", flush=True)
    inputs.sort(key=lambda x: x[4])
    if a.limit:
        inputs = inputs[:a.limit]
    print(f"  {n_rows} crash rows -> {len(cls)} classes; replaying "
          f"{len(inputs)}", flush=True)
    print(f"  masks per class: 0, the recorded mask, and the recorded mask "
          f"with each of its own bits cleared", flush=True)

    dest = Path(a.out) / f"{a.name}_necessity.csv"
    dest.parent.mkdir(parents=True, exist_ok=True)
    # Same column names as the sufficiency sweep where they mean the same
    # thing (`level1`, `candidates`, `sufficiency`), plus the necessity
    # evidence.  `candidates` is the necessary set; for `either-of-n` no bit is
    # necessary, so it lists every bit the recorded mask had on.
    # `level1`/`sufficiency`/`candidates` are the STRICT (crash-or-not) verdict;
    # `*_sig` are the signature-matched one; `disagree` flags the classes where
    # they differ, which are the ones to review by hand.
    FIELDS = ["benchmark", "crash_key", "canon_mask", "class_crashes",
              "testcase", "fuzzer", "trial", "time", "level1", "sufficiency",
              "candidates", "level1_sig", "sufficiency_sig", "candidates_sig",
              "disagree", "removal_effect", "recorded_bits", "control_sig",
              "mask0_sig", "removed_sigs"]
    fh = open(dest, "w", newline="")
    wr = csv.DictWriter(fh, fieldnames=FIELDS)
    wr.writeheader()
    lock = threading.Lock()
    rows = []
    pending = []
    logs = work / "logs"
    logs.mkdir(exist_ok=True)

    def one(job):
        n, (key, tc, fuzzer, trial, when, cmask, nmemb) = job
        payload = (raw / tc).read_bytes()[nbytes:]
        onbits = [b for b in used if cmask >> b & 1]
        vd = work / f"v_{n}"
        vd.mkdir(exist_ok=True)
        for p in vd.iterdir():
            p.unlink()
        todo = {"m0": 0, "mC": cmask}
        for b in onbits:
            todo[f"r{b}"] = cmask & ~(1 << b)
        for nm, m in todo.items():
            (vd / nm).write_bytes(t1.mask_prefix(m, nbytes) + payload)
        res = t1.run_masks(out_dir, a.target, vd, list(todo), a.tries, a.runs,
                           runner=runner_id)
        for p in vd.iterdir():
            p.unlink()
        vd.rmdir()

        ctrl = res.get("mC", "")
        zero = res.get("m0", "")
        ev = {"control": frames(ctrl), "mask0": frames(zero),
              "removed": {b: frames(res.get(f"r{b}", "")) for b in onbits},
              "raw": {b: bool(res.get(f"r{b}", "")) for b in onbits},
              "raw_ctrl": bool(ctrl), "raw_zero": bool(zero)}

        with lock:
            pending.append({
                "benchmark": a.name,
                "crash_key": (key or "").replace("\n", " "),
                "canon_mask": cmask, "class_crashes": nmemb, "testcase": tc,
                "fuzzer": fuzzer, "trial": trial, "time": when,
                "onbits": onbits, "ev": ev})
            if len(pending) % 100 == 0 or len(pending) == len(inputs):
                print(f"  [{len(pending)}/{len(inputs)}]", flush=True)
        with gzip.open(logs / f"{tc}.log.gz", "wt") as lf:
            lf.write(ctrl or "")

    with ThreadPoolExecutor(max_workers=a.jobs) as ex:
        list(ex.map(one, enumerate(inputs, 1)))

    # Which frames are sanitizer runtime?  One addr2line pass over every offset
    # seen in the target binary, then the verdicts are computed from the stored
    # evidence -- so the rule can change without replaying anything.
    module = Path(a.target).name
    seen = set()
    for p in pending:
        for entry in [p["ev"]["control"], p["ev"]["mask0"],
                      *p["ev"]["removed"].values()]:
            for mod, off in entry[1]:
                if mod == module:
                    seen.add(off)
    binary = (out_dir / a.target) if out_dir else None
    bad = interceptor_offsets(binary, seen) if binary else None
    print(f"  sanitizer-runtime frames: {len(bad) if bad is not None else 0} "
          f"offset(s) of {len(seen)} seen in {module}", flush=True)
    sig = make_sig(module, bad)

    for p in pending:
        onbits, ev = p["onbits"], p["ev"]
        csig, zsig = sig(ev["control"]), sig(ev["mask0"])
        removed = {b: sig(ev["removed"][b]) for b in onbits}
        if not csig:
            level1, suff, nec = "non-reproducing", "", []
        elif zsig == csig:
            level1, suff, nec = "graft-independent", "", []
        else:
            nec = [b for b in onbits if removed[b] != csig]
            level1, suff = (("graft-triggered", "one-bit") if len(nec) == 1
                            else ("composition-dependent", "") if nec
                            else ("graft-triggered", "either-of-n"))
        if not ev["raw_ctrl"]:
            raw_v, suff_raw, nec_raw = "non-reproducing", "", []
        elif ev["raw_zero"]:
            raw_v, suff_raw, nec_raw = "graft-independent", "", []
        else:
            nec_raw = [b for b in onbits if not ev["raw"][b]]
            raw_v, suff_raw = (("graft-triggered", "one-bit") if len(nec_raw) == 1
                               else ("composition-dependent", "") if nec_raw
                               else ("graft-triggered", "either-of-n"))
        row = {k: p[k] for k in ("benchmark", "crash_key", "canon_mask",
                                 "class_crashes", "testcase", "fuzzer",
                                 "trial", "time")}
        # What clearing each PRIMARY-necessary bit does to the fault: `silence`
        # (no report at all) or `redirect` (a crash, but not this one).  Under
        # the strict rule only silences count, so this is empty; it is the
        # column to read when checking a disagreement by hand.
        effect = " ".join(
            f"{inv[b]}={'silence' if not removed[b] else 'redirect'}"
            for b in (nec if nec else []))
        row.update({
            "level1": raw_v, "sufficiency": suff_raw,
            "candidates": "|".join(inv[b] for b in
                                   (nec_raw if nec_raw else
                                    onbits if suff_raw == "either-of-n"
                                    else [])),
            "level1_sig": level1, "sufficiency_sig": suff,
            "candidates_sig": "|".join(inv[b] for b in
                                       (nec if nec else
                                        onbits if suff == "either-of-n"
                                        else [])),
            "disagree": "yes" if (raw_v, suff_raw) != (level1, suff) else "",
            "removal_effect": effect,
            "recorded_bits": "|".join(inv[b] for b in onbits),
            "control_sig": csig, "mask0_sig": zsig,
            "removed_sigs": " ".join(f"{inv[b]}={removed[b]}" for b in onbits),
        })
        wr.writerow(row)
        rows.append(row)
    fh.close()

    def label(r, suffix=""):
        v = r["level1" + suffix]
        s = r["sufficiency" + suffix]
        return f"{v}/{s}" if s else v

    c = defaultdict(int)
    craw = defaultdict(int)
    for r in rows:
        c[label(r)] += 1
        craw[label(r, "_sig")] += 1
    print(f"\nwrote {dest} ({len(rows)} rows)")
    print("  strict (crash or not):  ", dict(c))
    print("  signature-matched:      ", dict(craw))
    print("  disagreeing classes:    ",
          sum(1 for r in rows if r["disagree"]))
    (Path(a.out) / f"{a.name}_necessity_run.json").write_text(json.dumps({
        "benchmark": str(bench), "name": a.name, "db": a.db,
        "experiment": a.experiment, "runner_image": a.runner_image,
        "runner_image_id": runner_id, "method": "leave-one-recorded-bit-out",
        "binary": a.binary,
        "classes": len(cls), "classes_replayed": len(inputs),
        "crash_rows": n_rows, "ubsan_classes_dropped": n_ubsan,
        "strict": dict(c), "signature_matched": dict(craw),
        "disagree": sum(1 for r in rows if r["disagree"]),
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
