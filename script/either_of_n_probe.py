#!/usr/bin/env python3
"""What makes an `either-of-n` class over-determined?

`graft-triggered / either-of-n` means: the recorded mask crashes, mask 0 does
not, and clearing any ONE recorded bit leaves the same fault.  So the crash
needs a graft, but no single graft is necessary -- there must be two or more
sufficient subsets of the recorded mask.  This finds them, bottom-up:

  1. every single recorded bit alone      -> which grafts suffice on their own
  2. every pair, for classes where no single bit sufficed
  3. (report only) classes still unexplained need a bigger subset

A class where NO single graft reproduces the recorded fault but a pair does is
composition-dependent, not `either-of-n`; the removal test misses it whenever an
unrelated graft crashes the same input alone, because clearing a genuinely
required bit then still leaves "a crash".  Those are emitted as
`composition-dependent (reclassify)` with `required` / `alternatives`.

Sufficiency is matched against the class's own control signature (sanitizer
class + frame-0 module+offset), not "some crash", so an unrelated graft's crash
never counts.

Usage:
  python3 script/either_of_n_probe.py --csv <target>_necessity.csv \
      --benchmark-dir ... --folders ... --runner-image ... --target ... \
      --cov-tar ... --workdir ... --out probe.csv
"""
import argparse
import csv
import itertools
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from pathlib import Path

import two_level_triage as t1
from pass1_necessity import RUNTIME, frames


_sym_cache = {}
_sym_lock = threading.Lock()


def is_runtime(binary, module, off, target_module):
    """Is this frame sanitizer runtime?  Resolved once per offset, cached."""
    if module != target_module:
        return False
    with _sym_lock:
        if off in _sym_cache:
            return _sym_cache[off]
    p = subprocess.run(["addr2line", "-f", "-C", "-e", str(binary)],
                       input="0x" + off, capture_output=True, text=True)
    name = (p.stdout.splitlines() or [""])[0].strip()
    v = name.startswith(RUNTIME)
    with _sym_lock:
        _sym_cache[off] = v
    return v


def make_sig(binary, target_module):
    def sig(entry):
        cls, fr = entry
        if not cls:
            return ""
        for mod, off in fr:
            if is_runtime(binary, mod, off, target_module):
                continue
            return f"{cls}:{mod}+0x{off}"
        return cls
    return sig


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--benchmark-dir", required=True)
    ap.add_argument("--folders", required=True)
    ap.add_argument("--runner-image", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--cov-tar", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tries", type=int, default=3)
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--max-pairs", type=int, default=80)
    a = ap.parse_args()

    runner_id, _ = t1.pin_image(a.runner_image)
    bench = Path(a.benchmark_dir)
    meta, nbytes, bits, always = t1.load_meta(bench)
    inv = {v: k for k, v in bits.items()}
    work = Path(a.workdir)
    work.mkdir(parents=True, exist_ok=True)
    out_dir = work / "covbin"
    if not (out_dir / a.target).is_file():
        import tarfile
        out_dir.mkdir(parents=True, exist_ok=True)
        with tarfile.open(a.cov_tar, "r:gz") as tf:
            tf.extractall(out_dir)

    sig = make_sig(out_dir / a.target, Path(a.target).name)
    rows = [r for r in csv.DictReader(open(a.csv))
            if r["sufficiency"] == "either-of-n"]
    raw = work / "raw"
    raw.mkdir(exist_ok=True)
    t1.extract(a.folders, {r["testcase"] for r in rows}, raw)
    print(f"{len(rows)} either-of-n classes", flush=True)

    fh = open(a.out, "w", newline="")
    W = csv.DictWriter(fh, fieldnames=[
        "testcase", "crash_key", "canon_mask", "class_crashes", "n_bits",
        "control_sig", "verdict", "singles_crash", "n_singles_crash",
        "singles_ok", "n_singles_ok", "pairs_ok", "n_pairs_ok",
        "recorded_bits"])
    W.writeheader()
    lock = threading.Lock()
    done = Counter()

    def one(job):
        i, r = job
        payload = (raw / r["testcase"]).read_bytes()[nbytes:]
        onbits = [b for b in sorted(bits.values())
                  if int(r["canon_mask"]) >> b & 1]
        ctrl = r["control_sig"]
        vd = work / f"p_{i}"
        vd.mkdir(exist_ok=True)

        def probe(masks):
            for p in vd.iterdir():
                p.unlink()
            names = {}
            for key, m in masks.items():
                (vd / key).write_bytes(t1.mask_prefix(m, nbytes) + payload)
                names[key] = m
            res = t1.run_masks(out_dir, a.target, vd, list(names), a.tries,
                               a.runs, runner=runner_id)
            return {k: (sig(frames(res.get(k, ""))), bool(res.get(k, "")))
                    for k in names}

        singles = probe({f"s{b}": 1 << b for b in onbits})
        # `crashes` is the strict reading (this graft alone crashes at all);
        # `ok` is the strict reading PLUS the same fault as the control.
        crashes = [inv[b] for b in onbits if singles.get(f"s{b}", ("", 0))[1]]
        ok = [inv[b] for b in onbits if singles.get(f"s{b}", ("", 0))[0] == ctrl]
        pairs_ok, verdict = [], ""
        if ok:
            verdict = "redundant singles"
        else:
            combos = list(itertools.combinations(onbits, 2))[:a.max_pairs]
            res = probe({f"p{x}_{y}": (1 << x) | (1 << y) for x, y in combos})
            pairs_ok = [f"{inv[x]}+{inv[y]}" for x, y in combos
                        if res.get(f"p{x}_{y}", ("", 0))[0] == ctrl]
            # No single graft reproduces the recorded fault but a set does:
            # that is a COMPOSITION-DEPENDENT class, not `either-of-n`.  The
            # removal test could not see it because an unrelated graft crashes
            # the same input on its own, so clearing a genuinely required bit
            # still left "a crash".  Emitted as a reclassification.
            verdict = ("composition-dependent (reclassify)" if pairs_ok
                       else "needs >2 grafts")
        for p in vd.iterdir():
            p.unlink()
        vd.rmdir()
        with lock:
            W.writerow({
                "testcase": r["testcase"], "crash_key": r["crash_key"][:80],
                "canon_mask": r["canon_mask"],
                "class_crashes": r["class_crashes"], "n_bits": len(onbits),
                "control_sig": ctrl, "verdict": verdict,
                "singles_crash": "|".join(crashes),
                "n_singles_crash": len(crashes),
                "singles_ok": "|".join(ok), "n_singles_ok": len(ok),
                "pairs_ok": "|".join(pairs_ok), "n_pairs_ok": len(pairs_ok),
                "minimal_sets": "|".join(pairs_ok),
                "required": "|".join(sorted(
                    set(pairs_ok[0].split("+")).intersection(
                        *[set(x.split("+")) for x in pairs_ok[1:]]))
                    if pairs_ok else []),
                "alternatives": "|".join(sorted(
                    {b for x in pairs_ok for b in x.split("+")} -
                    set(pairs_ok[0].split("+")).intersection(
                        *[set(x.split("+")) for x in pairs_ok[1:]]))
                    if pairs_ok else []),
                "recorded_bits": "|".join(inv[b] for b in onbits)})
            fh.flush()
            done[verdict] += 1
            if sum(done.values()) % 10 == 0:
                print(f"  [{sum(done.values())}/{len(rows)}] {dict(done)}",
                      flush=True)

    with ThreadPoolExecutor(max_workers=a.jobs) as ex:
        list(ex.map(one, enumerate(rows, 1)))
    fh.close()
    print(f"\nwrote {a.out}")
    for k, v in done.most_common():
        print(f"  {k:20} {v}")


if __name__ == "__main__":
    main()
