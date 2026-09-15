#!/usr/bin/env python3
"""Build a benchmark's initial seed corpus from the public ClusterFuzz corpus.

Three steps, in order:

1. **Download** the project's public corpus
   (``https://storage.googleapis.com/<project>-backup.clusterfuzz-external
   .appspot.com/corpus/libFuzzer/<project>_<fuzzer>/public.zip``).
2. **Prefix** every input with the dispatch-zero head byte(s). Slot 0 means
   "no bug", so no seed opens a grafted bug's gate and the fuzzer has to
   discover the selector byte itself.
3. **Filter** each candidate by replaying it against this benchmark's own
   fuzz target, dropping anything that crashes. A seed that already triggers
   a grafted bug would hand the fuzzer that bug for free.

Writes ``<benchmark>/corpus_seeds.zip``, which the benchmark Dockerfile
copies in and build.sh unpacks as the initial corpus.

Usage:
  python3 script/fuzzbench_corpus.py \
      --benchmark-dir fuzzbench/benchmarks/htslib_hts_open_fuzzer_graft_dcd4b730 \
      --project htslib --fuzz-target hts_open_fuzzer
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).resolve().parent
HOME_DIR = SCRIPT_DIR.parent

PUBLIC_CORPUS_URL = (
    "https://storage.googleapis.com/{project}-backup.clusterfuzz-external"
    ".appspot.com/corpus/libFuzzer/{qualified}/public.zip")

# Replay budget per candidate. A memory error can be flaky across process
# invocations (heap layout, ASan redzone placement), so one clean replay does
# not prove a seed is safe.
REPLAY_ATTEMPTS = 3
RSS_LIMIT_MB = 8192


def download_public_corpus(project: str, fuzz_target: str, dest: Path) -> int:
    """Download and unpack the public corpus. Returns the input count."""
    qualified = fuzz_target
    if not qualified.startswith(f"{project}_"):
        qualified = f"{project}_{fuzz_target}"
    url = PUBLIC_CORPUS_URL.format(project=project, qualified=qualified)
    zip_path = dest.parent / "public.zip"
    logger.info("Downloading %s", url)
    ret = subprocess.call(["wget", "-q", url, "-O", str(zip_path)])
    if ret != 0 or not zip_path.exists() or zip_path.stat().st_size == 0:
        logger.error("Download failed. The project may publish its corpus "
                     "under a different fuzz-target name; check %s", url)
        return 0
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(dest)
    zip_path.unlink()
    n = sum(1 for p in dest.rglob("*") if p.is_file())
    logger.info("Unpacked %d inputs (%.1f MB)", n,
                sum(p.stat().st_size for p in dest.rglob("*") if p.is_file()) / 1e6)
    return n


def dispatch_bytes_for(benchmark_dir: Path) -> int:
    """Dispatch prefix width, read from the benchmark's own metadata."""
    meta = benchmark_dir / "bug_metadata.json"
    if meta.exists():
        try:
            return int(json.loads(meta.read_text())["dispatch_bytes"])
        except Exception:
            pass
    logger.warning("No dispatch_bytes in bug_metadata.json; assuming 1")
    return 1


def build_runner_image(benchmark: str, fuzzer: str = "libfuzzer") -> str | None:
    """Build the benchmark so there is a binary to filter against."""
    tag = f"gcr.io/fuzzbench/builders/{fuzzer}/{benchmark}:latest"
    probe = subprocess.run(["docker", "image", "inspect", tag],
                           capture_output=True)
    if probe.returncode == 0:
        logger.info("Reusing existing image %s", tag)
        return tag
    logger.info("Building %s (needed to replay candidates)...", benchmark)
    ret = subprocess.call(
        ["make", f"build-{fuzzer}-{benchmark}"],
        cwd=str(HOME_DIR / "fuzzbench"),
    )
    if ret != 0:
        logger.error("Benchmark build failed; cannot filter candidates")
        return None
    return tag


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--benchmark-dir", required=True, type=Path)
    ap.add_argument("--project", required=True)
    ap.add_argument("--fuzz-target", required=True)
    ap.add_argument("--fuzzer", default="libfuzzer",
                    help="Fuzzer image used to replay candidates")
    ap.add_argument("--keep-work", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")

    bench = args.benchmark_dir.resolve()
    if not bench.is_dir():
        logger.error("No such benchmark dir: %s", bench)
        return 1
    benchmark = bench.name
    nbytes = dispatch_bytes_for(bench)
    logger.info("Benchmark %s (dispatch prefix: %d byte(s) of 0x00)",
                benchmark, nbytes)

    work = Path(tempfile.mkdtemp(prefix="corpus_"))
    raw = work / "raw"
    try:
        if not download_public_corpus(args.project, args.fuzz_target, raw):
            return 1

        prefixed = work / "prefixed"
        prefixed.mkdir()
        prefix = b"\x00" * nbytes
        n = 0
        for p in raw.rglob("*"):
            if not p.is_file():
                continue
            (prefixed / f"{n:06d}_{p.name}").write_bytes(prefix + p.read_bytes())
            n += 1
        logger.info("Prefixed %d inputs with %d dispatch-zero byte(s)", n, nbytes)

        image = build_runner_image(benchmark, args.fuzzer)
        if image is None:
            return 1

        kept = work / "kept"
        kept.mkdir()
        logger.info("Replaying %d candidates (%d attempts each)...",
                    n, REPLAY_ATTEMPTS)
        script = (
            f"for f in /cand/*; do ok=1; "
            f"for i in $(seq {REPLAY_ATTEMPTS}); do "
            f"timeout 30s env ASAN_OPTIONS=detect_leaks=0:"
            f"detect_stack_use_after_return=1 "
            f"/out/{args.fuzz_target} -rss_limit_mb={RSS_LIMIT_MB} -runs=1 "
            f'"$f" >/dev/null 2>&1 || {{ ok=0; break; }}; done; '
            f'[ "$ok" = 1 ] && cp "$f" /kept/; done; true'
        )
        ret = subprocess.call([
            "docker", "run", "--rm",
            "-v", f"{prefixed}:/cand:ro", "-v", f"{kept}:/kept",
            "--entrypoint", "bash", image, "-c", script,
        ])
        if ret != 0:
            logger.warning("Replay container exited %d", ret)

        survivors = sorted(p for p in kept.iterdir() if p.is_file())
        dropped = n - len(survivors)
        logger.info("Kept %d, dropped %d crashing candidate(s)",
                    len(survivors), dropped)
        if not survivors:
            logger.error("Every candidate crashed -- refusing to write an "
                         "empty corpus")
            return 1

        out = bench / "corpus_seeds.zip"
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for p in survivors:
                z.write(p, p.name)
        logger.info("Wrote %s (%d seeds, %.1f MB)",
                    out, len(survivors), out.stat().st_size / 1e6)
        return 0
    finally:
        if args.keep_work:
            logger.info("Work dir kept: %s", work)
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
