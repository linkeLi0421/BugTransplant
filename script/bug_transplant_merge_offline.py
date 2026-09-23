#!/usr/bin/env python3
"""Offline dispatch-wrapped merge of per-bug transplant patches.

Pre-wraps each bug's patch with dispatch gating before merging so bugs
can coexist without runtime interference. Each bug gets a bit in
__bug_dispatch[]; the fuzzer reads the dispatch byte from the first
byte(s) of the test input.

Usage:
    sudo -E python3 script/bug_transplant_merge_offline.py \
        --summary data/bug_transplant/batch_c-blosc2_79e921d9/summary.json \
        --bug_info osv_testcases_summary.json \
        --target c-blosc2 \
        --testcases-dir ~/oss-fuzz-for-select/pocs/tmp/ \
        --build_csv ~/log/c-blosc2_builds.csv
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR.parent / "data"
HOME_DIR = Path.home()

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# Import shared utilities from the existing merge script
sys.path.insert(0, str(SCRIPT_DIR))
from bug_transplant_merge import (
    _load_prompt,
    _exec,
    _exec_capture,
    _compile_cmd,
    _inject_dispatch_files,
    _apply_all_dispatch_bytes as _apply_all_dispatch_bytes_orig,
    _ensure_dispatch_capacity,
    _modify_harness_for_dispatch,
    _restore_testcases,
    _stage_untracked_source,
    start_merge_container,
    verify_bug_triggers,
    verify_all_bugs,
    _find_crash_log,
    compute_merge_order,
    files_in_diff,
    known_harness_source_paths,
    _prepare_container_testcases_dir,
    _save_work_testcase_to_host,
    CONTAINER_TESTCASES_DIR,
)
from bug_transplant import (
    SETENV_SCRIPT,
    load_setenv_defaults,
    set_active_agent,
)
from bug_verify import _RSS_LIMIT_MB  # noqa: E402


def _apply_all_dispatch_bytes(container, dispatch_state):
    """Prepend dispatch bytes to PoCs in /work/.

    Idempotent: compares the file size in /work/ against the pristine
    original in /testcases/.  If the file is already larger (i.e. the
    prefix was prepended by a previous call), it is left unchanged.

    The old implementation used ``d.startswith(prefix)`` which is a
    false-positive for zero-valued dispatch bytes (local bugs) when the
    testcase content naturally starts with 0x00 (e.g. H.264 NAL streams).
    """
    nbytes = dispatch_state.get("dispatch_bytes", 1)
    for bug_id, dval in dispatch_state["poc_bytes"].items():
        testcase = f"testcase-{bug_id}"
        prefix = dval.to_bytes(nbytes, "little")
        prefix_list = ",".join(str(b) for b in prefix)
        _exec_capture(
            container,
            f"if [ ! -f /work/{testcase} ]; then cp "
            f"{CONTAINER_TESTCASES_DIR}/{testcase} /work/{testcase}"
            f" 2>/dev/null; fi; python3 -c \""
            f"import os; p=bytes([{prefix_list}]); "
            f"orig=os.path.getsize('{CONTAINER_TESTCASES_DIR}/{testcase}') "
            f"if os.path.exists('{CONTAINER_TESTCASES_DIR}/{testcase}') else -1; "
            f"d=open('/work/{testcase}','rb').read(); "
            f"open('/work/{testcase}','wb').write(d if len(d)!=orig else p+d)\"",
        )


def _resolve_host_testcase_bytes(
    project: str,
    bug: dict,
    staged_dir: Path,
) -> bytes | None:
    """Return the host testcase bytes that should back `/work/<testcase>`."""
    testcase_name = bug.get("testcase", f"testcase-{bug['bug_id']}")
    explicit_patched = bug.get("patched_testcase")
    if explicit_patched and Path(explicit_patched).is_file():
        return Path(explicit_patched).read_bytes()

    out_dir = DATA_DIR / "bug_transplant" / f"{project}_{bug['bug_id']}"
    if out_dir.exists():
        for tc in out_dir.glob(f"{testcase_name}*"):
            if tc.is_file() and tc.stat().st_size > 0:
                return tc.read_bytes()

    staged_path = staged_dir / testcase_name
    if staged_path.is_file():
        return staged_path.read_bytes()
    return None


def _restore_testcases_with_dispatch(
    container: str,
    project: str,
    bugs: list[dict],
    staged_dir: Path,
    dispatch_state: dict,
) -> None:
    """Restore testcases and always write the exact dispatch-prefixed bytes.

    The generic size-based idempotence check breaks when a bug's minimized
    testcase differs in size from the original staged testcase. In that case
    it wrongly assumes dispatch bytes are already present and skips prefixing,
    so the bug-specific gate never turns on during verification.
    """
    nbytes = dispatch_state.get("dispatch_bytes", 1)
    for bug in bugs:
        testcase_name = bug.get("testcase", f"testcase-{bug['bug_id']}")
        payload = _resolve_host_testcase_bytes(project, bug, staged_dir)
        if payload is None:
            continue
        prefix = dispatch_state["poc_bytes"][bug["bug_id"]].to_bytes(nbytes, "little")
        subprocess.run(
            ["docker", "exec", "-i", container,
             "bash", "-c", f"cat > /work/{testcase_name}"],
            input=prefix + payload,
            timeout=10,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False,
        )
from bug_transplant import (
    CODEX_CONFIG, setup_codex_creds, build_codex_command, _exec_interactive,
    active_agent,
    _format_codex_output,
    _source_dir,
)
from codex_usage import CodexUsageTracker

# Pathspecs to exclude build artifacts from git diff
_DIFF_EXCLUDES = (
    "':(exclude)CMakeFiles/' ':(exclude)*/CMakeFiles/' "
    "':(exclude)CMakeCache.txt' ':(exclude)cmake_install.cmake' "
    "':(exclude)*/cmake_install.cmake' ':(exclude)CTestTestfile.cmake' "
    "':(exclude)*/CTestTestfile.cmake' ':(exclude)CPackConfig.cmake' "
    "':(exclude)CPackSourceConfig.cmake' ':(exclude)cmake_uninstall.cmake' "
    "':(exclude)Makefile' ':(exclude)*/Makefile' "
    "':(exclude)*.o' ':(exclude)*.a' ':(exclude)*.so' ':(exclude)*.so.*' "
    "':(exclude)*.d' ':(exclude)*.pc' ':(exclude)config.h' "
    "':(exclude)blosc/config.h' "
    "':(exclude)build/' ':(exclude)_build/' "
    "':(exclude)obj/' ':(exclude)obj*' ':(exclude)bin/' "
    "':(exclude)tiff-config*' "
    "':(exclude).codex/'"
)

# Directories excluded only when they do not hold the project's fuzz harness.
# Some OSS-Fuzz projects keep the harness inside one of these (libredwg's is
# examples/llvmfuzz.c); excluding it there silently strips every harness hunk
# -- both the dispatch-byte read and the per-bug `ver = ...` / `out = ...`
# lines a transplant needs to reach its crash path -- with no error anywhere.
_CONDITIONAL_DIFF_EXCLUDE_DIRS = ("examples/",)

# Repo-relative directories that hold a project's harness and must therefore
# survive the exclusions above.
_PROJECT_HARNESS_REPO_DIRS: dict[str, tuple[str, ...]] = {
    "libredwg": ("examples/",),
}


def _protected_harness_dirs(project: str) -> tuple[str, ...]:
    return _PROJECT_HARNESS_REPO_DIRS.get(project, ())

# Per-project extra exclusions. Use for vendored source trees that the
# project's build.sh removes at build time (so the resulting git deletion
# noise would otherwise pollute harness.diff / combined.diff).
_PROJECT_DIFF_EXCLUDES: dict[str, tuple[str, ...]] = {
    "ghostscript": ("cups/", "freetype/", "zlib/", "libpng/"),
    # vcpkg.json does not exist at libredwg's target commit (it is added
    # upstream later), but the agents bump its version string anyway. The
    # hunk then makes combined.diff unappliable in the benchmark build:
    # "error: vcpkg.json: does not exist in index".
    "libredwg": ("vcpkg.json",),
}


def _diff_excludes(project: str) -> str:
    protected = _protected_harness_dirs(project)
    parts = [_DIFF_EXCLUDES]
    parts += [
        f"':(exclude){d}'"
        for d in _CONDITIONAL_DIFF_EXCLUDE_DIRS
        if d not in protected
    ]
    parts += [f"':(exclude){p}'" for p in _PROJECT_DIFF_EXCLUDES.get(project, ())]
    return " ".join(parts)


_DIFF_INCLUDES = (
    # C/C++ source & headers
    "'*.c' '*.h' '*.cc' '*.cpp' '*.cxx' '*.hpp' '*.hh' '*.hxx' "
    "'*.spec' "
    # Build files
    "'*.cmake' '*.sh' "
    "'CMakeLists.txt' '*/CMakeLists.txt' '**/CMakeLists.txt' "
    "'Makefile.am' '*/Makefile.am' "
    # Interpreted-language resources (needed for cross-language dispatch
    # wraps — e.g. pdf_draw.ps for ghostscript). Without these, agent
    # edits to these files get silently stripped from the saved diff.
    "'*.ps' '*.lua' '*.tcl' '*.py' '*.pl' '*.rb' '*.js' "
    # Data/config the prompt's two-file + gated-loader pattern may add
    "'*.json' '*.yaml' '*.yml' '*.toml' '*.conf' '*.ini'"
)


# Session-wide token/cost tracker (shared across all codex invocations)
_usage_tracker = CodexUsageTracker()


def _strip_build_artifact_hunks(diff_text: str, project: str = "") -> str:
    """Remove diff hunks for build-artifact paths (CMakeFiles/, etc.).

    ``project`` keeps the project's harness directory (see
    :data:`_PROJECT_HARNESS_REPO_DIRS`) out of the strip list, mirroring
    :func:`_diff_excludes`. Without it the git pathspec would keep the
    harness hunk and this pass would drop it again.
    """
    import re
    protected = _protected_harness_dirs(project)
    conditional = "".join(
        f"{d}|" for d in _CONDITIONAL_DIFF_EXCLUDE_DIRS if d not in protected
    )
    # Split into per-file sections on 'diff --git' boundaries
    parts = re.split(r'(?=^diff --git )', diff_text, flags=re.MULTILINE)
    artifact_header = re.compile(
        r"^diff --git a/(?:"
        r"cups/|freetype/|zlib/|" + conditional +
        r"obj(?:[./-]|$)|obj\.stale-root-[^/]+/|"
        r"tiff-config(?:[./-]|$)|tiff-config\.stale-root-[^/]+/|"
        r"(?:.*/)?CMakeFiles/|"
        r".*\.o$|.*\.a$|.*\.so(?:\..*)?$"
        r")",
        re.MULTILINE,
    )
    kept = [p for p in parts if not artifact_header.search(p.split('\n', 1)[0])]
    return ''.join(kept)


def _slots_present_in_tree(container: str, project: str,
                          slots: list[int]) -> set[int]:
    """Which __BUG_ACTIVE(n) gates currently exist in the container tree."""
    if not slots:
        return set()
    pattern = "|".join(str(n) for n in slots)
    _, out = _exec_capture(
        container,
        f"cd {_source_dir(project)} && "
        f"git grep -ho -E '__BUG_ACTIVE *\\( *({pattern}) *\\)' -- "
        f"'*.c' '*.h' '*.cc' '*.cpp' '*.spec' 2>/dev/null",
    )
    found: set[int] = set()
    for m in re.finditer(r"__BUG_ACTIVE\s*\(\s*(\d+)\s*\)", out or ""):
        found.add(int(m.group(1)))
    return found


def _wrapped_set_digest(wrapped_diffs: dict) -> str:
    """Content hash of the wrapped diffs a combined.diff was built from."""
    import hashlib
    h = hashlib.sha256()
    for bug_id in sorted(wrapped_diffs):
        h.update(bug_id.encode())
        try:
            h.update(Path(wrapped_diffs[bug_id]).read_bytes())
        except OSError:
            h.update(b"<missing>")
    return h.hexdigest()


def _combined_sources_path(output_dir: Path) -> Path:
    return output_dir / "combined.diff.sources"


_WRAP_LOG_DIR: "Path | None" = None


def _wrap_log_dir_for(bug_id: str):
    """Where to drop per-bug wrap diagnostics (set once the run knows its dir)."""
    return _WRAP_LOG_DIR


_MAX_CONSECUTIVE_WRAP_FAILURES = 3

# Substrings that mean the agent never ran, as opposed to running and failing
# to produce a good wrap. Retrying these is pointless and merging afterwards
# is destructive.
_AGENT_AUTH_ERRORS = (
    "refresh_token_reused",
    "token_expired",
    "Provided authentication token is expired",
    "could not be refreshed because your refresh token was already used",
    "401 Unauthorized",
)


def _agent_credentials_expired(output: str) -> bool:
    return any(marker in (output or "") for marker in _AGENT_AUTH_ERRORS)


_REPO_ROOT = Path(__file__).resolve().parent.parent

_BUG_ACTIVE_RE = re.compile(r"__BUG_ACTIVE\s*\(\s*(\d+)\s*\)")


def _diff_target_files(diff_text: str) -> set[str]:
    """Repo-relative paths a unified diff touches."""
    return set(re.findall(r"^\+\+\+ b/(.+)$", diff_text, re.M))


# Files whose presence in a diff carries no transplant semantics, so their
# absence from a wrapped diff is not a dropped hunk.
_AUDIT_IGNORED_FILES = ("vcpkg.json", "__bug_dispatch.c", "__bug_dispatch.h")


def _audit_wrapped_diff(
    bug_id: str,
    slot: int,
    wrapped_text: str,
    original_diff: Path | None,
) -> list[str]:
    """Return the reasons *wrapped_text* is not a faithful gating of the bug.

    Two failures were silent before this check and cost 19 libredwg bugs:

    * the wrap produced a diff with no ``__BUG_ACTIVE(slot)`` at all, so the
      bug is either dead or permanently live rather than gated;
    * the wrap dropped a file the per-bug transplant needed (the harness,
      stripped by an over-broad diff exclusion), so the gate is present but
      the crash path is unreachable.
    """
    problems: list[str] = []

    slots = {int(m) for m in _BUG_ACTIVE_RE.findall(wrapped_text)}
    if slot not in slots:
        problems.append(
            f"no __BUG_ACTIVE({slot}) in the wrapped diff -- the patch is "
            f"ungated (found {sorted(slots) or 'no gates at all'})"
        )
    foreign = slots - {slot}
    if foreign:
        problems.append(
            f"wrapped diff also gates foreign slot(s) {sorted(foreign)}"
        )

    if original_diff is not None and original_diff.exists():
        orig = original_diff.read_text(errors="replace")
        want = {
            f for f in _diff_target_files(orig)
            if not f.endswith(_AUDIT_IGNORED_FILES)
        }
        have = _diff_target_files(wrapped_text)
        dropped = sorted(want - have)
        if dropped:
            problems.append(
                "wrapped diff dropped file(s) the transplant needed: "
                + ", ".join(dropped)
            )

    return problems


def _audit_all_wraps(
    output_dir: Path,
    dispatch_state: dict,
    wrapped_diffs: dict,
    project: str,
) -> dict[str, list[str]]:
    """Audit every wrapped diff and log a per-bug verdict."""
    slot_of = {
        info["bug_id"]: slot
        for slot, info in dispatch_state.get("bits", {}).items()
    }
    bad: dict[str, list[str]] = {}
    for bug_id, path in wrapped_diffs.items():
        slot = slot_of.get(bug_id)
        if slot is None:
            continue
        problems = _audit_wrapped_diff(
            bug_id, slot,
            Path(path).read_text(errors="replace"),
            _REPO_ROOT / "data" / "bug_transplant"
            / f"{project}_{bug_id}" / "bug_transplant.diff",
        )
        if problems:
            bad[bug_id] = problems

    if not bad:
        logger.info("Wrap audit: all %d wrapped diffs gate their own slot and "
                    "keep every file of their transplant", len(wrapped_diffs))
        return bad

    logger.error("Wrap audit: %d of %d wrapped diffs are not faithful -- "
                 "these bugs will NOT trigger in the merged build:",
                 len(bad), len(wrapped_diffs))
    for bug_id, problems in sorted(bad.items()):
        for problem in problems:
            logger.error("  [%s] %s", bug_id, problem)
    return bad


def _audit_merged_slots(
    combined_diff: str,
    dispatch_state: dict,
    wrapped_diffs: dict,
) -> list[str]:
    """Report wrapped bugs whose slot did not survive the merge."""
    slot_of = {
        info["bug_id"]: slot
        for slot, info in dispatch_state.get("bits", {}).items()
    }
    present = {int(m) for m in _BUG_ACTIVE_RE.findall(combined_diff)}
    lost = sorted(
        bug_id for bug_id in wrapped_diffs
        if slot_of.get(bug_id) is not None and slot_of[bug_id] not in present
    )
    if lost:
        logger.error("Merge audit: %d wrapped bug(s) have no gate in "
                     "combined.diff -- the merge dropped them: %s",
                     len(lost), ", ".join(lost))
    else:
        logger.info("Merge audit: all %d wrapped slots present in combined.diff",
                    len(wrapped_diffs))
    return lost


def _clean_diff(container: str, project: str) -> str:
    """Get a clean git diff excluding build artifacts."""
    _stage_untracked_source(container, project)
    _, diff = _exec_capture(
        container,
        f"cd {_source_dir(project)} && git diff HEAD -- {_DIFF_INCLUDES} {_diff_excludes(project)}",
    )
    return _strip_build_artifact_hunks(diff, project)


def _clean_diff_against(container: str, project: str, base_rev: str) -> str:
    """Get a clean git diff against a specific baseline revision."""
    _stage_untracked_source(container, project)
    _, diff = _exec_capture(
        container,
        f"cd {_source_dir(project)} && git diff {shlex.quote(base_rev)} -- {_DIFF_INCLUDES} {_diff_excludes(project)}",
    )
    return _strip_build_artifact_hunks(diff, project)


def _save_source_snapshot(container: str, project: str) -> None:
    """Save a git stash snapshot of the source tree."""
    _exec_capture(container,
                  f"cd {_source_dir(project)} && git add -A && "
                  f"git stash push -m snapshot --include-untracked 2>/dev/null; true")


def _restore_source_snapshot(container: str, project: str) -> None:
    """Restore the most recent source snapshot."""
    _exec_capture(container,
                  f"cd {_source_dir(project)} && git checkout -f HEAD && "
                  f"git stash pop 2>/dev/null; true")


def _clean_container_working_tree_before_harness_diff(container: str, project: str) -> None:
    """Reset /src/<project> before reapplying a saved harness diff."""
    _exec_capture(
        container,
        f"cd {_source_dir(project)} && "
        "(git reset --hard HEAD 2>/dev/null || true) && "
        "(git clean -fdx -e '*.tar.gz' -e '*.tar.bz2' -e '*.tar.xz' -e '*.zip' 2>/dev/null || true) && "
        "rm -f __bug_dispatch.c __bug_dispatch.h 2>/dev/null || true",
    )


def _create_harness_baseline_commit(
    container: str, project: str, message: str = "codex harness baseline",
) -> str:
    """Create a temporary commit for the harness-applied baseline.

    Also used to snapshot each merge chunk: once a chunk is committed, a
    later chunk's agent cannot lose it with ``git checkout``/``stash``/
    ``clean``, because the gates live in HEAD rather than only in the
    working tree.
    """
    ret, out = _exec_capture(
        container,
        f"cd {_source_dir(project)} && "
        "git add -A && "
        "git -c user.name='Codex' -c user.email='codex@example.com' "
        f"commit --allow-empty -m {shlex.quote(message)} >/dev/null 2>&1 && "
        "git rev-parse HEAD 2>/dev/null",
    )
    if ret != 0:
        raise RuntimeError(f"failed to create harness baseline commit: {out[-500:]}")
    # Extract the SHA — filter out git warnings (e.g. line-ending messages)
    # that may appear in captured stderr.
    for line in reversed(out.strip().splitlines()):
        line = line.strip()
        if len(line) >= 40 and all(c in '0123456789abcdef' for c in line[:40]):
            return line
    raise RuntimeError(f"no valid SHA found in harness baseline output: {out[-500:]}")


def _restore_harness_baseline(container: str, project: str, baseline_rev: str) -> None:
    """Restore the tree to an exact snapshot revision.

    ``baseline_rev`` is the harness baseline for phase 1, and the previous
    chunk's commit when a merge chunk has to be retried.
    """
    ret, out = _exec_capture(
        container,
        f"cd {_source_dir(project)} && "
        f"git checkout -f {shlex.quote(baseline_rev)} >/dev/null 2>&1 && "
        f"git reset --hard {shlex.quote(baseline_rev)} >/dev/null 2>&1 && "
        "git clean -fdx -e '*.tar.gz' -e '*.tar.bz2' -e '*.tar.xz' -e '*.zip' >/dev/null 2>&1 || true",
    )
    if ret != 0:
        raise RuntimeError(f"failed to restore harness baseline: {out[-500:]}")

_MAX_WRAP_RETRIES = 1

# A merge chunk that wipes earlier chunks' gates is rewound and re-run once
# with that failure spelled out, rather than merely reported at the end.
_MERGE_CHUNK_ATTEMPTS = 2


def _prior_merge_note(prior_bugs: list[str], prior_slots: list[int]) -> str:
    """Describe what a merge chunk inherits from the chunks before it."""
    if not prior_bugs:
        return (
            "This is the first chunk: the working tree is the clean harness "
            "baseline, so only your own patches should appear in `git diff`."
        )
    return (
        f"**The working tree is NOT clean.** {len(prior_bugs)} patch(es) from "
        "earlier chunks are already merged into it and must survive your "
        "changes:\n\n"
        f"- bugs: {', '.join(prior_bugs)}\n"
        f"- slots that must still be present when you finish: "
        f"{', '.join(str(n) for n in prior_slots)}\n\n"
        "Never run `git checkout`, `git stash`, `git reset` or `git clean` to "
        "get a \"clean\" tree -- that silently deletes every gate above. "
        "Apply your patches on top of what is there, and edit shared files in "
        "place rather than rewriting them."
    )


_OPENSC_RELINK_SENTINEL = "bug_transplant: force fuzz target relink"

_OPENSC_RELINK_SNIPPET = """\
# >>> {sentinel} <<<
# opensc's src/tests/fuzzing/Makefile.am puts libopensc.la in LIBS, not in
# <target>_LDADD, so automake emits an empty fuzz_<name>_DEPENDENCIES and make
# reports the fuzz binaries "up to date" no matter what changed in the library.
# Every wrap after the first one then verifies against the binary the FIRST
# compile produced -- so a correct wrap looks like it does not trigger. Delete
# the link outputs so make has to rebuild them.
find "$SRC/opensc/src/tests/fuzzing" -maxdepth 1 -type f -name 'fuzz_*' \\
    ! -name '*.*' -delete 2>/dev/null || true
# <<< {sentinel} >>>
""".format(sentinel=_OPENSC_RELINK_SENTINEL)


def _patch_build_sh_for_project(content: str, project: str) -> str:
    """Apply project-specific build.sh hygiene before repeated compiles."""
    if project == "opensc" and _OPENSC_RELINK_SENTINEL not in content:
        lines = content.splitlines(keepends=True)
        patched = []
        inserted = False
        for line in lines:
            if not inserted and re.match(r'^make\s', line.strip()):
                patched.append(_OPENSC_RELINK_SNIPPET)
                inserted = True
            patched.append(line)
        if inserted:
            content = "".join(patched)

    # A side build dir created with a bare `mkdir build` (ntopng and ndpi both
    # do this for the json-c they vendor) survives between compiles in a reused
    # container, and the second `mkdir` fails the whole build under `set -e`.
    # Harmless on a clean tree, so apply it for every project.
    content = re.sub(
        r"^(\s*)mkdir\s+build\s*$",
        r"\1mkdir -p build",
        content,
        flags=re.MULTILINE,
    )

    if project != "ghostscript":
        return content

    patched: list[str] = []
    for line in content.splitlines(keepends=True):
        stripped = line.strip()
        # Ghostscript's OSS-Fuzz build.sh destructively removes tracked source
        # directories. In merge mode those removals pollute git diff and break
        # resume, so keep the vendored directories in place.
        if re.match(r"^rm -rf (cups/libs|freetype|zlib)(?:\s|$)", stripped):
            continue
        patched.append(line)

    content = "".join(patched)
    content = re.sub(
        r"^mv \$SRC/freetype freetype$",
        'if [ ! -d freetype ] && [ -d "$SRC/freetype" ]; then cp -a "$SRC/freetype" freetype; fi',
        content,
        flags=re.MULTILINE,
    )
    content = re.sub(
        r"^if \[ -d \"\$SRC/freetype\" \]; then cp -a \"\$SRC/freetype\" freetype; fi$",
        'if [ ! -d freetype ] && [ -d "$SRC/freetype" ]; then cp -a "$SRC/freetype" freetype; fi',
        content,
        flags=re.MULTILINE,
    )
    return content


def _patch_build_sh_make_tolerant(content: str, project: str) -> str:
    """Patch build.sh for repeated merge compiles.

    Dispatch-wrapped library sources reference ``__bug_dispatch`` which is
    only linked into fuzz targets.  Non-fuzzer binaries (e.g. ndpiReader)
    will fail to link — but that's harmless.  ``make -k || true`` lets the
    build continue past those failures, and the fuzz-target existence
    check ensures we catch real compilation errors.
    """
    content = _patch_build_sh_for_project(content, project)
    lines = content.splitlines(keepends=True)
    patched: list[str] = []
    for line in lines:
        stripped = line.strip()
        # Match bare "make" or "make -jN" / "make -j$(nproc)" but not
        # "make install", "make -C subdir", "make clean", etc.
        if re.match(r'^make\s*(-j\S*)?\s*$', stripped):
            indent = line[:len(line) - len(line.lstrip())]
            patched.append(f"{indent}{stripped} -k 2>&1 || true\n")
        else:
            patched.append(line)
    return "".join(patched)


def _save_build_sh(container: str, output_dir: Path, project: str) -> None:
    """Snapshot /src/build.sh so it can be restored on resume.

    The agent may modify /src/build.sh to compile __bug_dispatch.c, but
    that file lives outside the project git repo and isn't captured by
    ``git diff``.  We save it alongside harness.diff.
    """
    ret, content = _exec_capture(container, "cat /src/build.sh 2>/dev/null")
    if ret != 0:
        return
    content = _patch_build_sh_make_tolerant(content, project)
    dst = output_dir / "harness_build.sh"
    dst.write_text(content)
    logger.info("Saved /src/build.sh (%d bytes) to %s", len(content), dst)


def _restore_build_sh(container: str, output_dir: Path, project: str) -> None:
    """Restore a previously saved /src/build.sh into the container."""
    src = output_dir / "harness_build.sh"
    if not src.exists():
        return
    content = _patch_build_sh_make_tolerant(src.read_text(errors='replace'), project)
    _exec_capture(
        container,
        f"cat > /src/build.sh << 'BUILDEOF'\n{content}BUILDEOF",
    )
    _exec_capture(container, "chmod +x /src/build.sh")
    logger.info("Restored /src/build.sh from %s", src)


def _candidate_fuzzer_source_paths(project: str, fuzzer: str) -> list[str]:
    """Return likely OSS-Fuzz harness source paths for a fuzzer."""
    exts = ("cc", "cpp", "cxx", "c")
    roots = ["/src", _source_dir(project), f"/src/{project}"]
    paths: list[str] = known_harness_source_paths(project, fuzzer)
    for root in roots:
        for ext in exts:
            paths.append(f"{root}/{fuzzer}.{ext}")
    return list(dict.fromkeys(paths))


def _find_harness_source_paths(
    container: str,
    project: str,
    fuzzer: str,
) -> list[str]:
    """Find existing harness source files for the primary fuzzer."""
    candidates = " ".join(
        shlex.quote(path) for path in _candidate_fuzzer_source_paths(project, fuzzer)
    )
    # Trailing `; true` so the loop's RC is always 0 — a non-existent
    # last candidate would otherwise short-circuit the `&&` chain and
    # make us discard valid output from earlier iterations.
    ret, out = _exec_capture(
        container,
        "for p in "
        f"{candidates}"
        "; do [ -f \"$p\" ] && grep -q 'LLVMFuzzerTestOneInput' \"$p\" "
        "&& printf '%s\n' \"$p\"; done; true",
    )
    paths = [line.strip() for line in out.splitlines() if line.strip()] if ret == 0 else []
    if paths:
        return list(dict.fromkeys(paths))

    # maxdepth 6: opensc's harnesses live at
    # /src/opensc/src/tests/fuzzing/<fuzzer>.c, four levels below the source
    # dir. A shallower sweep silently finds nothing, and every caller then
    # concludes the harness does not consume dispatch bytes.
    ret, out = _exec_capture(
        container,
        f"find /src {_source_dir(project)} -maxdepth 6 -type f "
        f"\\( -name {shlex.quote(fuzzer + '.cc')} "
        f"-o -name {shlex.quote(fuzzer + '.cpp')} "
        f"-o -name {shlex.quote(fuzzer + '.cxx')} "
        f"-o -name {shlex.quote(fuzzer + '.c')} \\) "
        "-exec grep -l 'LLVMFuzzerTestOneInput' {} \\; 2>/dev/null",
    )
    paths = list(dict.fromkeys(line.strip() for line in out.splitlines() if line.strip()))
    if paths:
        return paths

    # Last resort: the harness file may not be named after the fuzzer binary
    # at all. Take any fuzz source under the tree that defines the entrypoint.
    ret, out = _exec_capture(
        container,
        f"grep -rl --include='*.c' --include='*.cc' --include='*.cpp' "
        f"--include='*.cxx' 'LLVMFuzzerTestOneInput' /src {_source_dir(project)} "
        "2>/dev/null",
    )
    return list(dict.fromkeys(line.strip() for line in out.splitlines() if line.strip()))


def _harness_source_sets_dispatch(
    container: str,
    source_path: str,
) -> bool:
    """Return True when a harness source copies input bytes into __bug_dispatch."""
    qpath = shlex.quote(source_path)
    ret, _ = _exec_capture(
        container,
        "grep -q 'LLVMFuzzerTestOneInput' "
        f"{qpath} && grep -q '__bug_dispatch' {qpath} && "
        "grep -Eq 'memcpy[[:space:]]*\\([^;]*__bug_dispatch|"
        "__bug_dispatch\\[[^]]+\\][[:space:]]*=' "
        f"{qpath}",
    )
    return ret == 0


def _harness_dispatch_consumer_present(
    container: str,
    project: str,
    fuzzer: str,
) -> bool:
    """Return True if the primary fuzzer consumes dispatch bytes.

    When no harness source can be located at all the check has nothing to
    inspect; say so and pass, rather than reporting the agent's work as
    missing. The nm-level check in _modify_harness_for_dispatch still
    guarantees __bug_dispatch is linked into the fuzzer.
    """
    paths = _find_harness_source_paths(container, project, fuzzer)
    if not paths:
        logger.warning(
            "No harness source located for %s; skipping the source-level "
            "dispatch-consumer check (register the path in "
            "_HARNESS_SOURCE_TEMPLATES to restore it)",
            fuzzer,
        )
        return True
    return any(_harness_source_sets_dispatch(container, path) for path in paths)


def _harness_sources_dir(output_dir: Path) -> Path:
    return output_dir / "harness_sources"


def _harness_sources_manifest(output_dir: Path) -> Path:
    return _harness_sources_dir(output_dir) / "manifest.json"


def _snapshot_name(container_path: str) -> str:
    return container_path.strip("/").replace("/", "__")


def _save_harness_sources(
    container: str,
    project: str,
    fuzzer: str,
    output_dir: Path,
) -> bool:
    """Save out-of-repo harness sources that git diff cannot capture."""
    snapshot_dir = _harness_sources_dir(output_dir)
    snapshot_dir.mkdir(exist_ok=True)
    manifest = []

    for source_path in _find_harness_source_paths(container, project, fuzzer):
        if not _harness_source_sets_dispatch(container, source_path):
            continue
        ret, content = _exec_capture(container, f"cat {shlex.quote(source_path)}")
        if ret != 0:
            continue
        snapshot = _snapshot_name(source_path)
        (snapshot_dir / snapshot).write_text(content)
        manifest.append({"container_path": source_path, "snapshot": snapshot})

    if not manifest:
        logger.warning("No dispatch-consuming harness source snapshot saved")
        return False

    _harness_sources_manifest(output_dir).write_text(json.dumps(manifest, indent=2))
    logger.info("Saved %d harness source snapshot(s) to %s", len(manifest), snapshot_dir)
    return True


def _restore_harness_sources(container: str, output_dir: Path) -> bool:
    """Restore saved out-of-repo harness sources into a fresh container."""
    manifest_path = _harness_sources_manifest(output_dir)
    if not manifest_path.exists():
        return False

    restored = 0
    for entry in json.loads(manifest_path.read_text()):
        container_path = entry["container_path"]
        snapshot = _harness_sources_dir(output_dir) / entry["snapshot"]
        if not snapshot.exists():
            continue
        if _container_write_text(container, container_path, snapshot.read_text(errors='replace')):
            restored += 1

    if restored:
        logger.info("Restored %d harness source snapshot(s)", restored)
    return restored > 0


def _inject_dispatch_deps_fixer(container: str) -> None:
    """Inject a helper script + build.sh hook that creates autotools dep stubs.

    When Makefile.am references $(top_srcdir)/__bug_dispatch.c, autotools
    generates ``include .deps/<prefix>__bug_dispatch.P{o,lo}`` but never
    creates the top-level ``.deps/`` directory.  This writes a helper that
    scans generated Makefiles for those targets and touches them, then
    injects a one-line call in build.sh right before ``make``.
    """
    _exec_capture(
        container,
        "cat > /tmp/_fix_dispatch_deps.sh << 'FIXEOF'\n"
        "#!/bin/bash\n"
        "mkdir -p .deps\n"
        "grep -rh '__bug_dispatch.*\\.Pl\\|__bug_dispatch.*\\.Po' "
        "  */Makefile */*/Makefile */*/*/Makefile 2>/dev/null | "
        "grep -oE '[^ ]*__bug_dispatch[^ ]*' | sort -u | "
        "while read p; do mkdir -p $(dirname \"$p\") && touch \"$p\"; done\n"
        "FIXEOF\n"
        "chmod +x /tmp/_fix_dispatch_deps.sh",
    )
    _exec_capture(
        container,
        "grep -q '_fix_dispatch_deps' /src/build.sh 2>/dev/null || "
        "sed -i '/^make/i /tmp/_fix_dispatch_deps.sh' /src/build.sh",
    )


_MAKEFILE_SOURCES_RE = re.compile(r"^\s*[\w@.-]+_SOURCES\s*(?:\+?=|:=)")


def _container_write_text(container: str, path: str, content: str) -> bool:
    """Write text into a file inside the running container."""
    result = subprocess.run(
        ["docker", "exec", "-i", container, "bash", "-c", f"cat > {shlex.quote(path)}"],
        input=content.encode("utf-8"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    if result.returncode == 0:
        return True
    logger.warning(
        "Failed to write %s inside %s: %s",
        path, container, result.stderr.decode("utf-8", errors="replace")[-200:],
    )
    return False


def _iter_makefile_source_blocks(lines: list[str]) -> list[tuple[int, int]]:
    """Return inclusive line ranges for ``*_SOURCES`` assignments."""
    blocks: list[tuple[int, int]] = []
    i = 0
    while i < len(lines):
        if not _MAKEFILE_SOURCES_RE.match(lines[i]):
            i += 1
            continue
        start = i
        while lines[i].rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
        blocks.append((start, i))
        i += 1
    return blocks


def _patch_makefile_dispatch_source(
    content: str,
    source_markers: set[str],
) -> tuple[str, bool]:
    """Add ``$(top_srcdir)/__bug_dispatch.c`` to matching Makefile blocks."""
    lines = content.splitlines()
    changed = False

    for marker in sorted(source_markers):
        marker_name = PurePosixPath(marker).name
        for start, end in _iter_makefile_source_blocks(lines):
            block = lines[start:end + 1]
            block_text = "\n".join(block)
            if "__bug_dispatch.c" in block_text:
                if marker in block_text or marker_name in block_text:
                    break
                continue
            if marker not in block_text and marker_name not in block_text:
                continue

            if start == end and not lines[end].rstrip().endswith("\\"):
                lines[start] = f"{lines[start]} $(top_srcdir)/__bug_dispatch.c"
            else:
                if not lines[end].rstrip().endswith("\\"):
                    lines[end] = f"{lines[end]} \\"
                lines.insert(end + 1, "\t$(top_srcdir)/__bug_dispatch.c")
            changed = True
            break

    new_content = "\n".join(lines)
    if content.endswith("\n"):
        new_content += "\n"
    return new_content, changed


def _ensure_dispatch_linked_everywhere(container: str, project: str) -> None:
    """Ensure __bug_dispatch.c is compiled into libraries, not just fuzzers.

    Per-bug patches may add ``#include "__bug_dispatch.h"`` to library
    source files (e.g. libopensc).  Non-fuzzer tools that link the
    library will fail with undefined ``__bug_dispatch`` unless the
    object is also part of the library.  This function finds every
    Makefile.am that builds a library whose sources were patched and
    adds __bug_dispatch.c to it.
    """
    # Find all source files that reference __bug_dispatch after wrapping.
    ret, out = _exec_capture(
        container,
        f"cd {_source_dir(project)} && "
        "git grep -l '__bug_dispatch' -- '*.c' '*.cc' '*.cpp' '*.cxx' "
        "':(exclude)__bug_dispatch.c' 2>/dev/null",
    )
    if ret != 0 or not out.strip():
        return

    repo_root = PurePosixPath(_source_dir(project))
    makefile_cache: dict[str, str] = {}
    makefile_sources: dict[str, set[str]] = {}

    for rel_source in out.strip().splitlines():
        rel_source = rel_source.strip()
        if not rel_source:
            continue

        source_path = PurePosixPath(rel_source)
        for parent in source_path.parents:
            makefile_rel = (
                PurePosixPath("Makefile.am")
                if str(parent) == "."
                else parent / "Makefile.am"
            )
            makefile_rel_str = makefile_rel.as_posix()
            makefile_abs = (repo_root / makefile_rel).as_posix()
            if makefile_rel_str not in makefile_cache:
                ret2, makefile = _exec_capture(
                    container,
                    f"cat {shlex.quote(makefile_abs)} 2>/dev/null",
                )
                if ret2 != 0:
                    continue
                makefile_cache[makefile_rel_str] = makefile
            makefile = makefile_cache[makefile_rel_str]
            if "_SOURCES" not in makefile:
                continue

            parent_dir = "." if str(parent) == "." else parent.as_posix()
            rel_from_makefile = posixpath.relpath(source_path.as_posix(), parent_dir)
            if rel_from_makefile not in makefile and source_path.name not in makefile:
                continue

            makefile_sources.setdefault(makefile_rel_str, set()).add(rel_from_makefile)
            break

    for makefile_rel, source_markers in sorted(makefile_sources.items()):
        updated, changed = _patch_makefile_dispatch_source(
            makefile_cache[makefile_rel],
            source_markers,
        )
        if not changed:
            continue
        makefile_abs = (repo_root / PurePosixPath(makefile_rel)).as_posix()
        if _container_write_text(container, makefile_abs, updated):
            logger.info("Added __bug_dispatch.c to %s", makefile_rel)

    _inject_dispatch_deps_fixer(container)


# build_codex_command is now imported from bug_transplant


# ---------------------------------------------------------------------------
# Bug loading and categorization
# ---------------------------------------------------------------------------

_OSV_ID_RE = re.compile(r"^OSV-(\d+)-(\d+)$")


def _bug_id_sort_key(bug: dict) -> tuple[int, int, str]:
    """Sort OSV IDs numerically so dispatch bit assignment is stable."""
    bug_id = bug.get("bug_id", "")
    match = _OSV_ID_RE.match(bug_id)
    if not match:
        return (sys.maxsize, sys.maxsize, bug_id)
    return (int(match.group(1)), int(match.group(2)), bug_id)


def load_and_categorize_bugs(
    summary_path: str,
    bug_info_path: str,
    project: str,
    local_bug_overrides: list[str] | None = None,
    testcases_dir: str | None = None,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Load bugs and split into local, testcase-only, and diff bugs.

    This always returns EVERY bug, even when ``--only-bugs`` narrows the run.
    Dispatch slots are assigned from this list, and a slot depends on the
    total bug count, so filtering here would renumber every other bug and
    invalidate their already-wrapped diffs. ``--only-bugs`` is applied later,
    to the wrap loop alone.

    Returns (local_bugs, testcase_only_bugs, diff_bugs).
    """
    with open(summary_path) as f:
        summary = json.load(f)
    with open(bug_info_path) as f:
        bug_info_dataset = json.load(f)

    target_commit = summary["target_commit"]
    bug_transplant_dir = DATA_DIR / "bug_transplant"

    # --- Local bugs (already trigger at target) ---
    local_bug_ids = set(local_bug_overrides or summary.get("bugs_already_trigger_ids", []))
    local_bugs = []
    for bid in local_bug_ids:
        info = bug_info_dataset.get(bid, {})
        reproduce = info.get("reproduce", {})
        fuzzer = reproduce.get("fuzz_target", "")
        sanitizer = reproduce.get("sanitizer", "address").split(" ")[0]
        if not fuzzer:
            continue
        crash_log = _find_crash_log(bid, info)
        local_bugs.append({
            "bug_id": bid,
            "fuzzer": fuzzer,
            "testcase": f"testcase-{bid}",
            "sanitizer": sanitizer,
            "crash_log": crash_log,
            "type": "local",
        })

    # --- Transplanted bugs ---
    testcase_only_bugs = []
    diff_bugs = []
    seen = set(local_bug_ids)

    for result in summary.get("results", []):
        bid = result.get("bug_id", "")
        if not bid or bid in seen:
            continue
        if result.get("status") not in (None, "success"):
            continue

        out_dir = bug_transplant_dir / f"{project}_{bid}"
        if not out_dir.exists():
            continue

        # Skip impossible
        if (out_dir / "bug_transplant.impossible").exists():
            logger.info("Skipping %s: declared impossible", bid)
            continue

        # Find diff
        diff_path = None
        for name in ("bug_transplant.diff", "git_diff.diff"):
            p = out_dir / name
            if p.exists():
                diff_path = str(p)
                break

        has_diff = diff_path and Path(diff_path).stat().st_size > 0

        # Find patched testcase
        patched_testcase = None
        for tc in out_dir.glob(f"testcase-{bid}*"):
            if tc.is_file() and tc.stat().st_size > 0:
                patched_testcase = str(tc)
                break

        if not has_diff and not patched_testcase:
            continue

        info = bug_info_dataset.get(bid, {})
        reproduce = info.get("reproduce", {})
        fuzzer = reproduce.get("fuzz_target", "")
        sanitizer = reproduce.get("sanitizer", "address").split(" ")[0]
        if sanitizer != "address":
            # Every build path in the pipeline pins SANITIZER=address, and
            # the triage code drops UBSan-typed classes as "not part of the
            # oracle". Admitting a non-ASAN bug here only carried it into the
            # merge to be verified against a binary that cannot report it.
            logger.info("[%s] skipping: sanitizer=%s, merge builds ASAN only",
                        bid, sanitizer)
            continue
        if not fuzzer:
            continue

        crash_log = _find_crash_log(bid, info)
        seen.add(bid)

        entry = {
            "bug_id": bid,
            "diff_path": diff_path if has_diff else None,
            "patched_testcase": patched_testcase,
            "fuzzer": fuzzer,
            "testcase": f"testcase-{bid}",
            "sanitizer": sanitizer,
            "crash_log": crash_log,
            "type": "transplant",
        }

        if has_diff:
            diff_bugs.append(entry)
        else:
            testcase_only_bugs.append(entry)

    # Also scan disk for bug dirs not in summary
    for d in bug_transplant_dir.iterdir():
        if not d.is_dir() or not d.name.startswith(f"{project}_"):
            continue
        bid = d.name[len(f"{project}_"):]
        if bid in seen:
            continue
        if (d / "bug_transplant.impossible").exists():
            continue

        diff_path = None
        for name in ("bug_transplant.diff", "git_diff.diff"):
            p = d / name
            if p.exists():
                diff_path = str(p)
                break
        has_diff = diff_path and Path(diff_path).stat().st_size > 0

        patched_testcase = None
        for tc in d.glob(f"testcase-{bid}*"):
            if tc.is_file() and tc.stat().st_size > 0:
                patched_testcase = str(tc)
                break

        if not has_diff and not patched_testcase:
            continue

        info = bug_info_dataset.get(bid, {})
        reproduce = info.get("reproduce", {})
        fuzzer = reproduce.get("fuzz_target", "")
        sanitizer = reproduce.get("sanitizer", "address").split(" ")[0]
        if sanitizer != "address":
            logger.info("[%s] skipping: sanitizer=%s, merge builds ASAN only",
                        bid, sanitizer)
            continue
        if not fuzzer:
            continue

        crash_log = _find_crash_log(bid, info)
        seen.add(bid)

        entry = {
            "bug_id": bid,
            "diff_path": diff_path if has_diff else None,
            "patched_testcase": patched_testcase,
            "fuzzer": fuzzer,
            "testcase": f"testcase-{bid}",
            "sanitizer": sanitizer,
            "crash_log": crash_log,
            "type": "transplant",
        }
        if has_diff:
            diff_bugs.append(entry)
        else:
            testcase_only_bugs.append(entry)

    local_bugs.sort(key=_bug_id_sort_key)
    testcase_only_bugs.sort(key=_bug_id_sort_key)
    diff_bugs.sort(key=_bug_id_sort_key)
    return local_bugs, testcase_only_bugs, diff_bugs


# ---------------------------------------------------------------------------
# Dispatch bit assignment
# ---------------------------------------------------------------------------

def assign_dispatch_bits(
    diff_bugs: list[dict],
    local_bugs: list[dict],
    testcase_only_bugs: list[dict],
) -> dict:
    """Assign an exclusive dispatch slot to every bug with a diff.

    The prefix bytes are one little-endian selector. Dividing it by the slice
    width picks exactly one slot, so at most one bug is ever live in a run --
    unlike the old bitmask, where independent bits let one bug's patch shadow
    another's and left a crashing input ambiguous between several bugs.

    Slot 0 is reserved for "no bug" and is what seeds, local bugs and
    testcase-only bugs carry. N bugs therefore need N+1 slots. The value space
    is split evenly, so each bug owns ``slice`` consecutive values and is
    selected by roughly 1/(N+1) of random prefixes. Byte count grows
    automatically once the bug count exceeds what one byte can distinguish.

    A bug's PoC gets the middle of its slice, so an off-by-one in any
    downstream encoder still lands inside the right slot.
    """
    slots = len(diff_bugs) + 1  # slot 0 == no bug

    # Smallest prefix that gives every slot at least one distinct value.
    dispatch_bytes = 1
    while (1 << (8 * dispatch_bytes)) < slots:
        dispatch_bytes += 1

    space = 1 << (8 * dispatch_bytes)
    dispatch_slice = space // slots  # >= 1 by construction

    poc_bytes: dict[str, int] = {}
    bits = {}
    for i, bug in enumerate(diff_bugs):
        slot = i + 1  # slot 0 stays reserved
        bits[slot] = {"bug_id": bug["bug_id"]}
        poc_bytes[bug["bug_id"]] = slot * dispatch_slice + dispatch_slice // 2

    # Local + testcase-only bugs are native at the target: slot 0, no gating.
    for bug in local_bugs + testcase_only_bugs:
        poc_bytes[bug["bug_id"]] = 0

    return {
        "next_bit": slots,
        "dispatch_bytes": dispatch_bytes,
        "dispatch_slots": slots,
        "dispatch_slice": dispatch_slice,
        "bits": bits,
        "poc_bytes": poc_bytes,
        "harness_modified": False,
        "dispatch_file_injected": False,
    }


# ---------------------------------------------------------------------------
# Per-bug offline wrapping
# ---------------------------------------------------------------------------

def wrap_bug_with_dispatch(
    container: str,
    project: str,
    bug: dict,
    bit_index: int,
    dispatch_state: dict,
    model: str | None = None,
    codex_mode: str = "exec",
    log_dir: Path | None = None,
    attempt: int = 0,
) -> tuple[bool, str]:
    """Invoke codex to wrap a bug's patch with dispatch gating.

    Returns (success, output).
    """
    bug_id = bug["bug_id"]
    diff_path = bug["diff_path"]
    # bit_index is now the exclusive slot number (1..N; slot 0 = no bug).
    dispatch_slot = bit_index
    dispatch_value = dispatch_state["poc_bytes"][bug_id]

    # Copy diff into container via stdin (heredoc-inlining would blow past
    # ARG_MAX for multi-MB diffs).
    diff_bytes = Path(diff_path).read_bytes()
    subprocess.run(
        ["docker", "exec", "-i", container,
         "bash", "-c", f"cat > /tmp/patch_{bug_id}.diff"],
        input=diff_bytes, timeout=60,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    # Copy testcase (patched if available, else original)
    ptc = bug.get("patched_testcase")
    if ptc and Path(ptc).exists():
        tc_data = Path(ptc).read_bytes()
        subprocess.run(
            ["docker", "exec", "-i", container,
             "bash", "-c", f"cat > /work/{bug['testcase']}"],
            input=tc_data, timeout=10,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    # Setup codex credentials
    setup_codex_creds(container)

    prompt = _load_prompt(
        "dispatch_wrap_offline",
        project=project,
        bug_id=bug_id,
        dispatch_slot=str(dispatch_slot),
        dispatch_value=str(dispatch_value),
        dispatch_nbytes=str(dispatch_state.get("dispatch_bytes", 1)),
        # Hand the agent the verifier's own memory cap. Without it the agent
        # self-checks under libFuzzer's 2048MB default, reports an
        # out-of-memory as a successful trigger, and the wrap then fails
        # verification at ~40 min a time.
        dispatch_rss_limit_mb=str(_RSS_LIMIT_MB),
        fuzzer=bug.get("fuzzer", ""),
        patch_path=f"/tmp/patch_{bug_id}.diff",
        testcase_path=f"/work/{bug['testcase']}",
        output_testcase_path=f"/work/{bug['testcase']}",
    )

    agent_cmd = build_codex_command(prompt, model, mode=codex_mode)

    # Persist the prompt to the host. The container is destroyed at the end of
    # the merge, so anything left only inside it is unrecoverable when a wrap
    # fails -- which is exactly when it is needed.
    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / f"{bug_id}_attempt{attempt}.prompt.md").write_text(prompt)

    logger.info("[%s] Invoking %s for dispatch wrapping (slot %d)...",
                bug_id, active_agent(), bit_index)
    if codex_mode == "interactive":
        ret, output = _exec_interactive(container, agent_cmd, timeout=1800)
    else:
        ret, output = _exec_capture(container, agent_cmd, timeout=1800)

    _usage_tracker.log_usage(f"{bug_id} wrap", output, model)

    if log_dir is not None:
        stem = log_dir / f"{bug_id}_attempt{attempt}"
        stem.with_suffix(".jsonl").write_text(output or "")
        try:
            stem.with_suffix(".txt").write_text(_format_codex_output(output or ""))
        except Exception:  # formatter is best-effort; raw output is the record
            pass

    if ret != 0:
        logger.error("[%s] Agent failed (exit %d)", bug_id, ret)
        return False, output

    # Verify build — clear /out/ fuzz targets first so we only see freshly built binaries.
    fuzzer_name = bug.get("fuzzer", "")
    # Remove known fuzz targets so we can verify they get rebuilt.
    _exec_capture(container, "rm -f /out/fuzz_* /out/*_fuzzer /out/*_fuzzer_* 2>/dev/null")
    ret, build_out = _exec_capture(container, _compile_cmd(container), timeout=1800)
    # Check for the specific fuzzer binary, or fall back to any *fuzzer* pattern.
    if fuzzer_name:
        ret2, fuzz_bins = _exec_capture(container, f"ls /out/{fuzzer_name} 2>/dev/null")
    else:
        ret2, fuzz_bins = _exec_capture(container, "ls /out/fuzz_* /out/*_fuzzer 2>/dev/null")
    if ret2 != 0 or not fuzz_bins.strip():
        # Fuzz targets didn't build — real failure.
        logger.error("[%s] Build failed after wrapping (fuzz targets missing)",
                     bug_id)
        # A 1000-char tail routinely ends *after* the compiler error, leaving
        # the failure undiagnosable once the container is gone (OSV-2023-566
        # failed twice with no error recorded anywhere). Save the whole log and
        # surface the error lines specifically.
        err_lines = [
            ln for ln in (build_out or "").splitlines()
            if re.search(r"\berror:|\bfatal error\b|undefined reference|No rule to make",
                         ln)
        ]
        if err_lines:
            logger.error("[%s] Build errors:\n  %s",
                         bug_id, "\n  ".join(err_lines[:15]))
        else:
            logger.error("[%s] Build tail: %s",
                         bug_id, build_out[-1000:] if build_out else "(no output)")
        try:
            log_dir = _wrap_log_dir_for(bug_id)
            if log_dir is not None:
                log_dir.mkdir(parents=True, exist_ok=True)
                fp = log_dir / f"{bug_id}_build_failed.log"
                fp.write_text(build_out or "")
                logger.error("[%s] Full build log: %s", bug_id, fp)
        except Exception as exc:  # diagnostics must never mask the failure
            logger.warning("[%s] Could not save build log: %s", bug_id, exc)
        return False, build_out
    if ret != 0:
        logger.warning("[%s] Compile had errors but fuzz targets built OK", bug_id)

    if not _verify_wrapped_dispatch(container, bug, bit_index, dispatch_state):
        logger.error("[%s] Wrapped patch failed dispatch verification", bug_id)
        return False, output

    logger.info("[%s] Dispatch wrapping OK "
                "(slot %d triggers, slot 0 does not)", bug_id, bit_index)
    return True, output


def _verify_wrapped_dispatch(
    container: str,
    bug: dict,
    bit_index: int,
    dispatch_state: dict,
) -> bool:
    """Run the freshly built fuzzer with bit-on / bit-off and check trigger asymmetry.

    Uses ``verify_bug_triggers`` (the same stack-matching + retry logic
    applied at final verification) so a wrap cannot pass on an
    unrelated sanitizer SUMMARY or a single flaky crash.

    Returns True iff:
      * bit-on triggers the bug under one of the two ASAN variants
        (stack match against the reference crash log when available,
        sanitizer SUMMARY otherwise), AND
      * bit-off does NOT trigger any crash across the same 10 attempts
        per variant.

    Skips with warning (returns True) when no payload is available.
    """
    bug_id = bug["bug_id"]
    fuzzer = bug.get("fuzzer", "")
    if not fuzzer:
        logger.warning("[%s] No fuzzer name; skipping dispatch verification", bug_id)
        return True

    ptc = bug.get("patched_testcase")
    if not ptc or not Path(ptc).is_file():
        logger.warning("[%s] No payload available; skipping dispatch verification", bug_id)
        return True
    payload = Path(ptc).read_bytes()

    nbytes = dispatch_state.get("dispatch_bytes", 1)
    # Exclusive dispatch: the "on" selector is this bug's slot value, not a
    # bit. Using `1 << slot` here selected some other slot entirely (slot 1
    # became selector 2, which floor-divides back to slot 0 = no bug), so a
    # correctly wrapped patch verified as non-triggering.
    selector_on = dispatch_state["poc_bytes"].get(bug_id)
    if selector_on is None:
        dslice = dispatch_state.get("dispatch_slice", 1)
        selector_on = bit_index * dslice + dslice // 2
    prefix_on = selector_on.to_bytes(nbytes, "little")
    prefix_off = b"\x00" * nbytes

    on_name = f"_verify_{bug_id}_on"
    off_name = f"_verify_{bug_id}_off"
    for name, blob in ((on_name, prefix_on + payload), (off_name, prefix_off + payload)):
        proc = subprocess.run(
            ["docker", "exec", "-i", container, "bash", "-c", f"cat > /work/{name}"],
            input=blob, timeout=10,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False,
        )
        if proc.returncode != 0:
            logger.warning("[%s] Failed to stage verify input (%s)", bug_id, name)
            return False

    sanitizer = bug.get("sanitizer", "address") or "address"
    crash_log = bug.get("crash_log")
    fuzzer_path = f"/out/{fuzzer}"

    # bit-on: must trigger the *reference* bug (not just any SUMMARY).
    bit_on_ok = verify_bug_triggers(
        container, bug_id, fuzzer, on_name, sanitizer, crash_log,
        fuzzer_path=fuzzer_path,
    )
    if not bit_on_ok:
        logger.warning(
            "[%s] Dispatch verification FAIL: bit-on did not reproduce the "
            "reference bug after 10 attempts x 2 ASAN variants",
            bug_id,
        )
        return False

    # bit-off: must NOT crash (quiet: we expect a non-trigger, so the
    # usual "Bug does NOT trigger" warning is the success path).
    bit_off_crash = verify_bug_triggers(
        container, bug_id, fuzzer, off_name, sanitizer, crash_log,
        fuzzer_path=fuzzer_path, quiet=True,
    )
    if bit_off_crash:
        logger.warning(
            "[%s] Dispatch verification FAIL: bit-off also triggered a crash "
            "(gating is not exclusive)",
            bug_id,
        )
        return False

    return True


# ---------------------------------------------------------------------------
# Main merge logic
# ---------------------------------------------------------------------------

def run_offline_merge(args: argparse.Namespace) -> int:
    """Run the full offline dispatch merge pipeline."""
    with open(args.summary) as f:
        summary = json.load(f)
    target_commit = args.target_commit or summary["target_commit"]
    project = args.target

    # Output directory
    output_dir = DATA_DIR / "bug_transplant" / f"merge_offline_{project}_{target_commit[:8]}"
    output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # 1. Load and categorize bugs
    # ------------------------------------------------------------------
    local_bugs, testcase_only_bugs, diff_bugs = load_and_categorize_bugs(
        args.summary, args.bug_info, project,
        local_bug_overrides=args.local_bugs,
        testcases_dir=args.testcases_dir,
    )

    logger.info("Local bugs: %d", len(local_bugs))
    logger.info("Testcase-only bugs: %d", len(testcase_only_bugs))
    logger.info("Bugs with diffs (need dispatch): %d", len(diff_bugs))

    all_bugs = local_bugs + testcase_only_bugs + diff_bugs
    if not all_bugs:
        logger.error("No bugs to merge")
        return 1
    primary_fuzzer = (diff_bugs + testcase_only_bugs + local_bugs)[0]["fuzzer"]
    testcase_stage_dir = _prepare_container_testcases_dir(
        args.testcases_dir,
        output_dir / "testcases",
        testcase_names=[bug["testcase"] for bug in all_bugs],
    )

    # ------------------------------------------------------------------
    # 2. Assign dispatch bits
    # ------------------------------------------------------------------
    # Incremental merge: if a prior run recorded a dispatch order, keep those
    # bugs at their original bit positions (so their wrapped diffs stay valid)
    # and append any newly-added diff bugs at the end. Without this, inserting
    # one bug shifts every later bug's bit and forces re-wrapping all of them.
    _incremental_added: list[str] = []
    _recorded_order = None
    _dorder_path = output_dir / "dispatch_order.json"
    if _dorder_path.exists():
        try:
            _recorded_order = json.loads(_dorder_path.read_text())
        except Exception:
            _recorded_order = None
    if _recorded_order:
        _by_id = {b["bug_id"]: b for b in diff_bugs}
        _recorded_set = set(_recorded_order)
        kept = [_by_id[n] for n in _recorded_order if n in _by_id]
        appended = [b for b in diff_bugs if b["bug_id"] not in _recorded_set]
        # Only reorder when the recorded bugs are still all present (kept count
        # matches); otherwise fall back to default order + full re-wrap.
        if len(kept) == len([n for n in _recorded_order if n in _by_id]) and (kept or appended):
            diff_bugs = kept + appended
            _incremental_added = [b["bug_id"] for b in appended]
            if _incremental_added:
                logger.info(
                    "Incremental merge: preserving %d recorded dispatch bits, "
                    "appending %d new bug(s): %s",
                    len(kept), len(_incremental_added),
                    ", ".join(_incremental_added),
                )

    dispatch_state = assign_dispatch_bits(diff_bugs, local_bugs, testcase_only_bugs)
    logger.info(
        "Exclusive dispatch: %d slots (slot 0 = no bug), %d byte(s), "
        "slice=%d values/slot",
        dispatch_state["dispatch_slots"], dispatch_state["dispatch_bytes"],
        dispatch_state["dispatch_slice"],
    )

    for slot in sorted(dispatch_state["bits"]):
        bug_id = dispatch_state["bits"][slot]["bug_id"]
        value = dispatch_state["poc_bytes"][bug_id]
        logger.info("  slot %d → %s (selector value %d, range %d-%d)",
                    slot, bug_id, value,
                    slot * dispatch_state["dispatch_slice"],
                    (slot + 1) * dispatch_state["dispatch_slice"] - 1)

    dispatch_order = [
        dispatch_state["bits"][i]["bug_id"]
        for i in sorted(dispatch_state["bits"])
    ]
    dispatch_order_path = output_dir / "dispatch_order.json"
    reuse_wrapped_cache = False
    dispatch_order_unchanged = False
    if dispatch_order_path.exists():
        try:
            recorded = json.loads(dispatch_order_path.read_text())
            dispatch_order_unchanged = (recorded == dispatch_order)
            # Reuse wraps when the recorded order is unchanged, OR is a prefix
            # of the new order (incremental add: recorded bugs keep their bits,
            # new bugs appended at the end). The per-bug reuse loop only loads
            # wraps that exist on disk, so appended bugs still get wrapped.
            reuse_wrapped_cache = (
                dispatch_order_unchanged
                or dispatch_order[: len(recorded)] == recorded
            )
        except Exception:
            reuse_wrapped_cache = False
            dispatch_order_unchanged = False
    if not reuse_wrapped_cache:
        logger.info(
            "Dispatch order changed or not recorded; regenerating wrapped diffs"
        )
    elif not dispatch_order_unchanged:
        logger.info(
            "Incremental merge: reusing %d cached wraps, wrapping only new bug(s)",
            len(json.loads(dispatch_order_path.read_text())),
        )

    if args.dry_run:
        logger.info("Dry run — exiting")
        return 0

    # ------------------------------------------------------------------
    # 3. Start container
    # ------------------------------------------------------------------
    container, build_ok = start_merge_container(
        project, target_commit,
        testcases_dir=str(testcase_stage_dir),
        build_csv=args.build_csv,
        extra_volumes=args.volume,
    )
    if not build_ok:
        logger.error("Container startup / initial build failed")
        return 1

    try:
        # ------------------------------------------------------------------
        # 4. Inject dispatch files and modify harness
        # ------------------------------------------------------------------
        # If we already have a harness diff from a previous run, reuse it.
        # This avoids re-invoking a code agent unnecessarily and keeps resume
        # behavior deterministic.
        harness_diff_path = output_dir / "harness.diff"
        if getattr(args, "regenerate_harness", False):
            logger.info("Ignoring existing harness artifacts because --regenerate-harness was set")
            harness_diff_path = None
        elif harness_diff_path.exists() and harness_diff_path.stat().st_size > 0:
            logger.info("Harness diff already exists, reusing: %s", harness_diff_path)
            _clean_container_working_tree_before_harness_diff(container, project)
            # Use docker cp instead of heredoc to avoid "Argument list too long"
            # for large diffs (e.g. ghostscript's 56MB harness diff).
            subprocess.run(
                ["docker", "cp", str(harness_diff_path), f"{container}:/tmp/harness.diff"],
                check=True, timeout=30,
            )
            ret, out = _exec_capture(container,
                                     f"cd {_source_dir(project)} && git apply /tmp/harness.diff 2>&1")
            if ret != 0:
                logger.error("Failed to apply existing harness.diff")
                logger.error(out)
                return 1
            _restore_build_sh(container, output_dir, project)
            _restore_harness_sources(container, output_dir)
            # If harness_build.sh was lost, re-save from container state.
            if not (output_dir / "harness_build.sh").exists():
                _save_build_sh(container, output_dir, project)
            # The harness diff references the global __bug_dispatch[] symbol,
            # but the .c/.h that defines it live outside git and weren't
            # restored above. Inject them before the dispatch-deps Makefile
            # fixer / build, otherwise the link fails with
            # "undefined reference to __bug_dispatch".
            _inject_dispatch_files(
                container, project, dispatch_state["dispatch_bytes"],
                dispatch_state.get("dispatch_slots", 2),
                dispatch_state.get("dispatch_slice", 1),
            )
            _inject_dispatch_deps_fixer(container)
            # ntopng's hand-written fuzz Makefile doesn't pick up __bug_dispatch.c
            # automatically; the saved harness_build.sh restored above doesn't
            # contain the compile+link patch either. Re-apply it on resume.
            if project == "ntopng":
                from bug_transplant_merge import _patch_ntopng_build_sh_for_dispatch
                _patch_ntopng_build_sh_for_dispatch(container)
            if not _harness_dispatch_consumer_present(container, project, primary_fuzzer):
                logger.error(
                    "Existing harness artifacts do not restore a dispatch-byte "
                    "consumer for %s. Rerun with --regenerate-harness or remove "
                    "%s and the stale wrapped/combined outputs.",
                    primary_fuzzer,
                    harness_diff_path,
                )
                return 1
            # The injection above overwrote __bug_dispatch.h/.c with the
            # current templates, so the saved harness.diff now carries stale
            # copies of them. It ships verbatim into the FuzzBench benchmark,
            # where the stale version would rebuild the link errors the
            # current template exists to avoid -- re-capture it.
            refreshed = _clean_diff(container, project)
            if refreshed.strip():
                harness_diff_path.write_text(refreshed)
                logger.info("Harness diff refreshed with current dispatch files (%d bytes)",
                            len(refreshed))
            ret, out = _exec_capture(container, _compile_cmd(container), timeout=1800)
            if ret != 0:
                logger.error("Build failed after applying existing harness.diff")
                logger.error(out[-500:] if out else "(no output)")
                return 1
            dispatch_state["dispatch_file_injected"] = True
            dispatch_state["harness_modified"] = True
        else:
            harness_diff_path = None

        if harness_diff_path is None:
            _inject_dispatch_files(
                container, project, dispatch_state["dispatch_bytes"],
                dispatch_state.get("dispatch_slots", 2),
                dispatch_state.get("dispatch_slice", 1),
            )
            dispatch_state["dispatch_file_injected"] = True
            ok = _modify_harness_for_dispatch(
                container, project, primary_fuzzer,
                model=args.model,
            )
            if not ok:
                logger.error("Failed to modify harness for dispatch")
                return 1
            if not _harness_dispatch_consumer_present(container, project, primary_fuzzer):
                logger.error(
                    "Harness modification completed, but %s still does not "
                    "write input dispatch bytes into __bug_dispatch",
                    primary_fuzzer,
                )
                return 1
            dispatch_state["harness_modified"] = True

            # Capture the harness diff immediately so we can re-apply it after
            # every git checkout -f during phase 1 and phase 2.
            harness_diff = _clean_diff(container, project)
            harness_diff_path = output_dir / "harness.diff"
            if harness_diff.strip():
                harness_diff_path.write_text(harness_diff)
                logger.info("Harness diff saved (%d bytes)", len(harness_diff))
            else:
                logger.warning("No harness diff captured after modification!")
                harness_diff_path = None

            # Save /src/build.sh — the agent may have modified it to
            # compile __bug_dispatch.c, but it's outside the git repo.
            _save_build_sh(container, output_dir, project)
            _save_harness_sources(container, project, primary_fuzzer, output_dir)

        harness_baseline_rev = _create_harness_baseline_commit(container, project)
        logger.info("Harness baseline commit: %s", harness_baseline_rev[:12])

        # Stash ASAN binaries (harness modification already built with ASAN)
        _exec_capture(container,
                      "mkdir -p /out/address && "
                      "for f in /out/*; do [ -f \"$f\" ] && [ -x \"$f\" ] && "
                      "cp \"$f\" /out/address/; done; "
                      # Mirror auxiliary directories (ntopng's install/,
                      # data-dir/, docs/, scripts/) so the stashed binary
                      # can find them when run from /out/address/.
                      "for d in /out/*/; do "
                      "name=$(basename \"$d\"); "
                      "[ \"$name\" = address ] && continue; "
                      "[ \"$name\" = ubsan ] && continue; "
                      "ln -sfn \"$d\" \"/out/address/$name\"; done; true")
        # Copy testcases (originals + patched)
        _restore_testcases_with_dispatch(
            container, project, all_bugs, testcase_stage_dir, dispatch_state,
        )

        # Persist patched local testcases into this run's testcase dir before
        # local verification. Later restores will prefer these patched files.
        for bug in local_bugs:
            tc_name = bug["testcase"]
            staged_patched = testcase_stage_dir / f"{tc_name}-patched"
            if _save_work_testcase_to_host(container, tc_name, staged_patched):
                logger.info("[%s] Staged patched local testcase: %s",
                            bug["bug_id"], staged_patched)

        # ------------------------------------------------------------------
        # 5. Verify local bugs at baseline  -- TEMPORARILY DISABLED
        # ------------------------------------------------------------------
        # libredwg 2026-09-18: all 3 "local" bugs (OSV-2023-314, -397, -1051)
        # HANG rather than crash at the target commit -- 300s with no crash on
        # a PRISTINE harness and the untouched PoC, so this is not the dispatch
        # byte and not the merge container.  Their "already triggers at target"
        # status comes from the CSV matrix, which was never re-checked.  Each
        # one costs ~80min here (40 attempts x a 120s timeout) to learn nothing,
        # so the loop is commented out rather than left to burn hours.
        #
        # NOTE: the local bugs are still staged into the merge; they are simply
        # not verified.  They contribute nothing to the benchmark until the
        # hang is understood, so treat the bug count as the transplanted set.
        # Re-enable by uncommenting once the target commit for them is fixed.
        logger.info("\n=== Verifying local bugs at baseline: SKIPPED ===")
        logger.info("Local bugs staged but NOT verified (%d): %s",
                    len(local_bugs), ", ".join(b["bug_id"] for b in local_bugs))
        # for bug in local_bugs:
        #     triggers = verify_bug_triggers(
        #         container, bug["bug_id"], bug["fuzzer"],
        #         bug["testcase"], bug.get("sanitizer", "address"),
        #         bug.get("crash_log"),
        #     )
        #     status = "OK" if triggers else "FAIL"
        #     logger.info("[%s] local: %s", bug["bug_id"], status)

        # ------------------------------------------------------------------
        # 6. Verify testcase-only bugs
        # ------------------------------------------------------------------
        logger.info("\n=== Verifying testcase-only bugs ===")
        for bug in testcase_only_bugs:
            triggers = verify_bug_triggers(
                container, bug["bug_id"], bug["fuzzer"],
                bug["testcase"], bug.get("sanitizer", "address"),
                bug.get("crash_log"),
            )
            status = "OK" if triggers else "FAIL"
            logger.info("[%s] testcase-only: %s", bug["bug_id"], status)

        # ------------------------------------------------------------------
        # 7. Phase 1: Wrap each patch independently on clean source
        # ------------------------------------------------------------------
        wrapped_diffs: dict[str, str] = {}  # bug_id -> wrapped diff path
        merge_results: list[dict] = []

        # Load previously wrapped diffs from disk only if the dispatch bit
        # order is unchanged. Otherwise stale wrappers check the wrong bit.
        # --only-bugs scopes WRAPPING, not the merge: the named bugs are
        # re-wrapped from scratch, every other bug keeps the wrapped diff it
        # already has, and phase 2 merges the union. That makes it usable to
        # redo one bug without paying to re-wrap the rest.
        rewrap_only = set(getattr(args, "only_bugs", None) or [])
        if reuse_wrapped_cache:
            for bd in diff_bugs:
                bid = bd["bug_id"]
                if bid in rewrap_only:
                    continue  # selected for re-wrapping; ignore the cache
                existing = output_dir / f"wrapped_{bid}.diff"
                if existing.exists() and existing.stat().st_size > 0:
                    wrapped_diffs[bid] = str(existing)
                    logger.info("[%s] Loaded existing wrapped diff (%d bytes)",
                                bid, existing.stat().st_size)
        if rewrap_only:
            missing = [bd["bug_id"] for bd in diff_bugs
                       if bd["bug_id"] not in rewrap_only
                       and bd["bug_id"] not in wrapped_diffs]
            logger.info("--only-bugs: re-wrapping %d bug(s): %s",
                        len(rewrap_only), ", ".join(sorted(rewrap_only)))
            if missing:
                logger.warning(
                    "--only-bugs: %d bug(s) have no wrapped diff and are NOT "
                    "being wrapped this run, so they will be ABSENT from the "
                    "merge: %s", len(missing), ", ".join(sorted(missing)))

        start_step = getattr(args, "start_step", 0)
        consecutive_wrap_failures = 0
        for i, bd in enumerate(diff_bugs):
            bug_id = bd["bug_id"]
            bit_index = next(
                idx for idx, info in dispatch_state["bits"].items()
                if info["bug_id"] == bug_id
            )

            # Skip if already wrapped (resume) or before start-step
            if bug_id in wrapped_diffs:
                logger.info("[%s] Already wrapped, skipping", bug_id)
                continue
            if rewrap_only and bug_id not in rewrap_only:
                logger.info("[%s] Not selected by --only-bugs, skipping wrap",
                            bug_id)
                continue
            if i < start_step:
                logger.info("[%s] Before start-step %d, skipping", bug_id, start_step)
                continue

            logger.info("\n=== Wrap %d/%d: %s (slot %d) ===",
                        i + 1, len(diff_bugs), bug_id, bit_index)

            step = {
                "step": i + 1,
                "bug_id": bug_id,
                "bit_index": bit_index,
                "success": False,
            }

            # Reset source to the exact harness baseline, then apply only the
            # bug-specific wrapped delta on top of it.
            _restore_harness_baseline(container, project, harness_baseline_rev)
            _restore_build_sh(container, output_dir, project)

            output = ""
            wrap_log_dir = output_dir / "wrap_logs"
            globals()["_WRAP_LOG_DIR"] = wrap_log_dir
            for attempt in range(_MAX_WRAP_RETRIES + 1):
                success, output = wrap_bug_with_dispatch(
                    container, project, bd, bit_index,
                    dispatch_state, model=args.model,
                    codex_mode=getattr(args, "codex_mode", "exec"),
                    log_dir=wrap_log_dir, attempt=attempt,
                )

                if success:
                    # Extract only the delta from the harness baseline.
                    wrapped_diff = _clean_diff_against(
                        container, project, harness_baseline_rev,
                    )
                    if wrapped_diff.strip():
                        wrapped_path = output_dir / f"wrapped_{bug_id}.diff"
                        wrapped_path.write_text(wrapped_diff)
                        wrapped_diffs[bug_id] = str(wrapped_path)
                        step["success"] = True
                        logger.info("[%s] Wrapped diff saved: %s (%d bytes)",
                                    bug_id, wrapped_path, len(wrapped_diff))
                        break
                    else:
                        logger.warning("[%s] Agent produced no diff after wrapping", bug_id)

                # Capture what the agent actually wrote before the reset
                # throws it away: a failed gate is only diagnosable from the
                # diff it produced.
                try:
                    failed_diff = _clean_diff_against(
                        container, project, harness_baseline_rev)
                    if failed_diff.strip():
                        wrap_log_dir.mkdir(parents=True, exist_ok=True)
                        fp = wrap_log_dir / f"{bug_id}_attempt{attempt}.failed.diff"
                        fp.write_text(failed_diff)
                        logger.info("[%s] Saved failing wrapped diff: %s (%d bytes)",
                                    bug_id, fp, len(failed_diff))
                    else:
                        logger.warning("[%s] Agent left no diff at all on this attempt",
                                       bug_id)
                except Exception as exc:  # diagnostics must never abort the merge
                    logger.warning("[%s] Could not capture failing diff: %s",
                                   bug_id, exc)

                logger.warning("[%s] Attempt %d failed, retrying...",
                               bug_id, attempt + 1)
                # Reset for retry to the exact harness baseline.
                _restore_harness_baseline(container, project, harness_baseline_rev)
                _restore_build_sh(container, output_dir, project)

            if not step["success"]:
                logger.error("[%s] FAILED after %d attempts, skipping",
                             bug_id, _MAX_WRAP_RETRIES + 1)
                consecutive_wrap_failures += 1
                if _agent_credentials_expired(output):
                    raise RuntimeError(
                        f"[{bug_id}] the code agent could not authenticate "
                        f"(expired/reused Codex token). Re-run `codex login` "
                        f"on the host so ~/.codex/auth.json is refreshed, then "
                        f"resume. Aborting before the merge destroys the "
                        f"existing combined.diff."
                    )
                if consecutive_wrap_failures >= _MAX_CONSECUTIVE_WRAP_FAILURES:
                    raise RuntimeError(
                        f"{consecutive_wrap_failures} wraps failed in a row -- "
                        f"this is a systemic failure (agent, container or "
                        f"build), not {consecutive_wrap_failures} independent "
                        f"bugs. Aborting rather than merging a tree where "
                        f"nothing got wrapped."
                    )
            else:
                consecutive_wrap_failures = 0

            step["output"] = output[-500:] if output else ""
            merge_results.append(step)
            _save_progress(output_dir, dispatch_state, merge_results,
                           list(wrapped_diffs.keys()))

        # Audit phase 1 before spending the merge on diffs that cannot work.
        bad_wraps = _audit_all_wraps(
            output_dir, dispatch_state, wrapped_diffs, project,
        )
        if bad_wraps and not getattr(args, "allow_lossy_wrap", False):
            raise RuntimeError(
                f"{len(bad_wraps)} wrapped diff(s) failed the wrap audit "
                f"({', '.join(sorted(bad_wraps))}). Fix the wrap (or pass "
                f"--allow-lossy-wrap to merge anyway) -- merging as-is "
                f"produces a benchmark where those bugs never trigger."
            )

        # ------------------------------------------------------------------
        # 8. Phase 2: Merge all wrapped diffs via code agent
        # ------------------------------------------------------------------
        combined_path = output_dir / "combined.diff"
        # A combined.diff is only reusable if it was built from exactly the
        # wrapped diffs we now hold. Re-wrapping a bug leaves the old
        # combined.diff on disk, and reusing it silently merges nothing --
        # the harness hunks a re-wrap just recovered never reach the build.
        wrapped_digest = _wrapped_set_digest(wrapped_diffs)
        recorded_digest = ""
        if _combined_sources_path(output_dir).exists():
            recorded_digest = _combined_sources_path(
                output_dir).read_text().strip()
        combined_is_current = recorded_digest == wrapped_digest
        if (combined_path.exists() and combined_path.stat().st_size > 0
                and not combined_is_current):
            logger.warning(
                "combined.diff exists but was NOT built from the current "
                "wrapped diffs (%s) -- re-merging instead of reusing it",
                "no digest recorded" if not recorded_digest
                else f"digest {recorded_digest[:12]} != {wrapped_digest[:12]}",
            )
        if (
            reuse_wrapped_cache
            and dispatch_order_unchanged
            and not rewrap_only
            and combined_is_current
            and combined_path.exists()
            and combined_path.stat().st_size > 0
            # A combined.diff that the audit already condemned must not be
            # reused: the wrapped-diff digest still matches, so every later
            # run would silently rebuild the same tree with the same bugs
            # missing. Re-merge instead.
            and not _audit_merged_slots(
                combined_path.read_text(errors='replace'),
                dispatch_state, wrapped_diffs)
        ):
            # Reuse existing combined diff — skip the agent merge entirely.
            # Only safe when the dispatch order is *unchanged*; an incremental
            # add must re-merge so the new bug's wrapped delta is included.
            logger.info("combined.diff already exists, reusing: %s (%d bytes)",
                        combined_path, combined_path.stat().st_size)
            _restore_harness_baseline(container, project, harness_baseline_rev)
            cdiff = combined_path.read_text(errors='replace')
            _exec_capture(container,
                          f"cat > /tmp/combined.diff << 'CEOF'\n{cdiff}CEOF")
            ret, out = _exec_capture(
                container,
                f"cd {_source_dir(project)} && git apply /tmp/combined.diff 2>&1",
            )
            if ret != 0:
                logger.error("Failed to apply existing combined.diff: %s", out[-500:])
                return 1
            _ensure_dispatch_linked_everywhere(container, project)
            ret, out = _exec_capture(container, _compile_cmd(container), timeout=1800)
            if ret != 0:
                logger.error("Build failed after applying combined.diff: %s",
                             out[-500:] if out else "(no output)")
                return 1
            applied_bugs = list(wrapped_diffs.keys())
        else:
            logger.info("\n=== Merging %d wrapped diffs ===", len(wrapped_diffs))

            # Reset source to the exact harness baseline before merging wrapped
            # bug deltas.
            _restore_harness_baseline(container, project, harness_baseline_rev)

            # Copy all wrapped patches into container
            patch_descriptions = []
            for bug_id, wdiff_path in wrapped_diffs.items():
                diff_content = Path(wdiff_path).read_text(errors='replace')
                if not diff_content.strip():
                    continue
                fname = f"wrapped_{bug_id}.diff"
                _exec_capture(container,
                              f"cat > /tmp/{fname} << 'DIFFEOF'\n{diff_content}DIFFEOF")
                patch_descriptions.append(f"- `/tmp/{fname}` — {bug_id}")

            if not patch_descriptions:
                logger.info("No patches to merge (all were dispatch-only)")
                applied_bugs = list(wrapped_diffs.keys())
            else:
                # Use code agent to merge patches in chunks (avoid single huge prompt).
                # We keep the existing merge prompt/behavior, but run it multiple times.
                # Each chunk is merged on top of the previous chunk's result.
                max_chunk = 15
                total_patches = len(patch_descriptions)
                logger.info(
                    "Merging %d patches in chunks of <=%d via %s",
                    total_patches, max_chunk, active_agent(),
                )

                applied_bugs = []
                merge_failed = False
                dropped_by_chunk: dict[int, list[str]] = {}
                merge_log_dir = output_dir / "merge_logs"
                merge_log_dir.mkdir(parents=True, exist_ok=True)
                # Each chunk is committed once it verifies, so the next
                # chunk's agent starts from a tree whose earlier gates are in
                # HEAD. A stray `git checkout`/`stash`/`clean` then costs
                # nothing, and a retry has an exact point to rewind to.
                chunk_base_rev = harness_baseline_rev
                for chunk_idx, start in enumerate(range(0, total_patches, max_chunk), start=1):
                    chunk = patch_descriptions[start:start + max_chunk]
                    patch_list = "\n".join(chunk)
                    chunk_bugs = [
                        m.group(1) for m in (
                            re.search(r"—\s+(OSV-[0-9]{4}-[0-9]+)\s*$", desc)
                            for desc in chunk
                        ) if m
                    ]
                    prior_bugs = list(applied_bugs)
                    prior_slots = sorted(
                        slot for slot, info in dispatch_state["bits"].items()
                        if info["bug_id"] in prior_bugs
                    )
                    feedback = ""

                    for attempt in range(1, _MERGE_CHUNK_ATTEMPTS + 1):
                        if attempt > 1:
                            logger.info(
                                "Rewinding chunk %d to %s and retrying (%d/%d)",
                                chunk_idx, chunk_base_rev[:12],
                                attempt, _MERGE_CHUNK_ATTEMPTS,
                            )
                            _restore_harness_baseline(
                                container, project, chunk_base_rev)

                        merge_prompt = _load_prompt(
                            "merge_wrapped_patches",
                            project=project,
                            target_commit=target_commit,
                            patch_list=patch_list,
                            source_dir=_source_dir(project),
                            prior_merge_state=_prior_merge_note(
                                prior_bugs, prior_slots) + feedback,
                        )

                        setup_codex_creds(container)
                        codex_mode = getattr(args, "codex_mode", "exec")
                        agent_cmd = build_codex_command(
                            merge_prompt, args.model, mode=codex_mode,
                        )

                        logger.info(
                            "Invoking codex to merge chunk %d (%d patches: %d..%d/%d)",
                            chunk_idx,
                            len(chunk),
                            start + 1,
                            min(start + len(chunk), total_patches),
                            total_patches,
                        )
                        if codex_mode == "interactive":
                            ret, output = _exec_interactive(container, agent_cmd, timeout=3600)
                        else:
                            ret, output = _exec_capture(container, agent_cmd, timeout=3600)
                        _usage_tracker.log_usage(f"merge chunk {chunk_idx}", output, args.model)

                        # The container is destroyed at the end of the run, so
                        # a chunk transcript left only inside it is
                        # unrecoverable exactly when it is needed.
                        stem = merge_log_dir / f"chunk{chunk_idx}_attempt{attempt}"
                        stem.with_suffix(".jsonl").write_text(output or "")
                        try:
                            stem.with_suffix(".txt").write_text(
                                _format_codex_output(output or ""))
                        except Exception:
                            pass
                        stem.with_suffix(".prompt.md").write_text(merge_prompt)

                        if ret != 0:
                            logger.error(
                                "Agent failed on chunk %d (exit %d). Output tail: %s",
                                chunk_idx, ret, output[-500:] if output else "",
                            )
                            merge_failed = True
                            break

                        # Verify build after each chunk so failures are localized.
                        ret, build_out = _exec_capture(
                            container, _compile_cmd(container), timeout=1800,
                        )
                        if ret != 0:
                            logger.error(
                                "Build failed after chunk %d: %s",
                                chunk_idx, build_out[-500:],
                            )
                            merge_failed = True
                            break

                        # A chunk merges on top of the previous ones, and the
                        # files it touches are often shared (on libredwg 24 of
                        # 62 bugs edit examples/llvmfuzz.c). An agent that
                        # rewrites such a file wholesale -- or resets the tree
                        # to get a "clean" checkout -- silently deletes the
                        # gates earlier chunks placed: on opensc chunk 2 left
                        # only its own 8 slots and all 15 of chunk 1's were
                        # gone. Check the earlier slots after every chunk.
                        lost = []
                        if prior_slots:
                            still_there = _slots_present_in_tree(
                                container, project, prior_slots)
                            lost = sorted(set(prior_slots) - still_there)
                        if not lost:
                            break

                        lost_bugs = [
                            dispatch_state["bits"][slot]["bug_id"]
                            for slot in lost
                        ]
                        logger.error(
                            "Chunk %d DROPPED %d gate(s) merged by earlier "
                            "chunks: %s",
                            chunk_idx, len(lost), ", ".join(lost_bugs),
                        )
                        if attempt < _MERGE_CHUNK_ATTEMPTS:
                            feedback = (
                                "\n\n## Your previous attempt destroyed earlier work\n\n"
                                "It removed these already-merged slots: "
                                + ", ".join(str(n) for n in lost)
                                + " (bugs " + ", ".join(lost_bugs) + ").\n"
                                "The tree has been rewound. Apply your patches "
                                "with `git apply --3way` ONLY, on top of what is "
                                "already there. Do not run `git checkout`, "
                                "`git stash`, `git reset` or `git clean`, and do "
                                "not rewrite a whole file -- edit it in place.\n"
                            )
                            continue
                        logger.error(
                            "Chunk %d still dropped gates after %d attempts. "
                            "Re-merge those bugs (their wrapped diffs are "
                            "unchanged) before trusting this tree.",
                            chunk_idx, _MERGE_CHUNK_ATTEMPTS,
                        )
                        dropped_by_chunk.setdefault(
                            chunk_idx, []).extend(lost_bugs)

                    if merge_failed:
                        break

                    applied_bugs.extend(chunk_bugs)
                    chunk_base_rev = _create_harness_baseline_commit(
                        container, project, f"codex merge chunk {chunk_idx}")
                    logger.info("Chunk %d committed: %s",
                                chunk_idx, chunk_base_rev[:12])

                if dropped_by_chunk:
                    all_lost = sorted(
                        {b for v in dropped_by_chunk.values() for b in v})
                    logger.error(
                        "Merge lost %d bug(s) to later chunks overwriting "
                        "shared files: %s", len(all_lost), ", ".join(all_lost))

                if not merge_failed:
                    # If everything succeeded, consider all wrapped diffs merged.
                    applied_bugs = list(wrapped_diffs.keys())

        # Build ASAN with all patches applied
        logger.info("Building with all patches applied...")
        _ensure_dispatch_linked_everywhere(container, project)
        build_ret, build_out = _exec_capture(
            container, _compile_cmd(container), timeout=1800,
        )
        if build_ret != 0:
            # Without this check a failed compile is invisible: verification
            # runs against the stale binary and every bug reports "does NOT
            # trigger", which reads as 62 broken patches instead of one broken
            # build. The reuse path above has always checked this.
            logger.error("Build FAILED after merging (exit %d). The merged "
                         "tree does not compile, so the verification below "
                         "would be meaningless. Last output:\n%s",
                         build_ret, build_out[-3000:] if build_out else "(none)")
            build_log = output_dir / "merge_build_failed.txt"
            build_log.write_text(build_out or "")
            logger.error("Full build output saved to %s", build_log)
            return 1
        logger.info("Build OK after merging")
        _exec_capture(container,
                      "mkdir -p /out/address && "
                      "for f in /out/*; do [ -f \"$f\" ] && [ -x \"$f\" ] && "
                      "cp \"$f\" /out/address/; done; "
                      # Mirror auxiliary directories (ntopng's install/,
                      # data-dir/, docs/, scripts/) so the stashed binary
                      # can find them when run from /out/address/.
                      "for d in /out/*/; do "
                      "name=$(basename \"$d\"); "
                      "[ \"$name\" = address ] && continue; "
                      "[ \"$name\" = ubsan ] && continue; "
                      "ln -sfn \"$d\" \"/out/address/$name\"; done; true")

        # Restore testcases with dispatch bytes
        _restore_testcases_with_dispatch(
            container, project, all_bugs, testcase_stage_dir, dispatch_state,
        )

        # ------------------------------------------------------------------
        # 9. Final verification
        # ------------------------------------------------------------------
        logger.info("\n=== Final verification ===")
        _restore_testcases_with_dispatch(
            container, project, all_bugs, testcase_stage_dir, dispatch_state,
        )

        # Verify only what this pipeline produced. `local_bugs` already
        # trigger at the target commit, so they carry no wrapped diff and no
        # dispatch slot -- verifying them tests the upstream project, not the
        # transplant, and it is not free: libredwg's three locals
        # (OSV-2023-314, -397, -1051) HANG rather than crash, and one of them
        # burned 47 minutes across five concurrent attempts before the run was
        # killed. This matches the baseline check, which is disabled for the
        # same bugs for the same reason.
        verify_bugs = testcase_only_bugs + diff_bugs
        if local_bugs:
            logger.info("Skipping final verification for %d local bug(s) "
                        "(already trigger at target, not a transplant "
                        "result): %s", len(local_bugs),
                        ", ".join(b["bug_id"] for b in local_bugs))
        final_results = verify_all_bugs(container, verify_bugs)
        triggered = sum(1 for v in final_results.values() if v)
        total = len(final_results)
        logger.info("\nRESULT: %d / %d transplanted bugs triggering "
                    "(%d local bug(s) staged but not verified)",
                    triggered, total, len(local_bugs))
        for bid, ok in final_results.items():
            logger.info("  %s: %s", bid, "OK" if ok else "FAIL")

        # ------------------------------------------------------------------
        # 10. Save combined diff + testcases
        # ------------------------------------------------------------------
        combined_diff = _clean_diff_against(container, project, harness_baseline_rev)
        combined_path = output_dir / "combined.diff"
        # Keep the previous combined diff. This file is the merge's only
        # irreplaceable output, and a run that fails late (expired agent
        # credentials, a broken container) otherwise overwrites a good one
        # with a stub.
        if combined_path.exists() and combined_path.stat().st_size > 0:
            backup = output_dir / "combined.diff.bak"
            backup.write_text(combined_path.read_text(errors="replace"))
            if len(combined_diff) < combined_path.stat().st_size // 2:
                logger.error(
                    "New combined diff (%d bytes) is less than half the "
                    "previous one (%d bytes) -- the merge almost certainly "
                    "failed. Previous version kept at %s",
                    len(combined_diff), combined_path.stat().st_size, backup,
                )
        combined_path.write_text(combined_diff)
        _combined_sources_path(output_dir).write_text(
            _wrapped_set_digest(wrapped_diffs))
        logger.info("Combined diff: %s (%d bytes)", combined_path, len(combined_diff))

        # Re-snapshot the harness NOW, after the merge. The snapshot taken
        # right after dispatch modification holds only the clean dispatch
        # read; any per-bug harness gating the merge introduced lives solely
        # in the merged tree, and fuzzbench_generate.py restores the harness
        # from this snapshot whole-file, overwriting whatever combined.diff
        # says. Snapshotting late is what makes per-bug harness gates reach
        # the benchmark.
        if combined_diff.strip():
            _save_harness_sources(container, project, primary_fuzzer, output_dir)
        else:
            logger.error("Empty combined diff -- keeping the previous harness "
                         "snapshot rather than overwriting it")

        _audit_merged_slots(combined_diff, dispatch_state, wrapped_diffs)

    # Save testcases
        tc_dir = output_dir / "testcases"
        tc_dir.mkdir(exist_ok=True)
        # Only mark artifacts as "patched" if we actually introduced dispatch
        # bytes / harness changes. (In this offline pipeline this is normally
        # true, but keep the check to avoid misleading filenames.)
        mark_patched = bool(dispatch_state.get("dispatch_bytes", 0)) and bool(
            dispatch_state.get("harness_modified")
        )
        for bug in all_bugs:
            tc_name = bug["testcase"]
            tc_ret = subprocess.run(
                ["docker", "exec", container,
                 "bash", "-c", f"cat /work/{tc_name}"],
                capture_output=True, timeout=10,
            )
            if tc_ret.returncode == 0 and tc_ret.stdout:
                if mark_patched:
                    # After rewrite, treat the saved artifact as the patched testcase.
                    (tc_dir / f"{tc_name}-patched").write_bytes(tc_ret.stdout)
                else:
                    (tc_dir / tc_name).write_bytes(tc_ret.stdout)

        logger.info("Testcases saved to %s", tc_dir)

        # Save summary
        merge_summary = {
            "project": project,
            "target_commit": target_commit,
            "local_bugs": len(local_bugs),
            "testcase_only_bugs": len(testcase_only_bugs),
            "diff_bugs": len(diff_bugs),
            "applied": applied_bugs,
            "dispatch_state": {k: v for k, v in dispatch_state.items()
                               if k != "bits"},
            "triggered": triggered,
            "total": total,
            "results": {bid: ok for bid, ok in final_results.items()},
            "steps": merge_results,
        }
        (output_dir / "summary.json").write_text(
            json.dumps(merge_summary, indent=2))
        dispatch_order_path.write_text(json.dumps(dispatch_order, indent=2) + "\n")
        logger.info("Summary: %s", output_dir / "summary.json")

        _usage_tracker.log_session_total()

        return 0 if triggered == total else 1

    finally:
        if not args.keep_container:
            logger.info("Destroying container %s...", container)
            subprocess.call(
                ["docker", "rm", "-f", container],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        else:
            logger.info("Container kept: docker exec -it %s bash", container)


def _save_progress(output_dir, dispatch_state, merge_results, applied_bugs):
    """Save intermediate progress to disk."""
    progress = {
        "dispatch_state": {k: v for k, v in dispatch_state.items()
                           if k != "bits"},
        "applied_bugs": applied_bugs,
        "steps": merge_results,
    }
    (output_dir / "progress.json").write_text(json.dumps(progress, indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    filled = load_setenv_defaults("TESTCASES", "REPO_PATH", "BUGINFO_PATH")
    parser = argparse.ArgumentParser(
        description="Offline dispatch-wrapped merge of per-bug transplant patches",
    )
    parser.add_argument("--summary", required=True,
                        help="Path to batch summary.json")
    parser.add_argument("--bug_info", required=True,
                        help="Path to osv_testcases_summary.json")
    parser.add_argument("--target", required=True,
                        help="OSS-Fuzz project name")
    parser.add_argument("--target-commit", default=None,
                        help="Override target commit")
    parser.add_argument("--build_csv", default=None,
                        help="Build CSV for historical image pinning")
    parser.add_argument("--testcases-dir",
                        default=os.environ.get("TESTCASES") or None,
                        help="Directory containing testcase files "
                             "(default: $TESTCASES, else script/setenv.sh)")
    parser.add_argument("--local-bugs", nargs="*", default=None,
                        help="Bug IDs that already trigger at target")
    parser.add_argument("--only-bugs", nargs="+", default=None,
                        help="Re-wrap only these bug IDs. Every other bug "
                             "keeps its existing wrapped_<id>.diff and phase 2 "
                             "still merges them all, so this redoes one bug "
                             "without re-wrapping the rest. Dispatch slots are "
                             "still assigned across ALL bugs, so the geometry "
                             "matches a full run.")
    parser.add_argument("--agent", choices=["codex", "opencode"],
                        default="codex",
                        help="Agent CLI backend (default: codex)")
    parser.add_argument("--model", default=None,
                        help="Model override for codex")
    parser.add_argument("-v", "--volume", action="append",
                        help="Extra Docker volume mounts")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show plan without executing")
    parser.add_argument("--keep-container", action="store_true",
                        help="Keep container for debugging")
    parser.add_argument("--allow-lossy-wrap", action="store_true",
                        help="Merge even when the wrap audit finds wrapped "
                             "diffs that are ungated or dropped a file their "
                             "transplant needed (those bugs will not trigger)")
    parser.add_argument("--regenerate-harness", action="store_true",
                        help="Ignore saved harness artifacts and rebuild the "
                             "dispatch-consuming fuzz harness")
    parser.add_argument("--start-step", type=int, default=0,
                        help="Resume from step N")
    parser.add_argument("--max-steps", type=int, default=None,
                        help="Stop after N steps")
    parser.add_argument("--codex-mode", choices=["exec", "interactive"],
                        default="exec",
                        help="Agent invocation mode: exec (default, JSONL) "
                             "or interactive (TUI via tmux)")
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()
    set_active_agent(getattr(args, "agent", "codex"))
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    for name, value in filled.items():
        logger.info("%s not in environment; using %s from %s", name, value, SETENV_SCRIPT)

    return run_offline_merge(args)


if __name__ == "__main__":
    sys.exit(main())
