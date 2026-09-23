#!/usr/bin/env python3
"""Bug transplant launcher -- runs Codex inside an OSS-Fuzz container.

Workflow:
  Phase 0: Collect crash log and function trace via fuzz_helper.py
  Phase 1: Build Codex-layered Docker image on top of the project image
  Phase 2: Start persistent container with proper volumes
  Phase 3: Run Codex with the bug transplant prompt
  Phase 4: Collect output diff

Usage:
  # Full pipeline (collect data + run Codex):
  sudo -E python3 script/bug_transplant.py wavpack \\
    --buggy-commit 348ff60b \\
    --target-commit 0b99613e \\
    --bug-id OSV-2020-1006 \\
    --fuzzer-name fuzzer_decode_file \\
    --testcase testcase-OSV-2020-1006

  # Skip data collection (crash/trace already in data/):
  sudo -E python3 script/bug_transplant.py wavpack \\
    --buggy-commit 348ff60b \\
    --target-commit 0b99613e \\
    --bug-id OSV-2020-1006 \\
    --fuzzer-name fuzzer_decode_file \\
    --testcase testcase-OSV-2020-1006 \\
    --skip-collect

  # Use a specific model:
  sudo -E python3 script/bug_transplant.py wavpack \\
    ... \\
    --model o3
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import pwd
import re
import shlex
import shutil
import subprocess
import uuid
import sys
import tempfile
import textwrap
import time
from pathlib import Path

# Add script dir to path so the shared bug_verify module resolves both
# when executed directly (``python3 script/bug_transplant.py``) and when
# imported as a library (``from bug_transplant import ...``).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from bug_verify import verify_bug_triggers, _RSS_LIMIT_MB  # noqa: E402

# A verification rebuild is a correctness gate, not a performance knob: it has
# to be able to finish a FULL rebuild.  300s could not even complete one for
# libredwg (7 large files include dwg.spec, so a cold build is ~540s), and
# seven transplants the agent had verified in both directions were discarded as
# "Official compile failed" purely because the rebuild was cut off mid-flight.
_VERIFY_BUILD_TIMEOUT = 1800

logger = logging.getLogger(__name__)

# Lazy-initialized in main(); imported here so the module can be used as a library.
_usage_tracker = None

# Pin CLI version for reproducibility.
# 0.116.0's remote-compaction endpoint 404s, killing any session that fills
# its context window (long ghostscript runs in particular). 0.147.0 matches
# the CLI installed on the hosts and keeps every flag this script uses.
CODEX_VERSION = "0.147.0"  # @openai/codex

# Model used for all Codex agent sessions. A ChatGPT-account login rejects
# both Codex's default (gpt-5.2-codex) and the older gpt-5.4 with "model is
# not supported when using Codex with a ChatGPT account"; gpt-5.6-terra is
# the migration target named in config.toml and is what the account accepts.
DEFAULT_MODEL = "gpt-5.6-terra"

# Codex agent configuration
CODEX_CONFIG = {
    "npm_package": "@openai/codex",
    "cli_name": "codex",
    "cli_entry": "@openai/codex/bin/codex.js",
    "api_key_env": "OPENAI_API_KEY",
    "credentials_dir": ".codex",
    "run_cmd": "codex exec --dangerously-bypass-approvals-and-sandbox {prompt}",
    "model_flag": "--model",
}

# Second agent backend. opencode ships as one standalone binary that already
# runs on the Ubuntu 20.04 project images, so it is bind-mounted at container
# start rather than layered into the image. Its `opencode/*` models need no
# credentials at all, which is why it is the fallback when the Codex path is
# unavailable.
OPENCODE_CONFIG = {
    "cli_name": "opencode",
    "credentials_dir": ".local/share/opencode",
    "container_bin": "/usr/local/bin/opencode",
}
OPENCODE_DEFAULT_MODEL = "opencode/nemotron-3-ultra-free"

# Set from --agent in main(); module-level so the batch driver and the
# minimize pass agree on the backend without threading it through every call.
ACTIVE_AGENT = "codex"


def set_active_agent(agent: str) -> None:
    global ACTIVE_AGENT
    ACTIVE_AGENT = agent


def active_agent() -> str:
    """Name of the agent CLI in use, for log messages.

    A function, not a module constant: callers import this once but the value
    is chosen per run from --agent, so binding the name at import time would
    always report the default.
    """
    return ACTIVE_AGENT


def opencode_host_binary() -> Path | None:
    """The opencode executable on the host, or None when not installed."""
    candidate = _host_home() / ".opencode" / "bin" / "opencode"
    if candidate.exists():
        return candidate
    found = shutil.which("opencode")
    return Path(found) if found else None


def agent_mounts() -> list[str]:
    """``docker run`` args that give the container its agent CLI."""
    if ACTIVE_AGENT != "opencode":
        return []
    binary = opencode_host_binary()
    if binary is None:
        logger.error(
            "--agent opencode but no opencode binary found under %s or $PATH. "
            "Install it from https://opencode.ai before running.",
            _host_home() / ".opencode" / "bin",
        )
        sys.exit(1)
    mounts = ["-v", f"{binary}:{OPENCODE_CONFIG['container_bin']}:ro"]
    logger.info("Mounting opencode binary %s", binary)

    # `opencode auth login` writes auth.json; free `opencode/*` models need
    # none, but a paid provider key lives there and must reach the container.
    auth = _host_home() / OPENCODE_CONFIG["credentials_dir"] / "auth.json"
    if auth.exists():
        mounts += ["-v", f"{auth}:/tmp/.opencode-auth.json:ro"]
        logger.info("Mounting opencode credentials %s", auth)
    cfg = _host_home() / ".config" / "opencode" / "opencode.jsonc"
    if cfg.exists():
        mounts += ["-v", f"{cfg}:/tmp/.opencode-config.jsonc:ro"]
    # The provider/model catalog. opencode refreshes it over the network on
    # first use; a container that cannot reach the catalog resolves every
    # `<provider>/<model>` to `provider.no-route` and fails instantly.
    models = _host_home() / ".cache" / "opencode" / "models.json"
    if models.exists():
        mounts += ["-v", f"{models}:/tmp/.opencode-models.json:ro"]
        logger.info("Mounting opencode model catalog %s", models)
    for env_var in opencode_provider_env():
        mounts += ["-e", env_var]
    return mounts


# Provider keys opencode reads straight from the environment. Only those the
# host actually sets are forwarded, and the value is never logged.
OPENCODE_PROVIDER_ENV_VARS = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "MODELSCOPE_API_KEY",
    "GEMINI_API_KEY",
    "GROQ_API_KEY",
    "DEEPSEEK_API_KEY",
    "TOGETHER_API_KEY",
    "XAI_API_KEY",
    "ZHIPUAI_API_KEY",
)


def opencode_provider_env() -> list[str]:
    """``NAME=value`` for each provider key the host has set."""
    out = []
    for name in OPENCODE_PROVIDER_ENV_VARS:
        value = os.environ.get(name)
        if value:
            logger.info("Forwarding $%s to opencode", name)
            out.append(f"{name}={value}")
    return out


def _host_home() -> Path:
    """The invoking user's home, even under plain ``sudo``.

    ``Path.home()`` follows $HOME, which plain ``sudo`` resets to /root. The
    root account here carries a Codex ``auth.json`` from an unrelated login
    whose refresh token was rotated away months ago, so mounting it makes
    every agent die at startup with "your access token could not be
    refreshed" and the whole batch reports `failed` with an empty diff.
    Ask the passwd db for the real invoking user instead; not every host puts
    homes under /home.
    """
    user = os.environ.get("SUDO_USER")
    if user:
        try:
            return Path(pwd.getpwnam(user).pw_dir)
        except KeyError:
            return Path(f"/home/{user}")
    return Path.home()


def codex_cred_dir() -> Path:
    """Host directory holding the Codex credentials to mount.

    Logs the choice: a batch that mounts the wrong ``auth.json`` fails every
    bug in seconds with an empty diff, and the only way to tell which store
    was used is the docker command line.
    """
    cred_dir = _host_home() / CODEX_CONFIG["credentials_dir"]
    if ACTIVE_AGENT != "codex":
        # opencode carries its own credentials; this path is codex-only.
        return cred_dir
    if (cred_dir / "auth.json").exists():
        logger.info("Codex credentials: %s", cred_dir)
    else:
        logger.warning(
            "No Codex auth.json under %s -- the agent will fail at startup. "
            "Log in on the host, or run under the account that owns the "
            "credentials.", cred_dir,
        )
    return cred_dir


def codex_api_key_env() -> list[str]:
    """``NAME=value`` for the provider key Codex needs inside the container.

    A third-party provider block in ``config.toml`` names its secret with
    ``env_key`` and Codex reads it from the environment. The credentials
    directory is copied into the container, so the *config* travels but the
    *secret* does not, and the agent dies on turn one with "Missing
    environment variable". Forward it explicitly. Returns an empty list for
    ChatGPT OAuth, which carries its own token in ``auth.json``.
    """
    config = codex_cred_dir() / "config.toml"
    if not config.exists():
        return []
    try:
        import tomllib
        with open(config, "rb") as fh:
            cfg = tomllib.load(fh)
    except Exception as exc:                      # malformed / unreadable
        logger.warning("Could not parse %s: %s", config, exc)
        return []

    provider = cfg.get("model_provider")
    if not provider:
        return []
    env_key = (cfg.get("model_providers", {})
                  .get(provider, {})
                  .get("env_key"))
    if not env_key:
        return []

    value = os.environ.get(env_key, "")
    if not value:
        logger.warning(
            "Codex provider %r needs $%s but it is unset here, so the agent "
            "will fail on its first turn. It is likely exported in the "
            "invoking user's shell -- run under `sudo -E` to carry it "
            "through.", provider, env_key,
        )
        return []
    logger.info("Forwarding $%s for Codex provider %r", env_key, provider)
    return [f"{env_key}={value}"]


def setup_codex_creds(container: str) -> None:
    """Copy codex credentials into container.

    A no-op for opencode: its free ``opencode/*`` models are unauthenticated,
    and it keeps its own state under the container's HOME.
    """
    if ACTIVE_AGENT == "opencode":
        _exec(
            container,
            "mkdir -p /home/agent/.local/share/opencode /home/agent/.config/opencode; "
            "[ -f /tmp/.opencode-auth.json ] && "
            "cp /tmp/.opencode-auth.json /home/agent/.local/share/opencode/auth.json; "
            "[ -f /tmp/.opencode-config.jsonc ] && "
            "cp /tmp/.opencode-config.jsonc /home/agent/.config/opencode/opencode.jsonc; "
            "mkdir -p /home/agent/.cache/opencode; "
            "[ -f /tmp/.opencode-models.json ] && "
            "cp /tmp/.opencode-models.json /home/agent/.cache/opencode/models.json; "
            "chown -R agent:agent /home/agent/.local /home/agent/.config "
            "/home/agent/.cache 2>/dev/null; "
            "true",
            user="root",
        )
        return
    _exec(
        container,
        "cp -r /tmp/.agent-creds-src /home/agent/.codex 2>/dev/null; "
        "rm -rf /home/agent/.codex/projects 2>/dev/null; "
        "chown -R agent:agent /home/agent/.codex 2>/dev/null; "
        "true",
        user="root",
    )


def build_codex_command(
    prompt: str, model: str | None = None, mode: str = "exec",
    resume_session: str | None = None,
) -> str:
    """Build the codex CLI command.

    *mode* selects the invocation style:
      - ``"exec"``  (default) — ``codex exec … --json`` (non-interactive, JSONL)
      - ``"interactive"`` — ``codex … `` (TUI, needs a TTY via tmux)

    If *resume_session* is given, uses ``codex exec resume <id> <prompt>``
    to continue the specified session instead of starting a new one.
    """
    escaped = shlex.quote(prompt)
    if ACTIVE_AGENT == "opencode":
        # `--auto` is opencode's approval bypass; `--format json` gives the
        # per-part event stream the output parser reads.
        cmd = "opencode run --auto"
        if resume_session:
            cmd += f" --session {shlex.quote(resume_session)}"
        cmd += f" --model {shlex.quote(model or OPENCODE_DEFAULT_MODEL)}"
        if mode != "interactive":
            cmd += " --format json"
        return f"{cmd} -- {escaped}"

    if mode == "interactive":
        cmd = f"codex --dangerously-bypass-approvals-and-sandbox {escaped}"
    elif resume_session:
        cmd = (f"codex exec resume --dangerously-bypass-approvals-and-sandbox"
               f" {shlex.quote(resume_session)} {escaped}")
    else:
        cmd = f"codex exec --dangerously-bypass-approvals-and-sandbox {escaped}"
    cmd += f" --model {shlex.quote(model or DEFAULT_MODEL)}"
    if mode != "interactive":
        cmd += " --json"
    return cmd


def _extract_session_id(jsonl_output: str) -> str | None:
    """Extract the session ID from codex exec JSONL output.

    The first ``session_meta`` event contains the session UUID at
    ``payload.id``.
    """
    for line in jsonl_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, KeyError):
            continue
        # opencode stamps every event with the session it belongs to.
        if ACTIVE_AGENT == "opencode":
            if obj.get("sessionID"):
                return obj["sessionID"]
            continue
        if obj.get("type") == "session_meta":
            return obj.get("payload", {}).get("id")
    return None

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
HOME_DIR = SCRIPT_DIR.parent
OSS_FUZZ_DIR = HOME_DIR / "oss-fuzz"
DATA_DIR = HOME_DIR / "data"
TRACE_DIR = DATA_DIR / "trace"
FUZZ_HELPER = SCRIPT_DIR / "fuzz_helper.py"
PROMPT_TEMPLATE = SCRIPT_DIR / "prompts" / "bug_transplant.md"
SETENV_SCRIPT = SCRIPT_DIR / "setenv.sh"


def load_setenv_defaults(*names: str) -> dict[str, str]:
    """Fill missing environment variables from ``script/setenv.sh``.

    The launchers read ``$TESTCASES``, ``$REPO_PATH`` and ``$BUGINFO_PATH``
    from the environment, but those are lost whenever the command runs in a
    shell that never sourced ``setenv.sh`` or when ``sudo`` resets the
    environment. Rather than fail with "Testcases dir not set", parse the
    ``export NAME="value"`` lines of ``setenv.sh`` and use them as defaults
    for whichever of *names* is unset. Existing environment values win.

    Returns the variables that were filled in, for logging.
    """
    if not SETENV_SCRIPT.exists():
        return {}
    wanted = set(names)
    filled: dict[str, str] = {}
    pattern = re.compile(r'^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)=(.*?)\s*$')
    for line in SETENV_SCRIPT.read_text().splitlines():
        m = pattern.match(line)
        if not m:
            continue
        name, raw = m.group(1), m.group(2)
        if name not in wanted or os.environ.get(name):
            continue
        value = raw.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        # setenv.sh anchors the in-repo dataset paths on $REPO_ROOT, which is
        # a shell-local there and so absent from os.environ -- expandvars would
        # leave it literal and hand the caller a path that does not exist.
        value = value.replace("$REPO_ROOT", str(HOME_DIR)).replace(
            "${REPO_ROOT}", str(HOME_DIR))
        value = os.path.expandvars(os.path.expanduser(value))
        if value:
            os.environ[name] = value
            filled[name] = value
    return filled
MINIMIZE_TEMPLATE = SCRIPT_DIR / "prompts" / "minimize_patch.md"

# Set when main() starts, so the minimize phase can see how much of the
# caller's wall-clock budget the earlier phases actually consumed.
_RUN_START: float | None = None

# Wall-clock to hold back for the post-minimize rebuild and re-verification
# that run after the minimize agent returns.
_POST_MINIMIZE_RESERVE_SECONDS = 420

# Below this a minimize pass cannot finish anything useful, so skip it and
# keep the verified patch rather than lose the run to the caller's kill.
_MINIMIZE_FLOOR_SECONDS = 300


def _minimize_budget(args: argparse.Namespace) -> int:
    """Seconds to give the minimize agent, clamped to the time left.

    Returns 0 when too little remains to be worth starting.  Without this the
    minimizer would run against its full --minimize-timeout, overshoot the
    caller's cap, and be SIGKILLed mid-pass -- which discards its output
    entirely instead of falling back to the verified pre-minimize patch.
    """
    asked = args.minimize_timeout
    budget = getattr(args, "total_budget", None)
    if not budget or _RUN_START is None:
        return asked
    remaining = budget - (time.monotonic() - _RUN_START)
    allowed = int(remaining - _POST_MINIMIZE_RESERVE_SECONDS)
    if allowed >= asked:
        return asked
    if allowed < _MINIMIZE_FLOOR_SECONDS:
        return 0
    return allowed
MEMORY_TEMPLATE = SCRIPT_DIR / "prompts" / "bug_transplant_memory.md"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _container_repo_dir(project: str) -> str:
    """Return the git repo root inside the container for a project."""
    return _source_dir(project)


def _container_agents_md_path(project: str) -> str:
    """Return the shared AGENTS.md mount path inside the container."""
    return f"/src/{project}/AGENTS.md"


def _git_clean_excludes(project: str) -> str:
    """Return project-specific git-clean exclusions.

    Preserve vendored tarballs/zips placed by the Docker image but not
    tracked by git (e.g. libpcap-1.9.1.tar.gz for ndpi).  Without this
    ``git clean -fdx`` deletes them and subsequent ``compile`` fails.
    """
    excludes = [
        "-e .codex/",
        "-e '*.tar.gz'",
        "-e '*.tar.bz2'",
        "-e '*.tar.xz'",
        "-e '*.zip'",
    ]
    if _container_agents_md_path(project) == f"{_container_repo_dir(project)}/AGENTS.md":
        excludes.insert(0, "-e AGENTS.md")
    return " ".join(excludes)


def _container_in_dir(directory: str, command: str) -> str:
    """Run a shell command in a directory without changing caller cwd."""
    return f"(cd {shlex.quote(directory)} && {command})"


def _patch_build_sh_for_repeated_compile(
    container_name: str, project: str,
) -> None:
    """Apply project-specific /src/build.sh hygiene for reused containers."""
    # Ghostscript: build.sh destructively removes tracked vendored source
    # directories. Drop those removals so repeated compiles do not pollute
    # git diff or break resume.
    if project == "ghostscript":
        ret = _exec(
            container_name,
            r"""sed -i '/^rm -rf cups\/libs/d; /^rm -rf freetype/d; /^rm -rf zlib/d; """
            r"""s|^mv \$SRC/freetype freetype|if [ ! -d freetype ] && [ -d "$SRC/freetype" ]; then cp -a "$SRC/freetype" freetype; fi|; """
            r"""s|^if \[ -d "\$SRC/freetype" \]; then cp -a "\$SRC/freetype" freetype; fi|if [ ! -d freetype ] && [ -d "$SRC/freetype" ]; then cp -a "$SRC/freetype" freetype; fi|' """
            "/src/build.sh",
            user="root",
        )
        if ret != 0:
            logger.warning("Failed to patch ghostscript /src/build.sh")

    if project == "libredwg":
        # libredwg's build.sh re-runs ./autogen.sh on every compile. The
        # container's autoconf (2.69) regenerates src/config.h.in in a
        # different form than the committed file (autoconf 2.72+), which
        # rewrites src/config.h -- and every library object depends on it, so
        # all 39 sources recompile: ~9 min per build instead of ~21s.
        # Skip autogen once configure exists. `git clean -fdx` removes
        # configure between bugs, so each bug's first compile still
        # regenerates the full autotools stack from scratch; only the agent's
        # repeated rebuilds within a bug become incremental. The -nt guard
        # re-runs autogen if an agent edits configure.ac.
        ret = _exec(
            container_name,
            r"""sed -i 's@^sh \./autogen\.sh$@if [ ! -f configure ] || """
            r"""[ configure.ac -nt configure ]; then sh ./autogen.sh; fi@' """
            "/src/build.sh",
            user="root",
        )
        if ret != 0:
            logger.warning("Failed to patch libredwg /src/build.sh")

    # Several OSS-Fuzz build.sh files create a side build dir with a bare
    # `mkdir build` -- ntopng and ndpi both do it for the json-c they vendor.
    # In a reused container that directory survives the previous compile, so
    # `mkdir` fails, and under `set -e` it takes the whole build with it: the
    # bug then reports as failed with a sound agent diff already on disk.
    # `mkdir -p` is a no-op difference on a clean tree, so apply it for every
    # project rather than naming them one at a time.
    ret = _exec(
        container_name,
        r"""sed -i -E 's|^([[:space:]]*)mkdir[[:space:]]+build[[:space:]]*$|\1mkdir -p build|' /src/build.sh""",
        user="root",
    )
    if ret != 0:
        logger.warning("Failed to make `mkdir build` idempotent in /src/build.sh")


def _build_container_env(language: str) -> list[str]:
    """Match the default build env used by fuzz_helper.py build_version."""
    return [
        "FUZZING_ENGINE=libfuzzer",
        "SANITIZER=address",
        "ARCHITECTURE=x86_64",
        f"FUZZING_LANGUAGE={language}",
        "HELPER=True",
        # -j matters: libredwg and friends are autotools/make, where
        # CMAKE_BUILD_PARALLEL_LEVEL does nothing.  Without it every make
        # build ran serially (~540s cold for libredwg, ~72s per file).
        # --output-sync=line only has meaning for a parallel build.
        "MAKEFLAGS=-j30 --output-sync=line",
        "CMAKE_BUILD_PARALLEL_LEVEL=30",
        "NINJA_STATUS=",
        "TERM=dumb",
        "CLICOLOR=0",
        "FORCE_COLOR=0",
        "GCC_COLORS=",
        "CLANG_FORCE_COLOR=0",
        "CMAKE_COLOR_DIAGNOSTICS=OFF",
    ]

def _run_quiet(cmd: list[str], label: str = "", **kwargs) -> int:
    """Run a command, capture output, and only show it on failure.

    On success, output is logged at DEBUG level.
    On failure, the last 30 lines of combined output are logged at ERROR.
    """
    label = label or cmd[0]
    logger.info("Running: %s", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace", **kwargs)
    combined = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        tail = "\n".join(combined.splitlines()[-30:])
        logger.error("[%s] failed (exit %d). Last 30 lines:\n%s",
                     label, proc.returncode, tail)
    elif combined.strip():
        logger.debug("[%s] output:\n%s", label, combined.strip())
    return proc.returncode


# Projects where the git repo directory differs from the project name.
_SOURCE_REPO_MAP: dict[str, str] = {
    "ghostscript": "ghostpdl",
    "php": "php-src",
}


def _source_dir(project: str) -> str:
    """Return the source directory path for a project inside the container."""
    repo_name = _SOURCE_REPO_MAP.get(project, project)
    return f"/src/{repo_name}"


# ---------------------------------------------------------------------------
# Phase 0: Collect crash and trace data
# ---------------------------------------------------------------------------

def collect_crash_data(args: argparse.Namespace) -> bool:
    """Run fuzz_helper.py collect_crash to get the crash stack."""
    crash_file = (
        DATA_DIR / "crash"
        / f"target_crash-{args.buggy_commit[:8]}-{args.testcase}.txt"
    )
    if crash_file.exists():
        logger.info("Crash data already exists: %s", crash_file)
        return True

    logger.info("Collecting crash data for %s at %s...", args.project, args.buggy_commit)
    cmd = [
        sys.executable, str(FUZZ_HELPER),
        "collect_crash", args.project,
        args.fuzzer_name,
        "--commit", args.buggy_commit,
        "--testcases", args.testcases_dir,
        "--test_input", args.testcase,
        "--ignore-leaks",
    ]
    if args.build_csv:
        cmd += ["--build_csv", args.build_csv]
    cmd += ["--runner-image", args.runner_image or "auto"]

    ret = _run_quiet(cmd, label="collect_crash")
    if ret != 0:
        return False

    if not crash_file.exists():
        logger.error("Expected crash file not found: %s", crash_file)
        return False

    logger.info("Crash data collected: %s", crash_file)
    return True


def collect_trace_data(args: argparse.Namespace) -> bool:
    """Run fuzz_helper.py collect_trace to get the function trace."""
    trace_file = (
        TRACE_DIR
        / f"target_trace-{args.buggy_commit[:8]}-{args.testcase}.txt"
    )
    TRACE_DIR.mkdir(parents=True, exist_ok=True)
    if trace_file.exists():
        logger.info("Trace data already exists: %s", trace_file)
        return True

    logger.info("Collecting trace data for %s at %s...", args.project, args.buggy_commit)
    cmd = [
        sys.executable, str(FUZZ_HELPER),
        "collect_trace", args.project,
        args.fuzzer_name,
        "--commit", args.buggy_commit,
        "--testcases", args.testcases_dir,
        "--test_input", args.testcase,
    ]
    if args.build_csv:
        cmd += ["--build_csv", args.build_csv]
    cmd += ["--runner-image", args.runner_image or "auto"]

    ret = _run_quiet(cmd, label="collect_trace")
    if ret != 0:
        return False

    if not trace_file.exists():
        logger.error("Expected trace file not found: %s", trace_file)
        return False

    logger.info("Trace data collected: %s", trace_file)
    return True


def collect_fix_diff(args: argparse.Namespace) -> bool:
    """Generate a diff between the buggy commit and the adjacent CSV commit.

    The adjacent commit must be provided via args.adjacent_commit (pre-computed
    by bug_transplant_batch.py from the CSV row immediately after the buggy row
    in the direction of the target).

    Saves the diff to DATA_DIR/patch_diffs/fix_hint-<buggy_short>-<testcase>.diff.
    Returns True if the diff was saved (or already exists), False otherwise.
    """
    adjacent_commit = getattr(args, 'adjacent_commit', None)
    repo_path = getattr(args, 'repo_path', None)
    if not adjacent_commit or not repo_path:
        return False

    buggy_short = args.buggy_commit[:8]
    patch_diffs_dir = DATA_DIR / "patch_diffs"
    patch_diffs_dir.mkdir(exist_ok=True)
    out_path = patch_diffs_dir / f"fix_hint-{buggy_short}-{args.testcase}.diff"

    if out_path.exists():
        logger.info("Fix diff already exists: %s", out_path)
        return True

    try:
        diff_result = subprocess.run(
            ["git", "diff", args.buggy_commit, adjacent_commit],
            cwd=repo_path,
            capture_output=True, encoding="utf-8", errors="replace",
        )
        diff_text = diff_result.stdout
    except Exception as exc:
        logger.debug("collect_fix_diff git diff error: %s", exc)
        return False

    if not diff_text.strip():
        logger.info("Fix diff is empty — skipping")
        return False

    out_path.write_text(diff_text)
    logger.info("Fix diff saved: %s (adjacent=%s)", out_path, adjacent_commit[:8])
    return True


# ---------------------------------------------------------------------------
# Phase 1: Build Docker image with Codex layered on top
# ---------------------------------------------------------------------------

# Sibling repos an OSS-Fuzz Dockerfile clones unpinned, whose HEAD must match
# the project's target commit. ntopng 08a87f27 (2025) does not compile against
# current nDPI HEAD -- undeclared NDPI_MAX_SUPPORTED_PROTOCOLS, changed
# ndpi_get_upper_proto signature -- so every rebuilt image silently produces a
# tree that cannot build the fuzz target. Pinning in the project Dockerfile is
# not durable: prepare_repository() does `git clean -fdx` + `git checkout -f`
# on the oss-fuzz checkout before each build. Pin the built image instead.
_PROJECT_SIBLING_PINS: dict[str, dict[str, str]] = {
    "ntopng": {"nDPI": "5424d144242c5b85176465acb7376237d80c6d91"},
}


def _pin_image_siblings(project: str, image_tag: str) -> None:
    """Check out pinned sibling repos inside *image_tag*, in place.

    Applied as a ``docker build`` layer rather than ``docker run`` +
    ``docker commit``: commit writes the *container's* config into the image,
    so the ``--entrypoint bash`` needed to run git would be baked in as the
    image's ENTRYPOINT. The Codex layer on top then inherits it and its
    ``CMD ["sleep","infinity"]`` runs as ``bash sleep infinity``, which exits
    at once -- the shared container dies before the first agent session.
    A RUN layer leaves Entrypoint and Cmd untouched.
    """
    pins = _PROJECT_SIBLING_PINS.get(project)
    if not pins:
        return
    steps = "".join(
        f'RUN git -C /src/{repo} fetch --quiet origin {sha} 2>/dev/null || true; \\\n'
        f'    git -C /src/{repo} checkout --force --quiet {sha} && \\\n'
        f'    echo "pinned {repo} -> {sha[:12]}"\n'
        for repo, sha in pins.items()
    )
    dockerfile = f"FROM {image_tag}\n{steps}"
    # Empty build context: the repo would otherwise be uploaded to the daemon.
    # --progress=plain so BuildKit echoes the RUN output we log below.
    with tempfile.TemporaryDirectory() as ctx:
        ret = subprocess.run(
            ["docker", "build", "--progress=plain", "-t", image_tag, "-f", "-", ctx],
            input=dockerfile, capture_output=True,
            encoding="utf-8", errors="replace",
        )
    if ret.returncode != 0:
        logger.warning("[%s] sibling pin failed: %s", project,
                       ((ret.stderr or "") + (ret.stdout or ""))[-500:])
        return
    seen: set[str] = set()
    for line in ((ret.stdout or "") + (ret.stderr or "")).splitlines():
        if "pinned " not in line:
            continue
        # BuildKit echoes both the RUN command and its output; strip the shell
        # quoting from the echo so the same pin is not logged twice.
        msg = line.split("pinned ", 1)[1].strip().strip('"')
        if msg not in seen:
            seen.add(msg)
            logger.info("[%s] pinned %s", project, msg)


def build_project_image(
    project: str,
    target_commit: str | None = None,
    build_csv: str | None = None,
) -> str:
    """Build the OSS-Fuzz project image using the correct OSS-Fuzz commit.

    Uses ``fuzz_helper.py build_version`` to call ``prepare_repository()``
    (checkout matching OSS-Fuzz commit) and ``build_image_impl()`` so the
    project's ``build.sh`` matches the target commit.

    Returns the project image tag.
    """
    image_tag = f"gcr.io/oss-fuzz/{project}"

    # Use fuzz_helper.py build_version to build with correct OSS-Fuzz commit.
    # This calls prepare_repository() + build_image_impl() + runs a build.
    # Even if the image exists, re-build to ensure build.sh matches.
    if target_commit:
        logger.info("Building project image for %s at commit %s...", project, target_commit[:12])
        cmd = [
            sys.executable, str(FUZZ_HELPER),
            "build_version", project,
            "--commit", target_commit,
            "--no_corpus",
            "--runner-image", "auto",
        ]
        if build_csv:
            cmd += ["--build_csv", build_csv]
        ret = _run_quiet(cmd, label="build_version")
        if ret != 0:
            logger.error("fuzz_helper.py build_version failed for %s", project)
            sys.exit(1)
        _pin_image_siblings(project, image_tag)
        return image_tag

    # Fallback: simple build_image if no target commit
    ret = subprocess.call(
        ["docker", "image", "inspect", image_tag],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if ret == 0:
        logger.info("Project image already exists: %s", image_tag)
        return image_tag

    logger.info("Building OSS-Fuzz project image for %s...", project)
    helper_py = OSS_FUZZ_DIR / "infra" / "helper.py"
    ret = _run_quiet(
        [sys.executable, str(helper_py), "build_image", project],
        label="build_image",
    )
    if ret != 0:
        logger.error("Failed to build project image for %s", project)
        sys.exit(1)

    return image_tag


def _image_workdir(image_tag: str) -> str:
    """Return an image's configured working directory, defaulting to /src.

    ``compile`` only works reliably in the base image's original WORKDIR
    (e.g. /src for most projects, /src/ghostpdl for ghostscript), so we
    capture it here to bake into the compile wrapper without overriding
    the WORKDIR itself.
    """
    proc = subprocess.run(
        ["docker", "image", "inspect", image_tag, "--format", "{{.Config.WorkingDir}}"],
        capture_output=True,
        encoding="utf-8", errors="replace",
    )
    if proc.returncode == 0:
        workdir = proc.stdout.strip()
        if workdir:
            return workdir
    logger.warning("Could not inspect workdir for %s; defaulting to /src", image_tag)
    return "/src"


def build_agent_image(project: str, project_image: str) -> str:
    """Layer the Codex CLI on top of the project image.

    Produces ``bug-transplant-<project>:latest``.
    """
    npm_pkg = CODEX_CONFIG["npm_package"]
    cli_name = CODEX_CONFIG["cli_name"]
    cli_entry = CODEX_CONFIG["cli_entry"]
    tag = f"bug-transplant-{project}:latest"
    base_workdir = _image_workdir(project_image)

    # Resolve the current project image's content ID so we can invalidate
    # the agent-image cache whenever the project image has been rebuilt
    # (e.g. by fuzz_helper.py build_version pinning a new base-builder
    # digest). Without this check, the agent image keeps the stale project
    # layers it was first built against, silently diverging from the base
    # image used for original crash classification.
    project_id_result = subprocess.run(
        ["docker", "image", "inspect", project_image, "--format", "{{.Id}}"],
        capture_output=True, encoding="utf-8", errors="replace",
    )
    if project_id_result.returncode != 0:
        logger.error(
            "Failed to inspect project image %s: %s",
            project_image, project_id_result.stderr.strip(),
        )
        sys.exit(1)
    project_image_id = project_id_result.stdout.strip()

    # Skip rebuild only when BOTH the base WORKDIR and the underlying
    # project image ID match what the cached agent image was built from.
    inspect = subprocess.run(
        ["docker", "image", "inspect", tag, "--format",
         '{{index .Config.Labels "bug-transplant.base-workdir"}}|'
         '{{index .Config.Labels "bug-transplant.project-image-id"}}'],
        capture_output=True,
        encoding="utf-8", errors="replace",
    )
    if inspect.returncode == 0:
        cached_workdir, _, cached_project_id = inspect.stdout.strip().partition("|")
        if cached_workdir == base_workdir and cached_project_id == project_image_id:
            logger.info("Agent image already exists, reusing: %s", tag)
            return tag
        if cached_workdir != base_workdir:
            logger.info(
                "Rebuilding agent image %s because baked base WORKDIR is %r, expected %r",
                tag, cached_workdir, base_workdir,
            )
        else:
            logger.info(
                "Rebuilding agent image %s because project image ID changed "
                "(cached %s..., current %s...)",
                tag, cached_project_id[:19], project_image_id[:19],
            )
        subprocess.call(
            ["docker", "rmi", "-f", tag],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    logger.info("Building %s agent image '%s' on top of '%s'...",
                ACTIVE_AGENT, tag, project_image)

    dockerfile_content = textwrap.dedent(f"""\
        # Stage 1: Install agent CLI on a modern base (glibc >= 2.28).
        FROM ubuntu:22.04 AS agent-builder
        ENV DEBIAN_FRONTEND=noninteractive
        RUN apt-get update && apt-get install -y --no-install-recommends \\
                curl ca-certificates \\
            && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \\
            && apt-get install -y --no-install-recommends nodejs \\
            && npm install -g {npm_pkg}@{CODEX_VERSION} \\
            && rm -rf /var/lib/apt/lists/*

        # Stage 2: Project image with agent CLI copied in.
        FROM {project_image}
        ENV DEBIAN_FRONTEND=noninteractive

        # Copy Node.js and agent CLI with all dependencies
        COPY --from=agent-builder /usr/bin/node /usr/local/bin/node
        COPY --from=agent-builder /usr/lib/node_modules /usr/local/lib/node_modules
        # Copy glibc and libstdc++ from builder so node binary works on old bases
        COPY --from=agent-builder /lib/x86_64-linux-gnu/libc.so.6 /opt/node-libs/libc.so.6
        COPY --from=agent-builder /lib/x86_64-linux-gnu/libm.so.6 /opt/node-libs/libm.so.6
        COPY --from=agent-builder /lib/x86_64-linux-gnu/libpthread.so.0 /opt/node-libs/libpthread.so.0
        COPY --from=agent-builder /lib/x86_64-linux-gnu/libdl.so.2 /opt/node-libs/libdl.so.2
        COPY --from=agent-builder /lib/x86_64-linux-gnu/librt.so.1 /opt/node-libs/librt.so.1
        COPY --from=agent-builder /lib64/ld-linux-x86-64.so.2 /opt/node-libs/ld-linux-x86-64.so.2
        COPY --from=agent-builder /usr/lib/x86_64-linux-gnu/libstdc++.so.6 /opt/node-libs/libstdc++.so.6
        COPY --from=agent-builder /lib/x86_64-linux-gnu/libgcc_s.so.1 /opt/node-libs/libgcc_s.so.1

        # Create wrapper script that uses the bundled libs
        RUN echo '#!/bin/bash' > /usr/local/bin/{cli_name} \\
            && echo 'exec /opt/node-libs/ld-linux-x86-64.so.2 --library-path /opt/node-libs /usr/local/bin/node /usr/local/lib/node_modules/{cli_entry} "$@"' >> /usr/local/bin/{cli_name} \\
            && chmod +x /usr/local/bin/{cli_name}

        # sudo may not exist on older base images
        RUN apt-get update && apt-get install -y --no-install-recommends sudo \\
            && rm -rf /var/lib/apt/lists/* || true

        # Create a non-root user (some CLIs refuse to run as root)
        RUN (useradd -m -d /home/agent -s /bin/bash agent 2>/dev/null || true) \\
            && echo "agent ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \\
            && chown -R agent:agent /src/ /out/ /work/ || true

        # Wrapper so the agent can call "compile" without sudo
        # (codex CLI may block sudo even with --dangerously-bypass-approvals-and-sandbox)
        # compile only works reliably from the base image's original
        # WORKDIR, so cd there explicitly and do not override WORKDIR below.
        RUN printf '#!/bin/bash\\ncd {base_workdir} && exec sudo -E /usr/local/bin/compile "$@"\\n' \
            > /home/agent/compile && chmod +x /home/agent/compile

        ENV HOME=/home/agent
        ENV PATH="/home/agent:$PATH"
        USER agent

        LABEL bug-transplant.base-workdir="{base_workdir}"
        LABEL bug-transplant.project-image-id="{project_image_id}"
        CMD ["sleep", "infinity"]
    """)

    with tempfile.TemporaryDirectory() as tmpdir:
        df_path = Path(tmpdir) / "Dockerfile"
        df_path.write_text(dockerfile_content)
        ret = _run_quiet(
            ["docker", "build", "-t", tag, "-f", str(df_path), tmpdir],
            label="build_agent_image",
        )
        if ret != 0:
            logger.error("Failed to build %s agent image", ACTIVE_AGENT)
            sys.exit(1)

    logger.info("%s agent image built: %s", ACTIVE_AGENT, tag)
    return tag


# ---------------------------------------------------------------------------
# Phase 2 + 3: Run Codex inside a persistent container
# ---------------------------------------------------------------------------

def build_prompt(args: argparse.Namespace) -> str:
    """Read the prompt template and fill in parameters."""
    template = PROMPT_TEMPLATE.read_text()
    buggy_short = args.buggy_commit[:8]
    repo_dir = _container_repo_dir(args.project)
    agents_md = _container_agents_md_path(args.project)

    adjacent_commit = getattr(args, 'adjacent_commit', None)
    if adjacent_commit:
        fix_diff_line = (
            f"\n- `/data/patch_diffs/fix_hint-{buggy_short}-{args.testcase}.diff` -- "
            f"diff from buggy commit to adjacent CSV commit `{adjacent_commit[:8]}` "
            f"(optional hint from the next tested commit toward the fix; use if helpful, not as a required recipe)"
        )
        adjacent_commit_hint = (
            f" If available, you may inspect"
            f" `/data/patch_diffs/fix_hint-{buggy_short}-{args.testcase}.diff`:"
            f" it is the diff from the buggy commit to the next tested commit"
            f" `{adjacent_commit[:8]}` and may contain a relevant clue, but it is only a hint."
        )
    else:
        fix_diff_line = ""
        adjacent_commit_hint = ""

    source_dir = getattr(args, "source_dir", None) or _source_dir(args.project)
    prompt = template.format(
        project=args.project,
        bug_id=args.bug_id,
        buggy_commit=args.buggy_commit,
        target_commit=args.target_commit,
        buggy_short=buggy_short,
        testcase_name=args.testcase,
        fuzzer_name=args.fuzzer_name,
        repo_dir=repo_dir,
        agents_md=agents_md,
        fix_diff_line=fix_diff_line,
        adjacent_commit=adjacent_commit or "",
        adjacent_commit_hint=adjacent_commit_hint,
        source_dir=source_dir,
    )
    return prompt


def _write_minimize_delta(output_dir: Path, premin_path: Path,
                          final_path: Path, minimized_kept: bool) -> Path:
    """Write a unified diff of the pre- vs post-minimization patches.

    The result shows what the minimize agent stripped out (or added back).
    ``minimized_kept`` is False when post-minimize verification failed and
    the pre-minimize patch was restored -- the delta is then empty by
    construction, and we say so in the header.
    """
    import difflib

    premin = premin_path.read_text() if premin_path.exists() else ""
    final = final_path.read_text() if final_path.exists() else ""
    delta_path = output_dir / "minimize_delta.diff"
    body = "".join(difflib.unified_diff(
        premin.splitlines(keepends=True),
        final.splitlines(keepends=True),
        fromfile="bug_transplant_premin.diff",
        tofile="bug_transplant.diff",
    ))
    header = (
        f"# pre-minimize patch: {len(premin)} bytes\n"
        f"# final patch:        {len(final)} bytes\n"
        f"# minimized patch kept: {minimized_kept}\n"
    )
    if not body:
        header += "# (no difference: minimization changed nothing)\n"
    delta_path.write_text(header + body)
    logger.info("Minimize delta saved: %s (%d -> %d bytes)",
                delta_path, len(premin), len(final))
    return delta_path


def _build_minimize_prompt(args: argparse.Namespace) -> str:
    """Read the minimize prompt template and fill in parameters."""
    template = MINIMIZE_TEMPLATE.read_text()
    source_dir = getattr(args, "source_dir", None) or _source_dir(args.project)
    return template.format(
        project=args.project,
        bug_id=args.bug_id,
        buggy_short=args.buggy_commit[:8],
        target_commit=args.target_commit,
        testcase_name=args.testcase,
        fuzzer_name=args.fuzzer_name,
        source_dir=source_dir,
    )


def setup_agents_dir(args: argparse.Namespace) -> Path:
    """Prepare a temporary directory containing AGENTS.md shared knowledge.

    Returns the path to the temporary directory that will be
    mounted into the container at /src/{project}/AGENTS.md.
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="bug_transplant_agents_"))

    # Seed AGENTS.md: use saved knowledge from a previous batch run if available,
    # otherwise fall back to the blank template.
    agents_md = tmpdir / "AGENTS.md"
    saved_agents_md = (
        DATA_DIR / "bug_transplant"
        / f"batch_{args.project}_{args.target_commit[:8]}"
        / "AGENTS.md"
    )
    if saved_agents_md.exists():
        agents_md.write_text(saved_agents_md.read_text())
        logger.info("Seeding AGENTS.md from previous run: %s", saved_agents_md)
    else:
        template = MEMORY_TEMPLATE.read_text()
        agents_md.write_text(template.format(
            project=args.project,
            target_commit=args.target_commit,
            fuzzer_name=args.fuzzer_name,
        ))

    return tmpdir


def create_shared_container(
    project: str,
    target_commit: str,
    container_name: str,
    agents_dir: Path,
    testcases_dir: str = "",
    env: list[str] | None = None,
    volume: list[str] | None = None,
) -> int:
    """Create a persistent container for batch bug transplant.

    Returns 0 on success, non-zero on failure.
    """
    image_tag = f"bug-transplant-{project}:latest"

    data_dir = str(DATA_DIR)
    testcases_dir = str(Path(testcases_dir).resolve()) if testcases_dir else ""
    script_dir = str(SCRIPT_DIR)
    out_dir = str(HOME_DIR / "build" / "out" / project)
    work_dir = str(HOME_DIR / "build" / "work" / project)

    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(work_dir, exist_ok=True)

    # Remove existing container with same name
    subprocess.call(
        ["docker", "rm", "-f", container_name],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    # Detect project language
    project_yaml = HOME_DIR / "oss-fuzz" / "projects" / project / "project.yaml"
    language = "c++"
    if project_yaml.exists():
        for line in project_yaml.read_text().splitlines():
            if line.startswith("language:"):
                language = line.split(":", 1)[1].strip().strip('"').strip("'")
                break

    docker_run_cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        "--privileged",
        "--shm-size=2g",
        "-v", f"{data_dir}:/data",
        "-v", f"{testcases_dir}:/corpus",
        "-v", f"{script_dir}:/script:ro",
        "-v", f"{out_dir}:/out",
        "-v", f"{work_dir}:/work",
        "-v", f"{agents_dir}/AGENTS.md:/src/{project}/AGENTS.md",
    ]
    for env_var in _build_container_env(language):
        docker_run_cmd += ["-e", env_var]

    # Mount codex credentials
    cred_dir = codex_cred_dir()
    if cred_dir.exists():
        docker_run_cmd += ["-v", f"{cred_dir}:/tmp/.agent-creds-src:ro"]
    for env_var in codex_api_key_env():
        docker_run_cmd += ["-e", env_var]
    docker_run_cmd += agent_mounts()

    if env:
        for e in env:
            docker_run_cmd += ["-e", e]
    if volume:
        for v in volume:
            docker_run_cmd += ["-v", v]

    docker_run_cmd += [image_tag, "sleep", "infinity"]

    repo_dir = _container_repo_dir(project)
    agents_md_path = _container_agents_md_path(project)
    logger.info("Creating shared container: %s", container_name)
    ret = _run_quiet(docker_run_cmd, label="docker-run-shared")
    if ret != 0:
        logger.error("Failed to create shared container")
        return 1

    # Initial setup: git safe directory, checkout, credentials
    _exec(container_name, "git config --global --add safe.directory '*'", user="root")
    clean_excludes = _git_clean_excludes(project)
    clean_ret = _exec(
        container_name,
        _container_in_dir(repo_dir, f"git clean -fdx {clean_excludes}"),
        user="root",
    )
    if clean_ret != 0:
        logger.warning("git clean returned %d (transient files?) — continuing", clean_ret)
    checkout_ret = _exec(
        container_name,
        _container_in_dir(repo_dir, f"git checkout -f {shlex.quote(target_commit)}"),
        user="root",
    )
    if checkout_ret != 0:
        logger.error(
            "Failed to prepare repo in container %s (repo_dir=%s)",
            container_name, repo_dir,
        )
        return 1
    if repo_dir != f"/src/{project}":
        _exec(
            container_name,
            f"ln -sf {shlex.quote(agents_md_path)} {shlex.quote(repo_dir)}/AGENTS.md 2>/dev/null || true",
            user="root",
        )
    _patch_build_sh_for_repeated_compile(container_name, project)
    _exec(container_name, "sudo chown -R agent:agent /src/ /out/ /work/ /data/ 2>/dev/null || true", user="root")

    # Setup codex credentials
    setup_codex_creds(container_name)

    logger.info("Shared container ready: %s", container_name)
    return 0


def run_agent_in_container(args: argparse.Namespace) -> int:
    """Start container, run Codex agent, collect results.

    Returns 0 on success, non-zero on failure.
    """
    image_tag = f"bug-transplant-{args.project}:latest"
    reuse_container = getattr(args, "container_name", None)
    container_name = reuse_container or f"bug-transplant-{args.project}-{args.bug_id}"
    buggy_short = args.buggy_commit[:8]

    # Prepare volumes
    data_dir = str(DATA_DIR)
    testcases_dir = str(Path(args.testcases_dir).resolve())
    script_dir = str(SCRIPT_DIR)
    # When this run owns its container (no --container-name), it may be one of
    # several running concurrently under `bug_transplant_batch.py --jobs N`.
    # Project-level /out and /work would then be bind-mounted into every
    # container at once: each bug builds /out/<fuzzer> over the others and the
    # verification step runs whichever binary won the race, against its own
    # testcase -- silently wrong results rather than a visible failure.  Give
    # each bug its own directories.  The shared-container path stays
    # project-level: it is sequential by construction.
    _mount_key = args.project if reuse_container else f"{args.project}_{args.bug_id}"
    out_dir = str(HOME_DIR / "build" / "out" / _mount_key)
    work_dir = str(HOME_DIR / "build" / "work" / _mount_key)

    # Clean and recreate build directories to avoid stale binaries/artifacts
    # from previous runs (prevents "Text file busy" and wrong test results).
    # When reusing a shared container, do NOT delete the host-side directories:
    # Docker bind-mount backing directories must not be removed while the
    # container is running — doing so breaks the mount inside the container.
    if reuse_container:
        os.makedirs(out_dir, exist_ok=True)
        os.makedirs(work_dir, exist_ok=True)
    else:
        shutil.rmtree(out_dir, ignore_errors=True)
        shutil.rmtree(work_dir, ignore_errors=True)
        os.makedirs(out_dir, exist_ok=True)
        os.makedirs(work_dir, exist_ok=True)

    # Use shared agents_dir if provided (batch mode), otherwise create new
    shared_agents_dir = getattr(args, "agents_dir", None)
    agents_dir = Path(shared_agents_dir) if shared_agents_dir else setup_agents_dir(args)
    owns_agents_dir = shared_agents_dir is None
    repo_dir = _container_repo_dir(args.project)
    agents_md_path = _container_agents_md_path(args.project)

    if not reuse_container:
        # --- Stop any existing container with the same name ---
        subprocess.call(
            ["docker", "rm", "-f", container_name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        # Detect project language from project.yaml
        project_yaml = HOME_DIR / "oss-fuzz" / "projects" / args.project / "project.yaml"
        language = "c++"
        if project_yaml.exists():
            for line in project_yaml.read_text().splitlines():
                if line.startswith("language:"):
                    language = line.split(":", 1)[1].strip().strip('"').strip("'")
                    break

        # --- Start persistent container ---
        docker_run_cmd = [
            "docker", "run", "-d",
            "--name", container_name,
            "--privileged",
            "--shm-size=2g",
            # Volumes
            "-v", f"{data_dir}:/data",
            "-v", f"{testcases_dir}:/corpus",
            "-v", f"{script_dir}:/script:ro",
            "-v", f"{out_dir}:/out",
            "-v", f"{work_dir}:/work",
            # AGENTS.md as shared memory (rw)
            "-v", f"{agents_dir}/AGENTS.md:/src/{args.project}/AGENTS.md",
        ]
        for env_var in _build_container_env(language):
            docker_run_cmd += ["-e", env_var]

        # Mount codex credentials (login mode)
        cred_dir = codex_cred_dir()
        if cred_dir.exists():
            docker_run_cmd += ["-v", f"{cred_dir}:/tmp/.agent-creds-src:ro"]
        for env_var in codex_api_key_env():
            docker_run_cmd += ["-e", env_var]
        docker_run_cmd += agent_mounts()

        # Additional user-specified env vars
        if args.env:
            for e in args.env:
                docker_run_cmd += ["-e", e]

        # Additional user-specified volume mounts
        if args.volume:
            for v in args.volume:
                docker_run_cmd += ["-v", v]

        docker_run_cmd += [image_tag, "sleep", "infinity"]

        logger.info("Starting container: %s", container_name)
        ret = _run_quiet(docker_run_cmd, label="docker-run")
        if ret != 0:
            logger.error("Failed to start container")
            return 1
    else:
        logger.info("Reusing container: %s", container_name)
        # An agent whose docker exec timed out on a previous bug is still
        # alive in here: it keeps reverting files in /src and deleting the
        # fuzz target in /out, which corrupts this bug's run.  Reap before
        # touching anything else.
        _exec_sweep(container_name, user="root")
        # Wipe /out and /work contents from inside the container so stale
        # binaries don't bleed across bugs. (We cannot rmtree the host-side
        # directories while the bind mount is live.)
        _exec(container_name, "rm -rf /out/* /work/*", user="root")

    try:
        args.source_dir = repo_dir
        prompt = build_prompt(args)
        repo_dir_q = shlex.quote(repo_dir)
        clean_excludes = _git_clean_excludes(args.project)

        # --- Checkout target commit inside container ---
        logger.info("Checking out target commit %s...", args.target_commit)
        _exec(container_name, "git config --global --add safe.directory '*'", user="root")
        # Clean build artifacts (cmake-generated Makefiles, .o files, etc.)
        # before checkout so they don't pollute the git diff later.
        clean_ret = _exec(
            container_name,
            _container_in_dir(repo_dir, f"git clean -fdx {clean_excludes}"),
            user="root",
        )
        if clean_ret != 0:
            logger.warning("git clean returned %d (transient files?) — continuing", clean_ret)
        checkout_ret = _exec(
            container_name,
            _container_in_dir(repo_dir, f"git checkout -f {shlex.quote(args.target_commit)}"),
            user="root",
        )
        if checkout_ret != 0:
            logger.error(
                "Failed to prepare repo in container %s (repo_dir=%s)",
                container_name, repo_dir,
            )
            return 1
        if repo_dir != f"/src/{args.project}":
            _exec(
                container_name,
                f"ln -sf {shlex.quote(agents_md_path)} {repo_dir_q}/AGENTS.md 2>/dev/null || true",
                user="root",
            )

        _patch_build_sh_for_repeated_compile(container_name, args.project)

        # Snapshot /src/build.sh after our legitimate hygiene edits so the
        # between-bug reset can restore it if an agent modified it. Without
        # this, one agent's build.sh edit (e.g. adding `python3 /tmp/foo.py`)
        # contaminates every subsequent bug's `compile` in the shared
        # container.
        _exec(
            container_name,
            "if [ ! -f /src/build.sh.transplant_pristine ]; then "
            "cp /src/build.sh /src/build.sh.transplant_pristine; fi",
            user="root",
        )

        # --- Copy testcase to /work for easier access ---
        minimize_only = bool(getattr(args, "minimize_only", False))
        saved_dir = DATA_DIR / "bug_transplant" / f"{args.project}_{args.bug_id}"
        saved_tc = saved_dir / args.testcase
        if minimize_only and saved_tc.exists():
            # The transplant may have patched the testcase binary; the saved
            # one is what the patch was verified against, not /corpus.
            ctc = f"/data/bug_transplant/{args.project}_{args.bug_id}/{args.testcase}"
            _exec(
                container_name,
                f"cp {shlex.quote(ctc)} /work/{args.testcase} && "
                f"cp {shlex.quote(ctc)} /out/{args.testcase}",
                user="root",
            )
        else:
            _exec(
                container_name,
                f"cp /corpus/{args.testcase} /work/{args.testcase}",
                user="root",
            )
        _exec(container_name, "sudo chown -R agent:agent /src/ /out/ /work/ /data/ 2>/dev/null || true", user="root")

        # --- Setup codex credentials ---
        setup_codex_creds(container_name)

        # --- Run agent (or, in --minimize-only mode, re-apply its patch) ---
        codex_mode = getattr(args, "codex_mode", "exec")
        if minimize_only:
            saved_diff = saved_dir / "bug_transplant.diff"
            if not saved_diff.exists() or not saved_diff.stat().st_size:
                logger.error("--minimize-only: no patch to minimize at %s",
                             saved_diff)
                return 1
            logger.info("Minimize-only: re-applying saved patch %s (%d bytes)",
                        saved_diff, saved_diff.stat().st_size)
            cdiff = (f"/data/bug_transplant/{args.project}_{args.bug_id}"
                     "/bug_transplant.diff")
            # The `chown -R agent:agent /src/` above invalidates git's stat
            # cache, so `git apply --3way` (which implies --index) fails with
            # "does not match index". Refresh the cache, apply against the
            # worktree, and keep --3way only as a fallback for context drift.
            apply_ret = _exec(
                container_name,
                _container_in_dir(
                    repo_dir,
                    "git update-index -q --refresh || true; "
                    f"git apply {shlex.quote(cdiff)} || "
                    f"git apply --3way {shlex.quote(cdiff)}",
                ),
                user="root",
            )
            if apply_ret != 0:
                logger.error("--minimize-only: failed to apply %s", saved_diff)
                return 1
            _exec(container_name,
                  "sudo chown -R agent:agent /src/ /out/ /work/ 2>/dev/null || true",
                  user="root")
            exit_code, output, elapsed = 0, "", 0.0
        else:
            logger.info("Running %s agent (mode=%s, this may take a while)...",
                         ACTIVE_AGENT, codex_mode)
            agent_cmd = build_codex_command(
                prompt, getattr(args, "model", None), mode=codex_mode,
            )
            agent_cmd = _container_in_dir(repo_dir, agent_cmd)

            start_time = time.monotonic()
            if codex_mode == "interactive":
                exit_code, output = _exec_interactive(
                    container_name, agent_cmd, timeout=args.timeout,
                )
            else:
                exit_code, output = _exec_capture(
                    container_name, agent_cmd, timeout=args.timeout,
                )
            elapsed = time.monotonic() - start_time

            if _usage_tracker:
                _usage_tracker.log_usage("transplant", output, getattr(args, "model", None))

            logger.info(
                "%s agent finished in %.0fs (exit code %d)",
                ACTIVE_AGENT, elapsed, exit_code,
            )

        # --- Save output ---
        output_dir = DATA_DIR / "bug_transplant" / f"{args.project}_{args.bug_id}"
        os.makedirs(output_dir, exist_ok=True)

        if minimize_only:
            # Keep the original transplant transcript; this run produced none.
            pass
        elif codex_mode == "interactive":
            # TUI output captured via tmux pipe-pane (includes ANSI codes)
            (output_dir / "agent_output_tui.txt").write_text(output)
        else:
            # Save raw JSONL and human-readable transcript
            (output_dir / "agent_output.jsonl").write_text(output)
            (output_dir / "agent_output.txt").write_text(
                _format_codex_output(output)
            )

        # Check if agent declared the bug impossible to transplant
        impossible_path = output_dir / "bug_transplant.impossible"
        imp_ret = subprocess.run(
            ["docker", "exec", container_name,
             "bash", "-c", "cat /out/bug_transplant.impossible"],
            capture_output=True, timeout=10,
        )
        if imp_ret.returncode == 0 and imp_ret.stdout.strip():
            impossible_path.write_text(imp_ret.stdout.decode(errors='replace'))
        if impossible_path.exists():
            reason = impossible_path.read_text().strip()
            logger.warning("Agent declared bug impossible: %s", reason)
            return 0  # treat as success (intentional skip)

        # Collect source-only diff (exclude build artifacts from CMake
        # in-source builds, .o/.a/.so files, and agent config dirs).
        # Always regenerate from git to avoid the agent accidentally
        # capturing build artifacts via bare `git diff`.
        diff_path = output_dir / "bug_transplant.diff"
        _git_diff_excludes = (
            "':(exclude).codex/' "
            "':(exclude)CMakeFiles/' ':(exclude)*/CMakeFiles/' "
            "':(exclude)CMakeCache.txt' ':(exclude)cmake_install.cmake' "
            "':(exclude)*/cmake_install.cmake' ':(exclude)CTestTestfile.cmake' "
            "':(exclude)*/CTestTestfile.cmake' ':(exclude)CPackConfig.cmake' "
            "':(exclude)CPackSourceConfig.cmake' ':(exclude)cmake_uninstall.cmake' "
            "':(exclude)Makefile' ':(exclude)*/Makefile' "
            "':(exclude)*.o' ':(exclude)*.a' ':(exclude)*.so' ':(exclude)*.so.*' "
            "':(exclude)*.d' ':(exclude)*.pc' ':(exclude)config.h' "
            "':(exclude)*config.h.in' "
            "':(exclude)build/' ':(exclude)_build/'"
        )
        # Ghostscript: build.sh replaces freetype/ and zlib/ with external
        # copies and removes cups/libs/ and libpng/; exclude these
        # build-script artifacts so they do not pollute bug_transplant.diff.
        if args.project == "ghostscript":
            _git_diff_excludes += (
                " ':(exclude)freetype/' ':(exclude)zlib/'"
                " ':(exclude)cups/libs/' ':(exclude)libpng/'"
            )
        # ntopng's Docker/image setup can leave submodule gitlinks checked out
        # at revisions different from the target commit. Those are not source
        # edits from the transplant and must not force a minimization pass for
        # testcase-only results.
        if args.project == "ntopng":
            _git_diff_excludes += (
                " ':(exclude)httpdocs/dist' ':(exclude)tests/e2e'"
            )
        _, git_diff = _exec_capture(
            container_name,
            _container_in_dir(repo_dir, f"git diff HEAD -- . {_git_diff_excludes}"),
        )
        diff_path.write_text(git_diff)
        has_source_diff = bool(git_diff.strip())
        if has_source_diff:
            logger.info("Source diff saved: %s (%d bytes)", diff_path, len(git_diff))
        else:
            logger.info("Diff is empty (testcase-only transplant or no changes)")

        # --- Collect modified testcase (agent may have patched it) ---
        # Use docker exec + cat to avoid docker cp bind mount issues
        testcase_out = output_dir / args.testcase
        for tc_src in [f"/out/{args.testcase}", f"/work/{args.testcase}", f"/tmp/{args.testcase}"]:
            tc_ret = subprocess.run(
                ["docker", "exec", container_name,
                 "bash", "-c", f"cat {tc_src}"],
                capture_output=True, timeout=30,
            )
            if tc_ret.returncode == 0 and tc_ret.stdout:
                testcase_out.write_bytes(tc_ret.stdout)
                logger.info("Collected testcase from %s: %s", tc_src, testcase_out)
                break
        else:
            logger.warning("No modified testcase found in container")

        # ---------------------------------------------------------------
        # Post-agent verification: rebuild with official `compile` and
        # check that the bug actually triggers.  The agent may have used
        # a non-standard build that produces different binaries.
        # ---------------------------------------------------------------
        if exit_code == 0 or (getattr(args, "skip_verify", False)
                              and has_source_diff):
            if exit_code != 0:
                logger.warning(
                    "Agent exited %d but --skip-verify is set and a source "
                    "diff exists -- continuing to minimization anyway",
                    exit_code,
                )
            logger.info("=== Post-agent verification ===")
            fuzzer = args.fuzzer_name
            testcase = args.testcase
            warned_relaxed_crash_match = False

            # Force official build (delete fuzzer binary to force re-link;
            # autotools/cmake may not re-link when only library sources change)
            logger.info("Rebuilding with official compile...")
            _exec_capture(
                container_name,
                f"find {repo_dir_q} -name '{fuzzer}' -type f -executable -delete; "
                f"rm -f /out/{fuzzer}",
            )
            # 300s suits the normal flow, where the agent has already built
            # the tree and this rebuild is incremental. In --minimize-only
            # mode the tree was just cleaned, so this is the cold build and
            # needs the full budget (libredwg alone takes ~540s).
            ret_build, build_out = _exec_capture(
                container_name,
                "sudo -E compile 2>&1",
                timeout=_VERIFY_BUILD_TIMEOUT,
            )
            if ret_build != 0:
                # A non-zero `compile` does not always mean the fuzz target is
                # missing. ndpi's build.sh ends with `make unit`, which builds
                # the project's unit-test binary -- at historical commits that
                # step fails ("json.h file not found") because OSS-Fuzz's
                # current build.sh is newer than the pinned source, long after
                # every /out/fuzz_* target has been linked. Treating that as
                # fatal threw away sound transplants. Mirror the merge flow:
                # the target binary's existence is the build's real outcome.
                ret_bin, _ = _exec_capture(
                    container_name, f"test -x /out/{fuzzer}",
                )
                if ret_bin != 0:
                    logger.error("Official compile failed after agent run")
                    logger.error("Build tail: %s", build_out[-500:] if build_out else "")
                    return 1
                logger.warning(
                    "compile exited %d but /out/%s was built -- continuing. "
                    "Build tail: %s",
                    ret_build, fuzzer, build_out[-300:] if build_out else "",
                )

            # Restore testcase: prefer agent's modified copy from /out,
            # fall back to /work (agent may have modified in-place),
            # last resort: original from /corpus
            _exec_capture(
                container_name,
                f"if [ -f /out/{testcase} ]; then cp /out/{testcase} /work/{testcase}; "
                f"elif [ ! -f /work/{testcase} ]; then cp /corpus/{testcase} /work/{testcase}; fi; true",
            )

            # Run fuzzer via the shared verification protocol (10 attempts
            # x 2 ASAN variants, stack-match against the reference crash).
            original_crash_file = (
                DATA_DIR / "crash"
                / f"target_crash-{buggy_short}-{testcase}.txt"
            )
            crash_log = (
                str(original_crash_file) if original_crash_file.exists() else None
            )
            if getattr(args, "skip_verify", False):
                logger.info("Post-agent verification SKIPPED (--skip-verify): "
                            "treating the transplant as successful")
                trigger_ok = True
            else:
                trigger_ok = verify_bug_triggers(
                    container_name, args.bug_id, fuzzer, testcase,
                    sanitizer="address", crash_log=crash_log,
                    fuzzer_path=f"/out/{fuzzer}",
                )
            # Capture a fresh fuzzer output so the saved crash log reflects
            # what the verifier just saw (and so the post-minimize diff
            # step has a reference text for stack-matching).
            # -rss_limit_mb: libFuzzer's 2048MB default also caps a single
            # allocation, so a bug reached through a large malloc (htslib
            # OSV-2020-999 allocates 4GB in vcf_parse_format) aborts as
            # `out-of-memory` here and the saved crash log records that
            # instead of the real fault. Use the same cap the verifier ran
            # with, so the log matches what it just judged.
            _, fuzz_out = _exec_capture(
                container_name,
                f"export ASAN_OPTIONS=detect_leaks=0"
                f":external_symbolizer_path=/out/llvm-symbolizer; "
                f"/out/{fuzzer} -runs=10 -rss_limit_mb={_RSS_LIMIT_MB} "
                f"/work/{testcase} 2>&1",
                timeout=120,
            )

            if trigger_ok:
                logger.info("Post-agent verification PASSED: bug triggers "
                            "with official build")
                # Save crash stack
                crash_out_path = output_dir / "transplant_crash.txt"
                crash_out_path.write_text(fuzz_out)
                logger.info("Crash stack saved: %s", crash_out_path)

                if not has_source_diff:
                    logger.info("=== Minimization phase ===")
                    logger.info("Skipping minimization: source diff is empty "
                                "after post-agent verification")
                    skip_output = (
                        "Minimization skipped because the verified source diff is empty.\n"
                        "This run produced a testcase-only transplant or no-op source "
                        "transplant, so there is no patch to minimize.\n"
                        "bug_transplant.diff intentionally remains empty.\n"
                    )
                    if codex_mode != "interactive":
                        (output_dir / "minimize_output.jsonl").write_text(skip_output)
                    (output_dir / "minimize_output.txt").write_text(skip_output)
                    return exit_code

                # --- Phase 2: Minimization (resume transplant session) ---
                logger.info("=== Minimization phase ===")
                # Clear verdict markers from an earlier attempt so a re-run
                # (notably --minimize-only) cannot leave this bug looking
                # failed after it has just succeeded.
                for stale in ("minimize_failed.txt", "minimize_unverified.txt"):
                    (output_dir / stale).unlink(missing_ok=True)
                # Snapshot the verified, not-yet-minimized patch so the
                # minimizer's effect can be inspected afterwards.
                premin_path = output_dir / "bug_transplant_premin.diff"
                _, premin_diff = _exec_capture(
                    container_name,
                    _container_in_dir(repo_dir, f"git diff HEAD -- . {_git_diff_excludes}"),
                )
                premin_path.write_text(premin_diff)
                logger.info("Pre-minimize diff saved: %s (%d bytes)",
                            premin_path, len(premin_diff))
                minimize_budget = _minimize_budget(args)
                if not minimize_budget:
                    logger.warning(
                        "Skipping minimization: only %.0fs of the caller's "
                        "%ss budget remain -- keeping the verified patch",
                        max(0.0, args.total_budget - (time.monotonic() - _RUN_START)),
                        args.total_budget,
                    )
                    skip_output = (
                        "Minimization skipped: not enough of the caller's "
                        "wall-clock budget remained after the transplant "
                        "phase.  The saved patch is the verified, "
                        "un-minimized one.\n"
                    )
                    if codex_mode != "interactive":
                        (output_dir / "minimize_output.jsonl").write_text(skip_output)
                    (output_dir / "minimize_output.txt").write_text(skip_output)
                    _write_minimize_delta(output_dir, premin_path, diff_path,
                                          minimized_kept=False)
                    return exit_code
                if minimize_budget < args.minimize_timeout:
                    logger.warning(
                        "Minimize budget trimmed to %ds (asked %ds): earlier "
                        "phases used more of the caller's %ss budget than "
                        "expected", minimize_budget, args.minimize_timeout,
                        args.total_budget,
                    )
                minimize_prompt = _build_minimize_prompt(args)
                # Resume the transplant session so the agent keeps
                # build-environment context (workarounds, paths, etc.)
                transplant_session_id = (
                    _extract_session_id(output) if codex_mode != "interactive"
                    else None
                )
                if transplant_session_id:
                    logger.info("Resuming transplant session %s for minimization",
                                transplant_session_id)
                else:
                    logger.info("No session ID found, starting fresh minimization session")
                minimize_cmd = build_codex_command(
                    minimize_prompt, getattr(args, "model", None),
                    mode=codex_mode,
                    resume_session=transplant_session_id,
                )
                # Must run in the repo, exactly like the transplant call
                # above. Without this the agent starts in the image WORKDIR
                # (/src), opencode bootstraps an instance there and then a
                # second, nested one for the resumed session's project --
                # and `--auto` no longer answers the nested instance's
                # permission prompts. The minimizer then blocks forever on
                # the first access outside /src (e.g. /out/llvmfuzz) until
                # the budget kills it with exit 124.
                minimize_cmd = _container_in_dir(repo_dir, minimize_cmd)
                min_start = time.monotonic()
                if codex_mode == "interactive":
                    min_exit, min_output = _exec_interactive(
                        container_name, minimize_cmd, timeout=minimize_budget,
                    )
                else:
                    min_exit, min_output = _exec_capture(
                        container_name, minimize_cmd, timeout=minimize_budget,
                    )
                min_elapsed = time.monotonic() - min_start
                if _usage_tracker:
                    _usage_tracker.log_usage("minimize", min_output, getattr(args, "model", None))
                logger.info("Minimization finished in %.0fs (exit %d)",
                            min_elapsed, min_exit)
                if codex_mode == "interactive":
                    (output_dir / "minimize_output.txt").write_text(min_output)
                else:
                    (output_dir / "minimize_output.jsonl").write_text(min_output)
                    (output_dir / "minimize_output.txt").write_text(
                        _format_codex_output(min_output)
                    )

                if min_exit != 0:
                    # The minimizer timed out or crashed.  Its exit status used
                    # to be logged and dropped, after which `git diff` was
                    # re-read and saved as "the minimized diff" -- but that
                    # tree is whatever the half-finished (and, before the
                    # reaping fix, still-running) agent left behind: possibly
                    # mid-revert, with the bug no longer reachable.  Keep the
                    # verified pre-minimize patch instead and say so.
                    logger.warning(
                        "Minimizer exited %d (not a clean finish) -- keeping "
                        "the verified pre-minimize patch; this bug is NOT "
                        "minimized", min_exit)
                    diff_path.write_text(premin_path.read_text())
                    (output_dir / "minimize_failed.txt").write_text(
                        f"minimizer exit={min_exit} after {min_elapsed:.0f}s "
                        f"(budget {minimize_budget}s)\n"
                        "bug_transplant.diff is the un-minimized, verified "
                        "transplant patch.\n"
                    )
                    _write_minimize_delta(output_dir, premin_path, diff_path,
                                          minimized_kept=False)
                    return exit_code

                # Re-save the (now minimized) diff via git diff
                _, min_diff = _exec_capture(
                    container_name,
                    _container_in_dir(repo_dir, f"git diff HEAD -- . {_git_diff_excludes}"),
                )
                diff_path.write_text(min_diff)
                logger.info("Minimized diff saved: %s (%d bytes)",
                            diff_path, len(min_diff))

                # Re-collect testcase (minimizer may have changed it)
                testcase_out = output_dir / testcase
                for tc_src in [f"/out/{testcase}", f"/work/{testcase}"]:
                    tc_ret = subprocess.run(
                        ["docker", "exec", container_name,
                         "bash", "-c", f"cat {tc_src}"],
                        capture_output=True, timeout=30,
                    )
                    if tc_ret.returncode == 0 and tc_ret.stdout:
                        testcase_out.write_bytes(tc_ret.stdout)
                        logger.info("Re-collected testcase from %s", tc_src)
                        break

                # Re-verify after minimization: force rebuild to avoid
                # stale binaries (autotools/cmake dependency tracking issue)
                _exec_capture(
                    container_name,
                    f"find {repo_dir_q} -name '{fuzzer}' -type f -executable -delete; "
                    f"rm -f /out/{fuzzer}",
                )
                # Same budget as the pre-minimize rebuild: a minimizer that
                # restored a build-generated file (e.g. libredwg's
                # src/config.h.in) turns this into a full rebuild, which
                # 300s cannot finish -- and a rebuild that silently timed
                # out leaves no fuzzer binary for the re-run below.
                ret_rebuild, _ = _exec_capture(
                    container_name,
                    "sudo -E compile 2>&1",
                    timeout=_VERIFY_BUILD_TIMEOUT,
                )
                if ret_rebuild != 0:
                    logger.warning("Post-minimize rebuild failed")
                _exec_capture(
                    container_name,
                    f"if [ -f /out/{testcase} ]; then cp /out/{testcase} /work/{testcase}; "
                    f"elif [ ! -f /work/{testcase} ]; then cp /corpus/{testcase} /work/{testcase}; fi; true",
                )
                if getattr(args, "skip_verify", False):
                    # Not a pass -- just unchecked.  Safe to keep the minimized
                    # diff only because a non-zero minimizer exit already
                    # returned above, so reaching here means the agent
                    # finished cleanly and claims the bug still triggers.
                    logger.warning("Post-minimize verification SKIPPED "
                                   "(--skip-verify): keeping the minimized "
                                   "diff UNVERIFIED")
                    (output_dir / "minimize_unverified.txt").write_text(
                        "Minimization completed but was never re-verified "
                        "(--skip-verify).\nThe crash is not confirmed to "
                        "survive minimization.\n"
                    )
                    post_min_ok = True
                else:
                    post_min_ok = verify_bug_triggers(
                        container_name, args.bug_id, fuzzer, testcase,
                        sanitizer="address", crash_log=crash_log,
                        fuzzer_path=f"/out/{fuzzer}",
                    )
                if post_min_ok:
                    logger.info("Post-minimize verification PASSED")
                    # Same memory cap as the pre-minimize capture, or the
                    # minimized diff's saved crash log records an OOM the
                    # verifier never saw.
                    _, fuzz_out2 = _exec_capture(
                        container_name,
                        f"export ASAN_OPTIONS=detect_leaks=0"
                        f":external_symbolizer_path=/out/llvm-symbolizer; "
                        f"/out/{fuzzer} -runs=10 -rss_limit_mb={_RSS_LIMIT_MB} "
                        f"/work/{testcase} 2>&1",
                        timeout=120,
                    )
                    # Only replace the verified pre-minimize crash log with
                    # something that is itself a crash. If the rebuild above
                    # failed, this run is a shell error ("/out/llvmfuzz: No
                    # such file or directory") and overwriting would destroy
                    # the reference stack that FuzzBench triage reads.
                    if "ERROR: AddressSanitizer" in (fuzz_out2 or ""):
                        crash_out_path.write_text(fuzz_out2)
                    else:
                        logger.warning(
                            "Post-minimize re-run produced no ASan crash; "
                            "keeping the pre-minimize crash log. tail=%.200s",
                            (fuzz_out2 or "(empty)")[-200:],
                        )
                else:
                    logger.warning("Post-minimize verification FAILED — "
                                   "keeping pre-minimize diff")
                    # Restore the unminimized diff
                    _, pre_min_diff = _exec_capture(
                        container_name,
                        _container_in_dir(repo_dir, "git diff"))
                    diff_path.write_text(pre_min_diff)

                # What the minimizer actually removed/changed: a diff of the
                # two patches (pre-minimize vs. the diff we ended up keeping).
                _write_minimize_delta(
                    output_dir, premin_path, diff_path, minimized_kept=post_min_ok)
            else:
                logger.error(
                    "Post-agent verification FAILED: bug does NOT trigger "
                    "with the reference stack. Removing artifacts. "
                    "tail=%.300s",
                    fuzz_out[-300:] if fuzz_out else "(empty)",
                )
                # Remove unverified diff so downstream doesn't use it
                if diff_path.exists():
                    diff_path.unlink()
                    logger.info("Removed unverified diff: %s", diff_path)
                return 1

        # Agent failed — keep the diff for manual inspection/recovery
        if exit_code != 0 and diff_path.exists():
            logger.warning("Agent failed (exit %d), keeping diff for review: %s",
                           exit_code, diff_path)

        return exit_code

    finally:
        if reuse_container:
            # Reused container — reset source for next bug but keep container
            logger.info("Resetting source tree for next bug...")
            _exec(container_name,
                  _container_in_dir(
                      repo_dir,
                      f"git checkout -f {shlex.quote(args.target_commit)} && "
                      f"git clean -fdx {clean_excludes}",
                  ),
                  user="root")
            # Restore /src/build.sh from the pristine snapshot and wipe
            # /tmp agent-helper scripts — these live outside the git repo
            # and would otherwise leak across bugs.
            _exec(
                container_name,
                "if [ -f /src/build.sh.transplant_pristine ]; then "
                "cp /src/build.sh.transplant_pristine /src/build.sh; fi; "
                "rm -f /tmp/patch_*.py /tmp/*.patch",
                user="root",
            )
        elif not args.keep_container:
            logger.info("Destroying container %s...", container_name)
            subprocess.call(
                ["docker", "rm", "-f", container_name],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        else:
            logger.info(
                "Container kept alive: docker exec -it %s bash", container_name,
            )
        # Clean up temp agents directory (only if we own it)
        if owns_agents_dir:
            shutil.rmtree(agents_dir, ignore_errors=True)


_CMD_OUTPUT_MAX_LINES = 30


def _format_codex_output(jsonl_output: str) -> str:
    """Convert codex --json JSONL output to agent-message-only summary.

    Only keeps AGENT: messages (the reasoning/status updates).
    Command outputs are omitted — full output is in the .jsonl file.
    """
    import json as _json
    lines = []
    for raw in jsonl_output.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            ev = _json.loads(raw)
        except _json.JSONDecodeError:
            continue
        if ACTIVE_AGENT == "opencode":
            # opencode emits one event per message part; `text` parts carry
            # what the agent said, the rest are tool calls and step markers.
            if ev.get("type") == "text":
                text = (ev.get("part") or {}).get("text", "")
                if text:
                    lines.append(f"\n{'='*60}")
                    lines.append("AGENT:")
                    lines.append(text)
            continue
        if ev.get("type") != "item.completed":
            continue
        item = ev.get("item", {})
        if item.get("type") == "agent_message":
            text = item.get("text", "")
            if text:
                lines.append(f"\n{'='*60}")
                lines.append(f"AGENT:")
                lines.append(text)
    return "\n".join(lines) + "\n" if lines else jsonl_output


def _exec(container_name: str, command: str, user: str | None = None) -> int:
    """docker exec a command, printing output to console."""
    cmd = ["docker", "exec"]
    if user:
        cmd += ["-u", user]
    cmd += [container_name, "bash", "-c", command]
    return subprocess.call(cmd)


# Marker every wrapped `docker exec` payload carries, so a stale process from
# an earlier bug can be swept even if its pid file is gone.
_EXEC_MARKER = "BT_EXEC_ID"


def _exec_sweep(container_name: str, user: str | None = None) -> int:
    """Kill any container-side process left over from an earlier _exec_capture.

    ``docker exec`` does not signal the container-side process when the client
    goes away, so a timeout (or a killed parent) leaves the command running.
    In the shared-container batch those orphans keep editing /src and /out --
    reverting files, deleting the fuzz target -- and silently corrupt whichever
    bug is running next.  Called before each bug as a backstop to the
    per-command reaping in _exec_capture.

    The marker pattern is passed through the environment rather than the
    script text: ``pgrep -f`` matches on argv, so a literal marker in the
    sweep's own command line would make it match (and kill) itself.
    """
    script = (
        'pids=$(pgrep -f "$BT_SWEEP_PAT" 2>/dev/null | grep -vx "$$" || true); '
        'if [ -z "$pids" ]; then exit 0; fi; '
        'echo "$pids"; '
        'for sig in TERM KILL; do '
        '  for p in $pids; do '
        '    g=$(ps -o pgid= -p "$p" 2>/dev/null | tr -d " "); '
        '    if [ -n "$g" ]; then kill -$sig -"$g" 2>/dev/null || true; '
        '    else kill -$sig "$p" 2>/dev/null || true; fi; '
        '  done; '
        '  [ "$sig" = TERM ] && sleep 3; '
        'done; true'
    )
    cmd = ["docker", "exec", "-e", f"BT_SWEEP_PAT={_EXEC_MARKER}="]
    if user:
        cmd += ["-u", user]
    cmd += [container_name, "bash", "-c", script]
    try:
        res = subprocess.run(cmd, capture_output=True, encoding="utf-8",
                             errors="replace", timeout=60)
    except Exception as exc:
        logger.warning("Orphan sweep failed: %s", exc)
        return 0
    found = [ln for ln in (res.stdout or "").split() if ln.strip().isdigit()]
    if found:
        logger.warning("Swept %d orphaned container process(es) left by an "
                       "earlier command: %s", len(found), " ".join(found))
    return len(found)


def _exec_kill(container_name: str, pid_file: str,
               user: str | None = None) -> None:
    """Kill the container-side process group started by _exec_capture."""
    script = (
        f"p=$(cat {pid_file} 2>/dev/null); [ -z \"$p\" ] && exit 0; "
        "g=$(ps -o pgid= -p $p 2>/dev/null | tr -d ' '); "
        "if [ -n \"$g\" ]; then kill -TERM -$g 2>/dev/null; else kill -TERM $p 2>/dev/null; fi; "
        "sleep 3; "
        "if [ -n \"$g\" ]; then kill -KILL -$g 2>/dev/null; else kill -KILL $p 2>/dev/null; fi; "
        "true"
    )
    cmd = ["docker", "exec"]
    if user:
        cmd += ["-u", user]
    cmd += [container_name, "bash", "-c", script]
    try:
        subprocess.run(cmd, capture_output=True, timeout=60)
    except Exception as exc:
        logger.warning("Could not kill container-side process: %s", exc)


def _exec_capture(
    container_name: str,
    command: str,
    timeout: int = 3600,
    user: str | None = None,
) -> tuple[int, str]:
    """docker exec a command, capturing output.

    The payload runs as a backgrounded job inside the container with its pid
    recorded and its output redirected to a file.  That buys two things a
    plain ``subprocess.run(["docker","exec",...], timeout=...)`` cannot give:

    * On timeout the container-side process group is killed.  Python only
      kills the local ``docker exec`` client, and Docker does not forward
      that to the process in the container -- so every timeout used to leak a
      live agent into the shared source tree.
    * Whatever the command printed before being killed is still recovered,
      instead of being replaced by a bare "TIMEOUT" string.
    """
    exec_id = uuid.uuid4().hex[:12]
    pid_file = f"/tmp/.bt_exec_{exec_id}.pid"
    out_file = f"/tmp/.bt_exec_{exec_id}.out"
    wrapped = (
        f"export {_EXEC_MARKER}={exec_id}\n"
        f"{{\n{command}\n}} > {out_file} 2>&1 &\n"
        f"echo $! > {pid_file}\n"
        "wait $!"
    )
    base = ["docker", "exec"]
    if user:
        base += ["-u", user]
    timed_out = False
    try:
        result = subprocess.run(
            base + [container_name, "bash", "-c", wrapped],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        returncode = result.returncode
        client_err = result.stderr or ""
    except subprocess.TimeoutExpired:
        timed_out = True
        returncode = 124
        client_err = ""
        logger.error("Command timed out after %ds -- killing container-side "
                     "process group", timeout)
        _exec_kill(container_name, pid_file, user)

    # Drain the output file and clean up in a single exec.
    try:
        drain = subprocess.run(
            base + [container_name, "bash", "-c",
                    f"cat {out_file} 2>/dev/null; rm -f {out_file} {pid_file}"],
            capture_output=True, encoding="utf-8", errors="replace", timeout=120,
        )
        output = drain.stdout or ""
    except Exception as exc:
        logger.warning("Could not read command output: %s", exc)
        output = ""
    if client_err:
        output += client_err
    if timed_out:
        output += (f"\n[TIMEOUT after {timeout}s -- container-side process "
                   f"group killed; output above is what it produced first]\n")
    return returncode, output


def _exec_interactive(
    container_name: str, command: str, timeout: int = 3600,
) -> tuple[int, str]:
    """Run *command* inside a container with an interactive TTY via tmux.

    Launches a tmux session that runs ``docker exec -it`` so the Codex TUI
    gets a proper PTY, then attaches so the user can interact.  Uses
    ``tmux pipe-pane`` to capture all terminal output for cost tracking.

    Returns ``(exit_code, captured_output)`` — same signature as
    :func:`_exec_capture` so callers can handle both modes uniformly.
    """
    session = f"codex_{os.getpid()}_{int(time.time())}"
    exit_file = f"/tmp/.codex_exit_{session}"
    log_file = f"/tmp/.codex_log_{session}"
    Path(exit_file).unlink(missing_ok=True)
    Path(log_file).unlink(missing_ok=True)

    docker_cmd = (
        f"docker exec -it {container_name} bash -c {shlex.quote(command)}"
    )
    inner = f"{docker_cmd}; echo $? > {exit_file}"

    try:
        subprocess.run(
            ["tmux", "new-session", "-d", "-s", session, "bash", "-c", inner],
            check=True,
        )
    except FileNotFoundError:
        logger.error("tmux not found — install tmux for interactive mode")
        return 1, ""
    except subprocess.CalledProcessError as exc:
        logger.error("Failed to create tmux session: %s", exc)
        return 1, ""

    # Capture all pane output to a log file for cost tracking.
    subprocess.run(
        ["tmux", "pipe-pane", "-t", session, f"cat >> {log_file}"],
        check=False,
    )

    # Attach blocks until the session ends (command finishes).
    subprocess.call(["tmux", "attach-session", "-t", session])

    # Read captured output
    output = ""
    try:
        output = Path(log_file).read_text(errors="replace")
    except FileNotFoundError:
        logger.warning("No captured output from tmux pipe-pane")
    finally:
        Path(log_file).unlink(missing_ok=True)

    try:
        exit_code = int(Path(exit_file).read_text().strip())
    except (FileNotFoundError, ValueError):
        logger.warning("Could not read exit code from %s", exit_file)
        exit_code = 1
    finally:
        Path(exit_file).unlink(missing_ok=True)

    return exit_code, output


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bug transplant via Codex inside OSS-Fuzz container",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Full pipeline
              sudo -E python3 script/bug_transplant.py wavpack \\
                --buggy-commit 348ff60b --target-commit 0b99613e \\
                --bug-id OSV-2020-1006 --fuzzer-name fuzzer_decode_file \\
                --testcase testcase-OSV-2020-1006

              # Skip data collection, keep container alive for debugging
              sudo -E python3 script/bug_transplant.py wavpack \\
                --buggy-commit 348ff60b --target-commit 0b99613e \\
                --bug-id OSV-2020-1006 --fuzzer-name fuzzer_decode_file \\
                --testcase testcase-OSV-2020-1006 \\
                --skip-collect --keep-container
        """),
    )

    # Required
    parser.add_argument("project", help="OSS-Fuzz project name")
    parser.add_argument("--buggy-commit", required=True,
                        help="Commit hash where the bug exists")
    parser.add_argument("--target-commit", required=True,
                        help="Current/fixed commit to transplant into")
    parser.add_argument("--bug-id", required=True,
                        help="Bug identifier (e.g. OSV-2020-1006)")
    parser.add_argument("--fuzzer-name", required=True,
                        help="Fuzzer binary name (e.g. fuzzer_decode_file)")
    parser.add_argument("--testcase", required=True,
                        help="Testcase filename (must exist in testcases dir)")

    # Data collection
    parser.add_argument("--testcases-dir",
                        default=os.environ.get("TESTCASES", ""),
                        help="Directory containing testcase files "
                             "(default: $TESTCASES env var)")
    parser.add_argument("--repo-path",
                        default=os.environ.get("REPO_PATH", ""),
                        help="Local git repo of the target project for fix-diff generation "
                             "(default: $REPO_PATH env var)")
    parser.add_argument("--adjacent-commit", default=None,
                        help="First CSV commit after the buggy commit toward target "
                             "(pre-computed by bug_transplant_batch.py)")
    parser.add_argument("--build-csv", default=None,
                        help="Build CSV mapping commits to OSS-Fuzz versions")
    parser.add_argument("--runner-image", default=None,
                        help="Base runner image (e.g. 'auto')")
    parser.add_argument("--skip-collect", action="store_true",
                        help="Skip crash/trace collection (data already exists)")
    # Default ON: the gate rejects any diff whose crash stack does not match
    # the reference, which also discards diffs worth inspecting by hand. Pass
    # --verify to put the gate back and have unmatched diffs deleted again.
    parser.add_argument("--skip-verify", dest="skip_verify",
                        action="store_true", default=True,
                        help="Skip the crash-triggering verification gates "
                             "(DEFAULT). The patch is still rebuilt with "
                             "official `compile` and minimized, but a "
                             "non-reproducing or agent-errored run is kept "
                             "instead of discarded. Diffs produced this way "
                             "are NOT confirmed to trigger the bug.")
    parser.add_argument("--verify", dest="skip_verify", action="store_false",
                        help="Enforce the verification gate: a diff whose "
                             "crash stack does not match the reference is "
                             "discarded and the bug is marked failed.")
    parser.add_argument("--skip-image-build", action="store_true",
                        help="Trust that the project and agent Docker images "
                             "are already current (bug_transplant_batch.py "
                             "builds them once per run) instead of re-running "
                             "build_version per bug. Falls back to building if "
                             "either image is missing.")
    parser.add_argument("--minimize-only", action="store_true",
                        help="Skip the transplant agent: re-apply the saved "
                             "bug_transplant.diff (and its saved testcase) to "
                             "a clean tree, verify it, then run only the "
                             "minimization pass. Use to re-minimize bugs whose "
                             "minimizer failed; the original transplant "
                             "transcript is left untouched.")

    # Agent
    parser.add_argument("--agent", choices=["codex", "opencode"],
                        default="codex",
                        help="Agent CLI backend (default: codex)")
    parser.add_argument("--model", default=None,
                        help="Model to use (passed to agent CLI)")
    parser.add_argument("--timeout", type=int, default=3600,
                        help="Timeout in seconds for transplant agent (default: 3600)")
    parser.add_argument("--minimize-timeout", type=int, default=1200,
                        help="Timeout in seconds for minimize agent (default: 1200)")
    parser.add_argument("--total-budget", type=int, default=None,
                        help="Total wall-clock seconds the caller will allow "
                             "this run before it is killed.  When set, the "
                             "minimize agent's timeout is clamped to what is "
                             "actually left, so an over-long build cannot "
                             "starve minimization into a hard kill.")
    parser.add_argument("--codex-mode", choices=["exec", "interactive"],
                        default="exec",
                        help="Agent invocation mode: exec (default, JSONL) "
                             "or interactive (TUI via tmux)")
    # Docker
    parser.add_argument("--keep-container", action="store_true",
                        help="Keep container alive after completion for debugging")
    parser.add_argument("--container-name", default=None,
                        help="Reuse an existing container (batch mode)")
    parser.add_argument("--agents-dir", default=None,
                        help="Shared AGENTS.md directory (batch mode)")
    parser.add_argument("-e", "--env", action="append",
                        help="Additional env vars for container (VAR=value)")
    parser.add_argument("-v", "--volume", action="append",
                        help="Additional volume mounts (host:container)")

    # Logging
    parser.add_argument("--verbose", "-V", action="store_true",
                        help="Verbose logging")

    return parser


def main() -> int:
    global _usage_tracker, _RUN_START

    _RUN_START = time.monotonic()

    filled = load_setenv_defaults("TESTCASES", "REPO_PATH", "BUGINFO_PATH")
    parser = build_parser()
    args = parser.parse_args()
    set_active_agent(getattr(args, "agent", "codex"))

    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    for name, value in filled.items():
        logger.info("%s not in environment; using %s from %s", name, value, SETENV_SCRIPT)

    # Initialize codex token tracker
    from codex_usage import CodexUsageTracker
    _usage_tracker = CodexUsageTracker()

    # Validate testcases dir
    if not args.testcases_dir:
        logger.error(
            "Testcases directory not specified. "
            "Set --testcases-dir or $TESTCASES environment variable."
        )
        return 1

    buggy_short = args.buggy_commit[:8]

    # ------------------------------------------------------------------
    # Phase 0: Collect crash and trace data
    # ------------------------------------------------------------------
    if not args.skip_collect:
        logger.info("=== Phase 0: Collecting crash and trace data ===")
        if not collect_crash_data(args):
            logger.error("Failed to collect crash data")
            return 1
        if not collect_trace_data(args):
            logger.warning("Failed to collect trace data (non-fatal, agent will work without it)")
    else:
        logger.info("=== Phase 0: Skipped (--skip-collect) ===")
        # Verify data exists
        crash_file = DATA_DIR / "crash" / f"target_crash-{buggy_short}-{args.testcase}.txt"
        trace_file = TRACE_DIR / f"target_trace-{buggy_short}-{args.testcase}.txt"
        missing = []
        if not crash_file.exists():
            missing.append(str(crash_file))
        if not trace_file.exists():
            missing.append(str(trace_file))
        if missing:
            logger.warning("Missing data files (agent will work without them):")
            for f in missing:
                logger.warning("  %s", f)

    # Fix diff: generate for standalone runs (batch pre-generates these already)
    if args.repo_path:
        project_repo = os.path.join(args.repo_path, args.project)
        args.repo_path = project_repo if os.path.isdir(project_repo) else args.repo_path
        collect_fix_diff(args)

    # ------------------------------------------------------------------
    # Phase 1: Build Docker images
    # ------------------------------------------------------------------
    # Pin the project image to the same oss-fuzz commit + base-builder
    # digest that buildAndtest.py / collect_crash / collect_trace use for
    # this target. Without these args build_project_image falls through
    # to its unpinned `docker build` branch, so the agent's `compile`
    # would run against today's base-builder:latest rather than the
    # historical digest that produced the cached /mnt/nas binary and the
    # reference crash log. That mismatch is the layout-drift source of
    # "bug triggers in transplant container but nowhere else" outcomes.
    logger.info("=== Phase 1: Building Docker images ===")
    if getattr(args, "skip_image_build", False):
        # bug_transplant_batch.py builds both images once at startup, for the
        # same project and target commit.  Repeating it per bug costs ~9min of
        # pure wall-clock (build_version re-runs the project build even when
        # the image is current) and cannot change the result.
        project_image = f"gcr.io/oss-fuzz/{args.project}"
        agent_image = f"bug-transplant-{args.project}:latest"
        missing = [
            tag for tag in (project_image, agent_image)
            if subprocess.call(["docker", "image", "inspect", tag],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL) != 0
        ]
        if missing:
            logger.warning("--skip-image-build: %s absent; building after all",
                           ", ".join(missing))
            project_image = build_project_image(
                args.project, args.target_commit, args.build_csv,
            )
            agent_image = build_agent_image(args.project, project_image)
        else:
            logger.info("Skipping image build (--skip-image-build): reusing %s",
                        agent_image)
    else:
        project_image = build_project_image(
            args.project, args.target_commit, args.build_csv,
        )
        agent_image = build_agent_image(args.project, project_image)

    # ------------------------------------------------------------------
    # Phase 2+3: Run Codex in container
    # ------------------------------------------------------------------
    logger.info("=== Phase 2+3: Running %s in container ===", ACTIVE_AGENT)
    exit_code = run_agent_in_container(args)

    # ------------------------------------------------------------------
    # Phase 4: Report results
    # ------------------------------------------------------------------
    output_dir = DATA_DIR / "bug_transplant" / f"{args.project}_{args.bug_id}"
    diff_path = output_dir / "bug_transplant.diff"
    git_diff_path = output_dir / "git_diff.diff"

    logger.info("=== Results ===")
    logger.info("Output directory: %s", output_dir)
    if diff_path.exists() and diff_path.stat().st_size > 0:
        logger.info("Bug transplant diff: %s", diff_path)
    elif git_diff_path.exists() and git_diff_path.stat().st_size > 0:
        logger.info("Git diff (fallback): %s", git_diff_path)
    else:
        logger.warning("No diff produced -- check agent_output.txt for details")

    if (output_dir / "agent_output.txt").exists():
        logger.info("Agent output: %s", output_dir / "agent_output.txt")

    _usage_tracker.log_session_total()

    # Write usage stats to output dir so batch can aggregate
    if _usage_tracker.cost > 0 and output_dir.exists():
        import json
        usage_path = output_dir / "token_usage.json"
        usage_path.write_text(json.dumps({
            "input_tokens": _usage_tracker.input_tokens,
            "cached_input_tokens": _usage_tracker.cached_input_tokens,
            "output_tokens": _usage_tracker.output_tokens,
            "cost": round(_usage_tracker.cost, 6),
        }, indent=2))

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
