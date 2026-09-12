#!/usr/bin/env python3
"""Coding-agent CLI plumbing for the ungated pipeline.

Same approach as ``bug_transplant.py``'s Codex machinery -- layer a Node-based
agent CLI onto the project image, run it non-interactively inside a persistent
container with approvals bypassed, capture JSONL -- but with the agent
selectable.  Claude Code is the default because the Codex CLI is currently
unavailable.

Two things are deliberately kept from the Codex path:

* **Credentials are mounted, never injected as an API key.**  Both CLIs
  authenticate from a file in the user's home (``~/.claude/.credentials.json``,
  ``~/.codex/auth.json``); injecting ``ANTHROPIC_API_KEY``/``OPENAI_API_KEY``
  bills a different account and, for Codex, silently fails.
* **The agent runs as a non-root user.**  Claude Code refuses
  ``--dangerously-skip-permissions`` as root, and Codex dislikes it too, so the
  image creates an ``agent`` user whose uid matches the host owner of the
  mounted worktree -- otherwise the agent cannot write the source it is asked
  to edit.

Usage (as a library):
    import agent_cli
    agent_cli.build_agent_image("ungated-base:htslib",
                                "ungated-agent-htslib:latest", uid=1000)
    agent_cli.install_credentials("ungated_htslib")
    rc, raw = agent_cli.run("ungated_htslib", prompt, workdir="/src/htslib")
    print(agent_cli.final_message(raw))
"""
from __future__ import annotations

import json
import logging
import os
import pwd
import shlex
import subprocess
import tempfile
import textwrap
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------

DEFAULT_AGENT = "claude"

AGENTS = {
    "claude": {
        "npm_package": "@anthropic-ai/claude-code",
        "version": "2.0.22",
        "cli_name": "claude",
        "cli_entry": "@anthropic-ai/claude-code/cli.js",
        # Files copied from the host home into the container home.  The OAuth
        # credentials are what authenticate; ~/.claude.json only carries the
        # "onboarding done" flags that keep the CLI from trying to prompt.
        "credentials": [".claude/.credentials.json"],
        "config_seed": {
            ".claude.json": {
                "hasCompletedOnboarding": True,
                "theme": "dark",
                "autoUpdates": False,
            },
        },
        # -p is non-interactive; stream-json requires --verbose.
        "run_cmd": ("{cli} -p {prompt} --dangerously-skip-permissions "
                    "--output-format stream-json --verbose"),
        "model_flag": "--model",
        "resume_flag": "--resume",
        "default_model": None,
        "env": {
            "DISABLE_AUTOUPDATER": "1",
            "DISABLE_TELEMETRY": "1",
        },
    },
    "codex": {
        "npm_package": "@openai/codex",
        # Match the host CLI: the mounted auth.json is written by whatever
        # version logged in, and bug_transplant.py's 0.116.0 pin predates it.
        "version": "0.147.0",
        "cli_name": "codex",
        "cli_entry": "@openai/codex/bin/codex.js",
        # The whole directory, not just auth.json: this account authenticates
        # through a custom provider declared in config.toml (`model_provider`,
        # `base_url`).  With auth.json alone Codex talks to api.openai.com and
        # gets 401.  Mirrors bug_transplant.py, which copies ~/.codex wholesale.
        "credentials": [],
        "credentials_dir": ".codex",
        "prune": ["projects", "sessions", "logs", "cache", "log", "ipc"],
        "config_seed": {},
        "run_cmd": "{cli} exec --dangerously-bypass-approvals-and-sandbox {prompt} --json",
        "model_flag": "--model",
        "resume_flag": "resume",
        # bug_transplant.py pins this: the account behind auth.json does not
        # serve Codex's own default model.
        "default_model": "gpt-5.6-terra",
        "env": {},
    },
}

CONTAINER_HOME = "/home/agent"

# (container, agent) pairs whose credentials are already in place.  Installing
# them again mid-run is not idempotent: Codex keeps each session's rollout under
# ~/.codex/sessions, so re-copying the host directory deletes the rollout that
# `exec resume` needs and every retry dies with "no rollout found for thread id".
_INSTALLED: set[tuple[str, str]] = set()


def config(agent: str = DEFAULT_AGENT) -> dict:
    if agent not in AGENTS:
        raise SystemExit(f"unknown agent {agent!r}; known: {', '.join(AGENTS)}")
    return AGENTS[agent]


# ---------------------------------------------------------------------------
# Image
# ---------------------------------------------------------------------------

def _image_workdir(image: str) -> str:
    p = subprocess.run(["docker", "image", "inspect", image, "--format",
                        "{{.Config.WorkingDir}}"], capture_output=True, text=True)
    return (p.stdout.strip() or "/src") if p.returncode == 0 else "/src"


def build_agent_image(base_image: str, tag: str, *, agent: str = DEFAULT_AGENT,
                      uid: int = 1000, force: bool = False) -> str:
    """Layer the agent CLI onto *base_image*, reusing the build when unchanged.

    The cache key is (base image id, uid, agent, version): rebuilding the base
    -- which happens whenever the benchmark Dockerfile changes -- must not leave
    the agent image pinned to stale layers, the same trap
    ``bug_transplant.build_agent_image`` guards against.
    """
    cfg = config(agent)
    p = subprocess.run(["docker", "image", "inspect", base_image, "--format",
                        "{{.Id}}"], capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"base image {base_image} not found: {p.stderr.strip()}")
    base_id = p.stdout.strip()
    key = f"{base_id}|{uid}|{agent}|{cfg['version']}"

    if not force:
        got = subprocess.run(
            ["docker", "image", "inspect", tag, "--format",
             '{{index .Config.Labels "ungated.agent-key"}}'],
            capture_output=True, text=True)
        if got.returncode == 0 and got.stdout.strip() == key:
            logger.info("agent image up to date: %s", tag)
            return tag

    workdir = _image_workdir(base_image)
    logger.info("building agent image %s (%s %s) on %s",
                tag, cfg["cli_name"], cfg["version"], base_image)
    dockerfile = textwrap.dedent(f"""\
        # Stage 1: install the agent CLI on a modern base (glibc >= 2.28).
        FROM ubuntu:22.04 AS agent-builder
        ENV DEBIAN_FRONTEND=noninteractive
        RUN apt-get update && apt-get install -y --no-install-recommends \\
                curl ca-certificates \\
            && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \\
            && apt-get install -y --no-install-recommends nodejs \\
            && npm install -g {cfg['npm_package']}@{cfg['version']} \\
            && rm -rf /var/lib/apt/lists/*

        # Stage 2: the replay image with the CLI copied in.
        FROM {base_image}
        ENV DEBIAN_FRONTEND=noninteractive

        COPY --from=agent-builder /usr/bin/node /usr/local/bin/node
        COPY --from=agent-builder /usr/lib/node_modules /usr/local/lib/node_modules
        # Bundle the builder's glibc/libstdc++ so node runs on older bases too.
        COPY --from=agent-builder /lib/x86_64-linux-gnu/libc.so.6 /opt/node-libs/libc.so.6
        COPY --from=agent-builder /lib/x86_64-linux-gnu/libm.so.6 /opt/node-libs/libm.so.6
        COPY --from=agent-builder /lib/x86_64-linux-gnu/libpthread.so.0 /opt/node-libs/libpthread.so.0
        COPY --from=agent-builder /lib/x86_64-linux-gnu/libdl.so.2 /opt/node-libs/libdl.so.2
        COPY --from=agent-builder /lib/x86_64-linux-gnu/librt.so.1 /opt/node-libs/librt.so.1
        COPY --from=agent-builder /lib64/ld-linux-x86-64.so.2 /opt/node-libs/ld-linux-x86-64.so.2
        COPY --from=agent-builder /usr/lib/x86_64-linux-gnu/libstdc++.so.6 /opt/node-libs/libstdc++.so.6
        COPY --from=agent-builder /lib/x86_64-linux-gnu/libgcc_s.so.1 /opt/node-libs/libgcc_s.so.1

        RUN printf '#!/bin/bash\\nexec /opt/node-libs/ld-linux-x86-64.so.2 \
--library-path /opt/node-libs /usr/local/bin/node \
/usr/local/lib/node_modules/{cfg['cli_entry']} "$@"\\n' \
                > /usr/local/bin/{cfg['cli_name']} \\
            && chmod +x /usr/local/bin/{cfg['cli_name']}

        RUN apt-get update && apt-get install -y --no-install-recommends sudo ripgrep \\
            && rm -rf /var/lib/apt/lists/* || true

        # The agent's uid must match the host owner of the mounted worktree, or
        # it cannot edit the source it is asked to gate.
        RUN (userdel -r $(getent passwd {uid} | cut -d: -f1) 2>/dev/null || true) \\
            && (useradd -m -u {uid} -d {CONTAINER_HOME} -s /bin/bash agent 2>/dev/null || true) \\
            && echo "agent ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \\
            && mkdir -p {CONTAINER_HOME}/.claude {CONTAINER_HOME}/.codex \\
            && chown -R agent:agent {CONTAINER_HOME}

        # `compile` writes to /out, which is a root-owned bind mount.
        RUN printf '#!/bin/bash\\ncd {workdir} && exec sudo -E /usr/local/bin/compile "$@"\\n' \\
                > /usr/local/bin/agent-compile \\
            && chmod +x /usr/local/bin/agent-compile

        ENV HOME={CONTAINER_HOME}
        LABEL ungated.agent-key="{key}"
        CMD ["sleep", "infinity"]
    """)
    with tempfile.TemporaryDirectory() as tmp:
        df = Path(tmp) / "Dockerfile"
        df.write_text(dockerfile)
        p = subprocess.run(["docker", "build", "-t", tag, "-f", str(df), tmp],
                           capture_output=True)
        if p.returncode != 0:
            raise SystemExit("agent image build failed:\n"
                             + p.stderr.decode("latin-1")[-3000:])
    logger.info("agent image built: %s", tag)
    return tag


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

def _host_home() -> Path:
    """The invoking user's home, even under ``sudo -E``."""
    user = os.environ.get("SUDO_USER")
    if user:
        # Not every host puts homes under /home -- CloudLab uses /users/<name>,
        # and guessing sent the libredwg run through 24 bugs reporting "no
        # claude credentials" while the file sat there.  Ask the passwd db.
        try:
            return Path(pwd.getpwnam(user).pw_dir)
        except KeyError:
            return Path(f"/home/{user}")
    return Path.home()


def install_credentials(container: str, *, agent: str = DEFAULT_AGENT,
                        home: Path | None = None) -> bool:
    """Copy the host's agent credentials into *container*.

    Returns False when nothing was found, so callers can fail the bug with a
    clear status instead of letting the agent burn a session on a login prompt.
    """
    cfg = config(agent)
    home = home or _host_home()
    if (container, agent) in _INSTALLED:
        return True
    ok = False

    if cfg.get("credentials_dir"):
        src = home / cfg["credentials_dir"]
        dst = f"{CONTAINER_HOME}/{cfg['credentials_dir']}"
        if src.exists():
            p = subprocess.run(["docker", "cp", f"{src}/.", f"{container}:{dst}"],
                               capture_output=True)
            ok = p.returncode == 0
            if not ok:
                logger.error("failed to copy %s: %s", src,
                             p.stderr.decode("latin-1")[:200])
            for junk in cfg.get("prune", []):
                subprocess.run(["docker", "exec", "-u", "root", container,
                                "rm", "-rf", f"{dst}/{junk}"], capture_output=True)
        else:
            logger.warning("no %s on the host -- the agent cannot authenticate",
                           src)

    for rel in cfg["credentials"]:
        src = home / rel
        if not src.exists():
            logger.warning("no %s on the host -- the agent will not be able to "
                           "authenticate", src)
            continue
        dst = f"{CONTAINER_HOME}/{rel}"
        subprocess.run(["docker", "exec", "-u", "root", container,
                        "mkdir", "-p", str(Path(dst).parent)],
                       capture_output=True)
        p = subprocess.run(["docker", "cp", str(src), f"{container}:{dst}"],
                           capture_output=True)
        if p.returncode != 0:
            logger.error("failed to copy %s: %s", src,
                         p.stderr.decode("latin-1")[:200])
            continue
        ok = True
    for name, seed in cfg["config_seed"].items():
        dst = f"{CONTAINER_HOME}/{name}"
        payload = json.dumps(seed)
        subprocess.run(
            ["docker", "exec", "-u", "root", container, "bash", "-c",
             f"test -s {shlex.quote(dst)} || echo {shlex.quote(payload)} > {shlex.quote(dst)}"],
            capture_output=True)
    subprocess.run(["docker", "exec", "-u", "root", container,
                    "chown", "-R", "agent:agent", CONTAINER_HOME],
                   capture_output=True)
    if ok:
        _INSTALLED.add((container, agent))
    return ok


# ---------------------------------------------------------------------------
# Invocation
# ---------------------------------------------------------------------------

def auth_env(agent: str = DEFAULT_AGENT, home: Path | None = None) -> dict:
    """Secrets the CLI needs in its environment, read from the host's own config.

    Claude Code needs none -- it reads ``~/.claude/.credentials.json``.  Codex
    does when the account goes through a custom provider: ``config.toml`` names
    it with ``env_key = "APIROUTER_API_KEY"``, and the CLI looks that up in the
    environment, not in ``auth.json``.  Without it the run fails with
    "Missing environment variable".  Values come from the host's own
    ``~/.codex/auth.json`` (falling back to this process's environment), so
    nothing new is stored anywhere.
    """
    if agent != "codex":
        return {}
    out = {}
    src = (home or _host_home()) / ".codex" / "auth.json"
    if src.exists():
        try:
            data = json.loads(src.read_text())
        except json.JSONDecodeError:
            data = {}
        for key, value in data.items():
            if key.endswith("_API_KEY") and isinstance(value, str) and value:
                out[key] = value
    for key in ("OPENAI_API_KEY", "APIROUTER_API_KEY"):
        if key not in out and os.environ.get(key):
            out[key] = os.environ[key]
    return out


def build_command(prompt: str, *, agent: str = DEFAULT_AGENT,
                  model: str | None = None, resume: str | None = None) -> str:
    """The CLI invocation.

    Resuming differs in shape, not just in flag: Claude Code takes
    ``--resume <id>`` anywhere, while Codex needs ``exec resume <id> <prompt>``
    -- the sub-command comes *before* the prompt, so it cannot be appended.
    """
    cfg = config(agent)
    quoted = shlex.quote(prompt)
    if resume and agent == "codex":
        cmd = (f"{cfg['cli_name']} exec resume "
               f"--dangerously-bypass-approvals-and-sandbox "
               f"{shlex.quote(resume)} {quoted} --json")
    else:
        cmd = cfg["run_cmd"].format(cli=cfg["cli_name"], prompt=quoted)
        if resume:
            cmd += f" {cfg['resume_flag']} {shlex.quote(resume)}"
    model = model or cfg.get("default_model")
    if model:
        cmd += f" {cfg['model_flag']} {shlex.quote(model)}"
    return cmd


def _events(raw: str):
    """Yield the JSON events in a CLI transcript, tolerating malformed lines.

    Not a line-by-line parse: Claude Code's ``result`` event embeds the agent's
    final message with **raw newlines inside the JSON string**, so splitting on
    newlines shreds exactly the event that carries the answer and the cost.
    ``strict=False`` accepts those control characters and ``raw_decode`` walks
    object by object, so stray non-JSON output (a CLI warning on stderr) is
    skipped instead of derailing the scan.
    """
    decoder = json.JSONDecoder(strict=False)
    i, n = 0, len(raw)
    while i < n:
        j = raw.find("{", i)
        if j < 0:
            return
        try:
            obj, end = decoder.raw_decode(raw, j)
        except ValueError:
            i = j + 1
            continue
        if isinstance(obj, dict):
            yield obj
        i = end


def session_id(raw: str, *, agent: str = DEFAULT_AGENT) -> str:
    """Session id of a finished run, so a retry can continue it in context."""
    for event in _events(raw):
        if agent == "claude" and event.get("session_id"):
            return event["session_id"]
        if agent == "codex":
            # 0.147 opens with `thread.started`; older builds used
            # `session_meta`.  Accept either so a version bump does not
            # silently break resuming.
            if event.get("type") == "thread.started" and event.get("thread_id"):
                return event["thread_id"]
            if event.get("type") == "session_meta":
                return event.get("payload", {}).get("id", "")
    return ""


def _text(data: bytes | None) -> str:
    """Decode agent output as the UTF-8 it is, without ever raising.

    ``latin-1`` never fails, which is why it was here -- but it mangles every
    non-ASCII byte, and these strings are kept: c-blosc2 OSV-2022-511's recorded
    exclusion reason came out with "frame_get_lazychunk \xe2\x86\x92
    blosc2_decompress_ctx" instead of an arrow, in a field written for a human
    to read later.
    """
    return (data or b"").decode("utf-8", errors="replace")



_AUTH_EXPIRED = ("OAuth access token has been revoked", "Invalid API key",
                 "authentication_error", "Please run /login")


def _auth_expired(raw: str) -> bool:
    """Whether this failure is the container's credential, not the task."""
    return any(m in raw for m in _AUTH_EXPIRED)


def run(container: str, prompt: str, *, workdir: str,
        agent: str = DEFAULT_AGENT, model: str | None = None,
        timeout: int = 1800, user: str = "agent",
        resume: str | None = None, _retry: bool = False) -> tuple[int, str]:
    """Run one agent session inside *container*.  Returns ``(rc, raw output)``."""
    cfg = config(agent)
    env_args = []
    for key, value in {**cfg["env"], **auth_env(agent)}.items():
        env_args += ["-e", f"{key}={value}"]
    cmd = ["docker", "exec", "-u", user, "-w", workdir,
           "-e", f"HOME={CONTAINER_HOME}", *env_args, container,
           "bash", "-lc",
           build_command(prompt, agent=agent, model=model, resume=resume)]
    logger.info("running %s in %s (timeout %ds)", cfg["cli_name"], container,
                timeout)
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raw = _text(exc.stdout) + _text(exc.stderr)
        logger.error("%s timed out after %ds", cfg["cli_name"], timeout)
        return 124, raw
    raw = _text(p.stdout) + _text(p.stderr)

    # A credential installed at container start goes stale mid-run: logging in
    # again anywhere revokes the previous OAuth token, and every session after
    # that dies with "OAuth access token has been revoked" / "Invalid API key".
    # The token on the host is already the new one, so re-install it and retry
    # once instead of burning the bug -- 15 libredwg bugs failed this way while
    # a valid credential sat on the host.
    if p.returncode != 0 and _auth_expired(raw) and not _retry:
        logger.warning("%s rejected the container's credentials; re-installing "
                       "from the host and retrying once", cfg["cli_name"])
        _INSTALLED.discard((container, agent))
        if install_credentials(container, agent=agent):
            return run(container, prompt, workdir=workdir, agent=agent,
                       model=model, timeout=timeout, user=user, resume=resume,
                       _retry=True)

    if p.returncode != 0:
        logger.error("%s exited %d: %s", cfg["cli_name"], p.returncode,
                     raw[-500:])
    return p.returncode, raw


def final_message(raw: str, *, agent: str = DEFAULT_AGENT) -> str:
    """The agent's closing message, for logs and failure diagnosis."""
    last = ""
    for event in _events(raw):
        if agent == "claude":
            if event.get("type") == "result" and event.get("result"):
                last = event["result"]
            elif event.get("type") == "assistant":
                for block in event.get("message", {}).get("content", []):
                    if block.get("type") == "text" and block.get("text", "").strip():
                        last = block["text"]
        else:                                   # codex JSONL
            if event.get("type") == "item.completed":
                item = event.get("item", {})
                if item.get("type") == "agent_message" and item.get("text"):
                    last = item["text"]
                elif event.get("payload", {}).get("text"):   # older builds
                    last = event["payload"]["text"]
            elif event.get("msg", {}).get("type") == "agent_message":
                last = event["msg"].get("message", last)
    return last.strip()


def usage(raw: str, *, agent: str = DEFAULT_AGENT) -> dict:
    """Token/cost accounting from the session's result event, when present."""
    out: dict = {}
    for event in _events(raw):
        if agent == "claude" and event.get("type") == "result":
            out = {"usage": event.get("usage", {}),
                   "total_cost_usd": event.get("total_cost_usd"),
                   "num_turns": event.get("num_turns"),
                   "duration_ms": event.get("duration_ms")}
        elif agent == "codex" and event.get("type") == "turn.completed":
            out = {"usage": event.get("usage", {})}
    return out
