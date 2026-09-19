#!/bin/bash
# Copy to setenv.sh and adjust the two external paths at the bottom.
#
#   source script/setenv.sh
#
# Everything the pipeline reads now lives in dataset/ inside this repo, so the
# data variables below need no editing.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---- in-repo data (dataset/, see dataset/README.md) ------------------------
export TESTCASES="$REPO_ROOT/dataset/testcases"
export BUGINFO_PATH="$REPO_ROOT/dataset/osv_testcases_summary.json"
export BUGIDS_PATH="$REPO_ROOT/dataset/osv_projects.json"

# Where buildAndtest.py writes the bug matrices it generates. Point it at
# dataset/csv/per_target to regenerate them in place.
export LOG_PATH="$REPO_ROOT/log"

# ---- external, not vendored ------------------------------------------------
# Git clones of the target projects, checked out per commit during transplant.
export REPO_PATH="/home/user/tasks-git"
# Cache for built fuzzer binaries, keyed <project>-<commit>-<sanitizer>.
# Large; keep it off the repo.
export STORAGE_PATH="/mnt/nas/linke"

# ---- optional --------------------------------------------------------------
# Agent credentials. Codex/opencode authenticate via their own mounted config;
# set this only for a provider that wants a key in the environment.
# export OPENAI_API_KEY=...
