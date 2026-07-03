#!/usr/bin/env bash
# Drip-push commits to GitHub one batch per run.
#
# Each batch contains roughly one week's worth of commits. The script
# tracks its position in a state file (.push_state) so it picks up where
# it left off. Run via cron (see scripts/crontab.txt) to spread the
# project history across 4 weeks of GitHub activity.
#
# First run: sets the remote and pushes the initial batch.
# Subsequent runs: each pushes the next batch.
# Once all commits are pushed, further runs are no-ops.
#
# Usage: bash scripts/push_schedule.sh [--dry-run]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

REMOTE_URL="https://github.com/Mahmoud-Berkoti/Bastion.git"
STATE_FILE="$REPO_ROOT/.push_state"
DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

# Ordered list of commits to push, oldest first.
COMMITS=(
  "a217696"  # Week 1 — chore(env): Phase 0, Vagrant, Makefile, veth harness
  "33b8335"  # Week 1 — feat(bpf): XDP data plane
  "ba94d95"  # Week 2 — feat(control-plane): loader, rules, stats, events
  "2fa503b"  # Week 2 — feat(api,web): REST API, SSE, dashboard
  "69192c0"  # Week 3 — test: BPF_PROG_TEST_RUN unit tests
  "75a54cc"  # Week 3 — feat(bench): pktgen + iptables comparison
  "3aa8c91"  # Week 4 — docs: README, architecture, API reference
  "c0b5dc4"  # Week 4 — fix(make): go binary path under sudo
  "7dfc1fd"  # Week 4 — feat(demo): cross-platform demo mode
  "737e2f6"  # Week 4 — fix(security): API hardening
  "077d618"  # Week 4 — chore(deploy): push schedule scripts
)

# Commits to include in each weekly batch (index into COMMITS array).
# Batches are defined as: "first_index:count"
BATCHES=(
  "0:2"   # Week 1: env + BPF data plane
  "2:2"   # Week 2: control plane + API/web
  "4:2"   # Week 3: tests + benchmarks
  "6:5"   # Week 4: docs, fixes, demo, security, deploy scripts
)

# ---------- helpers ----------

log() { echo "[$(date '+%Y-%m-%d %H:%M')] $*"; }

current_batch() {
  [[ -f "$STATE_FILE" ]] && cat "$STATE_FILE" || echo "0"
}

save_batch() { echo "$1" > "$STATE_FILE"; }

ensure_remote() {
  if ! git remote get-url origin &>/dev/null; then
    log "Adding remote origin → $REMOTE_URL"
    git remote add origin "$REMOTE_URL"
  fi
}

# Returns the full SHA for a short hash.
full_sha() { git rev-parse "$1"; }

# ---------- main ----------

ensure_remote

BATCH_IDX=$(current_batch)
TOTAL_BATCHES=${#BATCHES[@]}

if [[ $BATCH_IDX -ge $TOTAL_BATCHES ]]; then
  log "All $TOTAL_BATCHES batches already pushed. Nothing to do."
  exit 0
fi

IFS=: read -r START COUNT <<< "${BATCHES[$BATCH_IDX]}"
END=$(( START + COUNT - 1 ))

log "Batch $((BATCH_IDX + 1))/$TOTAL_BATCHES — pushing ${COMMITS[$START]}..${COMMITS[$END]}"

TARGET_SHA=$(full_sha "${COMMITS[$END]}")

if [[ $DRY_RUN -eq 1 ]]; then
  log "DRY RUN: would push up to $TARGET_SHA"
  log "Commits in this batch:"
  for (( i=START; i<=END; i++ )); do
    git log --oneline -1 "${COMMITS[$i]}"
  done
  exit 0
fi

# Push up to and including the last commit in this batch.
# refspec pushes a specific SHA to main rather than the local HEAD, so
# later batches on the local branch stay invisible until their turn.
git push origin "${TARGET_SHA}:refs/heads/main" --set-upstream

BATCH_IDX=$(( BATCH_IDX + 1 ))
save_batch "$BATCH_IDX"

if [[ $BATCH_IDX -ge $TOTAL_BATCHES ]]; then
  log "All commits pushed. Bastion is fully live at $REMOTE_URL"
else
  REMAINING=$(( TOTAL_BATCHES - BATCH_IDX ))
  log "Done. $REMAINING batch(es) remaining — next run will push the Week $((BATCH_IDX + 1)) batch."
fi
