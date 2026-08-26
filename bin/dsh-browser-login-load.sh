#!/usr/bin/env bash
# Open many DSH one-time login links in isolated browser profiles.
#
# Each profile owns an independent cookie jar. Opening every URL in one normal
# browser profile would only test the last user because dsh_session is an
# origin-wide cookie and each login overwrites the previous user's session.
#
# Usage:
#   DSH_LOGIN_API_KEY='...' ./bin/dsh-browser-login-load.sh \
#     https://dsh.example.com users.txt
#
# users.txt: one username per line; blank lines and lines beginning with # are
# ignored. Usernames follow the gateway's [A-Za-z0-9_-] grammar.
#
# Optional environment variables:
#   BROWSER_BIN=/usr/bin/chromium   Browser executable (auto-detected)
#   CONCURRENCY=5                   Simultaneous isolated browsers
#   HOLD_SECONDS=60                 How long each browser stays open
#   HEADLESS=1                      1=headless, 0=visible windows
#   RETURN_TO=/                     Same-origin path after login
#   OUTPUT_DIR=./login-load-...     Per-user responses/browser logs/results
set -uo pipefail
umask 077

usage() {
  echo "usage: DSH_LOGIN_API_KEY=<token> $0 <base-url> <users-file>" >&2
  exit 2
}

[ "$#" -eq 2 ] || usage
[ -n "${DSH_LOGIN_API_KEY:-}" ] || { echo "error: DSH_LOGIN_API_KEY is required" >&2; exit 2; }

BASE_URL="${1%/}"
USERS_FILE="$2"
CONCURRENCY="${CONCURRENCY:-5}"
HOLD_SECONDS="${HOLD_SECONDS:-60}"
HEADLESS="${HEADLESS:-1}"
RETURN_TO="${RETURN_TO:-/}"
OUTPUT_DIR="${OUTPUT_DIR:-$PWD/login-load-$(date +%Y%m%d-%H%M%S)}"

case "$BASE_URL" in http://*|https://*) ;; *) echo "error: base-url must start with http:// or https://" >&2; exit 2 ;; esac
[ -f "$USERS_FILE" ] || { echo "error: users file not found: $USERS_FILE" >&2; exit 2; }
case "$CONCURRENCY" in ''|*[!0-9]*) echo "error: CONCURRENCY must be a positive integer" >&2; exit 2 ;; esac
case "$HOLD_SECONDS" in ''|*[!0-9]*) echo "error: HOLD_SECONDS must be a positive integer" >&2; exit 2 ;; esac
[ "$CONCURRENCY" -gt 0 ] || { echo "error: CONCURRENCY must be greater than zero" >&2; exit 2; }
[ "$HOLD_SECONDS" -gt 0 ] || { echo "error: HOLD_SECONDS must be greater than zero" >&2; exit 2; }
[ "$HEADLESS" = "0" ] || [ "$HEADLESS" = "1" ] || { echo "error: HEADLESS must be 0 or 1" >&2; exit 2; }
[[ "$RETURN_TO" == /* && "$RETURN_TO" != //* ]] \
  || { echo "error: RETURN_TO must be a same-origin absolute path" >&2; exit 2; }

for required in curl node timeout; do
  command -v "$required" >/dev/null 2>&1 || { echo "error: missing command: $required" >&2; exit 2; }
done

if [ -z "${BROWSER_BIN:-}" ]; then
  for candidate in chromium chromium-browser google-chrome google-chrome-stable; do
    if command -v "$candidate" >/dev/null 2>&1; then BROWSER_BIN="$(command -v "$candidate")"; break; fi
  done
fi
[ -n "${BROWSER_BIN:-}" ] && [ -x "$BROWSER_BIN" ] \
  || { echo "error: Chromium/Chrome not found; set BROWSER_BIN" >&2; exit 2; }

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

mapfile -t RAW_USERS < <(awk 'NF && $1 !~ /^#/ { print $1 }' "$USERS_FILE")
declare -a USERS=()
declare -A SEEN=()
for user in "${RAW_USERS[@]}"; do
  [[ "$user" =~ ^[A-Za-z0-9_-]{1,64}$ ]] \
    || { echo "error: invalid username in users file: $user" >&2; exit 2; }
  if [ -z "${SEEN[$user]+x}" ]; then USERS+=("$user"); SEEN[$user]=1; fi
done
[ "${#USERS[@]}" -gt 0 ] || { echo "error: users file contains no usernames" >&2; exit 2; }

run_one() {
  local user="$1"
  local response_file="$OUTPUT_DIR/$user.ticket.json"
  local browser_log="$OUTPUT_DIR/$user.browser.log"
  local result_file="$OUTPUT_DIR/$user.result"
  local profile http_code curl_code login_url payload browser_code browser_job=''

  profile="$(mktemp -d "${TMPDIR:-/tmp}/dsh-browser-$user.XXXXXX")" \
    || { printf 'FAILED\tprofile-create\n' >"$result_file"; return 1; }
  # shellcheck disable=SC2329  # invoked by the EXIT/INT/TERM trap below
  cleanup_one() {
    if [ -n "$browser_job" ] && kill -0 "$browser_job" 2>/dev/null; then
      kill "$browser_job" 2>/dev/null || true
      wait "$browser_job" 2>/dev/null || true
    fi
    rm -rf -- "$profile"
  }
  trap cleanup_one EXIT INT TERM

  payload="$(LOGIN_USER="$user" LOGIN_RETURN_TO="$RETURN_TO" node -e '
    process.stdout.write(JSON.stringify({
      username: process.env.LOGIN_USER,
      returnTo: process.env.LOGIN_RETURN_TO,
    }));
  ')" || { printf 'FAILED\tpayload\n' >"$result_file"; return 1; }

  # Read the privileged bearer header from stdin so it is not exposed in the
  # process command line (`ps`). The response file is protected by umask 077.
  http_code="$(printf 'Authorization: Bearer %s\n' "$DSH_LOGIN_API_KEY" | \
    curl -sS -o "$response_file" -w '%{http_code}' \
      -X POST "$BASE_URL/api/login-ticket" \
      -H @- \
      -H 'Content-Type: application/json' \
      --data "$payload")"
  curl_code=$?
  if [ "$curl_code" -ne 0 ]; then
    printf 'FAILED\tcurl-%s\n' "$curl_code" >"$result_file"
    return 1
  fi
  if [ "$http_code" != "200" ]; then
    printf 'FAILED\thttp-%s\n' "$http_code" >"$result_file"
    return 1
  fi

  login_url="$(node -e '
    const fs = require("fs");
    const reply = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    if (!reply || reply.ok !== true || typeof reply.loginUrl !== "string") process.exit(1);
    process.stdout.write(reply.loginUrl);
  ' "$response_file")" || { printf 'FAILED\tinvalid-ticket-response\n' >"$result_file"; return 1; }
  [[ "$login_url" == /* && "$login_url" != //* ]] \
    || { printf 'FAILED\tunsafe-login-url\n' >"$result_file"; return 1; }

  local -a browser_args=(
    "--user-data-dir=$profile"
    --no-first-run
    --no-default-browser-check
    --disable-background-networking
    --disable-sync
    --disable-extensions
    --disable-dev-shm-usage
    '--window-size=1280,900'
  )
  if [ "$HEADLESS" = "1" ]; then
    browser_args+=(--headless=new --disable-gpu --remote-debugging-port=0)
  fi
  if [ "$(id -u)" -eq 0 ]; then browser_args+=(--no-sandbox); fi
  browser_args+=("$BASE_URL$login_url")

  echo "[$(date -Is)] opening $user for ${HOLD_SECONDS}s" >"$browser_log"
  timeout --signal=TERM --kill-after=5 "${HOLD_SECONDS}s" \
    "$BROWSER_BIN" "${browser_args[@]}" >>"$browser_log" 2>&1 &
  browser_job=$!
  wait "$browser_job"
  browser_code=$?
  browser_job=''

  case "$browser_code" in
    124|137)
      printf 'OK\theld-%ss\n' "$HOLD_SECONDS" >"$result_file"
      return 0
      ;;
    0)
      printf 'FAILED\tbrowser-exited-early\n' >"$result_file"
      return 1
      ;;
    *)
      printf 'FAILED\tbrowser-exit-%s\n' "$browser_code" >"$result_file"
      return 1
      ;;
  esac
}

echo "target=$BASE_URL"
echo "users=${#USERS[@]} concurrency=$CONCURRENCY hold=${HOLD_SECONDS}s headless=$HEADLESS"
echo "browser=$BROWSER_BIN"
echo "output=$OUTPUT_DIR"

active=0
declare -a JOBS=()
for user in "${USERS[@]}"; do
  run_one "$user" &
  JOBS+=("$!")
  active=$((active + 1))
  if [ "$active" -ge "$CONCURRENCY" ]; then
    wait -n || true
    active=$((active - 1))
  fi
done
while [ "$active" -gt 0 ]; do
  wait -n || true
  active=$((active - 1))
done

shopt -s nullglob
results=("$OUTPUT_DIR"/*.result)
ok=0
failed=0
for result in "${results[@]}"; do
  if grep -q '^OK' "$result"; then ok=$((ok + 1)); else failed=$((failed + 1)); fi
done
if [ "${#results[@]}" -lt "${#USERS[@]}" ]; then
  failed=$((failed + ${#USERS[@]} - ${#results[@]}))
fi

echo "complete: ok=$ok failed=$failed total=${#USERS[@]}"
if [ "$failed" -gt 0 ]; then
  echo "failures:"
  grep -H '^FAILED' "$OUTPUT_DIR"/*.result 2>/dev/null || true
  exit 1
fi
