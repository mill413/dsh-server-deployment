#!/usr/bin/env bash
# Wake every registered lazy tenant. Intended for one-off load tests inside the
# container; normal production traffic should continue to wake tenants on login.
set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "wake-all must run as root" >&2
  exit 2
fi

control_socket="${DSH_CONTROL_SOCKET:-/run/dsh/control.sock}"
wait_seconds="${WAIT_SOCKET:-180}"
parallel="${WAKE_PARALLEL:-0}"

case "$wait_seconds" in
  ''|*[!0-9]*) echo "WAIT_SOCKET must be a non-negative integer" >&2; exit 2 ;;
esac
case "$parallel" in
  ''|*[!0-9]*) echo "WAKE_PARALLEL must be a non-negative integer" >&2; exit 2 ;;
esac

# Compatibility for volumes left by older images. The supervisor now creates
# /run/dsh/control.sock; these candidates only make the helper usable while
# diagnosing a still-running old container.
if [ ! -S "$control_socket" ]; then
  for candidate in \
    /run/dsh/control.sock \
    /var/lib/dsh/gateway/control.sock \
    /var/lib/dsh-gateway/control.sock \
    /srv/dsh/gateway/control.sock
  do
    if [ -S "$candidate" ]; then
      control_socket="$candidate"
      break
    fi
  done
fi

deadline=$((SECONDS + wait_seconds))
while [ ! -S "$control_socket" ] && [ "$SECONDS" -lt "$deadline" ]; do
  sleep 1
done
if [ ! -S "$control_socket" ]; then
  echo "control socket is not ready: $control_socket" >&2
  exit 1
fi

mapfile -t users < <(dsh-users list | awk 'NR > 1 && $1 != "(no" { print $1 }')
if [ "${#users[@]}" -eq 0 ]; then
  echo "no users to wake"
  exit 0
fi

wake_one() {
  local user="$1"
  if /usr/local/libexec/dsh/dsh-register --wake "$user" "$control_socket"; then
    echo "woke $user" >&2
  else
    echo "failed to wake $user" >&2
    return 1
  fi
}

failures=0
if [ "$parallel" -gt 0 ]; then
  running=0
  for user in "${users[@]}"; do
    wake_one "$user" &
    running=$((running + 1))
    if [ "$running" -ge "$parallel" ]; then
      if ! wait -n; then failures=$((failures + 1)); fi
      running=$((running - 1))
    fi
  done
  while [ "$running" -gt 0 ]; do
    if ! wait -n; then failures=$((failures + 1)); fi
    running=$((running - 1))
  done
else
  for user in "${users[@]}"; do
    if ! wake_one "$user"; then failures=$((failures + 1)); fi
  done
fi

echo "wake-all complete: total=${#users[@]} failures=$failures"
[ "$failures" -eq 0 ]
