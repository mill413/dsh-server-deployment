#!/usr/bin/env bash
# Register the same custom model provider for every persisted Docker tenant,
# using each tenant's own API key from .credentials.yaml.
set -euo pipefail
set +x

usage() {
  cat <<'EOF'
Usage (run as root inside the dsh deployment container):

  DSH_REGISTER_API_KEY='<gateway bearer token>' \
  PROVIDER_NAME='my-provider' \
  PROVIDER_BASE_URL='https://gateway.example.com/v1' \
  CREDENTIAL_REF='DEEPSEEK_API_KEY' \
  IMAGE_MODELS='vision-model-1,vision-model-2' \
    dsh-batch-register-models.sh

Environment:
  DSH_REGISTER_API_KEY  Required Bearer token for the gateway registration API.
  PROVIDER_NAME         Required llm-pi-ai provider id.
  PROVIDER_BASE_URL     Required OpenAI/Anthropic-compatible base URL.
  CREDENTIAL_REF        Key to read from every .credentials.yaml
                        (default: DEEPSEEK_API_KEY).
  PROVIDER_API          openai-completions (default), openai-responses, or
                        anthropic-messages.
  IMAGE_MODELS          Optional comma-separated image-capable model ids.
  GATEWAY_URL           Gateway origin (default: http://127.0.0.1:3100).
  USERS_FILE            users.json path; auto-detected when omitted.
  DRY_RUN               Set to 1 to read/validate without calling the API.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo 'error: run this script as root so it can read tenant credential files' >&2
  exit 2
fi

: "${DSH_REGISTER_API_KEY:?DSH_REGISTER_API_KEY is required}"
: "${PROVIDER_NAME:?PROVIDER_NAME is required}"
: "${PROVIDER_BASE_URL:?PROVIDER_BASE_URL is required}"

CREDENTIAL_REF="${CREDENTIAL_REF:-DEEPSEEK_API_KEY}"
PROVIDER_API="${PROVIDER_API:-openai-completions}"
IMAGE_MODELS="${IMAGE_MODELS:-}"
GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:3100}"
DRY_RUN="${DRY_RUN:-0}"

if [[ ! "$PROVIDER_NAME" =~ ^[A-Za-z0-9_-]{1,64}$ ]]; then
  echo 'error: PROVIDER_NAME contains invalid characters' >&2
  exit 2
fi
if [[ ! "$PROVIDER_BASE_URL" =~ ^https?://[^[:space:]]+$ ]]; then
  echo 'error: PROVIDER_BASE_URL must be an http(s) URL' >&2
  exit 2
fi
if [[ ! "$CREDENTIAL_REF" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
  echo 'error: CREDENTIAL_REF is invalid' >&2
  exit 2
fi
case "$PROVIDER_API" in
  openai-completions|openai-responses|anthropic-messages) ;;
  *) echo 'error: PROVIDER_API is invalid' >&2; exit 2 ;;
esac

if [[ -z "${USERS_FILE:-}" ]]; then
  for candidate in /var/lib/dsh/gateway/users.json /var/lib/dsh-gateway/users.json; do
    if [[ -f "$candidate" ]]; then USERS_FILE="$candidate"; break; fi
  done
fi
if [[ -z "${USERS_FILE:-}" || ! -f "$USERS_FILE" ]]; then
  echo 'error: users.json not found; set USERS_FILE explicitly' >&2
  exit 2
fi

# Emit exact username/home pairs from the authoritative user store. Usernames
# are deployment-validated and cannot contain tabs or newlines.
list_users() {
  USERS_FILE="$USERS_FILE" node <<'NODE'
const fs = require('fs');
const file = process.env.USERS_FILE;
const db = JSON.parse(fs.readFileSync(file, 'utf8'));
for (const [name, record] of Object.entries(db.users || {}).sort(([a], [b]) => a.localeCompare(b))) {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(name)) continue;
  if (!record || typeof record.home !== 'string' || !record.home) continue;
  process.stdout.write(name + '\t' + record.home + '\n');
}
NODE
}

# Current deployment credentials use version:1 / refs and JSON-compatible
# quoted scalar values. Legacy flat entries are accepted as a fallback.
read_key() {
  local file="$1"
  CREDENTIAL_FILE="$file" CREDENTIAL_REF="$CREDENTIAL_REF" node <<'NODE'
const fs = require('fs');
const file = process.env.CREDENTIAL_FILE;
const ref = process.env.CREDENTIAL_REF;
let raw;
try { raw = fs.readFileSync(file, 'utf8'); } catch (error) { process.exit(3); }
const escaped = ref.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const nested = new RegExp('^  ' + escaped + ':\\s*(.*?)\\s*$', 'm').exec(raw);
const legacy = new RegExp('^' + escaped + ':\\s*(.*?)\\s*$', 'm').exec(raw);
const match = nested || legacy;
if (!match) process.exit(3);
let value = match[1].trim();
try {
  if (value.startsWith('"')) value = JSON.parse(value);
  else if (value.startsWith("'") && value.endsWith("'")) value = value.slice(1, -1).replace(/''/g, "'");
} catch (error) { process.exit(4); }
if (typeof value !== 'string' || !value || /[\r\n]/.test(value)) process.exit(3);
process.stdout.write(value);
NODE
}

call_provider_api() {
  local username="$1"
  local api_key="$2"
  USERNAME="$username" API_KEY="$api_key" \
  DSH_REGISTER_API_KEY="$DSH_REGISTER_API_KEY" \
  PROVIDER_NAME="$PROVIDER_NAME" PROVIDER_BASE_URL="$PROVIDER_BASE_URL" \
  PROVIDER_API="$PROVIDER_API" IMAGE_MODELS="$IMAGE_MODELS" \
  GATEWAY_URL="$GATEWAY_URL" node <<'NODE'
const username = process.env.USERNAME;
const imageModels = process.env.IMAGE_MODELS.split(',').map(x => x.trim()).filter(Boolean);
const body = {
  provider: {
    name: process.env.PROVIDER_NAME,
    baseURL: process.env.PROVIDER_BASE_URL,
    api: process.env.PROVIDER_API,
  },
  apiKey: process.env.API_KEY,
  image_models: [...new Set(imageModels)],
};
const endpoint = process.env.GATEWAY_URL.replace(/\/+$/, '')
  + '/api/users/' + encodeURIComponent(username) + '/provider';
try {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      authorization: 'Bearer ' + process.env.DSH_REGISTER_API_KEY,
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(180000),
  });
  const text = await response.text();
  let reply;
  try { reply = JSON.parse(text); } catch (error) { reply = null; }
  if (!response.ok || !reply || reply.ok !== true) {
    const detail = reply && reply.error ? reply.error : ('HTTP ' + response.status + ' ' + text.slice(0, 300));
    console.error(detail);
    process.exit(1);
  }
  console.log('models=' + (Array.isArray(reply.models) ? reply.models.length : 0));
} catch (error) {
  console.error(error && error.message ? error.message : String(error));
  process.exit(1);
}
NODE
}

total=0
updated=0
skipped=0
failed=0

while IFS=$'\t' read -r username home; do
  [[ -n "$username" && -n "$home" ]] || continue
  total=$((total + 1))
  credential_file="$home/.credentials.yaml"
  if ! api_key="$(read_key "$credential_file")"; then
    echo "SKIP $username: $CREDENTIAL_REF is missing or unreadable"
    skipped=$((skipped + 1))
    continue
  fi

  if [[ "$DRY_RUN" == "1" ]]; then
    echo "DRY  $username: credential found"
    updated=$((updated + 1))
    unset api_key
    continue
  fi

  printf 'CALL %s: ' "$username"
  if call_provider_api "$username" "$api_key"; then
    updated=$((updated + 1))
  else
    failed=$((failed + 1))
  fi
  unset api_key
done < <(list_users)

echo "complete: total=$total updated=$updated skipped=$skipped failed=$failed"
[[ "$failed" -eq 0 ]]
