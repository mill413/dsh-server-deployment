# DeepSeek Harness Server Deployment (dsh-server-deployment)

[简体中文](README.md) | [English](README.en.md)

<p align="center">
  <img src="assets/cover.png" alt="DSH server deployment cover" width="100%">
</p>

A zero-dependency Node gateway that adds a **multi-user portal** to the web front end of [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (DSH): login authentication, one isolated DSH instance and OS-level data isolation per user, per-user API keys, and a built-in **delivery file drawer** (download / upload / automatic current-workspace detection). Isolation is enforced by the **OS account boundary**, not by gateway code — file access goes through sudo helpers that drop privileges via `runuser` to the `dsh-<name>` user (fixing the issue #1 TOCTOU race), and the gateway itself has zero permissions on user directories. See [docs/multi-user-isolation.md](docs/multi-user-isolation.md) for the full model.

> **Deployment scope (important)**: this project is a **server-side deployment** — the gateway, per-user DSH instances, and file helpers all run on a **remote server**; multiple users access their own sessions and delivery files via a browser (public domain + HTTPS). It is **not a local / desktop tool** and **requires no software installed on users' computers**. Example paths in the docs (e.g. `/opt/deepseek-harness`, `/etc/systemd/system`) are server-side paths.

## Features

- **Login portal**: custom dark login page (lacquer + gold-leaf style), scrypt passwords (with legacy APR1 compatibility), HMAC-signed session cookies (HttpOnly / Secure / SameSite=Lax), login rate limiting (both per-IP and per-account), and double-submit CSRF checks.
- **User isolation**: each user gets a dedicated DSH instance (own port) running as a dedicated system account `dsh-<name>`, with `DSH_HOME` pointing to their 0700 private directory; `userctl.js` provisions / re-passwords / deletes accounts and preloads keys with a single command.
- **Per-user API keys**: users without a key are guided to `/setup` after login; the key is written via loopback RPC into that user's private `.credentials.yaml` (0600, owned only by them).
- **Loopback privileged-endpoint fix**: the gateway presents `Host: 127.0.0.1:<port>` to the backend and strips browser trust markers, so DSH's loopback-pinned privileged endpoints (settings / credentials / agentPreset, …) keep working behind public HTTPS access.
- **Delivery file drawer (file management)**: its trigger sits at the bottom of the left sidebar above Logout and Settings, cloning the Settings row style; expanded shows icon + label and the collapsed rail shows only the same-sized icon. It opens a white embedded browser for directory listing, downloads (attachment + non-ASCII filenames), and multi-file uploads (100 MB limit), automatically locating the current conversation's working directory from session RPC traces.
- **Security boundary**: all user-file access goes through fixed-path sudo helper scripts — root only validates arguments and drops privileges; file operations execute as the `dsh-<name>` user itself (fixing the issue #1 TOCTOU race). The gateway process has zero permissions on user directories; hidden files (including `.credentials.yaml`) cannot be downloaded; the SPA injection respects `prefers-reduced-motion` and contains no glassmorphism / gradient decoration.

## Architecture

```
Browser ──https──▶ reverse proxy (TLS, e.g. OpenResty) ──▶ dsh-gateway(:3100) ──▶ per-user DSH instance (:3101+)
                                  │                     │
                                  │ sessions/throttle/ │ runs as dedicated OS account dsh-<name>
                                  │ CSRF/routing       │ DSH_HOME=<user-private 0700 dir>
                                  │ key setup/drawer   │
                                  └──────────┬──────────┘
                                             └─ file access via sudo helpers: dsh-file-{list,stat,read,put}
```

> The gateway's default port is **3100** in the live deployment (this repo's example uses 3081; override with the `PORT` environment variable); per-user instances increment from 3101, allocated by `userctl`.

See [docs/multi-user-isolation.md](docs/multi-user-isolation.md) for the full multi-user and data-isolation story.

## Repository layout

```
gateway/                # the gateway itself (zero-dependency Node)
  server.js             #   login/session/throttle/CSRF/reverse proxy/SPA injection/file drawer/upload-download
  auth.js               #   scrypt + APR1 password verification
  credentials.js        #   .credentials.yaml read/write (userctl only)
  userctl.js            #   user management: OS accounts/ports/instances/keys
  _smoke.js             #   gateway smoke tests (runs locally, no DSH needed)
  static/               #   pre-login static assets (manifest/favicon)
bin/                    # host-side entry points and root helpers
  dsh-users.sh          #   sudo entry for userctl (host/systemd deployments)
  dsh-file-{list,stat,read,put}[.js]
docker/                 # Docker deployment (all Docker-related files live here)
  Dockerfile            #   image build (build context is the repository root)
  Dockerfile.dockerignore #  build exclusions (repo-root `.dockerignore` is a symlink to this; the toolchain requires it at the context root)
  compose.yml           #   run from the repository root: docker compose -f docker/compose.yml ...
  dsh-users             #   userctl entry for Docker deployments (installed at /usr/local/libexec/dsh in the image)
  dsh-register          #   self-service registration root helper (sudoers allowlist; forwards registration to the supervisor)
  entrypoint.js         #   container entrypoint/supervisor: seeds tenants, manages users at runtime, control socket
  userctl.js            #   forwarding client behind the in-container `dsh-users` command
  healthcheck.js        #   health check (gateway in lazy mode; tenant ports in eager mode)
  dsh-gateway.sudoers   #   gateway sudoers allowlist (fixed path inside the image)
units/                  # systemd unit templates (gateway + per-user units generated by userctl)
nginx/                  # TLS reverse-proxy example config (placeholder domain)
```

## Docker test on a trusted network

During the build, the Docker test image shallow-clones the latest `master` branch directly from the official `https://github.com/deepseek-ai/deepseek-harness.git`; it does not read a sibling local Harness checkout. The build runs `dsh plugin --profile web add dsh-better-sidebar` once in a public profile and stores the complete dependency tree as root-owned read-only files under `/opt/dsh-public`. The entrypoint writes each tenant's lightweight `link:` dependency and symlink directly, without starting pnpm on the registration hot path; persisted and runtime-created users are both covered without copying the dependency tree. The runtime image includes pnpm and the build tools needed for other native plugins, and keeps the complete Harness source and build output under `/opt/deepseek-harness`, plus this complete deployment repository under `/opt/dsh-server-deployment`. The gateway and tenant instances share one container network namespace, while every instance still runs under its own `dsh-<name>` OS account with a separate `DSH_HOME`. The entrypoint applies linearly scaling loopback firewall rules before starting tenants and terminates the container if isolation cannot be installed. It needs only the `NET_ADMIN` capability, not `--privileged` or systemd inside the container.

Every Docker tenant starts with the deployment patch `docker/disable-llm-deepseek.patch.yml`, which disables the built-in `llm-deepseek` entry with `disabled: true`; `llm-pi-ai` and each tenant's own model settings remain available. This launcher patch is applied after user configuration, so the deployment policy does not need to be copied into or written to tenant homes.

The gateway injects a trusted-gateway marker into authenticated proxied DSH pages. During the image build, `docker/patches/deepseek-harness-trusted-gateway.patch` makes browsers served from a LAN IP or reverse-proxy domain use the Host Settings Mirror. Server-side session, Host, Origin, and tenant-isolation checks remain authoritative; this adaptation only removes the upstream client's non-loopback UI gate.

The image is split into two layers: `docker/Dockerfile.base` builds DSH, applies the Harness patch, installs system dependencies, and prepares public plugins; `docker/Dockerfile` only copies and installs this deployment repository on top of that base. Changes to the gateway or entrypoint therefore rebuild only the final image without recompiling DSH. Run all commands from the **repository root**:

```bash
# Rebuild the slower base when DSH, system dependencies, or public plugins change.
docker build --pull -f docker/Dockerfile.base -t dsh-server-base:local .

# Rebuild the fast final image for deployment-code-only changes.
docker compose -f docker/compose.yml build
docker compose -f docker/compose.yml up -d
docker compose -f docker/compose.yml ps
docker compose -f docker/compose.yml logs --tail=100
```

Set `DSH_BASE_IMAGE` to consume another base tag, for example: `DSH_BASE_IMAGE=registry.example.com/dsh-server-base:v1 docker compose -f docker/compose.yml build`. The final image includes all parent layers, so `docker save dsh-server-deployment:local` alone exports a complete runnable image.

Open `http://127.0.0.1:20810` in a browser. The default test accounts are:

| User | Password |
|---|---|
| `alice` | `alice-test-password` |
| `bob` | `bob-test-password` |

The Compose file defaults to `DSH_SKIP_KEY_SETUP=1` for login, UI, and tenant-isolation testing without a real API key; model calls do not work in this mode. Set it to `0` and restart to test complete conversations, then enter a separate key for each tenant at first login.

### Managing users at runtime (no Compose edits)

`DSH_TENANTS_JSON` is only a **bootstrap seed**: tenants are created (or updated) from it at container start. Afterwards the in-image `dsh-users` command adds / removes / changes users at any time — no Compose edit, no image rebuild, no container restart:

```bash
docker compose -f docker/compose.yml exec dsh-multitenant dsh-users list
docker compose -f docker/compose.yml exec dsh-multitenant dsh-users add carol                  # prompts for password (hidden) if omitted
docker compose -f docker/compose.yml exec dsh-multitenant dsh-users add carol 'carol-password'
docker compose -f docker/compose.yml exec dsh-multitenant dsh-users passwd carol 'new-password'
docker compose -f docker/compose.yml exec dsh-multitenant dsh-users set-key carol sk-xxxx
docker compose -f docker/compose.yml exec dsh-multitenant dsh-users key-status carol
docker compose -f docker/compose.yml exec dsh-multitenant dsh-users del carol                  # confirm, then deletes ALL of the user's data
```

Behavior notes:

- Runtime users are written to `docker/data/gateway/users.json` (container path `/var/lib/dsh/gateway/users.json`) and **survive container rebuilds / restarts** (at boot the seed list is merged with existing users; ports, passwords and identities are kept). All data is persisted via a bind mount to `docker/data/` on the host (container `/var/lib/dsh`: `users/` for user homes, `gateway/` for state), directly visible and backup-able. The supervisor IPC socket lives outside that volume at `/run/dsh/control.sock` (override with `DSH_CONTROL_SOCKET`); it is runtime-only, is excluded from backups, and must never be shared by multiple instances.
- To remove a user use `dsh-users del` (also removes their data); removing a user from `DSH_TENANTS_JSON` does NOT delete an existing user.
- `dsh-users` shares the same user store as the gateway: a new user can log in immediately (gateway cache refreshes within at most 2s).
- Passwords must be at least 8 characters; `passwd` immediately invalidates all of the user's issued sessions.
- `DSH_LAZY_TENANTS=1` is the default: provisioning creates the OS account, private HOME, port record, shared-plugin links and firewall rule without spawning DSH. The gateway starts and waits for that user's instance after the first successful login. It runs until logout/browser-presence recycling or container restart. Set `DSH_LAZY_TENANTS=0` to restore eager startup.
- Proxied DSH pages place Logout directly above Settings in the left sidebar, cloning the Settings row's styling and state: icon plus label when expanded, icon only on the collapsed rail. Manual logout persistently revokes all issued sessions for that user, stops the tenant process group, then kills any escaped process owned by that tenant's unique OS UID; the user's HOME and files are untouched. Per-tab heartbeats track browser presence: closing the last tab recycles the tenant process after a 5-second reload grace, while one tab closing among several does not. Crashes/disconnects fall back to a 120-second heartbeat timeout. Automatic recycling manages only process lifetime and preserves the login cookie, so the next request can wake the tenant with the existing session. Only manual logout, an administrator kick, or a password change revokes sessions. Tune the recycle timers with `DSH_BROWSER_STOP_GRACE_MS` and `DSH_BROWSER_PRESENCE_TTL_MS`.

### Persistent shared Web plugins (no Dockerfile change)

For day-to-day installation, use `dsh-users plugin add <spec>` inside the container. The supervisor installs arbitrary DSH bundles under `/var/lib/dsh/shared-plugins`, enables dependency lifecycle scripts by default, then synchronizes shared `link:` dependencies and symlinks into every existing tenant and restarts only tenant DSH processes. Runtime-created tenants receive the same synchronization before their process starts. The shared root lives in the `/var/lib/dsh` persistent volume, so later Pod recreations validate install receipts and skip completed npm installs. Only install trusted plugins because their installation scripts run with container root privileges.

The command streams pnpm download/build and tenant synchronization progress to the current terminal. Configure an internal registry in the shared installation home (a normal `npm config set registry` writes `/root/.npmrc`, which this isolated installation home does not read):

```bash
kubectl exec -n <namespace> <pod> -- \
  env HOME=/var/lib/dsh/shared-plugins \
  npm config set registry http://<internal-npm-registry>
```

```yaml
env:
  - name: DSH_SHARED_WEB_PLUGINS_JSON
    value: >-
      [{"name":"@huanlin/dsh-plugin-better-sidebar-plugin-office","spec":"@huanlin/dsh-plugin-better-sidebar-plugin-office@0.1.2"}]
```

Each item must provide the npm package `name`. `spec` may pin a version or use another pnpm-supported install spec and defaults to `name`. Legacy `allowBuilds` fields are ignored because all dependency builds are enabled. Removing an item from the environment does not automatically delete an already-persisted shared plugin. `DSH_SHARED_PLUGINS_HOME` overrides the shared root; by default it is the `shared-plugins/` sibling of `DSH_USERS_DIR`.

### Self-service registration (login page, Docker deployment)

The gateway supports self-service account creation through the login-page registration link, but this repository's Docker Compose sets `DSH_ENABLE_REGISTER=0` by default, so both the link and page are disabled. When enabled, a registration request flows gateway → allowlisted sudo helper `dsh-register` → entrypoint supervisor, which provisions the user exactly like the CLI (OS account / port / instance / firewall):

- **Enablement**: disabled by this Compose file; explicitly set `DSH_ENABLE_REGISTER=1` to enable it. If the variable is absent, the image auto-enables registration when the `dsh-register` helper is present (host deployments have no such helper, so it remains off there).
- **Limits**: username limited to letters/digits/underscore/hyphen; password at least 8 characters; per-IP rate limiting on failed registrations (`MAX_REGISTER_ATTEMPTS`, default 10 per 15 minutes).
- **Caution**: open registration means anyone who can reach the login page can create an account (each account = a separate process + port). For public deployments consider an invite-code gate or HTTPS, and evaluate the risk yourself.

### Admin console (admin account)

- **admin account**: created/updated from `DSH_ADMIN_PASSWORD` (scrypt-hashed in `users.json`, flagged `admin: true`). It is now a full isolated tenant with its own `dsh-admin` OS account, HOME, port and lazy DSH; legacy management-only records are migrated at boot. Admin login enters its own DSH, whose sidebar includes an Admin Console action; the console links back to the workspace.
- **User list**: `/__gw/admin` shows username, online state, port, last activity, the persisted API-key flag, and creation time. It refreshes only on an explicit admin click and caches the last result in the browser. Live DSH state, RSS, process count, disk usage, and on-disk key scans are temporarily disabled so management metrics cannot block the supervisor control socket shared with login.
- **Shared plugin management**: the admin console lists plugin name, version, image/runtime source and path; it can install or upgrade npm/Git/file specs and remove runtime plugins. Mutations run as background jobs with live pnpm and tenant-sync logs, then refresh automatically. Image-bundled plugins are marked non-removable, and only one mutation runs at a time.
- **Access control**: non-admin sessions are redirected away from `/__gw/admin`; the registration endpoint rejects the `admin` username (reserved).
- **Password change**: edit `DSH_ADMIN_PASSWORD` and restart the container (sessions are invalidated). Do not use `dsh-users passwd admin` — the env var overwrites it on the next boot.
- To disable, unset `DSH_ADMIN_PASSWORD` and remove the admin record from `users.json`.

### External automatic login (one-time ticket)

After setting a dedicated `DSH_LOGIN_API_KEY`, a trusted external **backend service** can obtain a one-time login URL for an existing user. The long-lived key must only exist server-side; never place it in browser JavaScript, a URL, or frontend configuration. The local test Compose defaults to `login-test-token` and allows an environment override of the same name; never use that default in production.

First, the external backend issues a ticket (`returnTo` is optional and only same-origin paths beginning with `/` are accepted):

```bash
curl -X POST https://dsh.example.com/api/login-ticket \
  -H "Authorization: Bearer <DSH_LOGIN_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","returnTo":"/"}'
# → 200 {"ok":true,"loginUrl":"/auth/external?ticket=...","expiresIn":60}
```

The external backend then redirects the user's browser to `https://dsh.example.com` plus the returned `loginUrl`. DSH consumes the ticket, sets the `dsh_session` cookie, and redirects to `returnTo`; a normal user without a configured key goes to `/setup` first, while an admin goes to the admin console.

- Tickets expire after 60 seconds by default, are single-use, and disappear on process restart. Set `LOGIN_TICKET_TTL` to 10–300 seconds if needed.
- The endpoint is disabled when `DSH_LOGIN_API_KEY` is unset. Unknown users return 404; a missing or invalid Bearer token returns 401.
- Tickets live in gateway process memory, so the current deployment must use a single gateway replica; issuing and consuming a ticket must reach the same process.
- `DSH_LOGIN_API_KEY` grants the ability to log in as any existing user. Keep it separate from `DSH_REGISTER_API_KEY` and inject it from a secret store such as a Kubernetes Secret.

For concurrent browser login testing, use `bin/dsh-browser-login-load.sh`. It creates one isolated Chromium profile per user so same-origin `dsh_session` cookies do not overwrite each other. The defaults run five browsers concurrently and hold each for 60 seconds; increase concurrency gradually instead of launching 100 browser processes immediately:

```bash
docker compose -f docker/compose.yml exec -T dsh-multitenant dsh-users list \
  | tail -n +2 | cut -f1 > /tmp/dsh-users.txt
DSH_LOGIN_API_KEY='<token>' CONCURRENCY=10 HOLD_SECONDS=60 \
  ./bin/dsh-browser-login-load.sh https://dsh.example.com /tmp/dsh-users.txt
```

### External registration API & model registration (machine-to-machine)

Setting `DSH_REGISTER_API_KEY` (compose env var, default `register-test-token`) enables two Bearer-token endpoints; leaving it unset disables them entirely.

**① Create a user (account only, no provider)** `POST /api/register`

```bash
curl -X POST http://<host>:20810/api/register \
  -H "Authorization: Bearer <DSH_REGISTER_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice2","password":"alice2-password"}'
# → 200 {"ok":true,"user":"alice2","port":3107}
```

- Creates the user only (OS account / port / instance); **does not accept a provider** (passing one returns 400 with a pointer to ②).
- Username/password are validated; duplicates return 409; missing token returns 401.

**② Model registration (configure custom provider + write API key)** `POST /api/users/<username>/provider`

```bash
curl -X POST http://<host>:20810/api/users/alice2/provider \
  -H "Authorization: Bearer <DSH_REGISTER_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"provider":{"name":"my-gateway","baseURL":"https://gateway.example.com/v1"},
       "apiKey":"sk-xxxx",
       "image_models":["gpt-4o","qwen-vl-max"]}'
# → 200 {"ok":true,"user":"alice2","provider":{"name":"my-gateway","baseURL":"...","model":"gpt-4o-mini","apiKeyEnv":"MY_GATEWAY_API_KEY"},"ref":"MY_GATEWAY_API_KEY"}
```

- **Strict validation**: `provider` is required (name limited to letters/digits/underscore/hyphen, baseURL must be an http(s) URL); `provider.api` is optional — `openai-completions` (default) / `openai-responses` / `anthropic-messages` — an invalid value makes the whole settings section rejected and the model unusable; `apiKey` is required; the target user must exist (admin included).
- **Automatic model discovery**: when `provider.model` (or a `models` array) is omitted, the gateway calls `GET <baseURL>/models` with the API key and writes the fetched model list (capped at 100) into the user's config; a fetch failure returns 502 with a hint to pass `provider.model` explicitly. Passing `model`/`models` skips the fetch. The response's `models` array is the effective model list.
- **Image-input allowlist**: the optional top-level `image_models` array (also accepted as `provider.image_models`) contains model ids. Discovered models in the allowlist are written with `input: [text, image]`; every other model gets `input: [text]`. It defaults to an empty array when omitted. The allowlist is not checked against the discovered catalog: unmatched entries remain in the response but do not create extra model configurations.
- Effect: writes the user's `settings.yaml` (an `llm-pi-ai.providers.<name>` OpenAI-compatible profile plus `agent-default-model`) and owner-only `.credentials.yaml` (0600). A dormant user stays dormant; an already-running user's instance is restarted so the change applies immediately.
- Re-calling the endpoint **replaces** the provider config and key (change baseURL/model/key anytime). The returned `ref` is the provider's credential name (`<NAME>_API_KEY`).
- Once configured, the user skips `/setup` and the provider is the default on login.

From the host, verify that Alice can reach her instance but cannot reach Bob's:

```bash
docker compose -f docker/compose.yml exec dsh-multitenant runuser -u dsh-alice -- \
  curl -fsS http://127.0.0.1:3101/ -o /dev/null
docker compose -f docker/compose.yml exec dsh-multitenant runuser -u dsh-alice -- \
  curl -fsS --connect-timeout 2 http://127.0.0.1:3102/ -o /dev/null
```

The second command must fail to connect. In the default lazy mode, an active tenant exiting unexpectedly is isolated to that tenant and a later request can start it again without terminating the gateway, other tenants, or the entrypoint supervisor. A core gateway failure remains fatal so the Kubernetes/Docker restart policy can recover the container. With `DSH_LAZY_TENANTS=0`, the image health check still covers every tenant backend port. This Compose topology is for single-host trusted-network acceptance; it does not provide public TLS, HA, dynamic scaling, or production secret management.

## Quick deployment (overview)

1. Install DSH (npm package) and prepare a Node runtime; configure the gateway systemd service from `units/` (`User=<service account>`, listening on 127.0.0.1 only).
2. Create users with `sudo bin/dsh-users.sh add <user>` (automatically creates the OS account, allocates a port, generates and starts the instance).
3. Install the root helpers and configure sudoers (fixed-path allowlist):

   ```bash
   install -o root -g root -m 0755 bin/dsh-file-* /opt/deepseek-harness/bin/
   # /etc/sudoers.d/dsh-upload:
   # <service-account> ALL=(root) NOPASSWD: /opt/deepseek-harness/bin/dsh-file-put, /opt/deepseek-harness/bin/dsh-file-stat, /opt/deepseek-harness/bin/dsh-file-read, /opt/deepseek-harness/bin/dsh-file-list
   ```

   After upgrades or for self-checks, verify the helpers on the server against this checklist (replace `<user>` with a real username):

   ```bash
   H=/opt/deepseek-harness/users/<user>
   sudo -n /opt/deepseek-harness/bin/dsh-file-list "$H" ''          # JSON directory listing
   printf 'BYTES 6\nhello\n' | sudo -n /opt/deepseek-harness/bin/dsh-file-put "$H" "$H/workspace" t.txt   # v2 length protocol; short streams exit=6 and are NOT committed
   sudo -n /opt/deepseek-harness/bin/dsh-file-stat  "$H" "$H/workspace/t.txt"   # prints 6
   sudo -n /opt/deepseek-harness/bin/dsh-file-read  "$H" "$H/workspace/t.txt"   # prints hello
   sudo -n /opt/deepseek-harness/bin/dsh-file-read  "$H" /etc/passwd; echo "exit=$?"  # exit=3 (out-of-scope denied)
   ps -ef | grep -E 'runuser.*dsh-'                                  # child processes should be dsh-<user>, not root
   ```

4. Configure the TLS reverse proxy from `nginx/dsh-https-1145.conf` (replace `server_name` with your domain and mount certificates).
5. On first use after login, users are guided to enter their DeepSeek API key (written only to their private directory).

> Environment variables: both the gateway and userctl let you override the default `/opt/deepseek-harness` prefix:

| Variable | Consumer | Default |
|---|---|---|
| `DSH_BASE_DIR` | installation prefix userctl / dsh-users.sh derives paths from | `/opt/deepseek-harness` |
| `DSH_USERS_DIR`, `DSH_USERS_FILE`, `DSH_SETTINGS_SRC`, `DSH_NODE_BIN`, `DSH_DSH_BIN` | fine-grained userctl overrides | derived from BASE_DIR |
| `USERS_FILE`, `SECRET_FILE`, `USERS_DIR` | gateway | `/opt/deepseek-harness/...` |
| `UPLOAD_HELPER`, `FILE_STAT_HELPER`, `FILE_READ_HELPER`, `FILE_LIST_HELPER` | absolute paths of helpers called by the gateway | `/opt/deepseek-harness/bin/dsh-file-*` (**if you customize the prefix you MUST update sudoers and these four variables in sync**) |
| `HOST`, `PORT`, `SESSION_TTL`, `COOKIE_SECURE`, `DEEPSEEK_BASE_URL`, `UPLOAD_MAX_MB`, `MAX_IP_ATTEMPTS`, `MAX_USER_ATTEMPTS`, `WINDOW_MS`, `LOCK_MS` | gateway | see `gateway/server.js` |
| `DSH_LOGIN_API_KEY`, `LOGIN_TICKET_TTL` | gateway external login | disabled by default; tickets default to 60s |

`bin/dsh-users.sh` and `bin/dsh-file-list` locate themselves relative to their own path: any checkout directory works as-is (`dsh-users.sh` auto-re-privileges to root on first call; node resolves relative to the script location, falling back to `PATH`). When using a custom installation prefix, generate the systemd units with the `sed` command above; the gateway systemd unit also supports `EnvironmentFile=-/etc/default/dsh-gateway` for injecting the environment variables above in one place.

## Delivery file drawer — behavioral details

- **Auto-location**: the gateway sniffs proxied traffic for `session.history` (opening a session) and `session.list` (cwd per session), remembers the current conversation directory and persists it to `state-cwd.json`; opening "文件管理" lists that directory (falling back to the workspace if it no longer exists).
- **Embedding & closing**: the drawer is embedded as a same-origin iframe (`X-Frame-Options: SAMEORIGIN`); the in-page "back to app" control detects the iframe environment at runtime and sends `postMessage('dshgw-close')` to close the drawer instead of navigating, preventing nested drawers.
- **Uploads**: raw-byte body `POST /__gw/upload?dir=&name=`; the helper drops privileges to `dsh-<name>` before writing (root only validates arguments), so file ownership is naturally the user's own; same-name files are overwritten; over-limit uploads get 413.

## Security notes

- **Install-tree integrity (the most critical item)**: the entire `/opt/deepseek-harness` tree — including the DSH monorepo sources (`packages/`, `apps/`, `node_modules/`) and the `.agents/` skill library — must carry no group/other write bits. All tenant instances **share and execute** this code, so any writable point is a cross-tenant injection vector (modify shared code or skill files → execute as another tenant → steal their API key). After every deploy/upgrade, self-check: `find /opt/deepseek-harness -not -path '*/users*' -perm /022 | wc -l` must print 0 (the `users/` user directories are the exception).
- Keep `gateway/` at `root:dsh-gateway 0770`: the gateway needs tmp+rename atomic writes inside it (users.json / secret / state-cwd.json); code files inside the directory (server/userctl/auth/credentials/static) are root:root 0644. Everything in `bin/` is root:root.
- The gateway runs as a dedicated system account `dsh-gateway` (no shell). **Never** run the gateway under a cloud-image account like `ubuntu` that ships NOPASSWD sudo; its sudo capability must be limited to the four file helpers allowlisted in `/etc/sudoers.d/dsh-upload`. The gateway systemd unit must **not** set `NoNewPrivileges=yes` (it blocks sudo to the root helpers, breaking upload/download/listing entirely).
- **Loopback tenant isolation** (`bin/dsh-loopback-guard` + `units/dsh-loopback-guard.service`): DSH instances authorize privileged endpoints by "the Host header is loopback", yet all instances share 127.0.0.1 — any tenant's agent can forge the Host header and hit another tenant's port directly to steal their API key. The mitigation is an iptables OUTPUT chain: each `dsh-<name>` may connect only to its own instance port; other tenant ports and the gateway port are REJECTed, while root/gateway accounts are unaffected. userctl refreshes the rules automatically on add/delete; rules REJECT **per destination port** (do not blanket-reject by uid — that would kill the kernel's reply path).
- Per-user instances carry systemd resource limits (TasksMax/MemoryMax/CPUQuota, tunable via `DSH_MEM_MAX`/`DSH_CPU_QUOTA`) and kernel-hardening directives.
- File helpers (dsh-file-put/read/stat/list): root only string-validates arguments and switches identity; all file operations run via `runuser -u dsh-<name>` as the user themselves (fixing the issue #1 TOCTOU race); the realpath prefix checks inside the helpers are kept only for exit-code semantics and are no longer the security boundary. Depends on `runuser` from util-linux. **The upload helper uses the v2 length protocol** (`BYTES <n>` header + exact byte-count verification): the gateway streams the request body through, and aborted/timed-out/over-limit uploads are refused with exit 6 — no truncated file is ever committed.
- User credential files must remain owner-readable only (0600): DSH enforces this at startup (`assertOwnerOnly`). The root-helper model satisfies this naturally; do not add any ACL read grants to user directories (this once caused instances to refuse to start).
- The gateway and all instances listen on 127.0.0.1 only; the public internet sees only the TLS reverse proxy. The proxy must **overwrite** (not append to) `X-Forwarded-For` with `$remote_addr` (the `nginx/dsh-https-1145.conf` template ships with this safe default) — otherwise an attacker can forge the XFF chain and bypass the gateway's IP-level rate limiting.
- Login rate limiting operates at both IP and account level; account lockout (5 attempts / 15 minutes) can itself be abused for DoS and is mitigated only by IP-level throttling and strong passwords. Changing a password bumps `pwdVer`, immediately invalidating every previously issued session (including old unversioned tokens).
- `/logout` accepts POST only (with double-submit CSRF verification), preventing cross-site logout.
- If you need client-behavior patches after upgrading DSH (e.g. settings persistence scope), evaluate them yourself; this repository does not modify the npm package.
- Microsoft's password autofill can cause problems with the left-hand workspace directory listing; keep autofill disabled where possible.

## License

[MIT](LICENSE)
