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
- **Delivery file drawer (file management)**: a single draggable "🗂 文件管理" capsule at the bottom-right of the main UI (merged from the former "交付文件" + "上传文件" pair as of 2026-08), opening a white drawer with an embedded file browser — directory listing, downloads (attachment + non-ASCII filenames), multi-file uploads (100 MB limit); it automatically locates the current conversation's working directory (by sniffing session RPC traces for the cwd, persisted across restarts). The capsule auto-hides while SPA panels/modals are open to avoid occlusion.
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
  healthcheck.js        #   health check (gateway + every tenant port)
  dsh-gateway.sudoers   #   gateway sudoers allowlist (fixed path inside the image)
units/                  # systemd unit templates (gateway + per-user units generated by userctl)
nginx/                  # TLS reverse-proxy example config (placeholder domain)
```

## Docker test on a trusted network

During the build, the Docker test image shallow-clones the latest `master` branch directly from the official `https://github.com/deepseek-ai/deepseek-harness.git`; it does not read a sibling local Harness checkout. The runtime image keeps the complete Harness source and build output under `/opt/deepseek-harness`, plus this complete deployment repository under `/opt/dsh-server-deployment`. The gateway and tenant instances share one container network namespace, while every instance still runs under its own `dsh-<name>` OS account with a separate `DSH_HOME`. The entrypoint applies the loopback firewall before starting any tenant and terminates the container if isolation cannot be installed. It needs only the `NET_ADMIN` capability, not `--privileged` or systemd inside the container.

All Docker files live in `docker/`. The commands below run from the **repository root** (compose is passed with `-f`; the build context is the repository root, so the Dockerfile path is `docker/Dockerfile`):

```bash
docker compose -f docker/compose.yml build --pull --no-cache
docker compose -f docker/compose.yml up -d
docker compose -f docker/compose.yml ps
docker compose -f docker/compose.yml logs --tail=100
```

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

- Runtime users are written to `docker/data/gateway/users.json` (container path `/var/lib/dsh/gateway/users.json`) and **survive container rebuilds / restarts** (at boot the seed list is merged with existing users; ports, passwords and identities are kept). All data is persisted via a bind mount to `docker/data/` on the host (container `/var/lib/dsh`: `users/` for user homes, `gateway/` for state), directly visible and backup-able.
- To remove a user use `dsh-users del` (also removes their data); removing a user from `DSH_TENANTS_JSON` does NOT delete an existing user.
- `dsh-users` shares the same user store as the gateway: a new user can log in immediately, and the health check covers the new tenant port automatically (gateway cache refreshes within at most 2s).
- Passwords must be at least 8 characters; `passwd` immediately invalidates all of the user's issued sessions.

### Self-service registration (login page, Docker deployment)

The login page has a "注册新账号" (register) link so users can create their own accounts (default: **fully open**). A registration request flows gateway → allowlisted sudo helper `dsh-register` → entrypoint supervisor, which provisions the user exactly like the CLI (OS account / port / instance / firewall):

- **Enablement**: auto-enabled when the `dsh-register` helper is present in the image (host deployments have no such helper, so it is off there); force with `DSH_ENABLE_REGISTER=1` / `DSH_ENABLE_REGISTER=0`.
- **Limits**: username limited to letters/digits/underscore/hyphen; password at least 8 characters; per-IP rate limiting on failed registrations (`MAX_REGISTER_ATTEMPTS`, default 10 per 15 minutes).
- **Caution**: open registration means anyone who can reach the login page can create an account (each account = a separate process + port). For public deployments consider an invite-code gate or HTTPS, and evaluate the risk yourself.

### Admin console (admin account)

- **admin account**: created/updated at boot from the `DSH_ADMIN_PASSWORD` env var (scrypt-hashed into `users.json`, flagged `admin: true`). It is a **management-only account with no DSH instance** (no OS account / port / process). After login it is redirected to the `/__gw/admin` console.
- **Online users**: `/__gw/admin` lists all users with online status (sessions are stateless HMAC cookies, so "online" = a valid session with a request within the last **15 minutes**; last-activity time and source IP are shown), auto-refreshing every 10s; `/__gw/admin/users` returns the same data as JSON.
- **Access control**: non-admin sessions are redirected away from `/__gw/admin`; the registration endpoint rejects the `admin` username (reserved).
- **Password change**: edit `DSH_ADMIN_PASSWORD` and restart the container (sessions are invalidated). Do not use `dsh-users passwd admin` — the env var overwrites it on the next boot.
- To disable, unset `DSH_ADMIN_PASSWORD` and remove the admin record from `users.json`.

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
  -d '{"provider":{"name":"my-gateway","baseURL":"https://gateway.example.com/v1","model":"gpt-4o-mini"},
       "apiKey":"sk-xxxx"}'
# → 200 {"ok":true,"user":"alice2","provider":{"name":"my-gateway","baseURL":"...","model":"gpt-4o-mini","apiKeyEnv":"MY_GATEWAY_API_KEY"},"ref":"MY_GATEWAY_API_KEY"}
```

- **Strict validation**: `provider` is required (name limited to letters/digits/underscore/hyphen, baseURL must be an http(s) URL, model required); `provider.api` is optional — `openai-completions` (default) / `openai-responses` / `anthropic-messages` — an invalid value makes the whole settings section rejected and the model unusable; `apiKey` is required; the user must exist and not be the admin.
- Effect: writes the user's `settings.yaml` (an `llm-pi-ai.providers.<name>` OpenAI-compatible profile plus `agent-default-model` pointing at it) and **restarts that user's instance so the config goes live**; the key is written by the user's own instance via the loopback RPC into their private `.credentials.yaml` (0600, owner-only) — the same write path as `/setup`.
- Re-calling the endpoint **replaces** the provider config and key (change baseURL/model/key anytime). The returned `ref` is the provider's credential name (`<NAME>_API_KEY`).
- Once configured, the user skips `/setup` and the provider is the default on login.

From the host, verify that Alice can reach her instance but cannot reach Bob's:

```bash
docker compose -f docker/compose.yml exec dsh-multitenant runuser -u dsh-alice -- \
  curl -fsS http://127.0.0.1:3101/ -o /dev/null
docker compose -f docker/compose.yml exec dsh-multitenant runuser -u dsh-alice -- \
  curl -fsS --connect-timeout 2 http://127.0.0.1:3102/ -o /dev/null
```

The second command must fail to connect. The image health check covers the gateway and every tenant backend port. This Compose topology is for single-host trusted-network acceptance; it does not provide public TLS, HA, dynamic scaling, or production secret management.

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
