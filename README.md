# DeepSeek Harness 服务器部署（dsh-server-deployment）

[简体中文](README.md) | [English](README.en.md)

<p align="center">
  <img src="assets/cover.png" alt="DSH 服务器部署封面" width="100%">
</p>

为 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（DSH）Web 端增加**多用户门户**的零依赖 Node 网关：登录认证、每用户独立 DSH 实例与 OS 级数据隔离、每用户独立 API Key，以及内置的**交付文件抽屉**（下载 / 上传 / 当前工作区自动定位）。隔离以 **OS 账号为边界**而非网关代码——文件访问经 sudo 助手 `runuser` 降权为 `dsh-<name>` 用户执行（修复 issue #1 TOCTOU 竞态），网关对用户目录零权限；完整机制见 [docs/multi-user-isolation.md](docs/multi-user-isolation.md)。

> **部署定位（重要）**：本项目是**服务器端部署**方案——网关、每用户 DSH 实例与文件助手全部运行在**远程服务器**上，多个用户通过浏览器（公网域名 + HTTPS）访问各自的会话与交付文件；它**不是本机 / 桌面工具**，**无需在用户电脑上安装任何软件**。文档中的示例路径（如 `/opt/deepseek-harness`、`/etc/systemd/system`）均为服务器端路径。

## 特性

- **登录门户**：自研暗色登录页（漆面 + 金箔风格），scrypt 口令（兼容旧版 APR1）、HMAC 签名会话 Cookie（HttpOnly / Secure / SameSite=Lax）、登录限流（IP + 账号两级）、CSRF 双提交校验。
- **用户隔离**：每个用户一个独立 DSH 实例（独立端口），以独立系统账号 `dsh-<name>` 运行，`DSH_HOME` 指向其 0700 私有目录；`userctl.js` 一条命令完成建号 / 改密 / 删号 / 预置 Key。
- **每用户独立 API Key**：登录后无 Key 自动引导 `/setup` 填写，经回环 RPC 写入该用户私有的 `.credentials.yaml`（0600，属主仅本人）。
- **回环特权接口修复**：网关向后端呈现 `Host: 127.0.0.1:<port>` 并剥离浏览器信任标记，DSH 钉在回环的 settings / credentials / agentPreset 等特权接口在公网访问下同样可用。
- **交付文件抽屉（文件管理）**：入口位于左侧栏底部、“退出登录”和“设置”上方，复用设置行样式；侧栏展开时显示图标与“文件管理”，收起时只显示同尺寸图标。点击后打开白色文件抽屉——目录浏览、下载（attachment + 中文文件名）、多文件上传（100MB 上限）；自动定位到当前对话所在工作目录（嗅探会话 RPC 追踪 cwd，持久化恢复）。
- **安全边界**：所有用户文件访问经 sudoers 固定路径的助手脚本——root 仅校验参数并降权，文件操作以 `dsh-<name>` 用户自身身份执行（修复 issue #1 的 TOCTOU 竞态）；网关进程对用户目录零权限；隐藏文件（含 `.credentials.yaml`）不可下载；SPA 注入尊重 `prefers-reduced-motion`、无玻璃拟态/渐变装饰。

## 架构

```
浏览器 ──https──▶ 反向代理(TLS, 例: OpenResty) ──▶ dsh-gateway(:3100) ──▶ 每用户 DSH 实例(:3101+)
                                  │                     │
                                  │ 会话/限流/CSRF/路由  │ 以独立 OS 账号 dsh-<name> 运行
                                  │ Key 引导/抽屉注入    │ DSH_HOME=<用户私有目录 0700>
                                  └──────────┬──────────┘
                                             └─ 文件访问走 sudo 助手: dsh-file-{list,stat,read,put}
```

> 网关默认端口在运行部署中为 **3100**（本仓库示例为 3081，可用环境变量 `PORT` 覆盖）；每用户实例
> 自 3101 递增，由 `userctl` 分配。

多用户与数据隔离的完整说明见 [docs/multi-user-isolation.md](docs/multi-user-isolation.md)。

## 目录结构

```
gateway/                # 网关本体（零依赖 Node）
  server.js             #   登录/会话/限流/CSRF/反代/SPA注入/文件抽屉/上传下载接口
  auth.js               #   scrypt + APR1 口令校验
  credentials.js        #   .credentials.yaml 读写（仅 userctl 使用）
  userctl.js            #   用户管理：OS 账号/端口/实例/Key
  _smoke.js             #   网关冒烟测试（本地即可运行，无需 DSH）
  static/               #   登录前可访问的静态资源（manifest/favicon）
bin/                    # 主机端入口与 root 助手
  dsh-users.sh          #   主机模式 userctl 的 sudo 入口（systemd 部署）
  dsh-file-{list,stat,read,put}[.js]
docker/                 # Docker 部署（全部 docker 相关文件集中于此）
  Dockerfile            #   镜像构建（构建上下文为仓库根目录）
  Dockerfile.dockerignore # 构建排除规则（仓库根目录的 `.dockerignore` 是指向它的软链，工具链要求）
  compose.yml           #   从仓库根目录运行：docker compose -f docker/compose.yml ...
  dsh-users             #   容器模式 userctl 入口（装进镜像 /usr/local/libexec/dsh）
  dsh-register          #   自助注册 root 助手（sudoers 白名单，转发注册到监管进程）
  entrypoint.js         #   容器入口/监管进程：种子租户 + 运行时增删用户 + 控制 socket
  userctl.js            #   容器内 dsh-users 命令的转发客户端
  healthcheck.js        #   健康检查（懒启动检查网关；eager 模式检查租户端口）
  dsh-gateway.sudoers   #   网关 sudoers 白名单（镜像内固定路径）
units/                  # systemd 单元模板（网关 + 每用户实例由 userctl 生成）
nginx/                  # TLS 反向代理示例配置（已占位化域名）
```

## Docker 可信网络测试

Docker 测试镜像会在构建阶段从官方 `https://github.com/deepseek-ai/deepseek-harness.git` 的 `master` 分支浅克隆最新代码并完成构建，不读取本机同级 harness 仓库。构建阶段会在公共 profile 中实际执行一次 `dsh plugin --profile web add dsh-better-sidebar`；完整插件依赖树以 root 只读形式保存在 `/opt/dsh-public`。入口进程为每个租户写入轻量 `link:` 依赖和软链接，不在注册热路径启动 pnpm；已有持久化用户和运行时新增用户都会覆盖，且不会复制插件依赖树。运行镜像包含 pnpm 以及安装其他原生插件所需的构建工具，并完整保留 `/opt/deepseek-harness` 源码与构建产物，以及 `/opt/dsh-server-deployment` 下的本部署仓库。网关与多个租户实例位于同一容器网络命名空间，但每个实例仍以独立的 `dsh-<name>` OS 账号和独立 `DSH_HOME` 运行。入口进程在启动租户前应用线性规模的回环防火墙规则；隔离规则失败会直接终止容器。容器只需要 `NET_ADMIN` capability，不需要 `--privileged` 或容器内 systemd。

所有 Docker 租户启动时都会应用部署级 patch `docker/disable-llm-deepseek.patch.yml`，以 `disabled: true` 停用内置 `llm-deepseek` 条目；`llm-pi-ai` 与每个用户自己的模型设置保持可用。该 patch 位于用户配置层之后，因此用户目录无需复制或修改这项部署策略。

网关在已认证后代理的 DSH 页面中注入受信任网关标记；镜像构建时应用 `docker/patches/deepseek-harness-trusted-gateway.patch`，使局域网 IP 或反向代理域名下的浏览器使用 Host Settings Mirror。服务端仍执行会话、Host、Origin 与租户隔离校验；该适配只解除上游客户端对非 loopback 浏览器的 UI 限制。

镜像拆分为两层：`docker/Dockerfile.base` 负责构建 DSH、应用 Harness 补丁、安装系统依赖和公共插件；`docker/Dockerfile` 只基于该 base 复制并安装本部署仓库。修改网关或入口代码时只需重建 final，无需重新编译 DSH。所有命令从**仓库根目录**执行：

```bash
# DSH、系统环境或公共插件变化时构建 base（耗时较长）
docker build --pull -f docker/Dockerfile.base -t dsh-server-base:local .

# 部署代码变化时只构建 final（通常只需数秒）
docker compose -f docker/compose.yml build
docker compose -f docker/compose.yml up -d
docker compose -f docker/compose.yml ps
docker compose -f docker/compose.yml logs --tail=100
```

使用其他 base 标签时设置 `DSH_BASE_IMAGE`，例如：`DSH_BASE_IMAGE=registry.example.com/dsh-server-base:v1 docker compose -f docker/compose.yml build`。最终镜像包含全部父层，单独 `docker save dsh-server-deployment:local` 即可完整导出运行镜像。

浏览器打开 `http://127.0.0.1:20810`，默认测试账号为：

| 用户 | 密码 |
|---|---|
| `alice` | `alice-test-password` |
| `bob` | `bob-test-password` |

默认 Compose 设置 `DSH_SKIP_KEY_SETUP=1`，仅用于无真实 API Key 的登录、页面与租户隔离测试；此模式不能实际调用模型。要测试完整对话流程，将其改为 `0`，重启后从首次登录页为每个租户分别填写 Key。

### Docker 下运行时管理用户（无需改 Compose）

`DSH_TENANTS_JSON` 只是**启动种子**：容器启动时按它创建/更新租户。之后可用镜像内置的 `dsh-users` 命令随时增删用户、改密、设置 Key，**无需编辑 compose、无需重建或重启容器**：

```bash
docker compose -f docker/compose.yml exec dsh-multitenant dsh-users list
docker compose -f docker/compose.yml exec dsh-multitenant dsh-users add carol                 # 未给密码时交互式输入（不回显）
docker compose -f docker/compose.yml exec dsh-multitenant dsh-users add carol 'carol-password' # 或直接给参数
docker compose -f docker/compose.yml exec dsh-multitenant dsh-users passwd carol 'new-password'
docker compose -f docker/compose.yml exec dsh-multitenant dsh-users set-key carol sk-xxxx
docker compose -f docker/compose.yml exec dsh-multitenant dsh-users key-status carol
docker compose -f docker/compose.yml exec dsh-multitenant dsh-users del carol                 # 确认后连同全部数据删除
```

行为要点：

- 运行时新增的用户写入 `docker/data/gateway/users.json`（容器内 `/var/lib/dsh/gateway/users.json`），**容器重建/重启后依然存在**（重启时种子列表与存量用户合并，端口/口令/身份保持不变）。所有数据通过绑定挂载持久化在宿主机 `docker/data/`（容器内 `/var/lib/dsh`：`users/` 用户目录 + `gateway/` 状态），直接可见、可备份。supervisor IPC socket 位于非持久化的 `/run/dsh/control.sock`（可用 `DSH_CONTROL_SOCKET` 覆盖），不会进入数据备份，也不能由多个实例共享。
- 删除用户请用 `dsh-users del`（会一并删除该用户的数据）；把用户从 `DSH_TENANTS_JSON` 里删掉**不会**删除已存在的用户。
- `dsh-users` 与网关共享同一份用户库：新用户立即可登录（网关侧缓存最长 2 秒刷新）。
- 口令最少 8 位；`passwd` 会使该用户所有已签发会话立即失效。
- 默认启用 `DSH_LAZY_TENANTS=1`：建号只创建 OS 账号、独立 HOME、端口记录、共享插件链接和防火墙规则，不启动 DSH。用户首次成功登录时网关调用监管进程启动该用户实例并等待就绪；实例运行到用户退出/浏览器离线回收或容器重启。设置 `DSH_LAZY_TENANTS=0` 可恢复启动容器/建号时立即拉起全部实例的旧行为。
- 登录后的 DSH 页面在左侧栏“设置”正上方提供“退出登录”按钮，直接复用设置行的样式和宽/窄状态：侧栏展开时显示图标与文字，收起时只显示同尺寸图标。手动退出会撤销该用户全部已签发会话，先停止租户进程组，再按租户唯一 OS UID 强制清理任何脱离进程组的后台进程；不会删除或修改用户 HOME、工作区、会话文件、配置或凭据。浏览器页面通过标签页心跳登记在线状态，关闭最后一个标签页后默认宽限 5 秒再回收租户进程；多标签页只关闭其中一个不会停止。浏览器崩溃、断网或来不及发送关闭通知时，默认 120 秒心跳超时后兜底回收。自动回收只管理进程生命周期，不撤销登录 Cookie；用户下次访问会使用原会话重新唤醒实例。只有手动退出、管理员强退或改密才撤销会话。可用 `DSH_BROWSER_STOP_GRACE_MS` 和 `DSH_BROWSER_PRESENCE_TTL_MS` 调整。

### 持久化共享 Web 插件（无需修改 Dockerfile）

日常安装直接使用容器内的管理命令，不需要修改环境变量、Dockerfile 或重启容器：

```bash
# 查看共享插件
docker compose -f docker/compose.yml exec dsh-multitenant dsh-users plugin list

# 安装/升级 registry 插件（包名可从 spec 自动推断）
docker compose -f docker/compose.yml exec dsh-multitenant \
  dsh-users plugin add @huanlin/dsh-plugin-better-sidebar-plugin-office@0.1.2

# Git、文件或 alias 等无法自动推断包名的 spec，显式给出包名
docker compose -f docker/compose.yml exec dsh-multitenant \
  dsh-users plugin add 'file:/tmp/my-plugin' --name my-plugin

# 删除运行时共享插件
docker compose -f docker/compose.yml exec dsh-multitenant \
  dsh-users plugin remove some-plugin
```

命令通过入口监管进程把插件安装到 `/var/lib/dsh/shared-plugins`，默认允许插件及其全部传递依赖执行 `preinstall`、`install`、`postinstall` 等构建脚本，不需要 `--allow-build`。随后将共享 `link:` 依赖和软链接同步到所有已有用户，并只重启各用户的 DSH 进程使插件生效（容器和网关不重启）。运行时新增用户在自己的 DSH 进程启动前自动执行同一同步，因此会直接拥有并启用当前全部共享插件。共享目录位于 `/var/lib/dsh` 持久化卷中，Pod 重建后仍然存在，不会为每个用户重复安装依赖。由于安装脚本以容器 root 权限执行，只应安装可信插件。

插件命令会在当前终端实时显示 pnpm 下载、构建、用户同步和租户重启输出。内网 registry 必须配置到共享安装 HOME；普通 `npm config set registry` 默认写入 `/root/.npmrc`，不会被共享安装进程读取：

```bash
kubectl exec -n <namespace> <pod> -- \
  env HOME=/var/lib/dsh/shared-plugins \
  npm config set registry http://<内网-npm-registry>

kubectl exec -n <namespace> <pod> -- \
  env HOME=/var/lib/dsh/shared-plugins \
  pnpm config get registry
```

`DSH_SHARED_WEB_PLUGINS_JSON` 仍可作为首次部署时的批量声明方式：

```yaml
env:
  - name: DSH_SHARED_WEB_PLUGINS_JSON
    value: >-
      [{"name":"@huanlin/dsh-plugin-better-sidebar-plugin-office","spec":"@huanlin/dsh-plugin-better-sidebar-plugin-office@0.1.2"}]
```

每项必须提供 npm 包 `name`；`spec` 可指定版本或其他 pnpm 支持的安装规格，省略时等于 `name`。旧配置中的 `allowBuilds` 字段会被忽略。配置项从环境变量删除时，已安装的持久化共享插件不会被自动删除。若一个插件仍在环境变量中声明，使用命令删除后也应同步移除该声明，否则下次 Pod 启动会再次安装。可用 `DSH_SHARED_PLUGINS_HOME` 覆盖共享根目录，默认是 `DSH_USERS_DIR` 的同级 `shared-plugins/`。

### 自助注册（登录页，Docker 模式）

网关支持通过登录页的「注册新账号」链接自行创建账号，但本仓库的 Docker Compose 默认设置 `DSH_ENABLE_REGISTER=0`，因此该链接和页面均关闭。开启后，注册请求经网关 → sudoers 白名单助手 `dsh-register` → 入口监管进程完成建号（OS 账号/端口/目录/防火墙），与 CLI 建号同一套流程；默认不会在注册请求中启动 DSH，首次登录才启动：

- **开启条件**：本 Compose 默认关闭；显式设置 `DSH_ENABLE_REGISTER=1` 才开启。未设置该变量时，镜像内置 `dsh-register` 助手会让功能自动开启（主机部署无此助手，自动关闭）。
- **限制**：用户名仅限字母/数字/下划线/连字符；密码至少 8 位；同 IP 注册失败限流（`MAX_REGISTER_ATTEMPTS`，默认 10 次/15 分钟，防刷）。
- **注意**：开放注册意味着任何能访问登录页的人都能创建账号；每个真正登录过的账号会占用一个独立 DSH 进程和端口。公网部署建议改为邀请制或加 HTTPS，并自行评估。

### 管理控制台（admin 账号）

- **admin 账号**：由 `DSH_ADMIN_PASSWORD` 环境变量在启动时创建/更新（scrypt 存入 `users.json`，标记 `admin: true`）。它现在是完整隔离租户，拥有自己的 `dsh-admin` OS 账号、HOME、端口和按需启动的 DSH；旧版纯管理记录会在启动时自动补齐这些字段。管理员登录默认进入自己的 DSH，左侧栏额外显示“管理后台”按钮，管理台也提供“返回工作区”。
- **用户列表**：`/__gw/admin` 展示用户名、在线状态、端口、最近活跃时间、持久化 API Key 标记和创建时间；仅在管理员手动点击时刷新，并在浏览器本地缓存上次结果。实时 DSH 状态、RSS、进程数、磁盘占用和磁盘 Key 扫描暂时停用，避免管理统计阻塞登录共用的 supervisor control socket。
- **共享插件管理**：管理后台直接展示共享插件名称、版本、镜像内置/运行时来源及路径，可提交 npm/Git/file spec 安装或升级，并移除运行时插件。操作作为后台任务执行，页面实时显示 pnpm 与全用户同步日志，完成后自动刷新；镜像内置插件标记为不可移除。同一时间只允许一个插件变更任务。
- **权限**：非 admin 账号访问 `/__gw/admin` 一律跳转登录页；注册接口拒绝使用 `admin` 用户名（保留名）。
- **改密**：改 `DSH_ADMIN_PASSWORD` 环境变量后重启容器（会话自动失效）；不要用 `dsh-users passwd admin`（下次启动会被环境变量覆盖）。
- 去掉 `DSH_ADMIN_PASSWORD` 并删除 `users.json` 里的 admin 记录即可关闭。

### 外部自动登录（一次性票据）

配置独立的 `DSH_LOGIN_API_KEY` 后，可信的外部**后端服务**可以为已有用户换取一次性登录地址。长期密钥只允许出现在服务端，严禁放入浏览器 JavaScript、URL 或前端配置。本地测试 Compose 默认使用 `login-test-token`，可通过同名宿主机环境变量覆盖；生产环境不可使用此默认值。

第一步，外部后端换票（`returnTo` 可选，且只接受本站 `/` 开头的相对路径）：

```bash
curl -X POST https://dsh.example.com/api/login-ticket \
  -H "Authorization: Bearer <DSH_LOGIN_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","returnTo":"/"}'
# → 200 {"ok":true,"loginUrl":"/auth/external?ticket=...","expiresIn":60}
```

第二步，外部后端把用户浏览器 `302` 到 `https://dsh.example.com` 加返回的 `loginUrl`。DSH 消费票据、写入 `dsh_session` Cookie，再跳转到 `returnTo`；未配置 Key 的普通用户会优先进入 `/setup`，admin 会进入管理台。

- 票据默认 60 秒有效、仅可使用一次、进程重启即失效；`LOGIN_TICKET_TTL` 可设为 10–300 秒。
- 接口未配置 `DSH_LOGIN_API_KEY` 时保持关闭；未知用户返回 404，错误/缺失的 Bearer Token 返回 401。
- 票据保存在网关进程内存中，因此当前部署必须保持单副本网关；换票与浏览器消费票据需要命中同一进程。
- `DSH_LOGIN_API_KEY` 拥有“以任意已有用户登录”的高权限，必须与 `DSH_REGISTER_API_KEY` 分开并通过 Kubernetes Secret 等机密存储注入。

浏览器并发登录压测可使用 `bin/dsh-browser-login-load.sh`。脚本为每个用户创建独立 Chromium profile，避免同源 `dsh_session` Cookie 互相覆盖；默认同时打开 5 个并保持 60 秒，建议逐步增加并发而非直接启动 100 个浏览器进程：

```bash
docker compose -f docker/compose.yml exec -T dsh-multitenant dsh-users list \
  | tail -n +2 | cut -f1 > /tmp/dsh-users.txt
DSH_LOGIN_API_KEY='<token>' CONCURRENCY=10 HOLD_SECONDS=60 \
  ./bin/dsh-browser-login-load.sh https://dsh.example.com /tmp/dsh-users.txt
```

### 外部注册 API 与模型注册接口（机器对机器）

配置 `DSH_REGISTER_API_KEY`（compose 环境变量，默认 `register-test-token`）后启用两个 Bearer Token 接口；不配置则完全关闭。

**① 注册用户（仅建号，不含提供商）** `POST /api/register`

```bash
curl -X POST http://<主机>:20810/api/register \
  -H "Authorization: Bearer <DSH_REGISTER_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice2","password":"alice2-password"}'
# → 200 {"ok":true,"user":"alice2","port":3107}
```

- 只创建用户（OS 账号/端口/目录/防火墙规则），不启动 DSH；**不接收 provider**（传了返回 400 并提示用②）。
- 用户名/密码均校验；重复注册返回 409；无 token 返回 401。

**② 模型注册接口（配置自定义提供商 + 写入 API Key）** `POST /api/users/<username>/provider`

```bash
curl -X POST http://<主机>:20810/api/users/alice2/provider \
  -H "Authorization: Bearer <DSH_REGISTER_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"provider":{"name":"my-gateway","baseURL":"https://gateway.example.com/v1"},
       "apiKey":"sk-xxxx",
       "image_models":["gpt-4o","qwen-vl-max"]}'
# → 200 {"ok":true,"user":"alice2","provider":{"name":"my-gateway","baseURL":"...","model":"gpt-4o-mini","apiKeyEnv":"MY_GATEWAY_API_KEY"},"ref":"MY_GATEWAY_API_KEY"}
```

- **严格校验**：`provider` 必填（name 限字母/数字/下划线/连字符、baseURL 必须是 http(s) URL）；`provider.api` 可选，取值 `openai-completions`（默认）/ `openai-responses` / `anthropic-messages`，必须合法否则整个设置段会被拒绝、模型不可用；`apiKey` 必填；目标用户必须存在（包括 admin）。
- **模型自动获取**：不传 `provider.model`（或 `models` 数组）时，网关用 `apiKey` 调 `GET <baseURL>/models` 自动拉取模型列表（上限 100 个）全部写入配置；拉取失败返回 502 并提示可显式传 `model` 兜底。显式传 `model`/`models` 则跳过拉取。响应里的 `models` 即生效的模型列表。
- **图片输入白名单**：可选的顶层 `image_models` 是模型 ID 数组（也兼容放在 `provider.image_models`）；命中的已获取模型写入 `input: [text, image]`，其余模型写入 `input: [text]`。未传时默认空数组。白名单本身不校验模型是否存在，不在本次模型列表中的条目会被保留在响应中但不会生成额外模型配置。
- 效果：写入用户 `settings.yaml`（`llm-pi-ai.providers.<name>` OpenAI 兼容适配器 + `agent-default-model` 指向第一个模型）以及私有 `.credentials.yaml`（0600，属主仅本人）。未登录用户保持休眠，不会因为配置 provider 而启动；若实例已经运行，则只重启该用户实例使配置立即生效。
- 重复调用 = **覆盖更新**（换 baseURL/模型/Key 都行）；返回的 `ref` 是该提供商的凭证名（`<NAME>_API_KEY`）。
- 配置完成后用户跳过 `/setup`，登录即默认使用该提供商。

可在宿主机验证 Alice 能访问自己的实例但无法访问 Bob 的实例：

```bash
docker compose -f docker/compose.yml exec dsh-multitenant runuser -u dsh-alice -- \
  curl -fsS http://127.0.0.1:3101/ -o /dev/null
docker compose -f docker/compose.yml exec dsh-multitenant runuser -u dsh-alice -- \
  curl -fsS --connect-timeout 2 http://127.0.0.1:3102/ -o /dev/null
```

第二条命令应连接失败。默认懒启动模式下镜像健康检查验证网关；活跃租户异常退出只隔离该租户并让后续请求重新触发启动，不会终止网关、其他租户或入口监管进程。核心 gateway 异常退出仍会使监管进程终止容器，由 Kubernetes/Docker 重启策略恢复。`DSH_LAZY_TENANTS=0` 时健康检查仍验证所有租户后端端口。该 Compose 面向单机可信网络验收，不包含公网 TLS、HA、动态扩缩容或生产密钥管理。

## 快速部署（概览）

1. 安装 DSH（npm 包）并准备 Node 运行时；按 `units/` 配置网关 systemd 服务（`User=<服务账号>`，仅监听 127.0.0.1）。
2. 用 `sudo bin/dsh-users.sh add <用户>` 建号（自动创建 OS 账号、分配端口、生成并启动实例）。
3. 安装 root 助手并配置 sudoers（固定路径白名单）：

   ```bash
   install -o root -g root -m 0755 bin/dsh-file-* /opt/deepseek-harness/bin/
   # /etc/sudoers.d/dsh-upload:
   # <服务账号> ALL=(root) NOPASSWD: /opt/deepseek-harness/bin/dsh-file-put, /opt/deepseek-harness/bin/dsh-file-stat, /opt/deepseek-harness/bin/dsh-file-read, /opt/deepseek-harness/bin/dsh-file-list
   ```

   升级或自检时可在服务器上按以下清单验证助手（把 `<user>` 换成真实用户名）：

   ```bash
   H=/opt/deepseek-harness/users/<user>
   sudo -n /opt/deepseek-harness/bin/dsh-file-list "$H" ''          # JSON 目录列表
   printf 'BYTES 6\nhello\n' | sudo -n /opt/deepseek-harness/bin/dsh-file-put "$H" "$H/workspace" t.txt   # v2 长度协议；短流 exit=6 不落盘
   sudo -n /opt/deepseek-harness/bin/dsh-file-stat  "$H" "$H/workspace/t.txt"   # 输出 6
   sudo -n /opt/deepseek-harness/bin/dsh-file-read  "$H" "$H/workspace/t.txt"   # 输出 hello
   sudo -n /opt/deepseek-harness/bin/dsh-file-read  "$H" /etc/passwd; echo "exit=$?"  # exit=3（越界拒绝）
   ps -ef | grep -E 'runuser.*dsh-'                                  # 子进程应为 dsh-<user> 而非 root
   ```

4. 按 `nginx/dsh-https-1145.conf` 配置 TLS 反向代理（替换 `server_name` 为你的域名并挂证书）。
5. 登录后首次使用会引导填写 DeepSeek API Key（仅写入用户私有目录）。

> 环境变量：网关与 userctl 均可用环境变量覆盖默认的 `/opt/deepseek-harness` 路径：

| 变量 | 作用方 | 默认 |
|---|---|---|
| `DSH_BASE_DIR` | userctl / dsh-users.sh 派生路径的安装前缀 | `/opt/deepseek-harness` |
| `DSH_USERS_DIR`、`DSH_USERS_FILE`、`DSH_SETTINGS_SRC`、`DSH_NODE_BIN`、`DSH_DSH_BIN` | userctl 细粒度覆盖 | 由 BASE_DIR 派生 |
| `USERS_FILE`、`SECRET_FILE`、`USERS_DIR` | 网关 | `/opt/deepseek-harness/...` |
| `UPLOAD_HELPER`、`FILE_STAT_HELPER`、`FILE_READ_HELPER`、`FILE_LIST_HELPER` | 网关调用助手的绝对路径 | `/opt/deepseek-harness/bin/dsh-file-*`（**自定义前缀时必须同步改 sudoers 与这四个变量**） |
| `HOST`、`PORT`、`SESSION_TTL`、`COOKIE_SECURE`、`DEEPSEEK_BASE_URL`、`UPLOAD_MAX_MB`、`MAX_IP_ATTEMPTS`、`MAX_USER_ATTEMPTS`、`WINDOW_MS`、`LOCK_MS` | 网关 | 见 `gateway/server.js` |
| `DSH_LOGIN_API_KEY`、`LOGIN_TICKET_TTL` | 网关外部自动登录 | 默认关闭；票据默认 60 秒 |

`bin/dsh-users.sh` 与 `bin/dsh-file-list` 已按自身位置自定位：任意目录检出即可直接运行（`dsh-users.sh` 首次调用自动重提权为 root；node 解析相对脚本位置，缺失时回退 `PATH`）。自定义安装前缀时 systemd 单元用上面的 `sed` 命令生成；网关 systemd 单元还支持 `EnvironmentFile=-/etc/default/dsh-gateway`，可在该文件里统一注入上述环境变量。

## 交付文件抽屉的行为细节

- **自动定位**：网关嗅探代理流量中的 `session.history`（打开会话）与 `session.list`（每会话含 cwd），记住当前对话目录并持久化到 `state-cwd.json`；打开「文件管理」即列出该目录（目录失效自动回退工作区）。
- **嵌入与关闭**：抽屉以同源 iframe 内嵌（`X-Frame-Options: SAMEORIGIN`）；页面内「返回应用」运行时检测 iframe 环境，发 `postMessage('dshgw-close')` 关闭抽屉而非导航，杜绝嵌套打开。
- **上传**：原始字节体 `POST /__gw/upload?dir=&name=`，助手降权为 `dsh-<name>` 落盘（root 仅校验参数），文件属主天然为本人，同名覆盖，超限 413。

## 安全注意事项

- **安装树完整性（最关键）**：`/opt/deepseek-harness` 整棵树——含 DSH monorepo 源码（`packages/`、`apps/`、`node_modules/`）与 `.agents/` 技能库——不得带 group/other 写位。所有租户实例**共享执行**这份代码，任何可写点都是跨租户注入点（改共享代码或技能文件 → 以其他租户身份执行 → 窃取其 API Key）。部署/升级后必须自检：`find /opt/deepseek-harness -not -path '*/users*' -perm /022 | wc -l` 输出 0（`users/` 用户目录除外）。
- `gateway/` 目录保持 `root:dsh-gateway 0770`：网关需要在其内做 tmp+rename 原子写（users.json / secret / state-cwd.json）；目录内代码文件（server/userctl/auth/credentials/static）归 root:root 0644。`bin/` 全部归 root:root。
- 网关以专用系统账号 `dsh-gateway`（无 shell）运行，**切勿**用 `ubuntu` 等自带 NOPASSWD sudo 的云镜像账号运行网关；其 sudo 能力仅限 `/etc/sudoers.d/dsh-upload` 白名单中的四个文件助手。网关 systemd 单元**不可**设置 `NoNewPrivileges=yes`（会阻断 sudo 调 root 助手，上传/下载/列表全部失效）。
- **回环租户隔离**（`bin/dsh-loopback-guard` + `units/dsh-loopback-guard.service`）：DSH 实例的特权接口按「Host 头是回环」放行，而所有实例同处 127.0.0.1--任何租户的 agent 都能伪造 Host 直连他人端口窃取 API Key。防护为 iptables OUTPUT 链：每个 `dsh-<name>` 只能连自己的实例端口，其他租户端口与网关端口被 REJECT，root/网关账号不受影响。userctl 增删用户自动刷新规则；规则按**目标端口**逐条 REJECT（不可按 uid 全量拒绝，否则会掐断内核回包路径）。
- 每用户实例带 systemd 资源限制（TasksMax/MemoryMax/CPUQuota，可经 `DSH_MEM_MAX`/`DSH_CPU_QUOTA` 调整）与内核加固项。
- 文件助手（dsh-file-put/read/stat/list）root 仅做参数字符串校验与身份切换，所有文件操作经 `runuser -u dsh-<name>` 以用户自身身份执行（修复 issue #1 的 TOCTOU 竞态）；助手内的 realpath 前缀校验仅保留退出码语义，不再是安全边界。依赖 util-linux 的 `runuser`。**上传助手为 v2 长度协议**（`BYTES <n>` 头 + 精确字节校验）：网关流式转发请求体，中断/超时/超限的上传会以 exit 6 拒绝提交，不会留下截断文件。
- 用户凭据文件必须保持仅属主可读（0600）：DSH 启动时会强制检查（`assertOwnerOnly`）。本网关的 root 助手模型天然满足，不要给用户目录添加任何 ACL 读取授权（曾因此触发实例拒绝启动）。
- 网关与所有实例仅监听 127.0.0.1，公网只暴露 TLS 反代；反代必须**覆盖**（非追加）`X-Forwarded-For` 为 `$remote_addr`（`nginx/dsh-https-1145.conf` 模板已按此安全默认值配置），否则攻击者可伪造 XFF 绕过网关 IP 限流。
- 登录限流为 IP + 账号两级；账号锁定（5 次/15 分钟）本身可被滥用作 DoS，仅靠 IP 级限流与强密码缓解。改密会使 `pwdVer` 递增，所有已签发会话立即失效（含无版本号的旧令牌）。
- `/logout` 仅接受 POST（带 CSRF 双提交校验），防跨站登出。
- 升级 DSH 后如需客户端行为修补（如 settings 持久化作用域），请自行评估，本仓库不修改 npm 包。
- 使用时微软的密码自动填充会给左侧工作区目录带来问题，尽量关闭自动填充。

## License

[MIT](LICENSE)
