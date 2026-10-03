# SSH Manager

SSH 连接管理系统：服务器清单、密码和密钥加密保存在云端，网页托管在 Cloudflare，实际的 SSH 连接由电脑上的 agent 通过本机 ssh-skill 执行。换电脑时在网页输入主密码，一条命令就能把全部连接信息同步到新电脑的 `~/.ssh/config`。

```
浏览器 ──(Cloudflare Access 邮箱登录)──▶ Worker（网页 + API）──Hyperdrive──▶ Supabase Postgres
                                            ▲
                                            │ 长轮询领取任务 / 回传结果（Access service token）
                                            │
                                    本机 agent ──▶ ssh-skill 脚本 ──▶ 远程服务器
                                            └──▶ ~/.ssh/config、~/.ssh/known_hosts、~/.ssh/ssh-manager/
```

## 功能

### 服务器与分组

| 功能 | 说明 |
|---|---|
| 服务器增删改查 | 别名、主机、端口、用户、认证方式（密钥 / 密码）、跳板机、分组、标签、位置、备注 |
| 分组管理 | 分组就是服务器的「环境」字段（写进 `~/.ssh/config` 的 `environment` 元数据，ssh-skill 可按环境批量操作）。可设中文显示名和颜色，可新建、改名、排序、删除（删除时把服务器迁到其他分组）。改英文名会自动同步到所有相关服务器 |
| 拖动分组 | 在左侧列表把服务器拖到另一个分组即可移动（桌面浏览器） |
| 搜索 | 按别名、主机、标签、备注搜索 |

### 连接与操作（由 agent 执行）

| 功能 | 说明 |
|---|---|
| 同步到本机 | 新增/修改服务器后自动写入 agent 所在电脑的 `~/.ssh/config`（ssh-skill 的注释元数据格式），Claude Code 里的 ssh-skill 也能直接用这些别名；也可「全部同步到本机」 |
| 从本机导入 | 把 `~/.ssh/config` 里已有的主机导入云端，可同时把它们使用的私钥文件加密上传（自动与云端已有密钥去重） |
| 主机指纹信任 | ssh-skill 严格校验主机密钥，从没连过的设备要先信任主机指纹。agent 用 `ssh-keyscan` 读取（不登录），网页显示 SHA256 指纹，确认后保存到云端，每台电脑同步时写入 `~/.ssh/known_hosts`。agent 连不到设备时（比如设备在另一个局域网），可一键复制 `ssh-keyscan` 命令到能访问它的电脑上运行，再把输出粘贴回来。指纹变化会醒目提示 |
| 测试连接 / 执行命令 | `ssh_execute.py`，支持超时、只读重试和命令历史；因为没信任指纹而失败时会直接弹出信任窗口 |
| 文件传输 | `ssh_upload.py` / `ssh_download.py`，路径是 agent 所在电脑的本地路径 |
| SSH 隧道 | `ssh_tunnel.py`，隧道监听在 agent 所在电脑的 127.0.0.1 |
| 操作日志 | 每个任务都记录在 `jobs` 表中，包括操作人、结果和耗时 |

### 密钥与备份

| 功能 | 说明 |
|---|---|
| 云端 SSH 密钥 | 网页上传私钥（浏览器端加密），多台服务器可共用。公钥自动从私钥提取（OpenSSH 格式任意算法、RSA PEM），也可手动提供 `.pub`；显示 SHA256 指纹，可一键复制公钥加到服务器的 `authorized_keys`。同步时写到 `~/.ssh/ssh-manager/<名称>.key`（600）和 `<名称>.key.pub` |
| 服务器密码 | 浏览器端加密后上传；同步时按 ssh-skill 的约定写进 `~/.ssh/config` 的 `# password:` 注释 |
| agent 私钥云端备份 | `./setup.sh backup` 用主密码把 agent 私钥和连接凭证加密后存到云端，换电脑时用主密码解开 |
| 新电脑同步 | 浏览器里输入主密码，生成同步命令，在终端运行一次即可，不需要源代码，支持 macOS / Windows / Linux（见「换电脑」） |

### 界面

- React + Tailwind + [shadcn/ui](https://ui.shadcn.com)，配色为 shadcn.io 的 Cyberpunk 主题，固定深色。
- 可选背景图：把图片放到 `worker/public/background.jpg` 后重新部署（已 gitignore，不会提交）；没有图片时显示霓虹网格。
- 顶部显示 agent 在线状态和备份状态；没有在线 agent、备份缺失或过时时会出现提醒。

## 使用指南

### 添加一台服务器

1. 点「新增服务器」，填写别名、主机、端口、用户名，选择分组和认证方式：
   - **密钥**：选择「云端密钥」（先在「密钥」里上传），或填本机密钥文件路径。
   - **密码**：直接填写，浏览器加密后才上传。
2. 保存后会自动同步到运行 agent 的电脑。
3. 在服务器详情里点「获取并信任指纹」，核对指纹后点「信任」。**从没连过的设备必须先做这一步**，否则 ssh-skill 会拒绝连接。
4. 点「测试连接」。

### 局域网设备（在另一个网络里，agent 连不到）

1. 打开该服务器的「获取并信任指纹」，点「复制命令」，在**能访问这台设备的电脑**上运行（终端或 Windows cmd 都可以），把输出粘贴回窗口，点「使用粘贴的公钥」，核对后信任。
2. 在那台电脑上用「新电脑」同步一次（见下文），主机指纹会随配置一起写进 `known_hosts`，之后 ssh-skill 就能用账号密码直接连接。

### 换电脑

不需要下载源代码，也不需要安装程序：

1. 在新电脑的浏览器里登录网页，点「新电脑」，输入主密码。浏览器在本地解开 agent 私钥，再解密服务器密码和 SSH 私钥（云端和 Worker 都看不到明文）。
2. 按页面上的系统选择操作（页面会自动识别）：

   | 系统 | 第 2 步 | 第 3 步 |
   |---|---|---|
   | macOS | 点「复制同步脚本」 | 在终端**输入** `pbpaste \| bash` |
   | Windows | 点「复制同步命令」 | 打开「命令提示符」(cmd) 或 PowerShell，**粘贴并回车** |
   | Linux | 点「复制同步脚本」 | 在终端输入 `xclip -o -selection clipboard \| bash` |

   Windows 复制的是一行命令（压缩编码后的 PowerShell 脚本），在 cmd 和 PowerShell 里粘贴都能运行；服务器特别多、超过 cmd 单行长度限制时，页面会改为提示输入 `powershell -nop -c "iex (Get-Clipboard -Raw)"`。

脚本会做这些事：

- 备份原配置为 `config.ssh-manager.bak`，按 ssh-skill 的格式把所有服务器写进 `~/.ssh/config`（Windows 为 `%USERPROFILE%\.ssh\config`，UTF-8 无 BOM）。同名条目先替换，其他配置不动。
- 私钥写到 `~/.ssh/ssh-manager/`（macOS/Linux 为 600 权限；Windows 用 `icacls` 设为仅当前用户可访问），同时写出 `.pub`。
- 已信任的主机指纹写进 `known_hosts`（替换该主机的旧记录）。
- 最后清空剪贴板；在 PowerShell 里运行时还会把这条命令从 PowerShell 历史文件里删掉。可以重复运行。

为什么还需要一条终端命令：浏览器明确禁止网页写入 `~/.ssh`（Chromium 的 File System Access API 把它列为敏感目录）。

可选：如果还想让网页上的「执行命令 / 测试连接」也在新电脑上执行，需要在新电脑上安装后台 agent（「新电脑」窗口底部有说明，需要源代码，见下文 `setup.sh`）。

## 安全设计

- **登录**：整个站点由 Cloudflare Access 保护，只允许指定邮箱登录。Worker 还会再校验一次 Access JWT 的签名、aud 和邮箱；Worker 的版本预览地址已关闭（`previewUrls: false`），不存在绕过 Access 的入口。
- **agent 身份**：agent 用 Access service token 访问，Worker 只允许这个 service token 调用 `/api/agent/*`，它也调不了网页用户的接口。
- **端到端加密**：agent 第一次启动时在本机生成 RSA 密钥对（`~/.config/ssh-manager/agent_key.pem`，600 权限），只把公钥登记到云端。
  - 服务器密码：浏览器用 agent 公钥（RSA-OAEP）加密后才上传。
  - SSH 私钥：随机 AES-256-GCM 密钥加密内容，再用 agent 公钥包裹 AES 密钥。暂不支持带口令的私钥。
  - Worker 和数据库只能看到密文；只有持有 agent 私钥的地方（本机 agent，或输入了主密码的浏览器）能解密。
- **主密码**：agent 私钥和连接凭证用主密码（scrypt 派生 + AES-256-GCM）加密后备份到云端；主密码只在本机或浏览器里使用，不会上传，至少 12 位。忘记主密码就无法恢复已保存的密码和私钥。
- **明文保存的只有公开信息**：SSH 公钥、主机公钥、服务器地址等。
- **数据库**：所有表开启 RLS 并收回 `anon` / `authenticated` 权限，Supabase 的 Data API 读不到这些表，只有 Worker（经 Hyperdrive）能访问。
- **主机密钥**：保持 ssh-skill 的严格校验，信任指纹前必须由你确认；指纹变化时要求再次确认。
- **跨站请求**：浏览器的写请求必须带 `X-SSH-Manager` 头。
- **本机文件**：改写 `~/.ssh/config` 前会备份；注意 ssh-skill 的约定是把密码明文写在 `~/.ssh/config` 的 `# password:` 注释里，能用密钥认证时建议用密钥。

## 部署

需要：Supabase 账号、Cloudflare 账号（已开通 Zero Trust）、[`cf` CLI](https://www.npmjs.com/package/cf)、Node.js 22+、[uv](https://docs.astral.sh/uv/)、已安装的 ssh-skill（`~/.claude/skills/ssh-skill`）。

1. **数据库**：创建 Supabase 项目（免费额度即可），按编号顺序执行 `db/migrations/` 下的全部 SQL：

   | 迁移 | 内容 |
   |---|---|
   | 001_init | 服务器、agent、设置、任务队列 |
   | 002_ssh_keys | 云端 SSH 私钥 |
   | 003_environments | 分组（环境）表，服务器的环境外键 |
   | 004_environment_labels | 分组中文显示名 |
   | 005 / 006 | 早期的配对码方案（已废弃，006 删除该表） |
   | 007_ssh_key_public | SSH 公钥与指纹 |
   | 008_host_keys | 已信任的主机指纹 |

2. **Hyperdrive**：用 Supabase 的 **Session pooler** 连接串（`aws-0-<region>.pooler.supabase.com:5432`，用户名 `postgres.<project-ref>`；直连地址只有 IPv6，Hyperdrive 连不上）创建 Hyperdrive 配置并**关闭缓存**（任务队列需要实时读取），把 ID 填到 `worker/cloudflare.config.ts`。

3. **Cloudflare Access**：
   - 创建一个 service token 给 agent 用。
   - 为 Worker 的域名创建 Access 应用，两条策略：Allow 你的邮箱；Service Auth 允许上面的 service token。

4. **部署 Worker**：

   ```bash
   cd worker && npm install && cf deploy --secrets-file .secrets.env
   ```

   `.secrets.env`（参考 `.dev.vars.example`，不要提交）：`ACCESS_TEAM_DOMAIN`、`ACCESS_AUD`（Access 应用的 AUD）、`ALLOWED_EMAILS`、`AGENT_CLIENT_ID`（service token 的 Client ID）。

5. **启动 agent**（在要执行 SSH 操作的电脑上）：

   ```bash
   cd agent && cp .env.example .env   # 填写 Worker 地址和 service token
   uv run python -m ssh_agent run
   ```

   安装为开机自启（macOS）：`./setup.sh service`

6. **备份**（强烈建议）：`./setup.sh backup`，设置主密码。没有备份就无法用「新电脑」同步。

## agent 命令

| 命令 | 说明 |
|---|---|
| `./setup.sh backup` | 用主密码加密 agent 私钥和连接凭证，备份到云端 |
| `./setup.sh service` | 安装 / 重启开机自启的后台服务（macOS launchd） |
| `./setup.sh status` | 查看后台服务状态和最近日志（日志在 `~/Library/Logs/ssh-manager/agent.log`） |
| `./setup.sh [设置文件]` | 在新电脑上安装后台 agent（需要网页「新电脑」里下载的 `ssh-manager-setup.json`） |
| `uv run python -m ssh_agent run` | 前台运行 agent（在 `agent/` 目录下） |
| `uv run python -m ssh_agent restore-key` | 用主密码从云端恢复 agent 私钥 |
| `uv run python -m ssh_agent pubkey` | 打印 agent 公钥 |

停用后台服务：`launchctl bootout gui/$(id -u)/com.ssh-manager.agent`

## 项目结构

```
worker/                 Cloudflare Worker：网页 + API
  src/                  Worker 代码（API、Access JWT 校验）
  client/               前端（React + shadcn/ui）
    lib/restore.ts      新电脑同步：浏览器端解密，生成 bash / PowerShell 同步脚本
    lib/sshkey.ts       从私钥提取 OpenSSH 公钥
  cloudflare.config.ts  Worker 配置（Hyperdrive、静态资源、密钥绑定）
agent/                  本机 agent（Python）
  ssh_agent/handlers.py 各类任务的处理（同步、执行、传输、隧道、导入、主机指纹）
  ssh_agent/skill.py    对 ssh-skill 脚本的封装
  ssh_agent/keys.py     agent 密钥对、加解密、主密码备份
db/migrations/          数据库迁移
setup.sh                agent 安装 / 备份 / 服务管理
```

## 开发

```bash
cd agent && uv run pytest -q          # agent 测试（不会改动真实的 ~/.ssh/config）
cd worker && npx tsc -b && cf build   # Worker + 前端类型检查与构建
```

本地预览（`localhost` 上以 `.dev.vars` 里的 `DEV_EMAIL` 身份登录，线上不会声明这个绑定）：

```bash
cd worker && SSH_MANAGER_DEV=1 DEV_DATABASE_URL='postgres://…' cf dev
```

添加 shadcn 组件：`cd worker && npx shadcn@latest add <组件>`
