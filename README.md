# SSH Manager

SSH 连接管理系统：服务器清单存在云端，网页托管在 Cloudflare，实际的 SSH 连接由你电脑上的 agent 通过本机 ssh-skill 执行。

```
浏览器 ──(Cloudflare Access 登录)──▶ Worker（网页 + API）──Hyperdrive──▶ Supabase Postgres
                                          ▲
                                          │ 长轮询领取任务 / 回传结果（Access service token）
                                          │
                                  本机 agent ──▶ ssh-skill 脚本 ──▶ 远程服务器
                                          └──▶ ~/.ssh/config（同步服务器配置）
```

- **worker/**：Cloudflare Worker，同时提供静态网页（Workers Static Assets）和 `/api/*`，通过 Hyperdrive 连接 Supabase Postgres。前端是 React + Tailwind + [shadcn/ui](https://ui.shadcn.com)（`worker/client/`，组件在 `client/components/ui/`，用 `npx shadcn@latest add <组件>` 添加），配色为 shadcn.io 的 Cyberpunk 主题，固定深色。
  - **背景图**：把你自己的图片放到 `worker/public/background.jpg` 后重新部署即可（该文件已 gitignore，不会提交到仓库；只部署到受 Access 保护的站点）。没有图片时显示霓虹网格背景。
- **agent/**：运行在本机的 Python 程序。从 Worker 领取任务（测试连接、执行命令、传输文件、隧道、同步配置……），调用 `~/.claude/skills/ssh-skill/scripts/*.py` 执行，不直接调用 ssh/scp。
- **db/migrations/**：数据库表结构。

## 功能

| 功能 | 说明 |
|---|---|
| 服务器增删改查 | 别名、主机、端口、用户、密钥/密码、跳板机、环境、标签、位置、备注 |
| 分组管理 | 分组即「环境」字段：可设中文显示名，新建、改名、改颜色、排序、删除（删除时把服务器迁到其他环境）；在侧边栏把服务器拖到其他分组即可移动。英文名变化会自动同步到本机 `~/.ssh/config` |
| 同步到本机 | 保存后自动写入 agent 所在电脑的 `~/.ssh/config`（ssh-skill 的注释元数据格式），Claude Code 里的 ssh-skill 也能直接用这些别名；换电脑时可「全部同步到本机」 |
| 从本机导入 | 把 `~/.ssh/config` 里已有的主机导入云端，可同时把它们使用的私钥文件加密上传 |
| 云端 SSH 私钥 | 在网页上传私钥（浏览器端加密），多台服务器可共用；同步时 agent 解密写到 `~/.ssh/ssh-manager/<名称>.key`（600 权限）。换电脑不用再拷私钥 |
| agent 私钥云端备份 | `backup-key` 用主密码加密后存到云端，新电脑上 `restore-key` 恢复 |
| 测试连接 / 执行命令 | `ssh_execute.py`，支持超时、只读重试和命令历史 |
| 文件传输 | `ssh_upload.py` / `ssh_download.py`，路径是 agent 所在电脑的本地路径 |
| SSH 隧道 | `ssh_tunnel.py`，隧道监听在 agent 所在电脑的 127.0.0.1 |
| 操作日志 | 每个任务都记录在 `jobs` 表中，包括操作人、结果和耗时 |

## 安全设计

- **登录**：整个站点由 Cloudflare Access 保护，只允许指定邮箱登录；Worker 还会再校验一次 Access JWT 的签名、aud 和邮箱，防止绕过 Access（比如通过 preview URL 访问）。
- **agent 身份**：agent 用 Access service token 访问，Worker 只允许这个 service token 调用 `/api/agent/*`。
- **密码**：agent 第一次启动时在本机生成 RSA 密钥对（`~/.config/ssh-manager/agent_key.pem`，权限 600），把公钥登记到云端。网页在浏览器里用公钥加密密码后才上传，Worker 和数据库都只能看到密文，只有本机 agent 能解密。
  - **SSH 私钥**同样端到端加密：随机 AES-256-GCM 密钥加密内容，再用 agent 公钥（RSA-OAEP）包裹 AES 密钥。暂不支持带口令的私钥。
  - **agent 私钥**可以用你的主密码（scrypt 派生 + AES-256-GCM）加密后备份到云端；主密码只在本机输入，不会上传。云端拿到的只有密文，安全性取决于主密码强度（至少 12 位）。
  - 多台电脑运行 agent 时，在新电脑上执行 `restore-key` 即可得到同一把 agent 私钥。
  - ssh-skill 的约定是把密码以明文写在本机 `~/.ssh/config` 的 `# password:` 注释里，所以能用密钥认证时建议用密钥。
- **跨站请求**：浏览器的写请求必须带 `X-SSH-Manager` 头。
- **本机配置**：第一次改写 `~/.ssh/config` 前会备份为 `~/.ssh/config.ssh-manager.bak`。

## 部署

需要：Supabase 账号、Cloudflare 账号（已开通 Zero Trust）、[`cf` CLI](https://www.npmjs.com/package/cf)、Node.js 22+、[uv](https://docs.astral.sh/uv/)、已安装的 ssh-skill。

1. **数据库**：创建 Supabase 项目（免费额度即可），按顺序执行 `db/migrations/` 下的 SQL。迁移会给所有表开启 RLS 并收回 `anon`/`authenticated` 的权限，因此 Supabase 的 Data API 读不到这些表。
2. **Hyperdrive**：用 Supabase 的 **Session pooler** 连接串（`aws-0-<region>.pooler.supabase.com:5432`，用户名 `postgres.<project-ref>`；直连地址只有 IPv6，Hyperdrive 连不上）创建 Hyperdrive 配置并**关闭缓存**（任务队列需要实时读取），把 ID 填到 `worker/cloudflare.config.ts`。
3. **部署 Worker**：

   ```bash
   cd worker && npm install && cf deploy --secrets-file .secrets.env
   ```

   `.secrets.env` 包含 `ACCESS_TEAM_DOMAIN`、`ACCESS_AUD`、`ALLOWED_EMAILS`、`AGENT_CLIENT_ID`（参考 `.dev.vars.example`），不要提交到仓库。
4. **Cloudflare Access**：为 Worker 的域名创建 Access 应用，策略允许你的邮箱 + agent 的 service token（Service Auth），把应用的 AUD 填进上一步的密钥。
5. **启动 agent**：

   ```bash
   cd agent && cp .env.example .env   # 填写 Worker 地址和 service token
   uv run python -m ssh_agent run
   ```

   安装为开机自启（macOS）：`uv run python -m ssh_agent install-launchd`

6. **备份**（强烈建议）：`./setup.sh backup`，设置主密码。agent 私钥和 agent 的连接凭证会用主密码加密后存到云端。

## 换电脑

不需要下载源代码，也不需要安装程序：

1. 在新电脑的浏览器里登录网页，点「新电脑」，输入主密码。浏览器在本地解开 agent 私钥，再解密云端的服务器密码和 SSH 私钥，生成同步脚本。
2. 点「复制同步脚本」，然后在终端输入（页面会按系统自动选择）：

   | 系统 | 命令 |
   |---|---|
   | macOS | `pbpaste \| bash` |
   | Windows（cmd 或 PowerShell） | 复制的就是一行命令，直接粘贴并回车（服务器特别多、超过 cmd 单行长度时，改为输入 `powershell -nop -c "iex (Get-Clipboard -Raw)"`） |
   | Linux | `xclip -o -selection clipboard \| bash` |

   脚本会备份原配置为 `~/.ssh/config.ssh-manager.bak`，用 ssh-skill 的格式把所有服务器写进 `~/.ssh/config`（同名条目先替换，其他配置不动），私钥写到 `~/.ssh/ssh-manager/`（macOS/Linux 为 600 权限；Windows 用 icacls 设为仅当前用户可访问），最后清空剪贴板。可以重复运行。Windows 写入 `%USERPROFILE%\.ssh\config`，UTF-8 无 BOM。

为什么还要一条终端命令：浏览器的 File System Access API 明确禁止网页写入 `~/.ssh`。

可选：如果还想让网页上的命令在新电脑上执行，就需要后台 agent。用源代码和下载的设置文件运行 `./setup.sh` 安装。

`setup.sh` 的其他用法：`./setup.sh backup`（更新云端备份）、`./setup.sh service`（安装/重启后台服务）、`./setup.sh status`（查看后台服务状态和日志）。

没有在线的 agent，或者备份缺失、过时的时候，网页顶部会出现提醒。

## 开发

```bash
cd agent && uv run pytest -q          # agent 测试（不会改动真实的 ~/.ssh/config）
cd worker && npx tsc -b && cf build   # Worker + 前端类型检查与构建
```

本地预览前端（`localhost` 上以 `.dev.vars` 里的 `DEV_EMAIL` 身份登录，线上不会声明这个绑定）：

```bash
cd worker && SSH_MANAGER_DEV=1 DEV_DATABASE_URL='postgres://…' cf dev
```
