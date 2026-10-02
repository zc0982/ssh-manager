# SSH Manager

SSH 连接管理系统：服务器清单存在云端，网页托管在 Cloudflare，实际的 SSH 连接由你电脑上的 agent 通过本机 ssh-skill 执行。

```
浏览器 ──(Cloudflare Access 登录)──▶ Worker（网页 + API）──Hyperdrive──▶ PlanetScale Postgres
                                          ▲
                                          │ 长轮询领取任务 / 回传结果（Access service token）
                                          │
                                  本机 agent ──▶ ssh-skill 脚本 ──▶ 远程服务器
                                          └──▶ ~/.ssh/config（同步服务器配置）
```

- **worker/**：Cloudflare Worker，同时提供静态网页（Workers Static Assets）和 `/api/*`，通过 Hyperdrive 连接 PlanetScale Postgres。
- **agent/**：运行在本机的 Python 程序。从 Worker 领取任务（测试连接、执行命令、传输文件、隧道、同步配置……），调用 `~/.claude/skills/ssh-skill/scripts/*.py` 执行，不直接调用 ssh/scp。
- **db/migrations/**：数据库表结构。

## 功能

| 功能 | 说明 |
|---|---|
| 服务器增删改查 | 别名、主机、端口、用户、密钥/密码、跳板机、环境、标签、位置、备注 |
| 同步到本机 | 保存后自动写入 agent 所在电脑的 `~/.ssh/config`（ssh-skill 的注释元数据格式），Claude Code 里的 ssh-skill 也能直接用这些别名；换电脑时可「全部同步到本机」 |
| 从本机导入 | 把 `~/.ssh/config` 里已有的主机导入云端 |
| 测试连接 / 执行命令 | `ssh_execute.py`，支持超时、只读重试和命令历史 |
| 文件传输 | `ssh_upload.py` / `ssh_download.py`，路径是 agent 所在电脑的本地路径 |
| SSH 隧道 | `ssh_tunnel.py`，隧道监听在 agent 所在电脑的 127.0.0.1 |
| 操作日志 | 每个任务都记录在 `jobs` 表中，包括操作人、结果和耗时 |

## 安全设计

- **登录**：整个站点由 Cloudflare Access 保护，只允许指定邮箱登录；Worker 还会再校验一次 Access JWT 的签名、aud 和邮箱，防止绕过 Access（比如通过 preview URL 访问）。
- **agent 身份**：agent 用 Access service token 访问，Worker 只允许这个 service token 调用 `/api/agent/*`。
- **密码**：agent 第一次启动时在本机生成 RSA 密钥对（`~/.config/ssh-manager/agent_key.pem`，权限 600），把公钥登记到云端。网页在浏览器里用公钥加密密码后才上传，Worker 和数据库都只能看到密文，只有本机 agent 能解密。
  - 多台电脑运行 agent 时，需要共用同一份私钥文件。私钥丢失后，已保存的密码无法解密，需要重新填写。
  - ssh-skill 的约定是把密码以明文写在本机 `~/.ssh/config` 的 `# password:` 注释里，所以能用密钥认证时建议用密钥。
- **跨站请求**：浏览器的写请求必须带 `X-SSH-Manager` 头。
- **本机配置**：第一次改写 `~/.ssh/config` 前会备份为 `~/.ssh/config.ssh-manager.bak`。

## 部署

需要：Cloudflare 账号（已开通 Zero Trust）、[`cf` CLI](https://www.npmjs.com/package/cf)、Node.js 22+、[uv](https://docs.astral.sh/uv/)、已安装的 ssh-skill。

1. **数据库**：创建 PlanetScale Postgres（可在 Cloudflare 控制台 Storage & databases → Postgres & MySQL 创建，费用计入 Cloudflare 账单），执行 `db/migrations/001_init.sql`。
2. **Hyperdrive**：用数据库连接串创建 Hyperdrive 配置并**关闭缓存**（任务队列需要实时读取），把 ID 填到 `worker/cloudflare.config.ts`。
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

## 开发

```bash
cd agent && uv run pytest -q        # agent 测试（不会改动真实的 ~/.ssh/config）
cd worker && npx tsc && cf build    # Worker 类型检查与构建
```
