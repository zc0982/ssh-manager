"""新电脑设置向导：用网页下载的 ssh-manager-setup.json + 主密码，恢复 agent 并同步所有服务器到本机。"""
import getpass
import json
import os
import platform
import shutil
import sys
from pathlib import Path

import httpx

from .handlers import Handlers
from .keys import KeyPair
from .skill import SkillBridge

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"


def step(n: int, total: int, title: str) -> None:
    print(f"\n[{n}/{total}] {title}")


def ok(msg: str) -> None:
    print(f"  ✓ {msg}")


def fail(msg: str, hint: str = "") -> None:
    print(f"  ✗ {msg}")
    if hint:
        print(f"    → {hint}")
    sys.exit(1)


def ask_yes(question: str, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    ans = input(f"  {question} {suffix} ").strip().lower()
    return default if not ans else ans in ("y", "yes", "是")


def find_bundle(arg: str | None) -> Path:
    if arg:
        return Path(os.path.expanduser(arg))
    candidates = sorted(Path.home().glob("Downloads/ssh-manager-setup*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if candidates:
        print(f"  找到设置文件：{candidates[0]}")
        if ask_yes("使用这个文件？"):
            return candidates[0]
    path = input("  请输入 ssh-manager-setup.json 的路径：").strip()
    return Path(os.path.expanduser(path))


def read_env() -> dict:
    env = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def write_env(values: dict) -> None:
    fd = os.open(ENV_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        for k in ("SSH_MANAGER_URL", "CF_ACCESS_CLIENT_ID", "CF_ACCESS_CLIENT_SECRET"):
            f.write(f"{k}={values.get(k, '')}\n")


def run_setup(bundle_arg: str | None, key_path: Path, skill_dir: Path, agent_name: str, install_launchd) -> None:
    total = 6
    print("SSH Manager 新电脑设置向导")
    print("会用到：网页「新电脑」里下载的 ssh-manager-setup.json，以及你设置的主密码。")

    # 1. 前置检查
    step(1, total, "检查本机环境")
    skill = SkillBridge(skill_dir)
    status = skill.check()
    if not status["ok"]:
        fail(status["error"], f"先安装 ssh-skill 到 {skill_dir}，并运行：python3 {skill_dir}/scripts/bootstrap_env.py")
    ok(f"ssh-skill：{skill_dir}")
    if not shutil.which("ssh"):
        fail("没有找到 ssh 命令", "安装 OpenSSH 客户端")
    ok("OpenSSH 客户端")

    # 2. 读取设置文件
    step(2, total, "读取设置文件")
    bundle_path = find_bundle(bundle_arg)
    try:
        bundle = json.loads(bundle_path.read_text())
        url, backup = bundle["url"].rstrip("/"), bundle["backup"]
    except (OSError, ValueError, KeyError) as e:
        fail(f"无法读取设置文件：{e}", "在网页上点「新电脑」重新下载")
    if not backup.get("has_env"):
        fail("这个备份只包含 agent 私钥，不含连接凭证（旧版备份）",
             "在旧电脑上运行 ./setup.sh backup 更新备份后，重新下载设置文件")
    ok(f"服务地址：{url}")

    # 3. 主密码解密
    step(3, total, "输入主密码解密")
    for attempt in range(3):
        try:
            opened = KeyPair.open_backup(backup, getpass.getpass("  主密码："))
            break
        except RuntimeError as e:
            print(f"  ✗ {e}")
    else:
        fail("主密码连续错误 3 次")
    env = {**opened["env"], "SSH_MANAGER_URL": url}
    ok("解密成功")

    # 4. 写入私钥和 .env
    step(4, total, "写入 agent 私钥和连接配置")
    if key_path.exists():
        existing = KeyPair.load_or_create(key_path)
        if not existing.matches({"n": backup["public_n"], "e": existing.public_jwk["e"]}):
            fail(f"本机已有另一把 agent 私钥：{key_path}", "确认不再需要后把它移走，再重新运行向导")
        keys = existing
        ok(f"本机已有相同的 agent 私钥：{key_path}")
    else:
        keys = KeyPair.install(opened["private_pem"], key_path)
        ok(f"已写入 {key_path}（权限 600）")
    old = read_env()
    differs = any(old.get(k) and old.get(k) != env.get(k) for k in ("SSH_MANAGER_URL", "CF_ACCESS_CLIENT_ID", "CF_ACCESS_CLIENT_SECRET"))
    if differs and not ask_yes(f"{ENV_FILE} 已存在且内容不同，覆盖？", default=False):
        print("  保留原有 .env")
        env = {**env, **{k: v for k, v in old.items() if v}}
    else:
        write_env(env)
        ok(f"已写入 {ENV_FILE}（权限 600）")
    os.environ.update(env)

    # 5. 连接云端并同步服务器
    step(5, total, "连接云端并同步所有服务器到本机 ~/.ssh/config")
    client = httpx.Client(base_url=url, timeout=30, headers={
        "CF-Access-Client-Id": env["CF_ACCESS_CLIENT_ID"], "CF-Access-Client-Secret": env["CF_ACCESS_CLIENT_SECRET"]})
    try:
        r = client.post("/api/agent/hello", json={"name": agent_name, "hostname": platform.node(),
                                                   "version": "setup", "public_key": keys.public_jwk})
        hello = r.json()
    except (httpx.HTTPError, ValueError) as e:
        fail(f"连接失败：{e}", "检查网络；如果返回的是登录页，说明 service token 已失效")
    if r.status_code != 200:
        fail(f"连接失败：HTTP {r.status_code} {hello.get('detail', '')}")
    if not keys.matches(hello.get("public_key")):
        fail("云端登记的公钥与备份的私钥不一致", "请确认设置文件来自同一个 SSH Manager")
    ok("已连接云端")
    servers = client.get("/api/agent/servers").json()
    handlers = Handlers(skill, keys)
    bad = []
    for s in servers:
        result, _ = handlers.handle({"type": "sync", "server": s, "payload": {}})
        if not result.get("success"):
            bad.append(f"{s['alias']}：{result.get('error')}")
    ok(f"已同步 {len(servers) - len(bad)}/{len(servers)} 台服务器")
    for b in bad:
        print(f"  ✗ {b}")

    # 6. 后台服务
    step(6, total, "安装后台服务")
    if platform.system() == "Darwin":
        if ask_yes("安装为开机自启的后台服务（推荐）？"):
            install_launchd()
        else:
            print("  跳过。之后可以运行：./setup.sh service")
    else:
        print("  非 macOS，请自行用 systemd 等方式运行：uv run python -m ssh_agent run")

    print("\n设置完成！打开网页，顶部应显示本机 agent 在线。")
