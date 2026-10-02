"""SSH Manager 本机 agent。

    uv run python -m ssh_agent run               # 前台运行
    uv run python -m ssh_agent install-launchd   # 安装为 macOS 登录后自动启动的服务
    uv run python -m ssh_agent pubkey            # 打印公钥（JWK）
"""
import argparse
import json
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv

from .handlers import Handlers
from .keys import KeyPair
from .skill import SkillBridge

VERSION = "0.2.0"
ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
log = logging.getLogger("ssh_agent")


def setting(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def key_path() -> Path:
    return Path(os.path.expanduser(setting("SSH_MANAGER_KEY_FILE", "~/.config/ssh-manager/agent_key.pem")))


def agent_name() -> str:
    name = setting("AGENT_NAME") or socket.gethostname().split(".")[0]
    return re.sub(r"[^A-Za-z0-9._-]", "-", name)[:64]


def make_client() -> httpx.Client:
    url = setting("SSH_MANAGER_URL").rstrip("/")
    cid, secret = setting("CF_ACCESS_CLIENT_ID"), setting("CF_ACCESS_CLIENT_SECRET")
    if not url or not cid or not secret:
        sys.exit("请在 agent/.env 中配置 SSH_MANAGER_URL、CF_ACCESS_CLIENT_ID、CF_ACCESS_CLIENT_SECRET")
    return httpx.Client(base_url=url, timeout=httpx.Timeout(10, read=60),
                        headers={"CF-Access-Client-Id": cid, "CF-Access-Client-Secret": secret,
                                 "User-Agent": f"ssh-manager-agent/{VERSION}"})


def check(r: httpx.Response) -> dict:
    if r.status_code >= 400:
        detail = r.text[:300]
        try:
            detail = r.json().get("detail", detail)
        except ValueError:
            pass
        raise RuntimeError(f"HTTP {r.status_code}: {detail}")
    try:
        return r.json()
    except ValueError as e:
        # Access 未放行时会返回登录页 HTML
        raise RuntimeError(f"响应不是 JSON（Access service token 是否正确？）：{r.text[:120]!r}") from e


def run() -> None:
    skill = SkillBridge(Path(os.path.expanduser(setting("SSH_SKILL_DIR", "~/.claude/skills/ssh-skill"))))
    status = skill.check()
    if not status["ok"]:
        sys.exit(status["error"])
    keys = KeyPair.load_or_create(key_path())
    handlers = Handlers(skill, keys)
    client = make_client()

    hello = check(client.post("/api/agent/hello", json={
        "name": agent_name(), "hostname": socket.gethostname(), "version": VERSION, "public_key": keys.public_jwk}))
    if not keys.matches(hello.get("public_key")):
        sys.exit(f"云端登记的公钥与本机私钥 {key_path()} 不一致。请把首台电脑的私钥文件复制到这里后再启动。")
    agent_id = hello["agent_id"]
    log.info("agent %s 已连接 %s（ssh-skill: %s）", agent_name(), client.base_url, status["skill_dir"])

    backoff = 1
    while True:
        try:
            job = check(client.post("/api/agent/poll", json={"agent_id": agent_id})).get("job")
            backoff = 1
        except (httpx.HTTPError, RuntimeError) as e:
            log.warning("轮询失败：%s，%ss 后重试", e, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
            continue
        if not job:
            continue

        log.info("任务 #%s %s %s", job["id"], job["type"], job.get("alias") or "")
        result, extra = handlers.handle(job)
        log.info("任务 #%s %s", job["id"], "成功" if result.get("success") else f"失败：{result.get('error') or result.get('stderr', '')[:200]}")
        for attempt in range(5):
            try:
                check(client.post(f"/api/agent/jobs/{job['id']}/result", json={"result": result, **extra}))
                break
            except (httpx.HTTPError, RuntimeError) as e:
                log.warning("回传任务 #%s 失败：%s", job["id"], e)
                time.sleep(2 ** attempt)


PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array><string>{uv}</string><string>run</string><string>--project</string><string>{root}</string><string>python</string><string>-m</string><string>ssh_agent</string><string>run</string></array>
  <key>WorkingDirectory</key><string>{root}</string>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>{path}</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{logdir}/agent.log</string>
  <key>StandardErrorPath</key><string>{logdir}/agent.log</string>
</dict>
</plist>
"""


def install_launchd() -> None:
    if platform.system() != "Darwin":
        sys.exit("仅支持 macOS")
    label = "com.ssh-manager.agent"
    uv = subprocess.run(["which", "uv"], capture_output=True, text=True).stdout.strip()
    if not uv:
        sys.exit("未找到 uv")
    logdir = Path.home() / "Library" / "Logs" / "ssh-manager"
    logdir.mkdir(parents=True, exist_ok=True)
    plist = Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"
    plist.write_text(PLIST.format(label=label, uv=uv, root=ROOT, logdir=logdir, path=os.environ.get("PATH", "")))
    uid = os.getuid()
    subprocess.run(["launchctl", "bootout", f"gui/{uid}/{label}"], capture_output=True)
    subprocess.run(["launchctl", "bootstrap", f"gui/{uid}", str(plist)], check=True)
    print(f"已安装并启动：{plist}\n日志：{logdir}/agent.log")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    p = argparse.ArgumentParser(prog="ssh_agent")
    p.add_argument("command", choices=["run", "install-launchd", "pubkey"])
    args = p.parse_args()
    if args.command == "run":
        run()
    elif args.command == "install-launchd":
        install_launchd()
    else:
        print(json.dumps(KeyPair.load_or_create(key_path()).public_jwk, indent=2))


if __name__ == "__main__":
    main()
