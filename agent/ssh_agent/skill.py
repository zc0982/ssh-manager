"""对本机 ssh-skill 脚本的封装。所有 SSH 操作都通过 skill 的脚本完成，不直接调用 ssh/scp。"""
import json
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

ALIAS_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class SkillError(RuntimeError):
    pass


def _parse_json(text: str) -> dict | None:
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        # 有的脚本会先输出进度信息，取最后一个完整 JSON 对象
        start = text.rfind("\n{")
        if start != -1:
            try:
                return json.loads(text[start + 1:])
            except ValueError:
                return None
        return None


class SkillBridge:
    def __init__(self, skill_dir: Path, home: Path | None = None):
        self.skill_dir = skill_dir
        self.scripts = skill_dir / "scripts"
        self.python = skill_dir / ".venv" / "bin" / "python"
        self.home = home or Path.home()
        self.config_path = self.home / ".ssh" / "config"
        self._lock = threading.Lock()
        self._backed_up = False

    # ---------- 基础 ----------

    def check(self) -> dict:
        if not (self.scripts / "ssh_execute.py").exists():
            return {"ok": False, "error": f"未找到 ssh-skill：{self.skill_dir}"}
        if not self.python.exists():
            return {"ok": False, "error": f"ssh-skill 虚拟环境不存在，请运行 python3 {self.scripts}/bootstrap_env.py"}
        return {"ok": True, "skill_dir": str(self.skill_dir), "config_path": str(self.config_path)}

    def _run(self, script: str, args: list[str], timeout: float = 60) -> dict:
        env = {**os.environ, "HOME": str(self.home), "MSYS_NO_PATHCONV": "1", "PYTHONIOENCODING": "utf-8"}
        cmd = [str(self.python), str(self.scripts / script), *args]
        started = time.monotonic()
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"本地调用超时（{timeout}s）",
                    "duration_ms": int((time.monotonic() - started) * 1000)}
        data = _parse_json(p.stdout) or _parse_json(p.stderr)
        if data is None:
            data = {"success": p.returncode == 0, "stdout": p.stdout, "stderr": p.stderr}
        data.setdefault("success", p.returncode == 0)
        data["duration_ms"] = int((time.monotonic() - started) * 1000)
        return data

    # ---------- ~/.ssh/config 同步 ----------

    def local_hosts(self) -> list[dict]:
        r = self._run("ssh_config_manager_v3.py", ["export"])
        if "hosts" not in r:
            raise SkillError(r.get("error") or "读取本地 SSH 配置失败")
        return r["hosts"]

    def _local_host(self, alias: str) -> dict | None:
        return next((h for h in self.local_hosts() if h["alias"] == alias), None)

    def _backup(self) -> None:
        if not self._backed_up and self.config_path.exists():
            shutil.copy2(self.config_path, self.config_path.with_name("config.ssh-manager.bak"))
            self._backed_up = True

    def sync_server(self, server: dict, password: str | None) -> dict:
        """把一台服务器写入 ~/.ssh/config（存在则更新，不存在则创建）。"""
        alias = server["alias"]
        if not ALIAS_RE.match(alias):
            raise SkillError(f"非法别名：{alias}")
        key = server.get("identity_file") if server.get("auth_type") == "key" else None
        jump = server.get("proxy_jump") or None

        # 统一用 --opt=value 形式，避免以 "-" 开头的值被 argparse 当成选项
        fields = [f"--host={server['hostname']}", f"--user={server['username']}",
                  f"--port={server.get('port') or 22}",
                  f"--environment={server.get('environment') or 'development'}",
                  f"--description={server.get('description') or ''}",
                  f"--location={server.get('location') or ''}"]
        if key:
            fields.append(f"--key={key}")
        if jump:
            fields.append(f"--jump={jump}")
        tags = [t for t in server.get("tags") or [] if t]
        if tags:
            fields += ["--tags", *tags]

        with self._lock:
            self._backup()
            local = self._local_host(alias)
            # update 只能设置字段、无法清除密钥/跳板机，这种情况下删除后重建
            needs_recreate = local is not None and (
                (local.get("identity_file") and not key) or (local.get("proxy_jump") and not jump)
                or (local.get("metadata", {}).get("tags") and not tags))
            if needs_recreate:
                self._must(self._run("ssh_config_manager_v3.py", ["delete", alias]))
                local = None
            if local is None:
                self._must(self._run("ssh_config_manager_v3.py", ["create", f"--alias={alias}", *fields]))
            else:
                self._must(self._run("ssh_config_manager_v3.py", ["update", alias, *fields]))
            self._set_password(alias, password if server.get("auth_type") == "password" else None)
        return {"alias": alias, "action": "updated" if local else "created"}

    def remove_server(self, alias: str) -> bool:
        with self._lock:
            self._backup()
            r = self._run("ssh_config_manager_v3.py", ["delete", alias])
            return bool(r.get("success"))

    def _set_password(self, alias: str, password: str | None) -> None:
        """skill 约定密码存放在 Host 块上方的 `# password:` 注释中，CLI 没有对应参数，这里直接改写该行。"""
        if password and ("\n" in password or "\r" in password):
            raise SkillError("密码不能包含换行")
        lines = self.config_path.read_text(encoding="utf-8").splitlines(keepends=True)
        host_idx = next((i for i, l in enumerate(lines) if l.strip() == f"Host {alias}"), None)
        if host_idx is None:
            raise SkillError(f"写入后未找到 Host {alias}")
        start = host_idx
        while start > 0 and lines[start - 1].lstrip().startswith("#"):
            start -= 1
        head = [l for l in lines[start:host_idx] if not l.lstrip().startswith("# password:")]
        if password:
            head.append(f"# password: {password}\n")
        new = lines[:start] + head + lines[host_idx:]
        if new != lines:
            self.config_path.write_text("".join(new), encoding="utf-8")
            os.chmod(self.config_path, 0o600)

    @staticmethod
    def _must(r: dict) -> None:
        if not r.get("success"):
            raise SkillError(r.get("error") or r.get("message") or "ssh-skill 调用失败")

    # ---------- 远程操作 ----------

    def execute(self, alias: str, command: str, timeout: int = 60, read_only: bool = False) -> dict:
        args = [alias, command, "--timeout", str(timeout)]
        if read_only:
            args += ["--read-only", "--connect-attempts", "3"]
        return self._run("ssh_execute.py", args, timeout=timeout * 4 + 30)

    def upload(self, alias: str, local: str, remote: str, recursive: bool) -> dict:
        args = [alias, local, remote, "--no-progress"] + (["--recursive"] if recursive else [])
        return self._run("ssh_upload.py", args, timeout=3600)

    def download(self, alias: str, remote: str, local: str, recursive: bool) -> dict:
        args = [alias, remote, local, "--no-progress"] + (["--recursive"] if recursive else [])
        return self._run("ssh_download.py", args, timeout=3600)

    def tunnels(self) -> dict:
        return self._run("ssh_tunnel.py", ["list"])

    def tunnel_start(self, alias: str, remote_port: int, local_port: int | None, remote_host: str | None) -> dict:
        args = ["start", alias, "--remote-port", str(remote_port)]
        if local_port:
            args += ["--local-port", str(local_port)]
        if remote_host:
            args += ["--remote-host", remote_host]
        return self._run("ssh_tunnel.py", args, timeout=60)

    def tunnel_stop(self, tunnel_id: str) -> dict:
        return self._run("ssh_tunnel.py", ["stop", tunnel_id])
