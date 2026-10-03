"""任务处理：每种任务类型对应一个函数，返回 (result, extra)，extra 会合并进回传给 Worker 的请求体。"""
import base64
import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

from .keys import KeyPair, private_key_encrypted, public_key_line
from .skill import ALIAS_RE, SkillBridge, SkillError

TEST_COMMAND = "hostname && uptime && (uname -sr || true)"
MAX_KEY_FILE = 64 * 1024
# 与 worker/shared/ssh.ts 的 HOSTKEY_RE 保持一致：主机和类型只允许安全字符
HOSTKEY_RE = re.compile(r"^(\[[A-Za-z0-9.:_-]+\]:\d{1,5}|[A-Za-z0-9.:_-]+) ([a-z0-9@.-]+) ([A-Za-z0-9+/]+={0,2})$")


def known_hosts_pattern(hostname: str, port: int) -> str:
    """known_hosts 里的主机写法：22 端口直接写主机名，其他端口写 [主机]:端口"""
    return hostname if int(port or 22) == 22 else f"[{hostname}]:{int(port)}"


def host_key_fingerprint(line: str) -> dict | None:
    m = HOSTKEY_RE.match(line.strip())
    if not m:
        return None
    digest = hashlib.sha256(base64.b64decode(m.group(3))).digest()
    return {"type": m.group(2), "fingerprint": "SHA256:" + base64.b64encode(digest).decode().rstrip("=")}


class Handlers:
    def __init__(self, skill: SkillBridge, keys: KeyPair):
        self.skill = skill
        self.keys = keys
        self._synced: dict[str, str] = {}  # alias -> 已同步的 server.updated_at
        self._derived: dict[str, str] = {}  # key_id -> 本次推导出的公钥（云端缺失时回报）

    def handle(self, job: dict) -> tuple[dict, dict]:
        fn = getattr(self, f"do_{job['type']}", None)
        if fn is None:
            return {"success": False, "error": f"agent 不支持的任务类型：{job['type']}"}, {}
        self._derived = {}
        try:
            out = fn(job)
        except (SkillError, RuntimeError, KeyError, ValueError) as e:
            return {"success": False, "error": str(e)}, {}
        result, extra = out if isinstance(out, tuple) else (out, {})
        if self._derived:
            extra = {**extra, "public_keys": self._derived}
        return result, extra

    # ---------- 同步 ----------

    def _password(self, server: dict) -> str | None:
        enc = server.get("password_encrypted")
        return self.keys.decrypt(enc) if enc and server.get("auth_type") == "password" else None

    def _write_key(self, key: dict) -> Path:
        """把云端密钥解密写到 ~/.ssh/ssh-manager/<name>.key（目录 700，文件 600）。"""
        if not ALIAS_RE.match(key["name"]):
            raise RuntimeError(f"非法密钥名：{key['name']}")
        data = self.keys.unseal(key["key_encrypted"])
        d = self.skill.home / ".ssh" / "ssh-manager"
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = d / f"{key['name']}.key"
        if not path.exists() or path.read_bytes() != data:
            tmp = path.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.replace(tmp, path)
        # 公钥：云端有就用云端的，没有就从私钥推导并回报给云端
        pub = key.get("public_key") or ""
        if not pub:
            pub = public_key_line(data, key["name"]) or ""
            if pub and key.get("id"):
                self._derived[key["id"]] = pub
        if pub:
            pub_path = path.with_name(path.name + ".pub")
            if not pub_path.exists() or pub_path.read_text() != pub + "\n":
                pub_path.write_text(pub + "\n")
                os.chmod(pub_path, 0o644)
        return path

    def _sync(self, server: dict) -> dict:
        if server.get("auth_type") == "key" and server.get("key"):
            server = {**server, "identity_file": str(self._write_key(server["key"]))}
        elif server.get("key_id") and not server.get("key"):
            raise RuntimeError("服务器引用的云端密钥不存在")
        r = self.skill.sync_server(server, self._password(server))
        if server.get("host_keys"):
            self._trust_host_keys(server)
        self._synced[server["alias"]] = server["updated_at"]
        return r

    def _trust_host_keys(self, server: dict) -> None:
        """把云端已确认的主机公钥写进 ~/.ssh/known_hosts（ssh-skill 严格校验主机密钥）。"""
        pattern = known_hosts_pattern(server["hostname"], server.get("port") or 22)
        lines = []
        for line in server["host_keys"]:
            m = HOSTKEY_RE.match(line.strip())
            if not m or m.group(1) != pattern:
                raise RuntimeError(f"主机公钥与服务器地址不符：{line[:60]}")
            lines.append(line.strip())
        kh = self.skill.home / ".ssh" / "known_hosts"
        existing = kh.read_text().splitlines() if kh.exists() else []
        if all(l in existing for l in lines):
            return
        if kh.exists() and shutil.which("ssh-keygen"):
            # 先删掉这个主机的旧记录（含哈希过的条目），会留下 known_hosts.old 备份
            subprocess.run(["ssh-keygen", "-R", pattern, "-f", str(kh)], capture_output=True)
            existing = kh.read_text().splitlines() if kh.exists() else []
        existing = [l for l in existing if not l.startswith(pattern + " ")]
        kh.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        kh.write_text("\n".join(existing + lines) + "\n")
        os.chmod(kh, 0o600)

    def _ensure_synced(self, job: dict) -> dict:
        server = job.get("server")
        if not server:
            raise RuntimeError("服务器已被删除")
        if self._synced.get(server["alias"]) != server["updated_at"]:
            self._sync(server)
        return server

    def do_sync(self, job):
        return {"success": True, **self._sync(self._ensure_server(job))}

    def _ensure_server(self, job):
        if not job.get("server"):
            raise RuntimeError("服务器已被删除")
        return job["server"]

    def do_sync_all(self, job):
        synced, errors = [], {}
        for s in job.get("servers") or []:
            try:
                self._sync(s)
                synced.append(s["alias"])
            except (SkillError, RuntimeError) as e:
                errors[s["alias"]] = str(e)
        return {"success": not errors, "synced": synced, "errors": errors}

    def do_remove_local(self, job):
        alias = job["payload"]["alias"]
        if not ALIAS_RE.match(alias):
            raise RuntimeError("非法别名")
        self._synced.pop(alias, None)
        return {"success": True, "removed": self.skill.remove_server(alias)}

    # ---------- 主机指纹 ----------

    def do_scan_host_key(self, job):
        s = self._ensure_server(job)
        if s.get("proxy_jump"):
            raise RuntimeError("经跳板机连接的服务器暂不支持自动获取指纹，请在跳板机上运行 ssh-keyscan 后手动确认")
        if not shutil.which("ssh-keyscan"):
            raise RuntimeError("本机没有 ssh-keyscan（OpenSSH 客户端）")
        port = int(s.get("port") or 22)
        p = subprocess.run(["ssh-keyscan", "-T", "8", "-p", str(port), "--", s["hostname"]],
                           capture_output=True, text=True, timeout=30)
        pattern = known_hosts_pattern(s["hostname"], port)
        lines = sorted({l.strip() for l in p.stdout.splitlines() if l.strip() and not l.startswith("#")})
        lines = [l for l in lines if HOSTKEY_RE.match(l) and HOSTKEY_RE.match(l).group(1) == pattern]
        if not lines:
            err = (p.stderr or "").strip().splitlines()
            raise RuntimeError("没有获取到主机公钥：" + (err[-1] if err else f"{s['hostname']}:{port} 无响应或不是 SSH 服务"))
        return {"success": True, "lines": lines, "fingerprints": [host_key_fingerprint(l) for l in lines]}

    # ---------- 远程操作 ----------

    def do_test(self, job):
        s = self._ensure_synced(job)
        return self.skill.execute(s["alias"], TEST_COMMAND, timeout=15, read_only=True)

    def do_exec(self, job):
        s = self._ensure_synced(job)
        p = job["payload"]
        timeout = max(1, min(int(p.get("timeout") or 60), 3600))
        return self.skill.execute(s["alias"], str(p["command"]), timeout=timeout, read_only=bool(p.get("read_only")))

    def do_upload(self, job):
        s = self._ensure_synced(job)
        p = job["payload"]
        return self.skill.upload(s["alias"], str(p["local_path"]), str(p["remote_path"]), bool(p.get("recursive")))

    def do_download(self, job):
        s = self._ensure_synced(job)
        p = job["payload"]
        return self.skill.download(s["alias"], str(p["remote_path"]), str(p["local_path"]), bool(p.get("recursive")))

    def do_tunnel_start(self, job):
        s = self._ensure_synced(job)
        p = job["payload"]
        local_port = int(p["local_port"]) if p.get("local_port") else None
        return self.skill.tunnel_start(s["alias"], int(p["remote_port"]), local_port, p.get("remote_host") or None)

    def do_tunnel_stop(self, job):
        return self.skill.tunnel_stop(str(job["payload"]["tunnel_id"]))

    def do_tunnel_list(self, job):
        return self.skill.tunnels()

    # ---------- 本机 -> 云端导入 ----------

    def do_local_list(self, job):
        cloud = {s["alias"] for s in job.get("servers") or []}
        hosts = []
        for h in self.skill.local_hosts():
            if h["alias"] in cloud:
                continue
            meta = h.get("metadata") or {}
            hosts.append({"alias": h["alias"], "hostname": h.get("hostname"), "user": h.get("user"),
                          "port": int(h.get("port") or 22), "description": meta.get("description", ""),
                          "has_password": bool(meta.get("password"))})  # 不回传明文密码
        return {"success": True, "hosts": hosts}

    def do_import(self, job):
        wanted = set(job["payload"].get("aliases") or [])
        upload_keys = bool(job["payload"].get("upload_keys"))
        cloud_keys = {}  # name -> 明文，用于比对去重
        for k in job.get("keys") or []:
            try:
                cloud_keys[k["name"]] = self.keys.unseal(k["key_encrypted"])
            except RuntimeError:
                cloud_keys[k["name"]] = None
        cloud = {s["alias"] for s in job.get("servers") or []}
        rows = []
        for h in self.skill.local_hosts():
            alias = h["alias"]
            if alias not in wanted or alias in cloud or not ALIAS_RE.match(alias):
                continue
            meta = h.get("metadata") or {}
            pw = meta.get("password")
            auth = "password" if pw and not h.get("identity_file") else "key"
            key = self._local_key(h.get("identity_file"), cloud_keys) if auth == "key" and upload_keys else None
            rows.append({
                "alias": alias, "hostname": h.get("hostname") or alias, "port": int(h.get("port") or 22),
                "username": h.get("user") or "root", "auth_type": auth,
                "identity_file": h.get("identity_file") if auth == "key" and not key else None,
                "key": key,
                "password_encrypted": self.keys.encrypt(pw) if pw and auth == "password" else None,
                "proxy_jump": h.get("proxy_jump"), "environment": meta.get("environment") or "development",
                "tags": meta.get("tags") or [], "location": meta.get("location", ""),
                "description": meta.get("description", ""),
            })
        return {"success": True, "requested": sorted(wanted)}, {"import_rows": rows}

    def _local_key(self, identity_file: str | None, cloud_keys: dict) -> dict | None:
        """读取本机私钥文件并加密，用于导入到云端。读不到就保留本机路径。"""
        if not identity_file:
            return None
        path = Path(os.path.expanduser(identity_file))
        if not path.is_file() or path.stat().st_size > MAX_KEY_FILE:
            return None
        data = path.read_bytes()
        if b"PRIVATE KEY" not in data or private_key_encrypted(data):
            return None  # 带口令的私钥 ssh-skill 无法非交互使用，保留本机路径、不上传
        for name, plain in cloud_keys.items():
            if plain == data:
                return {"name": name, "existing": True}
        base = re.sub(r"[^A-Za-z0-9._-]", "-", path.name)[:60] or "key"
        name, n = base, 2
        while name in cloud_keys:
            name, n = f"{base}-{n}", n + 1
        cloud_keys[name] = data  # 同一批次中其他主机引用同一文件时复用
        pub_file = path.with_name(path.name + ".pub")
        pub = pub_file.read_text().strip() if pub_file.is_file() else (public_key_line(data) or "")
        return {"name": name, "comment": f"从 {identity_file} 导入", "key_encrypted": self.keys.seal(data), "public_key": pub}
