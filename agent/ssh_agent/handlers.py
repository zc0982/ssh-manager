"""任务处理：每种任务类型对应一个函数，返回 (result, extra)，extra 会合并进回传给 Worker 的请求体。"""
from .keys import KeyPair
from .skill import ALIAS_RE, SkillBridge, SkillError

TEST_COMMAND = "hostname && uptime && (uname -sr || true)"


class Handlers:
    def __init__(self, skill: SkillBridge, keys: KeyPair):
        self.skill = skill
        self.keys = keys
        self._synced: dict[str, str] = {}  # alias -> 已同步的 server.updated_at

    def handle(self, job: dict) -> tuple[dict, dict]:
        fn = getattr(self, f"do_{job['type']}", None)
        if fn is None:
            return {"success": False, "error": f"agent 不支持的任务类型：{job['type']}"}, {}
        try:
            out = fn(job)
        except (SkillError, RuntimeError, KeyError, ValueError) as e:
            return {"success": False, "error": str(e)}, {}
        return out if isinstance(out, tuple) else (out, {})

    # ---------- 同步 ----------

    def _password(self, server: dict) -> str | None:
        enc = server.get("password_encrypted")
        return self.keys.decrypt(enc) if enc and server.get("auth_type") == "password" else None

    def _sync(self, server: dict) -> dict:
        r = self.skill.sync_server(server, self._password(server))
        self._synced[server["alias"]] = server["updated_at"]
        return r

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
        cloud = {s["alias"] for s in job.get("servers") or []}
        rows = []
        for h in self.skill.local_hosts():
            alias = h["alias"]
            if alias not in wanted or alias in cloud or not ALIAS_RE.match(alias):
                continue
            meta = h.get("metadata") or {}
            pw = meta.get("password")
            auth = "password" if pw and not h.get("identity_file") else "key"
            rows.append({
                "alias": alias, "hostname": h.get("hostname") or alias, "port": int(h.get("port") or 22),
                "username": h.get("user") or "root", "auth_type": auth,
                "identity_file": h.get("identity_file") if auth == "key" else None,
                "password_encrypted": self.keys.encrypt(pw) if pw and auth == "password" else None,
                "proxy_jump": h.get("proxy_jump"), "environment": meta.get("environment") or "development",
                "tags": meta.get("tags") or [], "location": meta.get("location", ""),
                "description": meta.get("description", ""),
            })
        return {"success": True, "requested": sorted(wanted)}, {"import_rows": rows}
