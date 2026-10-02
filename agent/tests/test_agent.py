import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ssh_agent.handlers import Handlers
from ssh_agent.keys import KeyPair
from ssh_agent.skill import SkillBridge

SKILL_DIR = Path.home() / ".claude" / "skills" / "ssh-skill"


@pytest.fixture
def env(tmp_path: Path):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    cfg = home / ".ssh" / "config"
    cfg.write_text("# ===== existing =====\n# description: 已有主机\n# password: oldpw\n"
                   "Host existing\n    HostName 10.0.0.9\n    User admin\n\n")
    keys = KeyPair.load_or_create(tmp_path / "key.pem")
    return Handlers(SkillBridge(SKILL_DIR, home=home), keys), keys, cfg


def server(**kw):
    base = {"id": "s1", "alias": "web-01", "hostname": "192.168.1.10", "port": 2222, "username": "deploy",
            "auth_type": "key", "identity_file": None, "password_encrypted": None, "proxy_jump": None,
            "environment": "production", "tags": ["web", "nginx"], "location": "", "description": "测试 Web",
            "updated_at": datetime.now(timezone.utc).isoformat()}
    return {**base, **kw}


def test_key_file_permissions_and_roundtrip(tmp_path):
    k = KeyPair.load_or_create(tmp_path / "k.pem")
    assert oct((tmp_path / "k.pem").stat().st_mode & 0o777) == "0o600"
    assert k.decrypt(k.encrypt("p@ss 中文")) == "p@ss 中文"
    assert KeyPair.load_or_create(tmp_path / "k.pem").matches(k.public_jwk)  # 重新加载是同一把钥匙


@pytest.mark.skipif(not shutil.which("node"), reason="需要 node")
def test_webcrypto_ciphertext_decrypts(tmp_path):
    """浏览器端用 WebCrypto RSA-OAEP(SHA-256) 加密，agent 必须能解密。"""
    k = KeyPair.load_or_create(tmp_path / "k.pem")
    script = """
const jwk = JSON.parse(process.argv[1]);
const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
const buf = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, key, new TextEncoder().encode("s3cret!密码"));
console.log(Buffer.from(buf).toString("base64"));
"""
    out = subprocess.run(["node", "--input-type=module", "-e", script, json.dumps(k.public_jwk)],
                         capture_output=True, text=True, check=True).stdout.strip()
    assert k.decrypt(out) == "s3cret!密码"


def test_sync_password_key_switch_and_remove(env):
    h, keys, cfg = env
    s = server(auth_type="password", password_encrypted=keys.encrypt("s3cret!"))
    r, _ = h.handle({"type": "sync", "server": s, "payload": {}})
    assert r["success"] and r["action"] == "created", r
    text = cfg.read_text()
    assert "Host web-01" in text and "Port 2222" in text and "# password: s3cret!" in text and "# tags: web,nginx" in text
    assert "# password: oldpw" in text  # 已有主机不受影响

    s2 = server(identity_file="~/.ssh/id_ed25519", updated_at="later")
    r, _ = h.handle({"type": "sync", "server": s2, "payload": {}})
    assert r["success"] and r["action"] == "updated"
    text = cfg.read_text()
    assert "s3cret!" not in text and "id_ed25519" in text

    s3 = server(auth_type="password", password_encrypted=keys.encrypt("pw2"), tags=[], updated_at="later2")
    assert h.handle({"type": "sync", "server": s3, "payload": {}})[0]["success"]
    text = cfg.read_text()
    assert "id_ed25519" not in text and "# tags:" not in text.split("Host existing")[1] and "# password: pw2" in text
    assert text.count("Host web-01") == 1

    r, _ = h.handle({"type": "remove_local", "payload": {"alias": "web-01"}})
    assert r == {"success": True, "removed": True}
    assert "Host web-01" not in cfg.read_text() and "Host existing" in cfg.read_text()
    assert (cfg.parent / "config.ssh-manager.bak").exists()


def test_wrong_key_ciphertext_fails_cleanly(env, tmp_path):
    h, _, _ = env
    other = KeyPair.load_or_create(tmp_path / "other.pem")
    r, _ = h.handle({"type": "sync", "server": server(auth_type="password", password_encrypted=other.encrypt("x")), "payload": {}})
    assert r["success"] is False and "解密失败" in r["error"]


def test_local_list_and_import(env):
    h, keys, _ = env
    r, _ = h.handle({"type": "local_list", "servers": [], "payload": {}})
    assert [x["alias"] for x in r["hosts"]] == ["existing"] and r["hosts"][0]["has_password"]
    assert "oldpw" not in json.dumps(r)

    r, extra = h.handle({"type": "import", "servers": [], "payload": {"aliases": ["existing"]}})
    row = extra["import_rows"][0]
    assert row["auth_type"] == "password" and row["hostname"] == "10.0.0.9"
    assert keys.decrypt(row["password_encrypted"]) == "oldpw"

    r, _ = h.handle({"type": "local_list", "servers": [{"alias": "existing"}], "payload": {}})
    assert r["hosts"] == []


def test_exec_unreachable_and_unknown_type(env):
    h, _, _ = env
    r, _ = h.handle({"type": "exec", "server": server(alias="dead", hostname="127.0.0.1", port=1),
                     "payload": {"command": "echo hi", "timeout": 5}})
    assert r["success"] is False
    assert h.handle({"type": "rm_rf", "payload": {}})[0]["success"] is False
    assert h.handle({"type": "exec", "server": None, "payload": {"command": "x"}})[0]["error"] == "服务器已被删除"


def test_postgres_array_literal_tags(env):
    h, _, cfg = env
    assert h.handle({"type": "sync", "server": server(tags="{e2e,web}"), "payload": {}})[0]["success"]
    assert "# tags: e2e,web" in cfg.read_text()
