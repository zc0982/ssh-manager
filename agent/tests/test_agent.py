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


FAKE_KEY = b"-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZS1rZXktZm9yLXRlc3Rz\n-----END OPENSSH PRIVATE KEY-----\n"


def test_seal_roundtrip_and_tamper(tmp_path):
    k = KeyPair.load_or_create(tmp_path / "k.pem")
    token = k.seal(FAKE_KEY)
    assert token.startswith("v1.") and k.unseal(token) == FAKE_KEY
    v, w, iv, ct = token.split(".")
    bad = ".".join([v, w, iv, ("A" if ct[0] != "A" else "B") + ct[1:]])
    with pytest.raises(RuntimeError):
        k.unseal(bad)


@pytest.mark.skipif(not shutil.which("node"), reason="需要 node")
def test_webcrypto_sealed_key_unseals(tmp_path):
    """与 client/app.js 的 sealData 相同的 WebCrypto 流程。"""
    k = KeyPair.load_or_create(tmp_path / "k.pem")
    script = """
const b64 = (buf) => Buffer.from(buf).toString("base64");
const jwk = JSON.parse(process.argv[1]);
const pub = await crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
const aes = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
const iv = crypto.getRandomValues(new Uint8Array(12));
const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aes, new TextEncoder().encode(process.argv[2]));
const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, await crypto.subtle.exportKey("raw", aes));
console.log(`v1.${b64(wrapped)}.${b64(iv)}.${b64(ct)}`);
"""
    out = subprocess.run(["node", "--input-type=module", "-e", script, json.dumps(k.public_jwk), FAKE_KEY.decode()],
                         capture_output=True, text=True, check=True).stdout.strip()
    assert k.unseal(out) == FAKE_KEY


def test_agent_key_backup_restore(tmp_path):
    k = KeyPair.load_or_create(tmp_path / "k.pem")
    backup = k.export_backup("correct horse battery")
    assert "PRIVATE" not in json.dumps(backup) and backup["public_n"] == k.public_jwk["n"]
    with pytest.raises(RuntimeError, match="主密码错误"):
        KeyPair.restore_backup(backup, "wrong passphrase!", tmp_path / "r1.pem")
    restored = KeyPair.restore_backup(backup, "correct horse battery", tmp_path / "r2.pem")
    assert restored.matches(k.public_jwk)
    assert oct((tmp_path / "r2.pem").stat().st_mode & 0o777) == "0o600"
    assert restored.decrypt(k.encrypt("x")) == "x"
    with pytest.raises(RuntimeError, match="已存在"):
        KeyPair.restore_backup(backup, "correct horse battery", tmp_path / "r2.pem")


def test_sync_with_cloud_key_writes_identity_file(env):
    h, keys, cfg = env
    s = server(key_id="k1", key={"id": "k1", "name": "deploy", "key_encrypted": keys.seal(FAKE_KEY)})
    r, _ = h.handle({"type": "sync", "server": s, "payload": {}})
    assert r["success"], r
    path = h.skill.home / ".ssh" / "ssh-manager" / "deploy.key"
    assert path.read_bytes() == FAKE_KEY
    assert oct(path.stat().st_mode & 0o777) == "0o600" and oct(path.parent.stat().st_mode & 0o777) == "0o700"
    assert f"IdentityFile {path}" in cfg.read_text()
    # 引用了密钥但密钥行缺失（被删除）时明确报错
    r, _ = h.handle({"type": "sync", "server": server(key_id="gone", updated_at="x"), "payload": {}})
    assert r["success"] is False and "云端密钥不存在" in r["error"]


def test_import_uploads_and_dedupes_keys(env):
    h, keys, cfg = env
    keyfile = h.skill.home / ".ssh" / "id_test"
    keyfile.write_bytes(FAKE_KEY)
    with cfg.open("a") as f:
        f.write(f"Host a1\n    HostName 10.0.0.1\n    User u\n    IdentityFile {keyfile}\n\n"
                f"Host a2\n    HostName 10.0.0.2\n    User u\n    IdentityFile {keyfile}\n\n")
    # 云端已有一把同名但内容不同的 id_test
    cloud = [{"name": "id_test", "key_encrypted": keys.seal(b"-----BEGIN OPENSSH PRIVATE KEY-----\nother\n")}]
    _, extra = h.handle({"type": "import", "servers": [], "keys": cloud, "payload": {"aliases": ["a1", "a2"], "upload_keys": True}})
    rows = {r["alias"]: r for r in extra["import_rows"]}
    assert rows["a1"]["key"]["name"] == "id_test-2" and keys.unseal(rows["a1"]["key"]["key_encrypted"]) == FAKE_KEY
    assert rows["a1"]["identity_file"] is None
    assert rows["a2"]["key"] == {"name": "id_test-2", "existing": True}  # 同批次复用
    # 云端已有同内容的密钥时直接复用
    cloud2 = [{"name": "mine", "key_encrypted": keys.seal(FAKE_KEY)}]
    _, extra = h.handle({"type": "import", "servers": [], "keys": cloud2, "payload": {"aliases": ["a1"], "upload_keys": True}})
    assert extra["import_rows"][0]["key"] == {"name": "mine", "existing": True}
    # 不勾选上传时保留本机路径
    _, extra = h.handle({"type": "import", "servers": [], "keys": [], "payload": {"aliases": ["a1"]}})
    assert extra["import_rows"][0]["key"] is None and extra["import_rows"][0]["identity_file"]
