"""agent 密钥对：网页用公钥（RSA-OAEP / SHA-256）加密服务器密码，只有本机私钥能解密。"""
import base64
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def _b64url_uint(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class KeyPair:
    def __init__(self, private_key: rsa.RSAPrivateKey):
        self._key = private_key

    @classmethod
    def load_or_create(cls, path: Path) -> "KeyPair":
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, rsa.RSAPrivateKey):
                raise RuntimeError(f"{path} 不是 RSA 私钥")
            return cls(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        return cls(key)

    @property
    def public_jwk(self) -> dict:
        nums = self._key.public_key().public_numbers()
        return {"kty": "RSA", "alg": "RSA-OAEP-256", "ext": True, "key_ops": ["encrypt"],
                "n": _b64url_uint(nums.n), "e": _b64url_uint(nums.e)}

    def matches(self, jwk: dict | None) -> bool:
        return bool(jwk) and jwk.get("n") == self.public_jwk["n"] and jwk.get("e") == self.public_jwk["e"]

    def encrypt(self, plain: str) -> str:
        return base64.b64encode(self._key.public_key().encrypt(plain.encode(), OAEP)).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self._key.decrypt(base64.b64decode(token), OAEP).decode()
        except Exception as e:
            raise RuntimeError("密码解密失败：密文不是用本 agent 的公钥加密的") from e

    # ---------- 大数据（SSH 私钥）：AES-256-GCM + RSA-OAEP 包裹 AES 密钥 ----------

    def seal(self, data: bytes) -> str:
        aes_key, iv = os.urandom(32), os.urandom(12)
        ct = AESGCM(aes_key).encrypt(iv, data, None)
        wrapped = self._key.public_key().encrypt(aes_key, OAEP)
        return "v1." + ".".join(base64.b64encode(x).decode() for x in (wrapped, iv, ct))

    def unseal(self, token: str) -> bytes:
        try:
            version, wrapped, iv, ct = token.split(".")
            assert version == "v1"
            aes_key = self._key.decrypt(base64.b64decode(wrapped), OAEP)
            return AESGCM(aes_key).decrypt(base64.b64decode(iv), base64.b64decode(ct), None)
        except Exception as e:
            raise RuntimeError("密钥解密失败：密文损坏或不是用本 agent 的公钥加密的") from e

    # ---------- agent 私钥的云端备份：主密码 -> scrypt -> AES-256-GCM ----------

    def private_pem(self) -> bytes:
        return self._key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption())

    def export_backup(self, passphrase: str) -> dict:
        salt, nonce = os.urandom(16), os.urandom(12)
        params = {"n": 2 ** 17, "r": 8, "p": 1}
        key = Scrypt(salt=salt, length=32, **params).derive(passphrase.encode())
        ct = AESGCM(key).encrypt(nonce, self.private_pem(), b"ssh-manager-agent-key")
        b64 = lambda b: base64.b64encode(b).decode()
        return {"v": 1, "kdf": "scrypt", **params, "salt": b64(salt), "nonce": b64(nonce), "ciphertext": b64(ct),
                "public_n": self.public_jwk["n"]}

    @staticmethod
    def restore_backup(backup: dict, passphrase: str, path: Path) -> "KeyPair":
        if backup.get("v") != 1 or backup.get("kdf") != "scrypt":
            raise RuntimeError("不支持的备份格式")
        d = lambda k: base64.b64decode(backup[k])
        key = Scrypt(salt=d("salt"), length=32, n=backup["n"], r=backup["r"], p=backup["p"]).derive(passphrase.encode())
        try:
            pem = AESGCM(key).decrypt(d("nonce"), d("ciphertext"), b"ssh-manager-agent-key")
        except InvalidTag as e:
            raise RuntimeError("主密码错误") from e
        if path.exists():
            raise RuntimeError(f"{path} 已存在，为避免覆盖请先移走")
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        return KeyPair.load_or_create(path)
