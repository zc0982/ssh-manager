"""agent 密钥对：网页用公钥（RSA-OAEP / SHA-256）加密服务器密码，只有本机私钥能解密。"""
import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

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
