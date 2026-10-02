// 浏览器端加密：只有本机 agent 持有对应私钥，Worker 和数据库只能看到密文。

const b64 = (buf: ArrayBuffer | Uint8Array) => {
	let s = "";
	for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
	return btoa(s);
};

let cached: { jwk: string; key: CryptoKey } | null = null;

async function agentKey(jwk: JsonWebKey | null): Promise<CryptoKey> {
	if (!jwk) throw new Error("本机 agent 尚未注册公钥，请先启动 agent");
	const id = JSON.stringify(jwk);
	if (cached?.jwk !== id) {
		const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
		cached = { jwk: id, key };
	}
	return cached.key;
}

/** 密码：RSA-OAEP(SHA-256) 直接加密 */
export async function encryptPassword(jwk: JsonWebKey | null, plain: string): Promise<string> {
	return b64(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, await agentKey(jwk), new TextEncoder().encode(plain)));
}

/** 大数据（SSH 私钥）：随机 AES-256-GCM 密钥加密内容，再用 agent 公钥包裹 AES 密钥 */
export async function sealData(jwk: JsonWebKey | null, bytes: Uint8Array<ArrayBuffer>): Promise<string> {
	const aes = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aes, bytes);
	const raw = await crypto.subtle.exportKey("raw", aes);
	const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, await agentKey(jwk), raw);
	return `v1.${b64(wrapped)}.${b64(iv)}.${b64(ct)}`;
}
