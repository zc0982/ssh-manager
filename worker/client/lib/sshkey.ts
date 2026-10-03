// 从私钥文件提取 OpenSSH 公钥（只读取公开部分，不涉及解密）。
// 支持：OpenSSH 格式（公钥以明文存在文件头里，任意算法）、RSA 的 PEM（PKCS#1 / PKCS#8）。
// 其他格式返回 null，由用户手动提供 .pub。

import { fromB64, toB64 } from "../../shared/ssh.ts";

function pemBody(text: string, label: RegExp): Uint8Array | null {
	const m = text.match(new RegExp(`-----BEGIN ${label.source}-----([\\s\\S]*?)-----END ${label.source}-----`));
	if (!m) return null;
	try {
		return fromB64(m[1].replace(/\s+/g, ""));
	} catch {
		return null;
	}
}

// ---------- OpenSSH: "openssh-key-v1\0" + string cipher + string kdf + string kdfopts + uint32 n + string pubkey ----------

function readString(buf: Uint8Array, off: number): [Uint8Array, number] {
	const len = new DataView(buf.buffer, buf.byteOffset).getUint32(off);
	if (off + 4 + len > buf.length) throw new Error("越界");
	return [buf.subarray(off + 4, off + 4 + len), off + 4 + len];
}

/** 解析 OpenSSH 私钥文件头：公钥（明文）和是否加了口令（cipher 不是 none） */
function opensshInfo(buf: Uint8Array): { publicKey: string; encrypted: boolean } | null {
	const magic = new TextEncoder().encode("openssh-key-v1\0");
	if (!magic.every((b, i) => buf[i] === b)) return null;
	let off = magic.length;
	let cipher: Uint8Array;
	[cipher, off] = readString(buf, off);
	[, off] = readString(buf, off); // kdf
	[, off] = readString(buf, off); // kdf options
	off += 4; // 密钥数量
	const [blob] = readString(buf, off);
	const [type] = readString(blob, 0);
	return { publicKey: `${new TextDecoder().decode(type)} ${toB64(blob)}`, encrypted: new TextDecoder().decode(cipher) !== "none" };
}

// ---------- RSA PEM：最小 DER 解析 ----------

function derItem(buf: Uint8Array, off: number): { tag: number; start: number; end: number } {
	const tag = buf[off];
	let len = buf[off + 1];
	let start = off + 2;
	if (len & 0x80) {
		const n = len & 0x7f;
		len = 0;
		for (let i = 0; i < n; i++) len = len * 256 + buf[start + i];
		start += n;
	}
	if (start + len > buf.length) throw new Error("越界");
	return { tag, start, end: start + len };
}

function derChildren(buf: Uint8Array, start: number, end: number) {
	const out: { tag: number; start: number; end: number }[] = [];
	for (let off = start; off < end; ) {
		const it = derItem(buf, off);
		out.push(it);
		off = it.end;
	}
	return out;
}

/** RSAPrivateKey ::= SEQUENCE { version, n, e, ... } */
function rsaFromPkcs1(der: Uint8Array): string | null {
	const seq = derItem(der, 0);
	const [, n, e] = derChildren(der, seq.start, seq.end);
	if (!n || !e || n.tag !== 2 || e.tag !== 2) return null;
	return sshRsa(der.subarray(e.start, e.end), der.subarray(n.start, n.end));
}

/** PrivateKeyInfo ::= SEQUENCE { version, AlgorithmIdentifier, OCTET STRING privateKey } */
function rsaFromPkcs8(der: Uint8Array): string | null {
	const seq = derItem(der, 0);
	const [, alg, key] = derChildren(der, seq.start, seq.end);
	if (!alg || !key || key.tag !== 4) return null;
	const [oid] = derChildren(der, alg.start, alg.end);
	const rsaOid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]; // 1.2.840.113549.1.1.1
	const got = der.subarray(oid.start, oid.end);
	if (got.length !== rsaOid.length || !rsaOid.every((b, i) => got[i] === b)) return null;
	return rsaFromPkcs1(der.subarray(key.start, key.end));
}

function sshString(data: Uint8Array) {
	const out = new Uint8Array(4 + data.length);
	new DataView(out.buffer).setUint32(0, data.length);
	out.set(data, 4);
	return out;
}

/** mpint：去掉多余前导 0，最高位为 1 时补一个 0 */
function mpint(int: Uint8Array) {
	let i = 0;
	while (i < int.length - 1 && int[i] === 0) i++;
	let v = int.subarray(i);
	if (v[0] & 0x80) v = Uint8Array.from([0, ...v]);
	return sshString(v);
}

function sshRsa(e: Uint8Array, n: Uint8Array) {
	const parts = [sshString(new TextEncoder().encode("ssh-rsa")), mpint(e), mpint(n)];
	const blob = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
	let off = 0;
	for (const p of parts) { blob.set(p, off); off += p.length; }
	return `ssh-rsa ${toB64(blob)}`;
}

export type PrivateKeyInfo = { publicKey: string | null; encrypted: boolean };

/** 检查私钥文件：提取公钥行（不含注释，无法识别时为 null），并判断是否加了口令 */
export function inspectPrivateKey(privateKey: string): PrivateKeyInfo {
	if (/Proc-Type: 4,ENCRYPTED|BEGIN ENCRYPTED PRIVATE KEY/.test(privateKey)) return { publicKey: null, encrypted: true };
	try {
		const openssh = pemBody(privateKey, /OPENSSH PRIVATE KEY/);
		if (openssh) return opensshInfo(openssh) ?? { publicKey: null, encrypted: false };
		const pkcs1 = pemBody(privateKey, /RSA PRIVATE KEY/);
		if (pkcs1) return { publicKey: rsaFromPkcs1(pkcs1), encrypted: false };
		const pkcs8 = pemBody(privateKey, /PRIVATE KEY/);
		if (pkcs8) return { publicKey: rsaFromPkcs8(pkcs8), encrypted: false };
	} catch {
		// 格式不认识
	}
	return { publicKey: null, encrypted: false };
}

/** 从私钥文件内容提取公钥行（不含注释）；无法识别时返回 null */
export const derivePublicKey = (privateKey: string) => inspectPrivateKey(privateKey).publicKey;
