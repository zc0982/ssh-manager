// Worker 与浏览器共用的 SSH 相关工具（主机公钥 / 公钥格式、指纹、base64）。

export const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export const toB64 = (b: ArrayBuffer | Uint8Array) => {
	let s = "";
	for (const x of new Uint8Array(b)) s += String.fromCharCode(x);
	return btoa(s);
};

/** 允许出现在 known_hosts 主机写法里的字符（会被放进生成脚本的单引号里，必须足够严格） */
export const SAFE_HOST_RE = /^[A-Za-z0-9.:_-]+$/;

/** known_hosts 行：主机 类型 base64。主机、类型都只允许安全字符，避免生成脚本时跳出引号 */
export const HOSTKEY_RE = /^(\[[A-Za-z0-9.:_-]+\]:\d{1,5}|[A-Za-z0-9.:_-]+) ([a-z0-9@.-]+) ([A-Za-z0-9+/]+={0,2})$/;

/** OpenSSH 公钥行：类型 base64 [注释]；注释不允许引号和换行 */
export const PUBKEY_RE = /^([a-z0-9@.-]+) ([A-Za-z0-9+/]+={0,2})(?: ([^\r\n'"]*))?$/;

/** known_hosts 里的主机写法：22 端口直接写主机名，其他端口写 [主机]:端口 */
export const knownHostsPattern = (hostname: string, port: number) => (port === 22 ? hostname : `[${hostname}]:${port}`);

/** SSH 公钥 blob 的 SHA256 指纹（与 ssh-keygen -l 相同） */
export async function fingerprint(blob: Uint8Array<ArrayBuffer>): Promise<string> {
	const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", blob));
	return "SHA256:" + toB64(hash).replace(/=+$/, "");
}

/** 读取 blob 开头的类型字符串（uint32 长度 + 内容）；格式不对返回空串 */
export function blobType(blob: Uint8Array): string {
	if (blob.length < 4) return "";
	const len = new DataView(blob.buffer, blob.byteOffset).getUint32(0);
	return len > 0 && len + 4 <= blob.length ? new TextDecoder().decode(blob.subarray(4, 4 + len)) : "";
}

export type HostKey = { type: string; fingerprint: string; line: string };

/** 解析并校验一行 known_hosts（类型须与 blob 一致）；无效返回 null */
export async function parseHostKey(line: string): Promise<HostKey | null> {
	const m = line.trim().match(HOSTKEY_RE);
	if (!m) return null;
	let blob: Uint8Array<ArrayBuffer>;
	try {
		blob = fromB64(m[3]);
	} catch {
		return null;
	}
	if (blobType(blob) !== m[2]) return null;
	return { type: m[2], fingerprint: await fingerprint(blob), line: line.trim() };
}
