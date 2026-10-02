// 新电脑同步：浏览器里用主密码解开 agent 私钥，再解密服务器密码和 SSH 私钥，
// 生成一段同步脚本（复制到剪贴板，在终端用 `pbpaste | bash` 运行）。
// 浏览器不能直接写 ~/.ssh（Chromium 的 File System Access 明确禁止），所以需要这一步终端命令。
import { scryptAsync } from "@noble/hashes/scrypt.js";

export type Backup = { v: number; kdf: string; n: number; r: number; p: number; salt: string; nonce: string; ciphertext: string };
export type ExportServer = {
	alias: string; hostname: string; port: number; username: string; auth_type: "key" | "password";
	identity_file: string | null; key_id: string | null; password_encrypted: string | null; proxy_jump: string | null;
	environment: string; tags: string[]; location: string; description: string; created_at: string; updated_at: string;
};
export type ExportKey = { id: string; name: string; key_encrypted: string };

const AAD = { 1: "ssh-manager-agent-key", 2: "ssh-manager-bundle-v2" } as Record<number, string>;
const ALIAS_RE = /^[A-Za-z0-9._-]+$/;
const enc = new TextEncoder();
const dec = new TextDecoder();

const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const toB64 = (b: Uint8Array) => {
	let s = "";
	for (const x of b) s += String.fromCharCode(x);
	return btoa(s);
};

/** 用主密码解开备份，得到 agent 私钥（WebCrypto RSA-OAEP 解密用） */
export async function unlockAgentKey(backup: Backup, passphrase: string): Promise<CryptoKey> {
	if (backup.kdf !== "scrypt" || !AAD[backup.v]) throw new Error("不支持的备份格式");
	const key = await scryptAsync(enc.encode(passphrase), fromB64(backup.salt), { N: backup.n, r: backup.r, p: backup.p, dkLen: 32, maxmem: 2 ** 29 });
	const aes = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
	let plain: Uint8Array;
	try {
		plain = new Uint8Array(await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: fromB64(backup.nonce), additionalData: enc.encode(AAD[backup.v]) }, aes, fromB64(backup.ciphertext)));
	} catch {
		throw new Error("主密码错误");
	}
	const pem = backup.v === 1 ? dec.decode(plain) : JSON.parse(dec.decode(plain)).private_pem as string;
	const der = fromB64(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
	return crypto.subtle.importKey("pkcs8", der, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
}

async function decryptPassword(priv: CryptoKey, token: string) {
	return dec.decode(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, fromB64(token)));
}

async function unseal(priv: CryptoKey, token: string): Promise<Uint8Array> {
	const [v, wrapped, iv, ct] = token.split(".");
	if (v !== "v1") throw new Error("不支持的密钥格式");
	const raw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, fromB64(wrapped));
	const aes = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
	return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv) }, aes, fromB64(ct)));
}

const oneLine = (s: string) => s.replace(/[\r\n]+/g, " ").trim();
const fmtTime = (t: string) => new Date(t).toISOString().replace("T", " ").slice(0, 19);

/** 生成与 ssh-skill（ssh_config_manager_v3）一致的注释元数据 + Host 块 */
function hostBlock(s: ExportServer, password: string | null, identityFile: string | null) {
	const meta = [
		`# ===== ${s.alias} =====`,
		s.description && `# description: ${oneLine(s.description)}`,
		s.environment && `# environment: ${s.environment}`,
		s.tags.length > 0 && `# tags: ${s.tags.join(",")}`,
		s.location && `# location: ${oneLine(s.location)}`,
		`# created_at: ${fmtTime(s.created_at)}`,
		`# updated_at: ${fmtTime(s.updated_at)}`,
		password && `# password: ${password}`,
	].filter(Boolean);
	const cfg = [
		`Host ${s.alias}`,
		`    HostName ${s.hostname}`,
		`    User ${s.username}`,
		s.port !== 22 && `    Port ${s.port}`,
		identityFile && `    IdentityFile ${identityFile}`,
		s.proxy_jump && `    ProxyJump ${s.proxy_jump}`,
	].filter(Boolean);
	return [...meta, ...cfg].join("\n");
}

/** 选一个不会出现在内容里的 heredoc 结束标记 */
function delimiter(content: string) {
	let d: string;
	do d = `SSHM_${toB64(crypto.getRandomValues(new Uint8Array(9))).replace(/[^A-Za-z0-9]/g, "")}`;
	while (content.includes(d));
	return d;
}

export type SyncResult = { script: string; servers: number; keyFiles: number; skipped: string[] };

/** 解密全部服务器与密钥，生成同步脚本 */
export async function buildSyncScript(priv: CryptoKey, servers: ExportServer[], keys: ExportKey[]): Promise<SyncResult> {
	const keyById = new Map(keys.map((k) => [k.id, k]));
	const usedKeys = new Map<string, Uint8Array>();
	const blocks: string[] = [];
	const aliases: string[] = [];
	const skipped: string[] = [];

	for (const s of servers) {
		if (!ALIAS_RE.test(s.alias)) { skipped.push(`${s.alias}（别名不合法）`); continue; }
		let password: string | null = null;
		let identity: string | null = null;
		if (s.auth_type === "password" && s.password_encrypted) {
			password = await decryptPassword(priv, s.password_encrypted);
			if (/[\r\n]/.test(password)) { skipped.push(`${s.alias}（密码含换行）`); continue; }
		}
		if (s.auth_type === "key") {
			const k = s.key_id ? keyById.get(s.key_id) : null;
			if (s.key_id && !k) { skipped.push(`${s.alias}（云端密钥缺失）`); continue; }
			if (k) {
				if (!ALIAS_RE.test(k.name)) { skipped.push(`${s.alias}（密钥名不合法）`); continue; }
				if (!usedKeys.has(k.name)) usedKeys.set(k.name, await unseal(priv, k.key_encrypted));
				identity = `~/.ssh/ssh-manager/${k.name}.key`;
			} else {
				identity = s.identity_file;
			}
		}
		aliases.push(s.alias);
		blocks.push(hostBlock(s, password, identity));
	}

	const keyCmds = [...usedKeys].map(([name, data]) => {
		const b64 = toB64(data).replace(/(.{76})/g, "$1\n");
		const d = delimiter(b64);
		return `base64 -d > "$KEYDIR/${name}.key" <<'${d}'\n${b64}\n${d}\nchmod 600 "$KEYDIR/${name}.key"`;
	});
	const cfgText = blocks.join("\n\n");
	const cd = delimiter(cfgText);

	const script = `#!/usr/bin/env bash
# SSH Manager：把云端的服务器、密码和私钥同步到本机 ~/.ssh（由网页生成，运行后会清空剪贴板）
set -euo pipefail
umask 077
SSH="$HOME/.ssh"; CFG="$SSH/config"; KEYDIR="$SSH/ssh-manager"
mkdir -p "$SSH" "$KEYDIR"; chmod 700 "$SSH" "$KEYDIR"
touch "$CFG"
cp "$CFG" "$CFG.ssh-manager.bak"
${keyCmds.join("\n")}
# 先移除同名的旧条目（只删 "# ===== 别名 =====" 起的元数据和 Host 块），再追加新条目
awk -v list="${aliases.join(" ")}" '
BEGIN { n = split(list, a, " "); for (i = 1; i <= n; i++) want[a[i]] = 1 }
function flush() { for (i = 1; i <= nb; i++) print buf[i]; nb = 0 }
{
  if (skip) { if ($0 ~ /^[ \\t]/ || $0 ~ /^[ \\t]*$/) next; skip = 0 }
  if ($0 ~ /^[ \\t]*#/ || $0 ~ /^[ \\t]*$/) { buf[++nb] = $0; next }
  if ($1 == "Host" && NF == 2 && ($2 in want)) {
    cut = 0
    for (i = nb; i >= 1; i--) if (buf[i] == "# ===== " $2 " =====") { cut = i; break }
    if (cut) nb = cut - 1
    flush(); skip = 1; next
  }
  flush(); print
}
END { flush() }' "$CFG.ssh-manager.bak" > "$CFG.tmp"
# 原有内容末尾统一留一个空行，再追加
if [ -s "$CFG.tmp" ]; then printf '%s\\n\\n' "$(cat "$CFG.tmp")" > "$CFG.tmp2" && mv "$CFG.tmp2" "$CFG.tmp"; fi
cat >> "$CFG.tmp" <<'${cd}'
${cfgText}
${cd}
mv "$CFG.tmp" "$CFG"; chmod 600 "$CFG"
command -v pbcopy >/dev/null 2>&1 && pbcopy </dev/null || true
echo "SSH Manager：已同步 ${aliases.length} 台服务器、${usedKeys.size} 个私钥到 ~/.ssh（原配置备份为 ~/.ssh/config.ssh-manager.bak）"
`;
	return { script, servers: aliases.length, keyFiles: usedKeys.size, skipped };
}
