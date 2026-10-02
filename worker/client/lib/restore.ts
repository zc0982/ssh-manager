// 新电脑同步：浏览器里用主密码解开 agent 私钥，再解密服务器密码和 SSH 私钥，
// 生成一段同步脚本（复制到剪贴板，在终端用 `pbpaste | bash` 运行）。
// 浏览器不能直接写 ~/.ssh（Chromium 的 File System Access 明确禁止），所以需要这一步终端命令。
import { scryptAsync } from "@noble/hashes/scrypt.js";

export type Backup = { v: number; kdf: string; n: number; r: number; p: number; salt: string; nonce: string; ciphertext: string };
export type ExportServer = {
	alias: string; hostname: string; port: number; username: string; auth_type: "key" | "password";
	identity_file: string | null; key_id: string | null; password_encrypted: string | null; proxy_jump: string | null;
	environment: string; tags: string[]; location: string; description: string; created_at: string; updated_at: string;
	host_keys?: string[];
};
export type ExportKey = { id: string; name: string; key_encrypted: string; public_key?: string };

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

export type Platform = "posix" | "windows";
export type SyncResult = { script: string; servers: number; keyFiles: number; skipped: string[]; platform: Platform };

type Prepared = { blocks: string[]; aliases: string[]; keys: Map<string, Uint8Array>; pubs: Map<string, string>; hostKeys: Map<string, string[]>; skipped: string[] };

const HOSTKEY_RE = /^(\S+) ((?:ssh-|ecdsa-|sk-)\S+) ([A-Za-z0-9+/]+={0,2})$/;

/** 解密全部服务器与密钥，生成 ssh-skill 格式的配置块 */
async function prepare(priv: CryptoKey, servers: ExportServer[], keys: ExportKey[]): Promise<Prepared> {
	const keyById = new Map(keys.map((k) => [k.id, k]));
	const used = new Map<string, Uint8Array>();
	const pubs = new Map<string, string>();
	const hostKeys = new Map<string, string[]>(); // known_hosts 主机写法 -> 已信任的主机公钥行
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
				if (!used.has(k.name)) used.set(k.name, await unseal(priv, k.key_encrypted));
				if (k.public_key && /^[a-z0-9@.-]+ [A-Za-z0-9+/=]+( [^\r\n'"]*)?$/.test(k.public_key)) pubs.set(k.name, k.public_key);
				identity = `~/.ssh/ssh-manager/${k.name}.key`; // Windows 版 OpenSSH 同样支持 ~
			} else {
				identity = s.identity_file;
			}
		}
		aliases.push(s.alias);
		blocks.push(hostBlock(s, password, identity));
		const pattern = s.port === 22 ? s.hostname : `[${s.hostname}]:${s.port}`;
		// 主机名会放进脚本的单引号里，只接受安全字符
		const lines = /^[A-Za-z0-9.:_-]+$/.test(s.hostname) ? (s.host_keys ?? []).filter((l) => HOSTKEY_RE.exec(l)?.[1] === pattern) : [];
		if (lines.length) hostKeys.set(pattern, lines);
	}
	return { blocks, aliases, keys: used, pubs, hostKeys, skipped };
}

const doneMsg = (p: Prepared, where: string) =>
	`SSH Manager：已同步 ${p.aliases.length} 台服务器、${p.keys.size} 个私钥到 ${where}（原配置备份为 config.ssh-manager.bak）`;

/** 已信任的主机公钥写入 known_hosts（ssh-skill 严格校验主机密钥） */
function knownHostsPosix(p: Prepared) {
	if (!p.hostKeys.size) return "";
	const cmds = [...p.hostKeys].map(([pattern, lines]) =>
		`ssh-keygen -R '${pattern}' -f "$KH" >/dev/null 2>&1 || true\nprintf '%s\\n' ${lines.map((l) => `'${l}'`).join(" ")} >> "$KH"`);
	return `KH="$SSH/known_hosts"; touch "$KH"\n${cmds.join("\n")}\nchmod 600 "$KH"\n`;
}

function knownHostsWindows(p: Prepared) {
	if (!p.hostKeys.size) return "";
	const patterns = [...p.hostKeys.keys()].map((k) => `'${k} '`).join(", ");
	const lines = [...p.hostKeys.values()].flat().map((l) => `'${l}'`).join(", ");
	return `$kh = Join-Path $ssh 'known_hosts'
$khLines = @()
if (Test-Path $kh) { $khLines = @([IO.File]::ReadAllText($kh) -split "\\r?\\n" | Where-Object { $_ -ne '' }) }
$drop = @(${patterns})
$khLines = @($khLines | Where-Object { $l = $_; -not ($drop | Where-Object { $l.StartsWith($_) }) }) + @(${lines})
[IO.File]::WriteAllText($kh, (($khLines -join "\`n") + "\`n"), $utf8)
Protect-SshFile $kh
`;
}

/** macOS / Linux：bash 脚本，`pbpaste | bash` 运行 */
function renderPosix(p: Prepared): string {
	const keyCmds = [...p.keys].map(([name, data]) => {
		const b64 = toB64(data).replace(/(.{76})/g, "$1\n");
		const d = delimiter(b64);
		const pub = p.pubs.get(name);
		const pubCmd = pub ? `\nprintf '%s\\n' '${pub}' > "$KEYDIR/${name}.key.pub"; chmod 644 "$KEYDIR/${name}.key.pub"` : "";
		return `base64 -d > "$KEYDIR/${name}.key" <<'${d}'\n${b64}\n${d}\nchmod 600 "$KEYDIR/${name}.key"${pubCmd}`;
	});
	const cfgText = p.blocks.join("\n\n");
	const cd = delimiter(cfgText);
	return `#!/usr/bin/env bash
# SSH Manager：把云端的服务器、密码和私钥同步到本机 ~/.ssh（由网页生成，运行后会清空剪贴板）
set -euo pipefail
umask 077
SSH="$HOME/.ssh"; CFG="$SSH/config"; KEYDIR="$SSH/ssh-manager"
mkdir -p "$SSH" "$KEYDIR"; chmod 700 "$SSH" "$KEYDIR"
touch "$CFG"
cp "$CFG" "$CFG.ssh-manager.bak"
${keyCmds.join("\n")}
# 先移除同名的旧条目（只删 "# ===== 别名 =====" 起的元数据和 Host 块），再追加新条目
awk -v list="${p.aliases.join(" ")}" '
BEGIN { n = split(list, a, " "); for (i = 1; i <= n; i++) want[a[i]] = 1 }
function flush() { for (i = 1; i <= nb; i++) print buf[i]; nb = 0 }
{
  if (skip) { if ($0 ~ /^[ \t]/ || $0 ~ /^[ \t]*$/) next; skip = 0 }
  if ($0 ~ /^[ \t]*#/ || $0 ~ /^[ \t]*$/) { buf[++nb] = $0; next }
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
if [ -s "$CFG.tmp" ]; then printf '%s\n\n' "$(cat "$CFG.tmp")" > "$CFG.tmp2" && mv "$CFG.tmp2" "$CFG.tmp"; fi
cat >> "$CFG.tmp" <<'${cd}'
${cfgText}
${cd}
mv "$CFG.tmp" "$CFG"; chmod 600 "$CFG"
${knownHostsPosix(p)}command -v pbcopy >/dev/null 2>&1 && pbcopy </dev/null || true
echo "${doneMsg(p, "~/.ssh")}"
`;
}

/** Windows：PowerShell 脚本，在 cmd 里用 `powershell -nop -c "iex (Get-Clipboard -Raw)"` 运行。
 *  兼容 Windows 自带的 PowerShell 5.1（不用 &&、??、三元运算等 7.x 语法）。 */
function renderWindows(p: Prepared): string {
	// 单引号 here-string 内容不能有以 '@ 开头的行；配置行都以 "#"、"Host" 或空格开头，base64 不含 '@
	const keyCmds = [...p.keys].map(([name, data]) => {
		const b64 = toB64(data).replace(/(.{76})/g, "$1\n");
		return `$k = Join-Path $keyDir '${name}.key'
$b64 = (@'
${b64}
'@) -replace '\\s', ''
[IO.File]::WriteAllBytes($k, [Convert]::FromBase64String($b64))
Protect-SshFile $k${p.pubs.get(name) ? `
[IO.File]::WriteAllText("$k.pub", '${p.pubs.get(name)}' + "\`n", $utf8)` : ""}`;
	});
	const list = p.aliases.map((a) => `'${a}'`).join(", ");
	return `# SSH Manager：把云端的服务器、密码和私钥同步到本机 %USERPROFILE%\\.ssh（由网页生成，运行后会清空剪贴板）
$ErrorActionPreference = 'Stop'
$ssh = Join-Path $HOME '.ssh'
$cfg = Join-Path $ssh 'config'
$keyDir = Join-Path $ssh 'ssh-manager'
New-Item -ItemType Directory -Force -Path $ssh, $keyDir | Out-Null
if (-not (Test-Path $cfg)) { New-Item -ItemType File -Path $cfg | Out-Null }
Copy-Item $cfg "$cfg.ssh-manager.bak" -Force
$utf8 = New-Object System.Text.UTF8Encoding $false
function Protect-SshFile($path) {
  # Windows 版 OpenSSH 拒绝其他用户可读的私钥：去掉继承权限，只保留当前用户
  if ($env:OS -eq 'Windows_NT') {
    icacls $path /inheritance:r /grant:r "$($env:USERDOMAIN)\\$($env:USERNAME):(F)" | Out-Null
  } else { chmod 600 $path }
}
${keyCmds.join("\n")}
# 先移除同名的旧条目（只删 "# ===== 别名 =====" 起的元数据和 Host 块），再追加新条目
$want = @{}
foreach ($a in @(${list})) { $want[$a] = $true }
$lines = [IO.File]::ReadAllText("$cfg.ssh-manager.bak") -split "\\r?\\n"
$out = New-Object System.Collections.Generic.List[string]
$buf = New-Object System.Collections.Generic.List[string]
$skip = $false
foreach ($line in $lines) {
  if ($skip) {
    if ($line -match '^[ \\t]' -or $line -match '^\\s*$') { continue }
    $skip = $false
  }
  if ($line -match '^\\s*#' -or $line -match '^\\s*$') { $buf.Add($line); continue }
  $parts = $line.Trim() -split '\\s+'
  if ($parts.Count -eq 2 -and $parts[0] -eq 'Host' -and $want.ContainsKey($parts[1])) {
    $cut = -1
    for ($i = $buf.Count - 1; $i -ge 0; $i--) { if ($buf[$i] -eq ('# ===== ' + $parts[1] + ' =====')) { $cut = $i; break } }
    if ($cut -ge 0) { $buf.RemoveRange($cut, $buf.Count - $cut) }
    $out.AddRange($buf); $buf.Clear(); $skip = $true; continue
  }
  $out.AddRange($buf); $buf.Clear(); $out.Add($line)
}
$out.AddRange($buf)
$text = ($out -join "\`n").TrimEnd()
if ($text) { $text += "\`n\`n" }
$text += (@'
${p.blocks.join("\n\n")}
'@) -replace "\`r", ''
$text += "\`n"
[IO.File]::WriteAllText($cfg, $text, $utf8)
Protect-SshFile $cfg
${knownHostsWindows(p)}try { Set-Clipboard -Value $null } catch { try { Set-Clipboard -Value ' ' } catch { } }
# 如果是在 PowerShell 里粘贴运行的，把这条含密文的命令从 PSReadLine 历史文件里删掉
try {
  $hp = Join-Path $env:APPDATA 'Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt'
  if ($env:APPDATA -and (Test-Path $hp)) {
    $keep = @(Get-Content $hp | Where-Object { $_ -notmatch 'GZipStream' })
    Set-Content -Path $hp -Value $keep -Encoding UTF8
  }
} catch { }
Write-Host "${doneMsg(p, "%USERPROFILE%\\.ssh")}"
`;
}

/** 解密全部服务器与密钥，生成对应平台的同步脚本 */
export async function buildSyncScript(priv: CryptoKey, servers: ExportServer[], keys: ExportKey[], platform: Platform = "posix"): Promise<SyncResult> {
	const p = await prepare(priv, servers, keys);
	const script = platform === "windows" ? renderWindows(p) : renderPosix(p);
	return { script, servers: p.aliases.length, keyFiles: p.keys.size, skipped: p.skipped, platform };
}

/** cmd 单行命令上限 8191 字符，留一点余量 */
const WINDOWS_MAX_LINE = 8000;

async function gzipB64(text: string): Promise<string> {
	const stream = new Blob([enc.encode(text)]).stream().pipeThrough(new CompressionStream("gzip"));
	return toB64(new Uint8Array(await new Response(stream).arrayBuffer()));
}

/** Windows：把脚本压缩成一行命令，粘贴到 cmd 或 PowerShell 直接回车即可运行。
 *  内层不含 $ 和双引号，所以在 PowerShell 里粘贴时外层字符串也不会被展开。超长时返回 null。 */
export async function windowsOneLiner(script: string): Promise<string | null> {
	const b64 = await gzipB64(script);
	const cmd =
		`powershell -nop -c "iex ([IO.StreamReader]::new([IO.Compression.GZipStream]::new([IO.MemoryStream]::new(` +
		`[Convert]::FromBase64String('${b64}')),[IO.Compression.CompressionMode]::Decompress),[Text.Encoding]::UTF8).ReadToEnd())"`;
	return cmd.length <= WINDOWS_MAX_LINE ? cmd : null;
}
