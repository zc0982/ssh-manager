import { CopyIcon, DownloadIcon, KeyRoundIcon, Trash2Icon } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api, fmtTime, runJob, type SshKey, type Status } from "@/lib/api";
import { sealData } from "@/lib/crypto";
import { type Backup, buildSyncScript, type ExportKey, type ExportServer, type SyncResult, unlockAgentKey, windowsOneLiner } from "@/lib/restore";
import { Field } from "./server-form";

type Open = { open: boolean; onOpenChange: (open: boolean) => void };

// ---------- 云端密钥 ----------

export function KeysDialog({ open, onOpenChange, keys, publicKey, onChanged }: Open & {
	keys: SshKey[]; publicKey: JsonWebKey | null; onChanged: () => void;
}) {
	const [name, setName] = useState("");
	const [comment, setComment] = useState("");
	const [text, setText] = useState("");
	const [error, setError] = useState("");
	const [busy, setBusy] = useState(false);
	const fileRef = useRef<HTMLInputElement>(null);

	async function upload() {
		setError("");
		setBusy(true);
		try {
			if (!/^[A-Za-z0-9._-]+$/.test(name)) throw new Error("名称只能包含字母、数字、. _ -");
			const file = fileRef.current?.files?.[0];
			const bytes = file ? new Uint8Array(await file.arrayBuffer()) : new TextEncoder().encode(text.trim() + "\n");
			const content = new TextDecoder().decode(bytes);
			if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(content)) throw new Error("看起来不是私钥文件（缺少 BEGIN ... PRIVATE KEY）");
			if (/Proc-Type: 4,ENCRYPTED|BEGIN ENCRYPTED PRIVATE KEY/.test(content)) throw new Error("暂不支持带口令的私钥");
			if (bytes.length > 64 * 1024) throw new Error("文件过大");
			const key_encrypted = await sealData(publicKey, bytes);
			await api("/api/keys", { method: "POST", body: { name, comment: comment.trim(), key_encrypted } });
			setName(""); setComment(""); setText("");
			if (fileRef.current) fileRef.current.value = "";
			toast.success(`已加密上传 ${name}`);
			onChanged();
		} catch (e: any) {
			setError(e.message);
		} finally {
			setBusy(false);
		}
	}

	async function remove(k: SshKey) {
		if (!confirm(`删除云端密钥 ${k.name}？已写到本机的密钥文件不会被删除。`)) return;
		try {
			await api(`/api/keys/${k.id}`, { method: "DELETE" });
			toast.success("已删除");
			onChanged();
		} catch (e: any) { toast.error(e.message); }
	}

	return (
		<Dialog open={open} onOpenChange={onOpenChange}>
			<DialogContent className="sm:max-w-2xl">
				<DialogHeader>
					<DialogTitle>云端 SSH 密钥</DialogTitle>
					<DialogDescription>
						私钥在浏览器里用本机 agent 的公钥加密后才上传，云端只保存密文。同步时由 agent 解密写到
						<code className="mx-1 rounded bg-muted px-1 text-xs">~/.ssh/ssh-manager/&lt;名称&gt;.key</code>（权限 600）。暂不支持带口令的私钥。
					</DialogDescription>
				</DialogHeader>
				{keys.length ? (
					<ScrollArea className="max-h-56 rounded-md border">
						<Table>
							<TableHeader><TableRow><TableHead>名称</TableHead><TableHead>说明</TableHead><TableHead>使用中</TableHead><TableHead>上传时间</TableHead><TableHead /></TableRow></TableHeader>
							<TableBody>
								{keys.map((k) => (
									<TableRow key={k.id}>
										<TableCell className="font-mono text-xs">{k.name}</TableCell>
										<TableCell className="max-w-48 truncate">{k.comment}</TableCell>
										<TableCell>{k.used_by} 台</TableCell>
										<TableCell className="text-muted-foreground">{fmtTime(k.created_at)}</TableCell>
										<TableCell className="text-right">
											<Button variant="ghost" size="icon-sm" disabled={k.used_by > 0} title={k.used_by ? "仍有服务器在使用" : "删除"} onClick={() => remove(k)}>
												<Trash2Icon />
											</Button>
										</TableCell>
									</TableRow>
								))}
							</TableBody>
						</Table>
					</ScrollArea>
				) : <p className="text-sm text-muted-foreground">还没有云端密钥</p>}
				<Separator />
				<div className="grid gap-3 sm:grid-cols-2">
					<Field label="名称"><Input placeholder="prod-deploy" value={name} onChange={(e) => setName(e.target.value)} /></Field>
					<Field label="说明"><Input placeholder="可选" value={comment} onChange={(e) => setComment(e.target.value)} /></Field>
					<Field label="私钥文件" className="sm:col-span-2">
						<Input ref={fileRef} type="file" onChange={(e) => {
							const file = e.target.files?.[0];
							if (file && !name) setName(file.name.replace(/[^A-Za-z0-9._-]/g, "-"));
						}} />
					</Field>
					<Field label="或直接粘贴" className="sm:col-span-2">
						<Textarea rows={4} className="font-mono text-xs" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" value={text} onChange={(e) => setText(e.target.value)} />
					</Field>
				</div>
				{error && <p className="text-sm text-destructive">{error}</p>}
				<DialogFooter>
					<Button variant="outline" onClick={() => onOpenChange(false)}>关闭</Button>
					<Button disabled={busy} onClick={upload}><KeyRoundIcon />{busy ? "加密上传中…" : "加密并上传"}</Button>
				</DialogFooter>
			</DialogContent>
		</Dialog>
	);
}

// ---------- 从本机导入 ----------

type LocalHost = { alias: string; hostname: string; user: string; port: number; description: string; has_password: boolean };

export function ImportDialog({ open, onOpenChange, hosts, onDone }: Open & { hosts: LocalHost[]; onDone: () => void }) {
	const [picked, setPicked] = useState<Set<string>>(new Set());
	const [uploadKeys, setUploadKeys] = useState(true);
	const [busy, setBusy] = useState(false);
	const [lastHosts, setLastHosts] = useState(hosts);
	if (hosts !== lastHosts) { setLastHosts(hosts); setPicked(new Set(hosts.map((h) => h.alias))); }

	async function doImport() {
		if (!picked.size) return;
		setBusy(true);
		try {
			const r = await runJob("import", { payload: { aliases: [...picked], upload_keys: uploadKeys } });
			const bad = Object.entries(r.errors || {});
			if (bad.length) toast.error(`导入失败：${bad.map(([a, err]) => `${a}(${err})`).join("，")}`);
			else toast.success(`已导入 ${(r.imported || []).length} 台`);
			onOpenChange(false);
			onDone();
		} catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
	}

	const toggle = (alias: string, on: boolean) => {
		const next = new Set(picked);
		if (on) next.add(alias); else next.delete(alias);
		setPicked(next);
	};

	return (
		<Dialog open={open} onOpenChange={onOpenChange}>
			<DialogContent className="sm:max-w-xl">
				<DialogHeader>
					<DialogTitle>从本机 ~/.ssh/config 导入到云端</DialogTitle>
					<DialogDescription>列出的是运行 agent 的电脑上、还没有导入云端的主机。</DialogDescription>
				</DialogHeader>
				{hosts.length ? (
					<ScrollArea className="max-h-72 rounded-md border">
						<div className="divide-y">
							{hosts.map((h) => (
								<label key={h.alias} className="flex cursor-pointer items-center gap-3 px-3 py-2 hover:bg-muted/50">
									<Checkbox checked={picked.has(h.alias)} onCheckedChange={(v) => toggle(h.alias, v === true)} />
									<div className="min-w-0">
										<div className="font-medium">{h.alias}</div>
										<div className="truncate font-mono text-xs text-muted-foreground">
											{h.user}@{h.hostname}:{h.port} {h.description} {h.has_password ? "· 含密码" : ""}
										</div>
									</div>
								</label>
							))}
						</div>
					</ScrollArea>
				) : <p className="text-sm text-muted-foreground">本机 ~/.ssh/config 中没有未导入的主机</p>}
				<label className="flex items-center gap-2 text-sm">
					<Checkbox checked={uploadKeys} onCheckedChange={(v) => setUploadKeys(v === true)} />
					同时把这些主机使用的私钥文件加密上传到云端
				</label>
				<DialogFooter>
					<Button variant="outline" onClick={() => onOpenChange(false)}>取消</Button>
					<Button disabled={busy || !picked.size} onClick={doImport}>{busy ? "导入中…" : `导入所选（${picked.size}）`}</Button>
				</DialogFooter>
			</DialogContent>
		</Dialog>
	);
}

// ---------- 新电脑同步 ----------

const detectedOs = (): "mac" | "linux" | "windows" => {
	const ua = navigator.userAgent;
	return /Windows/i.test(ua) ? "windows" : /Mac/i.test(ua) ? "mac" : "linux";
};
const RUN_CMD = {
	mac: "pbpaste | bash",
	linux: "xclip -o -selection clipboard | bash",
	windows: 'powershell -nop -c "iex (Get-Clipboard -Raw)"',
};
const OS_LABEL = { mac: "macOS", linux: "Linux", windows: "Windows" };
const AGENT_CMD = "git clone https://github.com/zc0982/ssh-manager.git\ncd ssh-manager && ./setup.sh";

async function copy(text: string, ok = "已复制") {
	try { await navigator.clipboard.writeText(text); toast.success(ok); return true; } catch { toast.error("复制失败，请检查浏览器的剪贴板权限"); return false; }
}

export function NewPcDialog({ open, onOpenChange, status }: Open & { status: Status | null }) {
	const ready = !!status?.key_backup;
	const [password, setPassword] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [result, setResult] = useState<SyncResult | null>(null);
	const [winLine, setWinLine] = useState<string | null>(null); // Windows：可直接粘贴运行的单行命令
	const [os, setOs] = useState(detectedOs);
	const [unlocked, setUnlocked] = useState<{ priv: CryptoKey; servers: ExportServer[]; keys: ExportKey[] } | null>(null);
	const [copied, setCopied] = useState(false);
	const [showAgent, setShowAgent] = useState(false);

	useEffect(() => {
		if (!open) { setPassword(""); setResult(null); setWinLine(null); setUnlocked(null); setCopied(false); setError(""); setShowAgent(false); }
	}, [open]);

	// 切换系统时用已解开的私钥重新生成脚本，不用再输密码
	useEffect(() => {
		if (!unlocked) return;
		setCopied(false);
		buildSyncScript(unlocked.priv, unlocked.servers, unlocked.keys, os === "windows" ? "windows" : "posix")
			.then(async (r) => {
				setWinLine(os === "windows" ? await windowsOneLiner(r.script) : null);
				setResult(r);
			}, (e) => setError(e.message));
	}, [unlocked, os]);

	const pasteMode = os === "windows" && !!winLine;

	async function prepare(e: React.FormEvent) {
		e.preventDefault();
		setBusy(true);
		setError("");
		try {
			const data = await api<{ backup: Backup; servers: ExportServer[]; keys: ExportKey[] }>("/api/export");
			const priv = await unlockAgentKey(data.backup, password);
			setUnlocked({ priv, servers: data.servers, keys: data.keys });
			setPassword("");
		} catch (err: any) { setError(err.message); } finally { setBusy(false); }
	}

	return (
		<Dialog open={open} onOpenChange={onOpenChange}>
			<DialogContent className="sm:max-w-xl">
				<DialogHeader>
					<DialogTitle>同步到这台电脑</DialogTitle>
					<DialogDescription>
						输入主密码，浏览器在本地解密云端的服务器、密码和私钥，生成同步脚本；在终端运行一次即可写入 ~/.ssh/config，供 ssh-skill 直接使用。不需要下载源代码。
					</DialogDescription>
				</DialogHeader>
				{!ready && (
					<Alert variant="destructive">
						<AlertTitle>云端还没有备份</AlertTitle>
						<AlertDescription>请先在已经在用的电脑上运行 <code className="rounded bg-muted px-1">./setup.sh backup</code> 并设置主密码。</AlertDescription>
					</Alert>
				)}
				<ol className="grid gap-4 text-sm">
					<Step n={1} title="输入主密码">
						<form onSubmit={prepare} className="mt-2 flex gap-2">
							<Input type="password" autoComplete="current-password" placeholder="主密码" value={password}
								disabled={!ready || busy || !!result} onChange={(ev) => setPassword(ev.target.value)} />
							<Button type="submit" disabled={!ready || busy || !password || !!result}>{busy ? "解密中…" : result ? "已解密" : "解密"}</Button>
						</form>
						{error && <p className="mt-1 text-destructive">{error}</p>}
						{result && (
							<p className="mt-1">
								已准备 {result.servers} 台服务器、{result.keyFiles} 个私钥
								{result.skipped.length > 0 && <span className="text-destructive">；跳过：{result.skipped.join("，")}</span>}
							</p>
						)}
					</Step>
					<Step n={2} title={pasteMode ? "复制同步命令" : "复制同步脚本"}>
						<Button className="mt-2" disabled={!result}
							onClick={async () => setCopied(await copy(pasteMode ? winLine! : result!.script, pasteMode ? "同步命令已复制" : "同步脚本已复制到剪贴板"))}>
							<CopyIcon />{copied ? "已复制，可再次复制" : pasteMode ? "复制同步命令" : "复制同步脚本"}
						</Button>
					</Step>
					<Step n={3} title={pasteMode ? "打开「命令提示符」(cmd) 或 PowerShell，粘贴并回车" : os === "windows" ? "打开「命令提示符」(cmd) 或 PowerShell，输入下面的命令（不要直接粘贴脚本）" : "在终端里输入下面的命令（不要直接粘贴脚本）"}>
						<div className="mt-2 flex flex-wrap gap-1">
							{(["mac", "windows", "linux"] as const).map((o) => (
								<Button key={o} size="xs" variant={os === o ? "default" : "outline"} onClick={() => setOs(o)}>{OS_LABEL[o]}</Button>
							))}
						</div>
						{pasteMode ? (
							<p className="mt-2 text-foreground">在窗口里点右键或按 <kbd className="rounded border px-1">Ctrl</kbd>+<kbd className="rounded border px-1">V</kbd> 粘贴刚才复制的那一行，然后按回车。</p>
						) : (
							<>
								{os === "windows" && result && !winLine && <p className="mt-2 text-amber-500">服务器较多，命令超过 cmd 单行长度限制，请改用下面的方式。</p>}
								<pre className="mt-2 w-fit max-w-full overflow-x-auto rounded-md bg-muted px-3 py-2 font-mono text-base text-foreground">{RUN_CMD[os]}</pre>
							</>
						)}
						<p className="mt-1">
							{os === "windows"
								? "写入 %USERPROFILE%\\.ssh\\config（原配置备份为 config.ssh-manager.bak），私钥写到 .ssh\\ssh-manager\\ 并设为仅当前用户可读，运行后自动清空剪贴板。"
								: "写入 ~/.ssh/config（原配置备份为 config.ssh-manager.bak），私钥写到 ~/.ssh/ssh-manager/（权限 600），运行后自动清空剪贴板。"}
							可重复运行，不会产生重复条目。
						</p>
					</Step>
				</ol>
				<div className="text-xs text-muted-foreground">
					<button type="button" className="underline" onClick={() => setShowAgent(!showAgent)}>
						{showAgent ? "收起" : "可选：让网页上的命令也在这台电脑执行（安装后台 agent）"}
					</button>
					{showAgent && (
						<div className="mt-2 grid gap-2">
							<p>需要源代码和 uv。按提示选择设置文件并输入主密码：</p>
							<Button size="sm" variant="outline" className="w-fit" disabled={!status?.key_backup_has_env} onClick={() => { location.href = "/api/setup-bundle"; }}>
								<DownloadIcon />下载 ssh-manager-setup.json
							</Button>
							<pre className="rounded-md bg-muted p-2 font-mono whitespace-pre-wrap">{AGENT_CMD}</pre>
							<Button size="sm" variant="ghost" className="w-fit" onClick={() => copy(AGENT_CMD)}><CopyIcon />复制</Button>
						</div>
					)}
				</div>
			</DialogContent>
		</Dialog>
	);
}

function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
	return (
		<li className="flex gap-3">
			<span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-primary text-xs font-medium text-primary-foreground">{n}</span>
			<div className="min-w-0 flex-1">
				<Label className="font-medium">{title}</Label>
				<div className="mt-1 text-muted-foreground">{children}</div>
			</div>
		</li>
	);
}
