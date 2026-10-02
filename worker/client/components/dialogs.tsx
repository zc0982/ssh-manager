import { CopyIcon, DownloadIcon, KeyRoundIcon, Trash2Icon } from "lucide-react";
import { useRef, useState } from "react";
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

// ---------- 新电脑向导 ----------

const SETUP_CMD = "git clone https://github.com/zc0982/ssh-manager.git\ncd ssh-manager && ./setup.sh";

export function NewPcDialog({ open, onOpenChange, status }: Open & { status: Status | null }) {
	const ready = !!status?.key_backup_has_env;
	return (
		<Dialog open={open} onOpenChange={onOpenChange}>
			<DialogContent className="sm:max-w-xl">
				<DialogHeader>
					<DialogTitle>在新电脑上使用 SSH Manager</DialogTitle>
					<DialogDescription>
						SSH 连接由电脑上的 agent 通过 ssh-skill 执行。换电脑后按下面的步骤设置，服务器配置、密码和云端私钥都会自动恢复。
					</DialogDescription>
				</DialogHeader>
				{!ready && (
					<Alert variant="destructive">
						<AlertTitle>{status?.key_backup ? "当前备份是旧格式" : "云端还没有备份"}</AlertTitle>
						<AlertDescription>
							请先在已经在用的电脑上运行 <code className="rounded bg-muted px-1">./setup.sh backup</code> 并设置主密码，再回来下载设置文件。
						</AlertDescription>
					</Alert>
				)}
				<ol className="grid gap-4 text-sm">
					<Step n={1} title="准备环境">
						安装 <a className="underline" href="https://docs.astral.sh/uv/" target="_blank" rel="noopener">uv</a>、git，以及 ssh-skill（放在 <code className="rounded bg-muted px-1 text-xs">~/.claude/skills/ssh-skill</code>）。
					</Step>
					<Step n={2} title="下载设置文件（已用你的主密码加密）">
						<Button className="mt-2" disabled={!ready} onClick={() => { location.href = "/api/setup-bundle"; }}>
							<DownloadIcon />下载 ssh-manager-setup.json
						</Button>
					</Step>
					<Step n={3} title="获取代码并运行向导，按提示输入主密码">
						<pre className="mt-2 rounded-md bg-muted p-3 font-mono text-xs whitespace-pre-wrap">{SETUP_CMD}</pre>
						<Button variant="outline" size="sm" className="mt-2" onClick={async () => {
							try { await navigator.clipboard.writeText(SETUP_CMD); toast.success("已复制"); } catch { toast.error("复制失败，请手动复制"); }
						}}><CopyIcon />复制命令</Button>
					</Step>
					<Step n={4} title="完成">
						向导会写入 agent 私钥和连接凭证、把所有服务器同步到 ~/.ssh/config，并安装开机自启的后台服务。回到这个页面，顶部会显示新电脑的 agent 在线。
					</Step>
				</ol>
				<p className="text-xs text-muted-foreground">
					旧电脑不再使用时，可在终端运行 <code className="rounded bg-muted px-1">{"launchctl bootout gui/$(id -u)/com.ssh-manager.agent"}</code> 停掉它的 agent。
				</p>
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
