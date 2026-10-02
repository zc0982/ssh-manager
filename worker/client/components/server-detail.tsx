import { ArrowDownToLineIcon, ArrowUpFromLineIcon, PencilIcon, PlayIcon, RefreshCwIcon, Trash2Icon, ZapIcon } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import {
	AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription,
	AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api, type Environment, fmtTime, type Job, type JobResult, runJob, type Server, type SshKey } from "@/lib/api";
import { EnvBadge } from "./environments-dialog";
import { HostKeyFact, isHostKeyError, TrustHostKeyDialog } from "./host-keys";
import { cn } from "@/lib/utils";
import { Field } from "./server-form";

type Line = { kind: "cmd" | "out" | "err" | "info"; text: string };

// 各服务器的终端输出在切换时保留
const termStore = new Map<string, Line[]>();
const history: string[] = [];

export function ServerDetail({ server, keys, envs, onEdit, onChanged, onDeleted }: {
	server: Server; keys: SshKey[]; envs: Environment[]; onEdit: () => void; onChanged: () => void; onDeleted: () => void;
}) {
	const [lines, setLines] = useState<Line[]>(() => termStore.get(server.id) ?? []);
	const [testing, setTesting] = useState(false);
	const [syncing, setSyncing] = useState(false);
	const [trustOpen, setTrustOpen] = useState(false);

	useEffect(() => setLines(termStore.get(server.id) ?? []), [server.id]);

	const append = useCallback((id: string, more: Line[]) => {
		const next = [...(termStore.get(id) ?? []), ...more];
		termStore.set(id, next);
		setLines((cur) => (id === server.id ? next : cur));
	}, [server.id]);

	const resultLines = (r: JobResult): Line[] => [
		...(r.stdout ? [{ kind: "out" as const, text: r.stdout.replace(/\n$/, "") }] : []),
		...(r.stderr ? [{ kind: "err" as const, text: r.stderr.replace(/\n$/, "") }] : []),
		...(r.error ? [{ kind: "err" as const, text: r.error }] : []),
		{ kind: "info", text: `[exit ${r.exit_code ?? "?"} · ${r.duration_ms ?? "?"}ms]` },
	];

	async function test() {
		setTesting(true);
		append(server.id, [{ kind: "info", text: "[测试连接]" }]);
		try {
			const r = await runJob("test", { serverId: server.id });
			append(server.id, resultLines(r));
			if (r.success) toast.success(`连接成功 · ${r.duration_ms}ms`);
			else if (isHostKeyError(`${r.error ?? ""} ${r.stderr ?? ""}`)) {
				toast.error("连接失败：还没有信任这台服务器的主机指纹", { action: { label: "去信任", onClick: () => setTrustOpen(true) } });
				setTrustOpen(true);
			} else toast.error(`连接失败：${r.error || r.stderr || "未知错误"}`);
		} catch (e: any) { toast.error(e.message); } finally { setTesting(false); onChanged(); }
	}

	async function sync() {
		setSyncing(true);
		try {
			const r = await runJob("sync", { serverId: server.id });
			if (r.success) toast.success(`已同步 ${r.alias}（${r.action}）`); else toast.error(`同步失败：${r.error}`);
		} catch (e: any) { toast.error(e.message); } finally { setSyncing(false); onChanged(); }
	}

	async function remove() {
		try {
			await api(`/api/servers/${server.id}`, { method: "DELETE" });
			toast.success(`已删除 ${server.alias}`);
			onDeleted();
		} catch (e: any) { toast.error(e.message); }
	}

	const notSynced = !server.last_synced_at || new Date(server.last_synced_at) < new Date(server.updated_at);
	const keyName = keys.find((k) => k.id === server.key_id)?.name;

	return (
		<div className="flex flex-col gap-4">
			<div className="flex flex-wrap items-start justify-between gap-3">
				<div className="min-w-0">
					<div className="flex flex-wrap items-center gap-2">
						<h1 className="text-xl font-semibold tracking-wide">{server.alias}</h1>
						<EnvBadge env={server.environment} envs={envs} />
						{notSynced && <Badge variant="outline" className="border-amber-500 text-amber-600">待同步到本机</Badge>}
					</div>
					<p className="mt-1 font-mono text-sm text-muted-foreground">
						{server.username}@{server.hostname}:{server.port}{server.proxy_jump ? ` via ${server.proxy_jump}` : ""}
					</p>
				</div>
				<div className="flex flex-wrap gap-2">
					<Button onClick={test} disabled={testing}><ZapIcon />{testing ? "测试中…" : "测试连接"}</Button>
					<Button variant="outline" onClick={sync} disabled={syncing}><RefreshCwIcon className={cn(syncing && "animate-spin")} />同步到本机</Button>
					<Button variant="outline" onClick={onEdit}><PencilIcon />编辑</Button>
					<AlertDialog>
						<AlertDialogTrigger asChild><Button variant="outline" className="text-destructive"><Trash2Icon />删除</Button></AlertDialogTrigger>
						<AlertDialogContent>
							<AlertDialogHeader>
								<AlertDialogTitle>删除 {server.alias}？</AlertDialogTitle>
								<AlertDialogDescription>将同时从云端和本机 ~/.ssh/config 中移除，操作日志会保留。</AlertDialogDescription>
							</AlertDialogHeader>
							<AlertDialogFooter>
								<AlertDialogCancel>取消</AlertDialogCancel>
								<AlertDialogAction variant="destructive" onClick={remove}>删除</AlertDialogAction>
							</AlertDialogFooter>
						</AlertDialogContent>
					</AlertDialog>
				</div>
			</div>

			<Card size="sm" className="bg-card/80 backdrop-blur-md">
				<CardContent className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm md:grid-cols-3">
					<Fact label="认证">
						{server.auth_type === "key"
							? (server.key_id ? `云端密钥 ${keyName ?? ""}` : `密钥 ${server.identity_file || "(默认)"}`)
							: `密码 ${server.has_password ? "(已加密保存)" : "(未设置)"}`}
					</Fact>
					<Fact label="标签">
						{server.tags.length ? <div className="flex flex-wrap gap-1">{server.tags.map((t) => <Badge key={t} variant="secondary">{t}</Badge>)}</div> : "—"}
					</Fact>
					<Fact label="位置">{server.location || "—"}</Fact>
					<Fact label="最近连接">
						{fmtTime(server.last_connected_at)}{" "}
						{server.last_status && <span className={server.last_status === "ok" ? "text-emerald-600" : "text-destructive"}>{server.last_status}</span>}
					</Fact>
					<Fact label="最近同步到本机">{fmtTime(server.last_synced_at)}</Fact>
					<Fact label="主机指纹" className="col-span-2"><HostKeyFact server={server} onTrust={() => setTrustOpen(true)} /></Fact>
					{server.description && <Fact label="备注" className="col-span-2 md:col-span-3">{server.description}</Fact>}
				</CardContent>
			</Card>

			<Tabs defaultValue="exec">
				<TabsList variant="line">
					<TabsTrigger value="exec">命令</TabsTrigger>
					<TabsTrigger value="files">文件传输</TabsTrigger>
					<TabsTrigger value="tunnels">隧道</TabsTrigger>
					<TabsTrigger value="logs">操作日志</TabsTrigger>
				</TabsList>
				<TabsContent value="exec"><ExecTab server={server} lines={lines} append={append} resultLines={resultLines} onDone={onChanged} /></TabsContent>
				<TabsContent value="files"><FilesTab server={server} /></TabsContent>
				<TabsContent value="tunnels"><TunnelsTab server={server} /></TabsContent>
				<TabsContent value="logs"><LogsTab server={server} /></TabsContent>
			</Tabs>
			<TrustHostKeyDialog server={server} open={trustOpen} onOpenChange={setTrustOpen} onDone={onChanged} />
		</div>
	);
}

function Fact({ label, className, children }: { label: string; className?: string; children: React.ReactNode }) {
	return (
		<div className={cn("min-w-0", className)}>
			<div className="text-xs text-muted-foreground">{label}</div>
			<div className="mt-0.5 break-words">{children}</div>
		</div>
	);
}

// ---------- 命令 ----------

function ExecTab({ server, lines, append, resultLines, onDone }: {
	server: Server; lines: Line[]; append: (id: string, l: Line[]) => void; resultLines: (r: JobResult) => Line[]; onDone: () => void;
}) {
	const [cmd, setCmd] = useState("");
	const [timeout, setTimeoutS] = useState("60");
	const [readOnly, setReadOnly] = useState(false);
	const [running, setRunning] = useState(false);
	const [hi, setHi] = useState(history.length);
	const termRef = useRef<HTMLPreElement>(null);
	const inputRef = useRef<HTMLInputElement>(null);

	useEffect(() => { inputRef.current?.focus({ preventScroll: true }); }, [server.id]);

	useEffect(() => { termRef.current?.scrollTo({ top: termRef.current.scrollHeight }); }, [lines]);

	async function run(e: React.FormEvent) {
		e.preventDefault();
		const command = cmd.trim();
		if (!command) return;
		history.push(command);
		setHi(history.length);
		setCmd("");
		const id = server.id;
		append(id, [{ kind: "cmd", text: `$ ${command}` }]);
		setRunning(true);
		try {
			const t = Number(timeout) || 60;
			const r = await runJob("exec", { serverId: id, payload: { command, timeout: t, read_only: readOnly }, timeoutMs: t * 4000 + 60_000 });
			append(id, resultLines(r));
		} catch (err: any) {
			append(id, [{ kind: "err", text: err.message }]);
		} finally { setRunning(false); onDone(); }
	}

	function onKey(e: React.KeyboardEvent<HTMLInputElement>) {
		if (e.key === "ArrowUp" && hi > 0) { e.preventDefault(); setHi(hi - 1); setCmd(history[hi - 1]); }
		if (e.key === "ArrowDown") { const n = Math.min(hi + 1, history.length); setHi(n); setCmd(history[n] ?? ""); }
	}

	return (
		<div className="flex flex-col gap-2 pt-2">
			<pre ref={termRef} className="neon-panel h-[clamp(14rem,38vh,32rem)] overflow-y-auto rounded-lg bg-black/80 p-3 font-mono text-[13px] leading-relaxed whitespace-pre-wrap break-all text-zinc-200 backdrop-blur-sm">
				{lines.length === 0 && <span className="text-zinc-500">命令会交给本机 agent，通过 ssh-skill 在 {server.alias} 上执行。↑/↓ 浏览历史。</span>}
				{lines.map((l, i) => (
					<div key={i} className={cn(l.kind === "cmd" && "text-primary", l.kind === "err" && "text-red-400", l.kind === "info" && "text-zinc-500")}>{l.text}</div>
				))}
				{running && <div className="animate-pulse text-zinc-500">执行中…</div>}
			</pre>
			<form onSubmit={run} className="flex flex-wrap items-center gap-2">
				<Input className="min-w-56 flex-1 font-mono" placeholder="例如：df -h && free -m" autoComplete="off"
					value={cmd} onChange={(e) => setCmd(e.target.value)} onKeyDown={onKey} ref={inputRef} />
				<Label className="text-xs text-muted-foreground">超时
					<Input type="number" min={1} max={3600} className="w-20" value={timeout} onChange={(e) => setTimeoutS(e.target.value)} />
				</Label>
				<Label className="text-xs text-muted-foreground" title="声明为只读命令，允许连接失败时安全重试">
					<Checkbox checked={readOnly} onCheckedChange={(v) => setReadOnly(v === true)} />只读
				</Label>
				<Button type="submit" disabled={running}><PlayIcon />执行</Button>
			</form>
		</div>
	);
}

// ---------- 文件传输 ----------

function FilesTab({ server }: { server: Server }) {
	const [out, setOut] = useState("");
	return (
		<div className="grid gap-4 pt-2">
			<p className="text-sm text-muted-foreground">路径是运行 agent 的那台电脑上的本地路径。</p>
			<TransferForm server={server} kind="upload" onResult={setOut} />
			<TransferForm server={server} kind="download" onResult={setOut} />
			{out && <pre className="max-h-64 overflow-auto rounded-lg bg-muted p-3 font-mono text-xs">{out}</pre>}
		</div>
	);
}

function TransferForm({ server, kind, onResult }: { server: Server; kind: "upload" | "download"; onResult: (s: string) => void }) {
	const [local, setLocal] = useState("");
	const [remote, setRemote] = useState("");
	const [recursive, setRecursive] = useState(false);
	const [busy, setBusy] = useState(false);
	const up = kind === "upload";

	async function submit(e: React.FormEvent) {
		e.preventDefault();
		setBusy(true);
		onResult("传输中…");
		try {
			const { _job, ...r } = await runJob(kind, {
				serverId: server.id, timeoutMs: 3_600_000, payload: { local_path: local, remote_path: remote, recursive },
			});
			onResult(JSON.stringify(r, null, 2));
			if (r.success) toast.success(up ? "上传完成" : "下载完成"); else toast.error(r.error || "传输失败");
		} catch (err: any) { onResult(err.message); } finally { setBusy(false); }
	}

	const localField = <Field label="本机路径"><Input required placeholder={up ? "/Users/me/app.tar.gz" : "/Users/me/Downloads/error.log"} value={local} onChange={(e) => setLocal(e.target.value)} /></Field>;
	const remoteField = <Field label="远程路径"><Input required placeholder={up ? "/tmp/app.tar.gz" : "/var/log/nginx/error.log"} value={remote} onChange={(e) => setRemote(e.target.value)} /></Field>;
	return (
		<form onSubmit={submit} className="grid items-end gap-2 md:grid-cols-[1fr_1fr_auto_auto]">
			{up ? <>{localField}{remoteField}</> : <>{remoteField}{localField}</>}
			<Label className="h-9 text-sm"><Checkbox checked={recursive} onCheckedChange={(v) => setRecursive(v === true)} />目录</Label>
			<Button type="submit" disabled={busy}>{up ? <ArrowUpFromLineIcon /> : <ArrowDownToLineIcon />}{up ? "上传" : "下载"}</Button>
		</form>
	);
}

// ---------- 隧道 ----------

type Tunnel = { tunnel_id: string; alias: string; local_port: number; remote_host?: string; remote_port: number; status?: string };

function TunnelsTab({ server }: { server: Server }) {
	const [tunnels, setTunnels] = useState<Tunnel[] | null>(null);
	const [error, setError] = useState("");
	const [remotePort, setRemotePort] = useState("");
	const [remoteHost, setRemoteHost] = useState("");
	const [localPort, setLocalPort] = useState("");
	const [busy, setBusy] = useState(false);

	const load = useCallback(async () => {
		setError("");
		try {
			const r = await runJob("tunnel_list");
			setTunnels((r.tunnels || []).filter((t: Tunnel) => t.alias === server.alias));
		} catch (e: any) { setError(e.message); }
	}, [server.alias]);

	useEffect(() => { setTunnels(null); load(); }, [load]);

	async function start(e: React.FormEvent) {
		e.preventDefault();
		setBusy(true);
		try {
			const r = await runJob("tunnel_start", {
				serverId: server.id,
				payload: { remote_port: Number(remotePort), remote_host: remoteHost || null, local_port: localPort ? Number(localPort) : null },
			});
			if (r.success) toast.success(`隧道已启动：127.0.0.1:${r.local_port ?? ""}`); else toast.error(r.error || "启动失败");
			load();
		} catch (err: any) { toast.error(err.message); } finally { setBusy(false); }
	}

	async function stop(id: string) {
		try { await runJob("tunnel_stop", { payload: { tunnel_id: id } }); load(); } catch (e: any) { toast.error(e.message); }
	}

	return (
		<div className="grid gap-4 pt-2">
			<form onSubmit={start} className="grid items-end gap-2 md:grid-cols-[1fr_1fr_1fr_auto]">
				<Field label="远程端口"><Input type="number" required placeholder="3306" value={remotePort} onChange={(e) => setRemotePort(e.target.value)} /></Field>
				<Field label="远程主机（默认 localhost）"><Input placeholder="10.0.0.5" value={remoteHost} onChange={(e) => setRemoteHost(e.target.value)} /></Field>
				<Field label="本地端口（默认自动）"><Input type="number" placeholder="自动" value={localPort} onChange={(e) => setLocalPort(e.target.value)} /></Field>
				<Button type="submit" disabled={busy}>启动隧道</Button>
			</form>
			<p className="text-xs text-muted-foreground">隧道监听在运行 agent 的电脑的 127.0.0.1 上。</p>
			{error ? <p className="text-sm text-destructive">{error}</p>
				: tunnels === null ? <p className="text-sm text-muted-foreground">加载中…</p>
				: tunnels.length === 0 ? <p className="text-sm text-muted-foreground">该服务器没有活动隧道</p>
				: (
					<Table>
						<TableHeader><TableRow><TableHead>ID</TableHead><TableHead>本地</TableHead><TableHead>远程</TableHead><TableHead>状态</TableHead><TableHead /></TableRow></TableHeader>
						<TableBody>
							{tunnels.map((t) => (
								<TableRow key={t.tunnel_id}>
									<TableCell className="font-mono text-xs">{t.tunnel_id}</TableCell>
									<TableCell className="font-mono text-xs">127.0.0.1:{t.local_port}</TableCell>
									<TableCell className="font-mono text-xs">{t.remote_host || "localhost"}:{t.remote_port}</TableCell>
									<TableCell>{t.status}</TableCell>
									<TableCell className="text-right"><Button variant="outline" size="sm" onClick={() => stop(t.tunnel_id)}>停止</Button></TableCell>
								</TableRow>
							))}
						</TableBody>
					</Table>
				)}
		</div>
	);
}

// ---------- 操作日志 ----------

const JOB_LABEL: Record<string, string> = {
	exec: "命令", test: "测试", sync: "同步", sync_all: "全部同步", remove_local: "移除本机配置", upload: "上传", download: "下载",
	tunnel_start: "隧道", tunnel_stop: "停止隧道", tunnel_list: "隧道列表", local_list: "读取本机", import: "导入",
};

function jobSummary(j: Job) {
	const p = j.payload || {};
	if (j.type === "exec") return p.command;
	if (j.type === "upload") return `${p.local_path} → ${p.remote_path}`;
	if (j.type === "download") return `${p.remote_path} → ${p.local_path}`;
	if (j.type === "tunnel_start") return `${p.remote_host || "localhost"}:${p.remote_port}`;
	return "";
}

function LogsTab({ server }: { server: Server }) {
	const [jobs, setJobs] = useState<Job[] | null>(null);
	const [error, setError] = useState("");
	useEffect(() => {
		setJobs(null);
		api<Job[]>(`/api/jobs?server_id=${server.id}&limit=100`).then(setJobs, (e) => setError(e.message));
	}, [server.id]);

	if (error) return <p className="pt-2 text-sm text-destructive">{error}</p>;
	if (!jobs) return <p className="pt-2 text-sm text-muted-foreground">加载中…</p>;
	if (!jobs.length) return <p className="pt-2 text-sm text-muted-foreground">暂无日志</p>;
	return (
		<Table className="mt-2">
			<TableHeader><TableRow><TableHead>时间</TableHead><TableHead>类型</TableHead><TableHead>内容</TableHead><TableHead>结果</TableHead><TableHead>耗时</TableHead><TableHead>操作人</TableHead></TableRow></TableHeader>
			<TableBody>
				{jobs.map((j) => {
					const r = j.result || {};
					return (
						<TableRow key={j.id}>
							<TableCell className="whitespace-nowrap">{fmtTime(j.created_at)}</TableCell>
							<TableCell>{JOB_LABEL[j.type] ?? j.type}</TableCell>
							<TableCell className="max-w-72 truncate font-mono text-xs" title={(r.stdout || "") + (r.stderr || r.error || "")}>{jobSummary(j)}</TableCell>
							<TableCell>
								{j.status === "done" ? <Badge variant="secondary" className="text-emerald-600">成功</Badge>
									: j.status === "failed" ? <Badge variant="destructive">失败</Badge>
									: <Badge variant="outline">{j.status}</Badge>}
								{r.exit_code != null && <span className="ml-1 text-xs text-muted-foreground">({r.exit_code})</span>}
							</TableCell>
							<TableCell className="text-muted-foreground">{r.duration_ms != null ? `${r.duration_ms}ms` : ""}</TableCell>
							<TableCell className="text-muted-foreground">{j.created_by}</TableCell>
						</TableRow>
					);
				})}
			</TableBody>
		</Table>
	);
}
