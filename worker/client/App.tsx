import { ChevronRightIcon, DownloadCloudIcon, FolderTreeIcon, KeyRoundIcon, LaptopIcon, PlusIcon, RefreshCwIcon, SearchIcon, ServerIcon, TerminalSquareIcon, TriangleAlertIcon } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Toaster } from "@/components/ui/sonner";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ImportDialog, KeysDialog, NewPcDialog } from "@/components/dialogs";
import { ColorDot, EnvBadge, EnvironmentsDialog } from "@/components/environments-dialog";
import { ServerDetail } from "@/components/server-detail";
import { ServerForm } from "@/components/server-form";
import { api, type Environment, fmtTime, runJob, type Server, type SshKey, type Status } from "@/lib/api";
import { cn } from "@/lib/utils";

export default function App() {
	const [me, setMe] = useState("");
	const [status, setStatus] = useState<Status | null>(null);
	const [servers, setServers] = useState<Server[]>([]);
	const [keys, setKeys] = useState<SshKey[]>([]);
	const [envs, setEnvs] = useState<Environment[]>([]);
	const [envsOpen, setEnvsOpen] = useState(false);
	const [collapsed, setCollapsed] = useState<Set<string>>(() => {
		try { return new Set(JSON.parse(localStorage.getItem("ssh-manager:collapsed") || "[]")); } catch { return new Set(); }
	});
	const [selectedId, setSelectedId] = useState<string | null>(null);
	const [query, setQuery] = useState("");
	const [formOpen, setFormOpen] = useState(false);
	const [editing, setEditing] = useState<Server | null>(null);
	const [keysOpen, setKeysOpen] = useState(false);
	const [newPcOpen, setNewPcOpen] = useState(false);
	const [importHosts, setImportHosts] = useState<any[] | null>(null);
	const [pulling, setPulling] = useState(false);
	const [loadingImport, setLoadingImport] = useState(false);

	const loadStatus = useCallback(() => api<Status>("/api/status").then(setStatus), []);
	const loadServers = useCallback(() => api<Server[]>("/api/servers").then(setServers), []);
	const loadKeys = useCallback(() => api<SshKey[]>("/api/keys").then(setKeys), []);
	const loadEnvs = useCallback(() => api<Environment[]>("/api/environments").then(setEnvs), []);

	useEffect(() => {
		const fail = (e: Error) => toast.error(e.message);
		api<{ email: string }>("/api/me").then((r) => setMe(r.email), fail);
		loadStatus().catch(fail);
		loadServers().catch(fail);
		loadKeys().catch(fail);
		loadEnvs().catch(fail);
		const t = setInterval(() => loadStatus().catch(() => {}), 30_000);
		return () => clearInterval(t);
	}, [loadStatus, loadServers, loadKeys, loadEnvs]);

	const toggleGroup = (id: string) => {
		const next = new Set(collapsed);
		if (next.has(id)) next.delete(id); else next.add(id);
		setCollapsed(next);
		try { localStorage.setItem("ssh-manager:collapsed", JSON.stringify([...next])); } catch { /* 隐私模式等情况下忽略 */ }
	};

	const selected = servers.find((s) => s.id === selectedId) ?? null;
	const visible = servers.filter((s) => {
		const q = query.trim().toLowerCase();
		return !q || [s.alias, s.hostname, s.description, s.location, ...s.tags].join(" ").toLowerCase().includes(q);
	});
	const online = status?.agents.some((a) => a.online) ?? false;
	const sections = useMemo(() => {
		const list = envs.map((e) => ({ id: e.name, name: e.name, color: e.color, servers: visible.filter((s) => s.environment === e.name) }));
		const known = new Set(envs.map((e) => e.name));
		const orphan = visible.filter((s) => !known.has(s.environment)); // 理论上不会出现（有外键）
		if (orphan.length) list.push({ id: "__other__", name: "其他", color: "gray", servers: orphan });
		// 搜索时隐藏空分组
		return list.filter((sec) => sec.servers.length || !query);
	}, [envs, visible, query]);

	async function pullAll() {
		setPulling(true);
		try {
			const r = await runJob("sync_all");
			const bad = Object.entries(r.errors || {});
			if (bad.length) toast.error(`失败 ${bad.length} 台：${bad.map(([a, e]) => `${a}(${e})`).join("，")}`);
			else toast.success(`已同步 ${(r.synced || []).length} 台到本机`);
			loadServers();
		} catch (e: any) { toast.error(e.message); } finally { setPulling(false); }
	}

	async function openImport() {
		setLoadingImport(true);
		try {
			const r = await runJob("local_list");
			if (!r.success) throw new Error(r.error || "读取本机配置失败");
			setImportHosts(r.hosts || []);
		} catch (e: any) { toast.error(e.message); } finally { setLoadingImport(false); }
	}

	return (
		<div className="flex h-dvh flex-col text-foreground">
			<Toaster richColors position="bottom-center" />
			<header className="flex flex-wrap items-center gap-3 border-b bg-background/70 px-4 py-2.5 backdrop-blur-md md:px-5">
				<div className="flex items-center gap-2 font-semibold tracking-wide"><TerminalSquareIcon className="size-5 text-primary" /><span className="neon-text">SSH Manager</span></div>
				<div className="flex flex-1 flex-wrap items-center gap-1.5">
					{status?.agents.length
						? status.agents.map((a) => (
							<Tooltip key={a.id}>
								<TooltipTrigger asChild>
									<Badge variant="outline" className="gap-1.5">
										<span className={cn("size-2 rounded-full", a.online ? "bg-emerald-500" : "bg-zinc-400")} />agent: {a.name}
									</Badge>
								</TooltipTrigger>
								<TooltipContent>{a.hostname} · 最后心跳 {fmtTime(a.last_seen)}</TooltipContent>
							</Tooltip>
						))
						: status && <Badge variant="outline" className="gap-1.5"><span className="size-2 rounded-full bg-red-500" />没有本机 agent</Badge>}
					{status?.public_key && (
						<Badge variant="outline" className="gap-1.5">
							<span className={cn("size-2 rounded-full", status.key_backup_has_env ? "bg-emerald-500" : "bg-amber-500")} />
							{status.key_backup_has_env ? "已备份" : status.key_backup ? "备份需更新" : "未备份"}
						</Badge>
					)}
					{me && <Badge variant="secondary" className="hidden sm:inline-flex">{me}</Badge>}
				</div>
				<div className="flex flex-wrap gap-1.5">
					<Button variant="ghost" size="sm" onClick={() => setNewPcOpen(true)}><LaptopIcon />新电脑</Button>
					<Button variant="ghost" size="sm" onClick={() => { loadEnvs(); setEnvsOpen(true); }}><FolderTreeIcon />分组</Button>
					<Button variant="ghost" size="sm" onClick={() => { loadKeys(); setKeysOpen(true); }}><KeyRoundIcon />密钥</Button>
					<Button variant="ghost" size="sm" disabled={loadingImport} onClick={openImport}><DownloadCloudIcon />从本机导入</Button>
					<Button variant="ghost" size="sm" disabled={pulling} onClick={pullAll}><RefreshCwIcon className={cn(pulling && "animate-spin")} />全部同步到本机</Button>
					<Button size="sm" onClick={() => { setEditing(null); setFormOpen(true); }}><PlusIcon />新增服务器</Button>
				</div>
			</header>

			{status && (!online || (status.public_key && !status.key_backup_has_env)) && (
				<Alert className="rounded-none border-x-0 border-t-0 bg-background/70 py-2 backdrop-blur-md">
					<TriangleAlertIcon />
					<AlertDescription className="flex flex-wrap items-center gap-2">
						{!online ? (
							<>
								{status.agents.length ? "没有在线的本机 agent，连接服务器的操作会排队等待。换了电脑？" : "还没有本机 agent。"}
								<Button variant="outline" size="xs" onClick={() => setNewPcOpen(true)}>新电脑设置向导</Button>
							</>
						) : (
							<>
								{status.key_backup ? "云端备份是旧格式，不含连接凭证" : "agent 私钥还没有备份"}，换电脑时将无法自动恢复。请在本机运行
								<code className="rounded bg-muted px-1 font-mono text-xs">./setup.sh backup</code>
							</>
						)}
					</AlertDescription>
				</Alert>
			)}

			<div className="grid min-h-0 flex-1 grid-rows-[auto_1fr] md:grid-cols-[280px_1fr] md:grid-rows-1">
				<aside className="flex max-h-[40vh] min-h-0 flex-col gap-2 border-b bg-background/60 p-3 backdrop-blur-md md:max-h-none md:border-r md:border-b-0">
					<div className="relative">
						<SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
						<Input className="pl-8" placeholder="搜索别名 / 主机 / 标签 / 备注" value={query} onChange={(e) => setQuery(e.target.value)} />
					</div>
					<div className="-mx-1 min-h-0 flex-1 overflow-x-hidden overflow-y-auto px-1">
						{envs.length === 0 ? (
							<ServerList servers={visible} envs={envs} selectedId={selectedId} onSelect={setSelectedId} />
						) : (
							<div className="flex flex-col gap-1">
								{sections.map((sec) => {
									const open = !collapsed.has(sec.id) || !!query;
									return (
										<section key={sec.id}>
											<button type="button" onClick={() => toggleGroup(sec.id)}
												className="flex w-full items-center gap-1.5 rounded-md px-1.5 py-1 font-mono text-xs font-medium text-muted-foreground hover:text-foreground">
												<ChevronRightIcon className={cn("size-3.5 transition-transform", open && "rotate-90")} />
												<ColorDot color={sec.color} className="size-2" />
												<span className="min-w-0 flex-1 truncate text-left">{sec.name}</span>
												<span className="tabular-nums">{sec.servers.length}</span>
											</button>
											{open && (sec.servers.length
												? <ServerList servers={sec.servers} envs={envs} selectedId={selectedId} onSelect={setSelectedId} />
												: <p className="py-1.5 pl-7 text-xs text-muted-foreground">空分组</p>)}
										</section>
									);
								})}
							</div>
						)}
						{!visible.length && <p className="px-2 py-6 text-center text-sm text-muted-foreground">暂无服务器</p>}
					</div>
				</aside>

				<main className="min-h-0 overflow-y-auto p-4 md:p-6">
					{selected ? (
						<ServerDetail
							key={selected.id}
							server={selected}
							keys={keys}
							envs={envs}
							onEdit={() => { setEditing(selected); setFormOpen(true); }}
							onChanged={() => loadServers()}
							onDeleted={() => { setSelectedId(null); loadServers(); loadKeys(); loadEnvs(); }}
						/>
					) : (
						<div className="flex h-full flex-col items-center justify-center gap-3 text-muted-foreground">
							<ServerIcon className="size-10 opacity-40" />
							<p>选择左侧服务器，或新增一台</p>
							<Button variant="outline" onClick={() => { setEditing(null); setFormOpen(true); }}><PlusIcon />新增服务器</Button>
						</div>
					)}
				</main>
			</div>

			<ServerForm
				open={formOpen}
				onOpenChange={setFormOpen}
				server={editing}
				keys={keys}
				envs={envs}
				publicKey={status?.public_key ?? null}
				onSaved={(s) => { setSelectedId(s.id); loadServers(); loadKeys(); loadEnvs(); }}
			/>
			<KeysDialog open={keysOpen} onOpenChange={setKeysOpen} keys={keys} publicKey={status?.public_key ?? null} onChanged={loadKeys} />
			<ImportDialog
				open={importHosts !== null}
				onOpenChange={(o) => !o && setImportHosts(null)}
				hosts={importHosts ?? []}
				onDone={() => { loadServers(); loadKeys(); }}
			/>
			<EnvironmentsDialog open={envsOpen} onOpenChange={setEnvsOpen} envs={envs} onChanged={() => { loadEnvs(); loadServers(); }} />
			<NewPcDialog open={newPcOpen} onOpenChange={setNewPcOpen} status={status} />
		</div>
	);
}

function ServerList({ servers, envs, selectedId, onSelect }: { servers: Server[]; envs: Environment[]; selectedId: string | null; onSelect: (id: string) => void }) {
	return (
		<ul className="flex flex-col gap-0.5">
			{servers.map((s) => (
				<li key={s.id} className="min-w-0">
					<button
						type="button"
						onClick={() => onSelect(s.id)}
						className={cn("w-full rounded-md px-2.5 py-2 text-left transition-colors hover:bg-muted", s.id === selectedId && "bg-muted")}
					>
						<div className="flex items-center gap-2 font-medium">
							<span className={cn("size-2 shrink-0 rounded-full", s.last_status === "ok" ? "bg-emerald-500" : s.last_status === "error" ? "bg-red-500" : "bg-zinc-300 dark:bg-zinc-600")} />
							<span className="min-w-0 flex-1 truncate">{s.alias}</span>
							<span className="shrink-0"><EnvBadge env={s.environment} envs={envs} /></span>
						</div>
						<div className="truncate pl-4 font-mono text-xs text-muted-foreground">{s.username}@{s.hostname}:{s.port}</div>
					</button>
				</li>
			))}
		</ul>
	);
}
