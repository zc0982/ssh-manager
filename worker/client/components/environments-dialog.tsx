import { ArrowDownIcon, ArrowUpIcon, CheckIcon, PencilIcon, PlusIcon, Trash2Icon, XIcon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { api, type Environment } from "@/lib/api";
import { colorOf, ENV_COLORS } from "@/lib/envs";
import { cn } from "@/lib/utils";

const NAME_RE = /^[A-Za-z0-9._-]{1,32}$/;

export function ColorDot({ color, className }: { color: string; className?: string }) {
	return <span className={cn("inline-block size-2.5 shrink-0 rounded-full", colorOf(color).dot, className)} />;
}

/** 按环境颜色显示的徽标 */
export function EnvBadge({ env, envs }: { env: string; envs: Environment[] }) {
	const color = envs.find((e) => e.name === env)?.color;
	return <Badge variant="outline" className={colorOf(color).badge}>{env}</Badge>;
}

export function EnvSelectItems({ envs }: { envs: Environment[] }) {
	return envs.map((e) => (
		<SelectItem key={e.name} value={e.name}><span className="flex items-center gap-2"><ColorDot color={e.color} />{e.name}</span></SelectItem>
	));
}

function ColorSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
	return (
		<Select value={value} onValueChange={onChange}>
			<SelectTrigger className="w-24"><SelectValue /></SelectTrigger>
			<SelectContent>
				{Object.entries(ENV_COLORS).map(([k, c]) => (
					<SelectItem key={k} value={k}><span className="flex items-center gap-2"><ColorDot color={k} />{c.label}</span></SelectItem>
				))}
			</SelectContent>
		</Select>
	);
}

export function EnvironmentsDialog({ open, onOpenChange, envs, onChanged }: {
	open: boolean; onOpenChange: (o: boolean) => void; envs: Environment[]; onChanged: () => void;
}) {
	const [name, setName] = useState("");
	const [color, setColor] = useState("magenta");
	const [editing, setEditing] = useState<{ from: string; name: string; color: string } | null>(null);
	const [deleting, setDeleting] = useState<{ env: Environment; moveTo: string } | null>(null);
	const [busy, setBusy] = useState(false);

	async function run(fn: () => Promise<any>, ok?: (r: any) => string) {
		setBusy(true);
		try {
			const r = await fn();
			if (ok) toast.success(ok(r));
			onChanged();
			return true;
		} catch (e: any) { toast.error(e.message); return false; } finally { setBusy(false); }
	}

	const create = (e: React.FormEvent) => {
		e.preventDefault();
		const n = name.trim();
		if (!NAME_RE.test(n)) return toast.error("名称只能包含字母、数字、. _ -，最长 32 位");
		run(async () => { await api("/api/environments", { method: "POST", body: { name: n, color } }); setName(""); }, () => `已创建 ${n}`);
	};

	const save = () => {
		if (!editing) return;
		const n = editing.name.trim();
		if (!NAME_RE.test(n)) return toast.error("名称只能包含字母、数字、. _ -，最长 32 位");
		run(
			async () => {
				const r = await api(`/api/environments/${encodeURIComponent(editing.from)}`, { method: "PUT", body: { name: n, color: editing.color } });
				setEditing(null);
				return r;
			},
			(r) => (r.synced ? `已改名，正在把 ${r.synced} 台服务器同步到本机` : "已保存"),
		);
	};

	const remove = (env: Environment) => {
		if (env.server_count === 0) {
			if (!confirm(`删除环境 ${env.name}？`)) return;
			run(() => api(`/api/environments/${encodeURIComponent(env.name)}`, { method: "DELETE" }), () => "已删除");
			return;
		}
		const fallback = envs.find((e) => e.name !== env.name)?.name;
		if (!fallback) return toast.error("这是唯一的环境，且仍有服务器在使用，无法删除");
		setDeleting({ env, moveTo: fallback });
	};

	const confirmDelete = async () => {
		if (!deleting) return;
		const ok = await run(
			() => api(`/api/environments/${encodeURIComponent(deleting.env.name)}?move_to=${encodeURIComponent(deleting.moveTo)}`, { method: "DELETE" }),
			(r) => `已删除，${r.moved} 台服务器移到 ${deleting.moveTo} 并开始同步到本机`,
		);
		if (ok) setDeleting(null);
	};

	const move = (i: number, d: -1 | 1) => {
		const names = envs.map((e) => e.name);
		[names[i], names[i + d]] = [names[i + d], names[i]];
		run(() => api("/api/environments/_order", { method: "PUT", body: { names } }));
	};

	return (
		<Dialog open={open} onOpenChange={(o) => { onOpenChange(o); if (!o) { setEditing(null); setDeleting(null); } }}>
			<DialogContent className="sm:max-w-lg">
				<DialogHeader>
					<DialogTitle>分组管理</DialogTitle>
					<DialogDescription>
						分组就是服务器的「环境」字段，会写进本机 ~/.ssh/config 的 environment 元数据（ssh-skill 可按环境批量操作）。
						改名会自动更新所有相关服务器并同步到本机。
					</DialogDescription>
				</DialogHeader>

				{deleting ? (
					<div className="grid gap-3 rounded-md border border-destructive/40 p-3 text-sm">
						<p>环境 <b>{deleting.env.name}</b> 还有 {deleting.env.server_count} 台服务器。删除前把它们移到：</p>
						<Select value={deleting.moveTo} onValueChange={(v) => setDeleting({ ...deleting, moveTo: v })}>
							<SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
							<SelectContent><EnvSelectItems envs={envs.filter((e) => e.name !== deleting.env.name)} /></SelectContent>
						</Select>
						<DialogFooter>
							<Button variant="outline" onClick={() => setDeleting(null)}>取消</Button>
							<Button variant="destructive" disabled={busy} onClick={confirmDelete}>迁移并删除</Button>
						</DialogFooter>
					</div>
				) : (
					<>
						<div className="grid max-h-80 gap-1 overflow-y-auto">
							{envs.length === 0 && <p className="py-4 text-center text-sm text-muted-foreground">还没有分组</p>}
							{envs.map((e, i) => (
								<div key={e.name} className="flex items-center gap-2 rounded-md px-2 py-1.5 hover:bg-muted/50">
									{editing?.from === e.name ? (
										<>
											<ColorSelect value={editing.color} onChange={(c) => setEditing({ ...editing, color: c })} />
											<Input className="h-8 flex-1 font-mono" value={editing.name} autoFocus maxLength={32}
												onChange={(ev) => setEditing({ ...editing, name: ev.target.value })}
												onKeyDown={(ev) => { if (ev.key === "Enter") save(); if (ev.key === "Escape") setEditing(null); }} />
											<Button size="icon-sm" disabled={busy} onClick={save} title="保存"><CheckIcon /></Button>
											<Button size="icon-sm" variant="ghost" onClick={() => setEditing(null)} title="取消"><XIcon /></Button>
										</>
									) : (
										<>
											<ColorDot color={e.color} />
											<span className="min-w-0 flex-1 truncate font-mono text-sm">{e.name}</span>
											<span className="text-xs text-muted-foreground">{e.server_count} 台</span>
											<Button size="icon-sm" variant="ghost" disabled={busy || i === 0} onClick={() => move(i, -1)} title="上移"><ArrowUpIcon /></Button>
											<Button size="icon-sm" variant="ghost" disabled={busy || i === envs.length - 1} onClick={() => move(i, 1)} title="下移"><ArrowDownIcon /></Button>
											<Button size="icon-sm" variant="ghost" onClick={() => setEditing({ from: e.name, name: e.name, color: e.color })} title="编辑"><PencilIcon /></Button>
											<Button size="icon-sm" variant="ghost" className="text-destructive" disabled={busy} onClick={() => remove(e)} title="删除"><Trash2Icon /></Button>
										</>
									)}
								</div>
							))}
						</div>
						<Separator />
						<form onSubmit={create} className="flex items-center gap-2">
							<ColorSelect value={color} onChange={setColor} />
							<Input className="flex-1 font-mono" placeholder="新分组，如 test、client-a" maxLength={32} value={name} onChange={(ev) => setName(ev.target.value)} />
							<Button type="submit" disabled={busy || !name.trim()}><PlusIcon />新建</Button>
						</form>
					</>
				)}
			</DialogContent>
		</Dialog>
	);
}
