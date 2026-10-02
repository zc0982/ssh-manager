import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api, type Job, type Server, type SshKey, waitJob } from "@/lib/api";
import { encryptPassword } from "@/lib/crypto";

const LOCAL = "__local__";
const ENVS = ["development", "staging", "production"];

type Props = {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	server: Server | null; // null = 新增
	keys: SshKey[];
	publicKey: JsonWebKey | null;
	onSaved: (server: Server) => void;
};

const empty = {
	alias: "", hostname: "", port: "22", username: "root", auth_type: "key" as "key" | "password",
	key_id: LOCAL, identity_file: "", password: "", proxy_jump: "", environment: "development",
	tags: "", location: "", description: "",
};

export function ServerForm({ open, onOpenChange, server, keys, publicKey, onSaved }: Props) {
	const [f, setF] = useState(empty);
	const [error, setError] = useState("");
	const [saving, setSaving] = useState(false);

	useEffect(() => {
		if (!open) return;
		setError("");
		setF(server
			? {
				alias: server.alias, hostname: server.hostname, port: String(server.port), username: server.username,
				auth_type: server.auth_type, key_id: server.key_id ?? LOCAL, identity_file: server.identity_file ?? "",
				password: "", proxy_jump: server.proxy_jump ?? "", environment: server.environment,
				tags: server.tags.join(", "), location: server.location, description: server.description,
			}
			: empty);
	}, [open, server]);

	const set = (k: keyof typeof empty) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });

	async function submit(e: React.FormEvent) {
		e.preventDefault();
		setError("");
		setSaving(true);
		try {
			const useCloudKey = f.auth_type === "key" && f.key_id !== LOCAL;
			const body: Record<string, unknown> = {
				alias: f.alias.trim(), hostname: f.hostname.trim(), port: Number(f.port) || 22, username: f.username.trim(),
				auth_type: f.auth_type, key_id: useCloudKey ? f.key_id : null,
				identity_file: f.auth_type === "key" && !useCloudKey ? f.identity_file.trim() || null : null,
				proxy_jump: f.proxy_jump.trim() || null, environment: f.environment,
				tags: f.tags.split(/[,，]/).map((t) => t.trim()).filter(Boolean),
				location: f.location.trim(), description: f.description.trim(),
			};
			if (f.auth_type === "password" && f.password) {
				if (/[\r\n]/.test(f.password)) throw new Error("密码不能包含换行");
				body.password_encrypted = await encryptPassword(publicKey, f.password);
			}
			const r = await api<{ server: Server; job: Job }>(server ? `/api/servers/${server.id}` : "/api/servers", {
				method: server ? "PUT" : "POST", body,
			});
			onOpenChange(false);
			onSaved(r.server);
			const id = toast.loading("已保存到云端，正在同步到本机…");
			const res = await waitJob(r.job.id, 60_000).catch((err) => ({ success: false, error: err.message }) as any);
			if (res.success) toast.success(`已${res.action === "created" ? "写入" : "更新"}本机 ~/.ssh/config`, { id });
			else toast.error(`同步到本机失败：${res.error}`, { id });
			onSaved(r.server);
		} catch (err: any) {
			setError(err.message);
		} finally {
			setSaving(false);
		}
	}

	return (
		<Dialog open={open} onOpenChange={onOpenChange}>
			<DialogContent className="sm:max-w-xl">
				<form onSubmit={submit} className="grid gap-4">
					<DialogHeader>
						<DialogTitle>{server ? `编辑 ${server.alias}` : "新增服务器"}</DialogTitle>
						<DialogDescription>保存后会自动同步到本机 agent 的 ~/.ssh/config。</DialogDescription>
					</DialogHeader>
					<div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
						<Field label="别名"><Input required pattern="[A-Za-z0-9._\-]+" placeholder="prod-web-01" value={f.alias} onChange={set("alias")} /></Field>
						<Field label="环境">
							<Select value={f.environment} onValueChange={(v) => setF({ ...f, environment: v })}>
								<SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
								<SelectContent>{ENVS.map((e) => <SelectItem key={e} value={e}>{e}</SelectItem>)}</SelectContent>
							</Select>
						</Field>
						<Field label="主机"><Input required placeholder="192.168.1.10" value={f.hostname} onChange={set("hostname")} /></Field>
						<Field label="端口"><Input type="number" min={1} max={65535} value={f.port} onChange={set("port")} /></Field>
						<Field label="用户名"><Input required value={f.username} onChange={set("username")} /></Field>
						<Field label="跳板机别名"><Input placeholder="可选" value={f.proxy_jump} onChange={set("proxy_jump")} /></Field>
						<Field label="认证方式">
							<Select value={f.auth_type} onValueChange={(v) => setF({ ...f, auth_type: v as "key" | "password" })}>
								<SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
								<SelectContent>
									<SelectItem value="key">密钥</SelectItem>
									<SelectItem value="password">密码</SelectItem>
								</SelectContent>
							</Select>
						</Field>
						{f.auth_type === "key" ? (
							<Field label="密钥">
								<Select value={f.key_id} onValueChange={(v) => setF({ ...f, key_id: v })}>
									<SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
									<SelectContent>
										<SelectItem value={LOCAL}>使用本机密钥文件路径</SelectItem>
										{keys.map((k) => <SelectItem key={k.id} value={k.id}>云端：{k.name}</SelectItem>)}
									</SelectContent>
								</Select>
							</Field>
						) : (
							<Field label="密码">
								<Input type="password" autoComplete="new-password" placeholder={server?.has_password ? "留空则保持不变" : ""}
									value={f.password} onChange={set("password")} />
							</Field>
						)}
						{f.auth_type === "key" && f.key_id === LOCAL && (
							<Field label="本机密钥文件路径" className="sm:col-span-2">
								<Input placeholder="~/.ssh/id_ed25519" value={f.identity_file} onChange={set("identity_file")} />
							</Field>
						)}
						<Field label="标签"><Input placeholder="web, nginx（逗号分隔）" value={f.tags} onChange={set("tags")} /></Field>
						<Field label="位置"><Input placeholder="阿里云-北京" value={f.location} onChange={set("location")} /></Field>
						<Field label="备注" className="sm:col-span-2"><Input value={f.description} onChange={set("description")} /></Field>
					</div>
					{f.auth_type === "password" && (
						<p className="text-xs text-muted-foreground">密码在浏览器里用本机 agent 的公钥加密后才上传，云端和 Worker 都看不到明文。</p>
					)}
					{error && <p className="text-sm text-destructive">{error}</p>}
					<DialogFooter>
						<Button type="button" variant="outline" onClick={() => onOpenChange(false)}>取消</Button>
						<Button type="submit" disabled={saving}>{saving ? "保存中…" : "保存并同步"}</Button>
					</DialogFooter>
				</form>
			</DialogContent>
		</Dialog>
	);
}

export function Field({ label, className, children }: { label: string; className?: string; children: React.ReactNode }) {
	return (
		<div className={`grid gap-1.5 ${className ?? ""}`}>
			<Label className="text-xs text-muted-foreground">{label}</Label>
			{children}
		</div>
	);
}
