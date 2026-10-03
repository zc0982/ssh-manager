import { CheckIcon, CopyIcon, ShieldAlertIcon, ShieldCheckIcon, ShieldQuestionIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { api, runJob, type Server } from "@/lib/api";

type Fp = { type: string; fingerprint: string; line: string };

/** 计算 known_hosts 行的 SHA256 指纹（与 ssh-keygen -l 相同） */
async function fingerprintOf(line: string): Promise<Fp | null> {
	const m = line.trim().match(/^(\S+) ((?:ssh-|ecdsa-|sk-)\S+) ([A-Za-z0-9+/]+={0,2})$/);
	if (!m) return null;
	const blob = Uint8Array.from(atob(m[3]), (c) => c.charCodeAt(0));
	const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", blob));
	return { type: m[2], fingerprint: "SHA256:" + btoa(String.fromCharCode(...hash)).replace(/=+$/, ""), line: line.trim() };
}

const typeLabel = (t: string) => t.replace(/^ssh-/, "").replace(/^ecdsa-sha2-/, "ECDSA ").toUpperCase();

/** 判断连接失败是不是因为主机密钥没有被信任 */
export const isHostKeyError = (text?: string) =>
	!!text && /host key verification failed|not found in known_hosts|server .* not found in known_hosts|REMOTE HOST IDENTIFICATION HAS CHANGED|No .* host key is known/i.test(text);

export function useFingerprints(lines: string[]) {
	const [fps, setFps] = useState<Fp[]>([]);
	const key = lines.join("\n");
	useEffect(() => {
		Promise.all(lines.map(fingerprintOf)).then((r) => setFps(r.filter(Boolean) as Fp[]));
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [key]);
	return fps;
}

/** 服务器详情里的「主机指纹」一项 */
export function HostKeyFact({ server, onTrust }: { server: Server; onTrust: () => void }) {
	const fps = useFingerprints(server.host_keys ?? []);
	if (!server.host_keys?.length) {
		return (
			<div className="flex flex-wrap items-center gap-2">
				<span className="flex items-center gap-1 text-amber-500"><ShieldQuestionIcon className="size-4" />未信任</span>
				<Button size="xs" variant="outline" onClick={onTrust}>获取并信任指纹</Button>
			</div>
		);
	}
	const main = fps.find((f) => f.type === "ssh-ed25519") ?? fps[0];
	return (
		<div className="flex flex-wrap items-center gap-2">
			<span className="flex min-w-0 items-center gap-1 text-emerald-500" title={fps.map((f) => `${typeLabel(f.type)} ${f.fingerprint}`).join("\n")}>
				<ShieldCheckIcon className="size-4 shrink-0" />
				<span className="truncate font-mono text-xs">{main ? `${typeLabel(main.type)} ${main.fingerprint}` : "已信任"}</span>
			</span>
			<Button size="xs" variant="ghost" onClick={onTrust}>重新获取</Button>
		</div>
	);
}

/** 获取主机公钥 -> 展示指纹 -> 用户确认后保存到云端并同步到本机 known_hosts */
export function TrustHostKeyDialog({ server, open, onOpenChange, onDone }: {
	server: Server; open: boolean; onOpenChange: (o: boolean) => void; onDone: () => void;
}) {
	const [scanning, setScanning] = useState(false);
	const [saving, setSaving] = useState(false);
	const [error, setError] = useState("");
	const [scanned, setScanned] = useState<Fp[] | null>(null);
	const [pasted, setPasted] = useState("");
	const [cmdCopied, setCmdCopied] = useState(false);
	const pattern = server.port === 22 ? server.hostname : `[${server.hostname}]:${server.port}`;
	const scanCmd = `ssh-keyscan${server.port === 22 ? "" : ` -p ${server.port}`} ${server.hostname}`;

	async function usePasted() {
		const lines = pasted.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
		const fps = (await Promise.all(lines.map(fingerprintOf))).filter((f): f is Fp => !!f && f.line.startsWith(pattern + " "));
		if (!fps.length) return setError(`没有找到 ${pattern} 的主机公钥行，请确认粘贴的是上面命令的输出`);
		setError("");
		setScanned(fps);
	}
	const trusted = useFingerprints(server.host_keys ?? []);
	const trustedSet = new Set(trusted.map((f) => f.line));
	const changed = !!scanned && trusted.length > 0 && scanned.some((f) => !trustedSet.has(f.line));

	useEffect(() => {
		if (!open) { setScanned(null); setError(""); setPasted(""); setCmdCopied(false); return; }
		setScanning(true);
		runJob("scan_host_key", { serverId: server.id, timeoutMs: 90_000 })
			.then(async (r) => {
				if (!r.success) throw new Error(r.error || "获取失败");
				setScanned((await Promise.all((r.lines as string[]).map(fingerprintOf))).filter(Boolean) as Fp[]);
			})
			.catch((e) => setError(e.message))
			.finally(() => setScanning(false));
	}, [open, server.id]);

	async function trust() {
		if (!scanned) return;
		setSaving(true);
		try {
			await api(`/api/servers/${server.id}/host-keys`, { method: "PUT", body: { lines: scanned.map((f) => f.line) } });
			toast.success(`已信任 ${server.alias} 的主机指纹，正在写入本机 known_hosts`);
			onOpenChange(false);
			onDone();
		} catch (e: any) { toast.error(e.message); } finally { setSaving(false); }
	}

	return (
		<Dialog open={open} onOpenChange={onOpenChange}>
			<DialogContent className="sm:max-w-lg">
				<DialogHeader>
					<DialogTitle>信任 {server.alias} 的主机指纹</DialogTitle>
					<DialogDescription>
						ssh-skill 会严格校验服务器身份，第一次连接前需要确认主机指纹。agent 只读取服务器公开的主机公钥，不会登录。
					</DialogDescription>
				</DialogHeader>
				{scanning && <p className="text-sm text-muted-foreground">正在从 {server.hostname}:{server.port} 获取主机公钥…</p>}
				{error && <p className="text-sm text-destructive">{error}</p>}
				{!scanned && (
					<div className="grid gap-2 border-t pt-3 text-sm">
						<p className="text-muted-foreground">
							{error ? "运行 agent 的电脑连不到这台设备（比如它在另一个局域网）。" : "不想等自动获取，或设备在别的局域网？"}
							在<b>能访问它的电脑</b>上运行下面的命令（终端或 Windows cmd 都可以），把输出粘贴进来：
						</p>
						<div className="flex flex-wrap items-center gap-2">
							<pre className="w-fit max-w-full overflow-x-auto rounded-md bg-muted px-3 py-2 font-mono text-xs">{scanCmd}</pre>
							<Button size="sm" variant="outline" onClick={async () => {
								try {
									await navigator.clipboard.writeText(scanCmd);
									setCmdCopied(true);
									toast.success("命令已复制");
								} catch { toast.error("复制失败，请手动选择复制"); }
							}}>
								{cmdCopied ? <CheckIcon /> : <CopyIcon />}{cmdCopied ? "已复制" : "复制命令"}
							</Button>
						</div>
						<Textarea rows={4} className="font-mono text-xs" placeholder={`${pattern} ssh-ed25519 AAAA…`} value={pasted} onChange={(e) => setPasted(e.target.value)} />
						<Button size="sm" variant="outline" className="w-fit" disabled={!pasted.trim()} onClick={usePasted}>使用粘贴的公钥</Button>
					</div>
				)}
				{scanned && (
					<>
						{changed && (
							<Alert variant="destructive">
								<ShieldAlertIcon />
								<AlertTitle>主机指纹和之前信任的不同</AlertTitle>
								<AlertDescription>可能是设备重装或重置过；如果没有，可能有人在冒充这台服务器。确认原因后再继续。</AlertDescription>
							</Alert>
						)}
						<div className="grid gap-1.5 rounded-md border p-3">
							{scanned.map((f) => (
								<div key={f.line} className="flex flex-wrap items-baseline gap-x-3 font-mono text-xs">
									<span className="w-20 shrink-0 text-muted-foreground">{typeLabel(f.type)}</span>
									<span className="break-all">{f.fingerprint}</span>
									{trustedSet.has(f.line) && <span className="text-emerald-500">已信任</span>}
								</div>
							))}
						</div>
						<p className="text-xs text-muted-foreground">
							可以在设备上运行 <code className="rounded bg-muted px-1">for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf $f; done</code> 核对；
							局域网里自己的设备通常可以直接信任。信任后会保存到云端，每台电脑同步时都会写入 known_hosts。
						</p>
					</>
				)}
				<DialogFooter>
					<Button variant="outline" onClick={() => onOpenChange(false)}>取消</Button>
					<Button disabled={!scanned || saving} variant={changed ? "destructive" : "default"} onClick={trust}>
						{changed ? "确认更换并信任" : "信任这些指纹"}
					</Button>
				</DialogFooter>
			</DialogContent>
		</Dialog>
	);
}
