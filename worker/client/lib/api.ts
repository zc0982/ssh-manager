export type Server = {
	id: string;
	alias: string;
	hostname: string;
	port: number;
	username: string;
	auth_type: "key" | "password";
	identity_file: string | null;
	key_id: string | null;
	proxy_jump: string | null;
	environment: string;
	tags: string[];
	location: string;
	description: string;
	has_password: boolean;
	last_synced_at: string | null;
	last_connected_at: string | null;
	last_status: "ok" | "error" | null;
	created_at: string;
	updated_at: string;
};

/** 环境即服务器分组 */
export type Environment = { name: string; label: string; color: string; description: string; sort_order: number; server_count: number };

export type SshKey = { id: string; name: string; comment: string; public_key: string; fingerprint: string; created_at: string; used_by: number };

export type Agent = { id: string; name: string; hostname: string; last_seen: string; online: boolean };

export type Status = {
	agents: Agent[];
	public_key: JsonWebKey | null;
	key_backup: boolean;
	key_backup_has_env: boolean;
};

export type Job = {
	id: number;
	type: string;
	server_id: string | null;
	alias: string | null;
	payload: Record<string, any>;
	status: "queued" | "running" | "done" | "failed";
	result: JobResult | null;
	created_by: string;
	created_at: string;
};

export type JobResult = {
	success?: boolean;
	stdout?: string;
	stderr?: string;
	error?: string;
	exit_code?: number | null;
	duration_ms?: number;
	[k: string]: any;
};

export async function api<T = any>(path: string, opts: { method?: string; body?: unknown } = {}): Promise<T> {
	const res = await fetch(path, {
		method: opts.method ?? "GET",
		credentials: "same-origin",
		headers: { "Content-Type": "application/json", "X-SSH-Manager": "1" },
		body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
	});
	const data = await res.json().catch(() => ({}));
	if (!res.ok) throw new Error(data.detail || `${res.status} ${res.statusText}`);
	return data as T;
}

/** 等待本机 agent 完成任务 */
export async function waitJob(id: number, timeoutMs = 120_000): Promise<JobResult & { _job: Job }> {
	const deadline = Date.now() + timeoutMs;
	let delay = 400;
	while (Date.now() < deadline) {
		await new Promise((r) => setTimeout(r, delay));
		delay = Math.min(delay * 1.3, 1500);
		const job = await api<Job>(`/api/jobs/${id}`);
		if (job.status === "done" || job.status === "failed") return { ...(job.result ?? {}), _job: job };
	}
	throw new Error("等待本机 agent 超时，请确认 agent 正在运行");
}

/** 提交任务给本机 agent 并等待结果 */
export async function runJob(
	type: string,
	{ serverId = null, payload = {}, timeoutMs = 120_000 }: { serverId?: string | null; payload?: Record<string, unknown>; timeoutMs?: number } = {},
) {
	const job = await api<Job>("/api/jobs", { method: "POST", body: { type, server_id: serverId, payload } });
	return waitJob(job.id, timeoutMs);
}

export const fmtTime = (t?: string | null) => (t ? new Date(t).toLocaleString() : "—");
