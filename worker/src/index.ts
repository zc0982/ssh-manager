import postgres from "postgres";
import { authenticate, type AuthEnv, type Identity } from "./auth.ts";

interface Env extends AuthEnv {
	HYPERDRIVE: Hyperdrive;
	ASSETS: Fetcher;
}

type Sql = postgres.Sql;

const ALIAS_RE = /^[A-Za-z0-9._-]+$/;
const TOKEN_RE = /^\S+$/;
const LINE_RE = /^[^\r\n]*$/;
const TAG_RE = /^[^\s,-][^\s,]*$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SEALED_RE = /^v1\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+$/;
const MAX_SEALED = 120_000;
const ENV_RE = /^[A-Za-z0-9._-]{1,32}$/;
const ENV_COLORS = new Set(["magenta", "cyan", "yellow", "purple", "green", "orange", "blue", "gray"]);
const MAX_RESULT_TEXT = 100_000;
const AGENT_ONLINE_MS = 60_000;
const POLL_WAIT_MS = 20_000;

// 网页可以提交的任务类型；需要绑定服务器的类型在 SERVER_JOBS 中
const USER_JOBS = new Set(["test", "exec", "upload", "download", "tunnel_start", "tunnel_stop", "tunnel_list", "sync", "sync_all", "local_list", "import"]);
const SERVER_JOBS = new Set(["test", "exec", "upload", "download", "tunnel_start", "sync"]);

class HttpError extends Error {
	constructor(public status: number, message: string) {
		super(message);
	}
}

const json = (data: unknown, status = 200) =>
	new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });

async function body<T = any>(req: Request): Promise<T> {
	try {
		return (await req.json()) as T;
	} catch {
		throw new HttpError(400, "请求体不是合法 JSON");
	}
}

// ---------- 校验 ----------

function str(v: unknown, field: string, { required = false, re = LINE_RE, max = 255 } = {}): string | null {
	if (v === undefined || v === null || v === "") {
		if (required) throw new HttpError(422, `${field} 不能为空`);
		return null;
	}
	if (typeof v !== "string" || v.length > max || !re.test(v)) throw new HttpError(422, `${field} 格式不正确`);
	return v;
}

function parseServer(b: any) {
	const port = b.port === undefined ? 22 : Number(b.port);
	if (!Number.isInteger(port) || port < 1 || port > 65535) throw new HttpError(422, "端口必须在 1-65535 之间");
	const auth_type = b.auth_type ?? "key";
	if (auth_type !== "key" && auth_type !== "password") throw new HttpError(422, "auth_type 只能是 key 或 password");
	const tags = Array.isArray(b.tags) ? b.tags.map((t: unknown) => String(t).trim()).filter(Boolean) : [];
	for (const t of tags) if (!TAG_RE.test(t)) throw new HttpError(422, `非法标签：${t}`);
	const key_id = auth_type === "key" ? str(b.key_id, "云端密钥", { re: UUID_RE, max: 36 }) : null;
	return {
		alias: str(b.alias, "别名", { required: true, re: ALIAS_RE, max: 64 })!,
		hostname: str(b.hostname, "主机", { required: true, re: TOKEN_RE })!,
		port,
		username: str(b.username, "用户名", { required: true, re: TOKEN_RE, max: 64 })!,
		auth_type,
		identity_file: auth_type === "key" && !key_id ? str(b.identity_file, "密钥文件", { max: 1024 }) : null,
		key_id,
		proxy_jump: str(b.proxy_jump, "跳板机", { re: ALIAS_RE, max: 64 }),
		environment: str(b.environment, "环境", { re: ENV_RE, max: 32 }) ?? "development",
		tags,
		location: str(b.location, "位置") ?? "",
		description: str(b.description, "备注", { max: 1000 }) ?? "",
	};
}

async function assertEnv(sql: Sql, name: string) {
	const [e] = await sql`select 1 from environments where name = ${name}`;
	if (!e) throw new HttpError(422, `环境 ${name} 不存在，请先在「分组」里创建`);
}

function parseEnv(b: any) {
	const name = str(typeof b?.name === "string" ? b.name.trim() : b?.name, "环境名称", { required: true, re: ENV_RE, max: 32 })!;
	const color = ENV_COLORS.has(b?.color) ? b.color : "magenta";
	return { name, color, description: str(b?.description, "说明", { max: 200 }) ?? "" };
}

/** 环境改名/迁移后，让受影响服务器的 ~/.ssh/config 也更新 */
async function resyncEnv(sql: Sql, who: string, env: string) {
	const rows = await sql`select id, alias from servers where environment = ${env}`;
	for (const r of rows) await enqueue(sql, who, "sync", r);
	return rows.length;
}

async function assertKey(sql: Sql, keyId: string | null) {
	if (!keyId) return;
	const [k] = await sql`select 1 from ssh_keys where id = ${keyId}`;
	if (!k) throw new HttpError(422, "选择的云端密钥不存在");
}

function parseKey(b: any) {
	const name = str(b?.name, "密钥名称", { required: true, re: ALIAS_RE, max: 64 })!;
	const key_encrypted = str(b?.key_encrypted, "密钥密文", { required: true, re: SEALED_RE, max: MAX_SEALED })!;
	return { name, key_encrypted, comment: str(b?.comment, "说明", { max: 500 }) ?? "" };
}

/** 给服务器行附上它引用的密钥（含密文），供 agent 解密写入本机 */
async function attachKeys(sql: Sql, servers: any[]) {
	const ids = [...new Set(servers.map((s) => s.key_id).filter(Boolean))];
	if (!ids.length) return;
	const keys = await sql`select id, name, key_encrypted from ssh_keys where id = any(${ids})`;
	const byId = new Map(keys.map((k: any) => [k.id, k]));
	for (const s of servers) if (s.key_id) s.key = byId.get(s.key_id) ?? null;
}

function publicServer(s: any) {
	const { password_encrypted, ...rest } = s;
	return { ...rest, has_password: !!password_encrypted };
}

// ---------- 任务 ----------

async function enqueue(sql: Sql, who: string, type: string, server: any | null, payload: Record<string, unknown> = {}) {
	const [job] = await sql`
		insert into jobs (type, server_id, alias, payload, created_by)
		values (${type}, ${server?.id ?? null}, ${server?.alias ?? (payload.alias as string) ?? null}, ${sql.json(payload as any)}, ${who})
		returning *`;
	return job;
}

/** 超时未回传的任务标记为失败（agent 崩溃或掉线时） */
async function reapStale(sql: Sql) {
	await sql`
		update jobs set status = 'failed', finished_at = now(),
			result = jsonb_build_object('success', false, 'error', 'agent 未在时限内回传结果')
		where status = 'running'
		  and started_at < now() - make_interval(secs => coalesce((payload->>'timeout')::int, 60) * 4 + 120)`;
	await sql`
		update jobs set status = 'failed', finished_at = now(),
			result = jsonb_build_object('success', false, 'error', '没有在线的本机 agent 领取该任务')
		where status = 'queued' and created_at < now() - interval '10 minutes'`;
}

function clip(v: unknown) {
	return typeof v === "string" && v.length > MAX_RESULT_TEXT ? v.slice(0, MAX_RESULT_TEXT) + "\n…(已截断)" : v;
}

// ---------- 用户 API ----------

async function userApi(req: Request, sql: Sql, me: string, path: string[]): Promise<Response> {
	const m = req.method;
	const [a, b, c] = path;

	if (a === "me" && m === "GET") return json({ email: me });

	if (a === "status" && m === "GET") {
		const agents = await sql`select id, name, hostname, version, last_seen from agents order by last_seen desc`;
		const [key] = await sql`select value from settings where key = 'agent_public_key'`;
		const [backup] = await sql`select value->>'has_env' as has_env from settings where key = 'agent_key_backup'`;
		const now = Date.now();
		return json({
			agents: agents.map((x: any) => ({ ...x, online: now - new Date(x.last_seen).getTime() < AGENT_ONLINE_MS })),
			public_key: key?.value ?? null,
			key_backup: !!backup,
			key_backup_has_env: backup?.has_env === "true",
		});
	}

	if (a === "setup-bundle" && m === "GET") {
		// 新电脑设置文件：服务地址 + 用主密码加密的备份（只能在本机用主密码解开）
		const [row] = await sql`select value from settings where key = 'agent_key_backup'`;
		if (!row) throw new HttpError(404, "还没有备份，请先在已运行 agent 的电脑上执行 ./setup.sh backup");
		const origin = new URL(req.url).origin;
		return new Response(JSON.stringify({ kind: "ssh-manager-setup", url: origin, created_at: new Date().toISOString(), backup: row.value }, null, 2), {
			headers: {
				"content-type": "application/json; charset=utf-8",
				"content-disposition": 'attachment; filename="ssh-manager-setup.json"',
				"cache-control": "no-store",
			},
		});
	}

	if (a === "environments") {
		if (!b && m === "GET") {
			return json(await sql`
				select e.*, (select count(*)::int from servers s where s.environment = e.name) as server_count
				from environments e order by e.sort_order, e.name`);
		}
		if (!b && m === "POST") {
			const e = parseEnv(await body(req));
			const dup = await sql`select 1 from environments where name = ${e.name}`;
			if (dup.length) throw new HttpError(409, `环境 ${e.name} 已存在`);
			const [row] = await sql`
				insert into environments (name, color, description, sort_order)
				values (${e.name}, ${e.color}, ${e.description}, (select coalesce(max(sort_order), 0) + 1 from environments))
				returning *`;
			return json({ ...row, server_count: 0 }, 201);
		}
		if (b === "_order" && m === "PUT") {
			const { names } = await body(req);
			if (!Array.isArray(names) || names.some((x) => typeof x !== "string" || !ENV_RE.test(x))) throw new HttpError(422, "names 格式不正确");
			await sql.begin(async (tx: any) => {
				for (const [i, name] of names.entries()) await tx`update environments set sort_order = ${i + 1} where name = ${name}`;
			});
			return json({ ok: true });
		}
		if (b && !c) {
			const name = decodeURIComponent(b);
			const [existing] = await sql`select * from environments where name = ${name}`;
			if (!existing) throw new HttpError(404, "环境不存在");
			if (m === "PUT") {
				const e = parseEnv(await body(req));
				if (e.name !== name) {
					const dup = await sql`select 1 from environments where name = ${e.name}`;
					if (dup.length) throw new HttpError(409, `环境 ${e.name} 已存在`);
				}
				// 外键 on update cascade：改名会同步更新所有服务器的 environment
				const [row] = await sql`update environments set ${sql(e as any)} where name = ${name} returning *`;
				const synced = e.name !== name ? await resyncEnv(sql, me, e.name) : 0;
				return json({ ...row, synced });
			}
			if (m === "DELETE") {
				const moveTo = new URL(req.url).searchParams.get("move_to");
				const [{ n }] = await sql`select count(*)::int as n from servers where environment = ${name}`;
				let moved: any[] = [];
				if (n > 0) {
					if (!moveTo) throw new HttpError(409, `还有 ${n} 台服务器使用该环境，请选择要迁移到的环境`);
					if (moveTo === name) throw new HttpError(422, "不能迁移到自身");
					await assertEnv(sql, moveTo);
					moved = await sql`update servers set environment = ${moveTo} where environment = ${name} returning id, alias`;
				}
				await sql`delete from environments where name = ${name}`;
				for (const r of moved) await enqueue(sql, me, "sync", r);
				return json({ deleted: true, moved: moved.length });
			}
		}
	}

	if (a === "keys") {
		if (!b && m === "GET") {
			return json(await sql`
				select k.id, k.name, k.comment, k.created_by, k.created_at,
					(select count(*)::int from servers s where s.key_id = k.id) as used_by
				from ssh_keys k order by k.name`);
		}
		if (!b && m === "POST") {
			const k = parseKey(await body(req));
			const dup = await sql`select 1 from ssh_keys where name = ${k.name}`;
			if (dup.length) throw new HttpError(409, `密钥名 ${k.name} 已存在`);
			const [row] = await sql`insert into ssh_keys ${sql({ ...k, created_by: me } as any)} returning id, name, comment, created_by, created_at`;
			return json({ ...row, used_by: 0 }, 201);
		}
		if (b && m === "DELETE") {
			const users = await sql`select alias from servers where key_id = ${b}`;
			if (users.length) throw new HttpError(409, `仍有服务器在使用该密钥：${users.map((u: any) => u.alias).join(", ")}`);
			await sql`delete from ssh_keys where id = ${b}`;
			return json({ deleted: true });
		}
	}

	if (a === "servers") {
		if (!b && m === "GET") return json((await sql`select * from servers order by alias`).map(publicServer));

		if (!b && m === "POST") {
			const input = await body(req);
			const s = parseServer(input);
			const enc = s.auth_type === "password" ? str(input.password_encrypted, "密码密文", { max: 2048 }) : null;
			if (s.auth_type === "password" && !enc) throw new HttpError(422, "密码认证需要填写密码");
			await assertKey(sql, s.key_id);
			await assertEnv(sql, s.environment);
			const exists = await sql`select 1 from servers where alias = ${s.alias}`;
			if (exists.length) throw new HttpError(409, `别名 ${s.alias} 已存在`);
			const [row] = await sql`insert into servers ${sql({ ...s, password_encrypted: enc } as any)} returning *`;
			const job = await enqueue(sql, me, "sync", row);
			return json({ server: publicServer(row), job }, 201);
		}

		if (b && !c) {
			const [existing] = await sql`select * from servers where id = ${b}`;
			if (!existing) throw new HttpError(404, "服务器不存在");

			if (m === "GET") return json(publicServer(existing));

			if (m === "PUT") {
				const input = await body(req);
				const s = parseServer(input);
				await assertKey(sql, s.key_id);
				await assertEnv(sql, s.environment);
				let enc: string | null = existing.password_encrypted;
				if (s.auth_type === "key" || input.clear_password) enc = null;
				const newEnc = str(input.password_encrypted, "密码密文", { max: 2048 });
				if (s.auth_type === "password" && newEnc) enc = newEnc;
				if (s.auth_type === "password" && !enc) throw new HttpError(422, "密码认证需要填写密码");
				if (s.alias !== existing.alias) {
					const dup = await sql`select 1 from servers where alias = ${s.alias} and id <> ${b}`;
					if (dup.length) throw new HttpError(409, `别名 ${s.alias} 已存在`);
				}
				const [row] = await sql`update servers set ${sql({ ...s, password_encrypted: enc } as any)} where id = ${b} returning *`;
				if (s.alias !== existing.alias) await enqueue(sql, me, "remove_local", null, { alias: existing.alias });
				const job = await enqueue(sql, me, "sync", row);
				return json({ server: publicServer(row), job });
			}

			if (m === "DELETE") {
				await sql`delete from servers where id = ${b}`;
				const job = await enqueue(sql, me, "remove_local", null, { alias: existing.alias });
				return json({ deleted: true, job });
			}
		}
	}

	if (a === "jobs") {
		await reapStale(sql);
		if (!b && m === "GET") {
			const url = new URL(req.url);
			const serverId = url.searchParams.get("server_id");
			const limit = Math.min(Math.max(Number(url.searchParams.get("limit")) || 50, 1), 200);
			const rows = serverId
				? await sql`select * from jobs where server_id = ${serverId} order by id desc limit ${limit}`
				: await sql`select * from jobs order by id desc limit ${limit}`;
			return json(rows);
		}
		if (!b && m === "POST") {
			const input = await body(req);
			const type = String(input.type ?? "");
			if (!USER_JOBS.has(type)) throw new HttpError(422, `不支持的任务类型：${type}`);
			const payload = input.payload && typeof input.payload === "object" ? input.payload : {};
			if (JSON.stringify(payload).length > 20_000) throw new HttpError(413, "任务参数过大");
			let server = null;
			if (SERVER_JOBS.has(type)) {
				[server] = await sql`select id, alias from servers where id = ${String(input.server_id ?? "")}`;
				if (!server) throw new HttpError(404, "服务器不存在");
			}
			return json(await enqueue(sql, me, type, server, payload), 201);
		}
		if (b && m === "GET") {
			const [job] = await sql`select * from jobs where id = ${Number(b)}`;
			if (!job) throw new HttpError(404, "任务不存在");
			return json(job);
		}
	}

	throw new HttpError(404, "Not Found");
}

// ---------- agent API ----------

async function agentApi(req: Request, sql: Sql, path: string[]): Promise<Response> {
	const [a, b, c] = path;

	if (a === "hello" && req.method === "POST") {
		const input = await body(req);
		const name = str(input.name, "name", { required: true, re: ALIAS_RE, max: 64 })!;
		const [agent] = await sql`
			insert into agents (name, hostname, version) values (${name}, ${String(input.hostname ?? "")}, ${String(input.version ?? "")})
			on conflict (name) do update set hostname = excluded.hostname, version = excluded.version, last_seen = now()
			returning *`;
		// 首个 agent 注册公钥；之后的 agent 必须使用同一把密钥（多台电脑共用私钥文件）
		if (input.public_key && typeof input.public_key === "object") {
			await sql`insert into settings (key, value) values ('agent_public_key', ${sql.json(input.public_key)}) on conflict (key) do nothing`;
		}
		const [key] = await sql`select value from settings where key = 'agent_public_key'`;
		return json({ agent_id: agent.id, public_key: key?.value ?? null });
	}

	if (a === "servers" && req.method === "GET") {
		const servers = await sql`select * from servers order by alias`;
		await attachKeys(sql, servers);
		return json(servers);
	}

	if (a === "key-backup") {
		if (req.method === "GET") {
			const [row] = await sql`select value from settings where key = 'agent_key_backup'`;
			return json({ backup: row?.value ?? null });
		}
		if (req.method === "PUT") {
			const { backup } = await body(req);
			if (!backup || typeof backup !== "object" || backup.kdf !== "scrypt" || typeof backup.ciphertext !== "string" || JSON.stringify(backup).length > 20_000) {
				throw new HttpError(422, "备份格式不正确");
			}
			const [pub] = await sql`select value from settings where key = 'agent_public_key'`;
			if (pub && pub.value.n !== backup.public_n) throw new HttpError(409, "备份的私钥与云端登记的公钥不匹配");
			await sql`insert into settings (key, value) values ('agent_key_backup', ${sql.json(backup)})
				on conflict (key) do update set value = excluded.value`;
			return json({ ok: true });
		}
	}

	if (a === "poll" && req.method === "POST") {
		const { agent_id } = await body(req);
		const deadline = Date.now() + POLL_WAIT_MS;
		while (true) {
			await sql`update agents set last_seen = now() where id = ${agent_id}`;
			const [job] = await sql`
				update jobs set status = 'running', started_at = now(), agent_id = ${agent_id}
				where id = (
					select id from jobs where status = 'queued' and (agent_id is null or agent_id = ${agent_id})
					order by id limit 1 for update skip locked)
				returning *`;
			if (job) {
				// 附带执行任务所需的服务器信息（包括密码密文，由 agent 本地解密）
				if (job.type === "sync_all" || job.type === "local_list" || job.type === "import") {
					job.servers = await sql`select * from servers order by alias`;
					await attachKeys(sql, job.servers);
					if (job.type === "import") job.keys = await sql`select id, name, key_encrypted from ssh_keys`;
				} else if (job.server_id) {
					[job.server] = await sql`select * from servers where id = ${job.server_id}`;
					if (job.server) await attachKeys(sql, [job.server]);
				}
				return json({ job });
			}
			if (Date.now() >= deadline) return json({ job: null });
			await new Promise((r) => setTimeout(r, 1000));
		}
	}

	if (a === "jobs" && b && c === "result" && req.method === "POST") {
		const id = Number(b);
		const input = await body(req);
		const result = input.result && typeof input.result === "object" ? input.result : {};
		for (const k of ["stdout", "stderr", "error", "message"]) result[k] = clip(result[k]);
		const ok = !!result.success;

		const [job] = await sql`select * from jobs where id = ${id} and status = 'running'`;
		if (!job) throw new HttpError(404, "任务不存在或已结束");

		// 任务的副作用
		if (job.type === "import" && Array.isArray(input.import_rows)) {
			const imported: string[] = [];
			const errors: Record<string, string> = {};
			for (const raw of input.import_rows) {
				try {
					if (raw?.key) {
						// agent 已比对过：existing 表示云端已有同内容的同名密钥
						const k = raw.key.existing
							? { name: str(raw.key.name, "密钥名称", { required: true, re: ALIAS_RE, max: 64 })! }
							: parseKey(raw.key);
						let [row] = await sql`select id from ssh_keys where name = ${k.name}`;
						if (!row && !raw.key.existing) [row] = await sql`insert into ssh_keys ${sql({ ...(k as any), created_by: job.created_by })} returning id`;
						if (!row) throw new HttpError(422, `云端密钥 ${k.name} 不存在`);
						raw.key_id = row.id;
					}
					const s = parseServer(raw);
					// 本机配置里的环境值不在列表中时自动创建
					await sql`insert into environments (name, color, sort_order)
						values (${s.environment}, 'gray', (select coalesce(max(sort_order), 0) + 1 from environments))
						on conflict (name) do nothing`;
					const enc = s.auth_type === "password" ? str(raw.password_encrypted, "密码密文", { max: 2048 }) : null;
					await sql`insert into servers ${sql({ ...s, password_encrypted: enc, last_synced_at: new Date() } as any)}`;
					imported.push(s.alias);
				} catch (e: any) {
					errors[String(raw?.alias)] = e.message;
				}
			}
			Object.assign(result, { imported, errors });
		}
		if (job.server_id && (job.type === "test" || job.type === "exec")) {
			await sql`update servers set last_connected_at = now(), last_status = ${ok ? "ok" : "error"} where id = ${job.server_id}`;
		}
		if (ok && (job.type === "sync" || job.type === "test" || job.type === "exec" || job.type === "upload" || job.type === "download" || job.type === "tunnel_start") && job.server_id) {
			await sql`update servers set last_synced_at = now() where id = ${job.server_id}`;
		}
		if (ok && job.type === "sync_all") {
			await sql`update servers set last_synced_at = now() where alias = any(${(result.synced as string[]) ?? []})`;
		}

		await sql`update jobs set status = ${ok ? "done" : "failed"}, result = ${sql.json(result)}, finished_at = now() where id = ${id}`;
		return json({ ok: true });
	}

	throw new HttpError(404, "Not Found");
}

// ---------- 入口 ----------

export default {
	async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(req.url);
		if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(req);

		const who: Identity | null = await authenticate(req, env);
		if (!who) return json({ detail: "未授权" }, 401);

		// 浏览器请求必须带自定义头（防止跨站表单提交）
		if (who.kind === "user" && req.method !== "GET" && req.headers.get("x-ssh-manager") !== "1") {
			return json({ detail: "missing X-SSH-Manager header" }, 403);
		}

		const sql = postgres(env.HYPERDRIVE.connectionString, { max: 5, prepare: true });
		try {
			const parts = url.pathname.slice("/api/".length).split("/").filter(Boolean);
			if (parts[0] === "agent") {
				if (who.kind !== "agent") return json({ detail: "仅限 agent" }, 403);
				return await agentApi(req, sql, parts.slice(1));
			}
			if (who.kind !== "user") return json({ detail: "仅限用户" }, 403);
			return await userApi(req, sql, who.email, parts);
		} catch (e: any) {
			if (e instanceof HttpError) return json({ detail: e.message }, e.status);
			console.error(e);
			return json({ detail: `服务器错误：${e?.message ?? e}` }, 500);
		} finally {
			ctx.waitUntil(sql.end());
		}
	},
} satisfies ExportedHandler<Env>;
