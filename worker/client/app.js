const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const state = { servers: [], selected: null, env: "all", tab: "exec", history: [], term: {}, status: null };

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-SSH-Manager": "1", ...(opts.headers || {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `${res.status} ${res.statusText}`);
  return data;
}

/** 提交任务给本机 agent 并等待结果 */
async function runJob(type, { serverId = null, payload = {}, timeoutMs = 120_000 } = {}) {
  const job = await api("/api/jobs", { method: "POST", body: { type, server_id: serverId, payload } });
  return waitJob(job.id, timeoutMs);
}

async function waitJob(id, timeoutMs = 120_000) {
  const deadline = Date.now() + timeoutMs;
  let delay = 400;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, delay));
    delay = Math.min(delay * 1.3, 1500);
    const job = await api(`/api/jobs/${id}`);
    if (job.status === "done" || job.status === "failed") return { ...(job.result || {}), _job: job };
  }
  throw new Error("等待本机 agent 超时，请确认 agent 正在运行");
}

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(t._h);
  t._h = setTimeout(() => t.classList.remove("show"), 3500);
}

async function busy(btn, fn) {
  if (btn) btn.disabled = true;
  try { return await fn(); } catch (e) { toast(e.message); } finally { if (btn) btn.disabled = false; }
}

// ---------- 密码加密（RSA-OAEP，agent 公钥） ----------

let publicKey = null;
async function encryptPassword(plain) {
  const jwk = state.status?.public_key;
  if (!jwk) throw new Error("本机 agent 尚未注册公钥，请先启动 agent");
  publicKey ??= await crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
  const buf = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, new TextEncoder().encode(plain));
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

// ---------- 状态与列表 ----------

const agentOnline = () => (state.status?.agents || []).some((a) => a.online);

async function loadStatus() {
  const [me, s] = await Promise.all([api("/api/me"), api("/api/status")]);
  state.status = s;
  const pill = (ok, label, title = "") => `<span class="pill ${ok ? "ok" : "bad"}" title="${esc(title)}">${esc(label)}</span>`;
  const agents = s.agents.length
    ? s.agents.map((a) => pill(a.online, `agent: ${a.name}`, `${a.hostname} · 最后心跳 ${fmtTime(a.last_seen)}`)).join("")
    : pill(false, "没有本机 agent", "在本机运行 agent 后才能连接服务器");
  $("#status").innerHTML = agents + `<span class="pill" title="Cloudflare Access 登录身份">${esc(me.email)}</span>`;
}

async function loadServers() {
  state.servers = await api("/api/servers");
  renderEnvFilter();
  renderList();
  if (state.selected) {
    state.selected = state.servers.find((x) => x.id === state.selected.id) || null;
    renderDetail();
  }
}

function renderEnvFilter() {
  const envs = ["all", ...new Set(state.servers.map((s) => s.environment))];
  $("#env-filter").innerHTML = envs
    .map((e) => `<button class="chip ${e === state.env ? "active" : ""}" data-env="${esc(e)}">${e === "all" ? "全部" : esc(e)}</button>`)
    .join("");
}

function renderList() {
  const q = $("#search").value.trim().toLowerCase();
  const list = state.servers.filter((s) => {
    if (state.env !== "all" && s.environment !== state.env) return false;
    if (!q) return true;
    return [s.alias, s.hostname, s.description, s.location, ...(s.tags || [])].join(" ").toLowerCase().includes(q);
  });
  $("#server-list").innerHTML = list.length
    ? list.map((s) => `
      <li data-id="${s.id}" class="${state.selected?.id === s.id ? "active" : ""}">
        <div class="name"><span class="dot ${esc(s.last_status || "")}"></span>${esc(s.alias)}
          <span class="env ${esc(s.environment)}">${esc(s.environment)}</span></div>
        <div class="sub">${esc(s.username)}@${esc(s.hostname)}:${s.port}</div>
      </li>`).join("")
    : `<li class="sub">暂无服务器</li>`;
}

// ---------- 详情 ----------

function fmtTime(t) { return t ? new Date(t).toLocaleString() : "—"; }

function renderDetail() {
  const s = state.selected;
  if (!s) { $("#detail").innerHTML = `<div class="empty">选择左侧服务器，或点击「新增服务器」</div>`; return; }
  const notSynced = !s.last_synced_at || new Date(s.last_synced_at) < new Date(s.updated_at);
  $("#detail").innerHTML = `
    <div class="detail-head">
      <div>
        <h1>${esc(s.alias)} ${notSynced ? `<span class="pill bad">待同步到本机</span>` : ""}</h1>
        <div class="meta">${esc(s.username)}@${esc(s.hostname)}:${s.port}${s.proxy_jump ? ` via ${esc(s.proxy_jump)}` : ""}</div>
      </div>
      <div class="actions">
        <button id="btn-test" class="primary">测试连接</button>
        <button id="btn-sync" class="ghost">同步到本机</button>
        <button id="btn-edit" class="ghost">编辑</button>
        <button id="btn-del" class="ghost danger">删除</button>
      </div>
    </div>
    <div class="facts">
      <div><span>认证</span>${s.auth_type === "key" ? `密钥 ${esc(s.identity_file || "(默认)")}` : `密码 ${s.has_password ? "(已加密保存)" : "(未设置)"}`}</div>
      <div><span>环境</span>${esc(s.environment)}</div>
      <div><span>标签</span>${esc((s.tags || []).join(", ") || "—")}</div>
      <div><span>位置</span>${esc(s.location || "—")}</div>
      <div><span>最近连接</span>${fmtTime(s.last_connected_at)} ${s.last_status ? `<b class="${s.last_status === "ok" ? "ok-text" : "err-text"}">${esc(s.last_status)}</b>` : ""}</div>
      <div><span>最近同步到本机</span>${fmtTime(s.last_synced_at)}</div>
      ${s.description ? `<div style="grid-column:1/-1"><span>备注</span>${esc(s.description)}</div>` : ""}
    </div>
    <nav class="tabs">
      ${[["exec", "命令"], ["files", "文件传输"], ["tunnels", "隧道"], ["logs", "操作日志"]]
        .map(([k, v]) => `<button data-tab="${k}" class="${state.tab === k ? "active" : ""}">${v}</button>`).join("")}
    </nav>
    <div class="tab-body" id="tab-body"></div>`;
  renderTab();
}

function renderTab() {
  const body = $("#tab-body");
  if (body) ({ exec: renderExec, files: renderFiles, tunnels: renderTunnels, logs: renderLogs })[state.tab](body);
}

function termAppend(id, html) {
  state.term[id] = (state.term[id] || "") + html;
  const term = $("#term");
  if (term && state.selected?.id === id) { term.innerHTML = state.term[id]; term.scrollTop = term.scrollHeight; }
}

function renderResult(id, r) {
  if (r.stdout) termAppend(id, esc(r.stdout).replace(/\n?$/, "\n"));
  if (r.stderr) termAppend(id, `<span class="err">${esc(r.stderr).replace(/\n?$/, "\n")}</span>`);
  if (r.error) termAppend(id, `<span class="err">${esc(r.error)}\n</span>`);
  termAppend(id, `<span class="info">[exit ${r.exit_code ?? "?"} · ${r.duration_ms ?? "?"}ms]</span>\n`);
}

function renderExec(body) {
  const id = state.selected.id;
  body.innerHTML = `
    <pre class="term" id="term">${state.term[id] || `<span class="info">命令会交给本机 agent，通过 ssh-skill 在 ${esc(state.selected.alias)} 上执行。↑/↓ 浏览历史。</span>\n`}</pre>
    <form class="cmdline" id="cmd-form">
      <input type="text" id="cmd" placeholder="例如：df -h && free -m" autocomplete="off">
      <label>超时<input type="number" id="cmd-timeout" value="60" min="1" max="3600"></label>
      <label title="声明为只读命令，允许连接失败时安全重试"><input type="checkbox" id="cmd-ro">只读</label>
      <button class="primary">执行</button>
    </form>`;
  const term = $("#term");
  term.scrollTop = term.scrollHeight;
  let hi = state.history.length;
  $("#cmd").addEventListener("keydown", (e) => {
    if (e.key === "ArrowUp" && hi > 0) { e.target.value = state.history[--hi]; e.preventDefault(); }
    if (e.key === "ArrowDown") { hi = Math.min(hi + 1, state.history.length); e.target.value = state.history[hi] || ""; }
  });
  $("#cmd-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const command = $("#cmd").value.trim();
    if (!command) return;
    state.history.push(command); hi = state.history.length;
    $("#cmd").value = "";
    termAppend(id, `<span class="cmd">$ ${esc(command)}</span>\n`);
    const timeout = +$("#cmd-timeout").value || 60;
    await busy(e.submitter, async () => {
      try {
        const r = await runJob("exec", { serverId: id, payload: { command, timeout, read_only: $("#cmd-ro").checked }, timeoutMs: timeout * 4000 + 60_000 });
        renderResult(id, r);
      } catch (err) { termAppend(id, `<span class="err">${esc(err.message)}\n</span>`); }
    });
    loadServers();
  });
  $("#cmd").focus();
}

function renderFiles(body) {
  body.innerHTML = `
    <p class="hint">路径是运行 agent 的那台电脑上的本地路径。</p>
    <form class="row" id="up-form">
      <label>本机路径<input name="local_path" required placeholder="/Users/me/app.tar.gz"></label>
      <label>远程路径<input name="remote_path" required placeholder="/tmp/app.tar.gz"></label>
      <label><input type="checkbox" name="recursive" style="width:auto"> 目录</label>
      <button class="primary">上传 ↑</button>
    </form>
    <form class="row" id="down-form">
      <label>远程路径<input name="remote_path" required placeholder="/var/log/nginx/error.log"></label>
      <label>本机路径<input name="local_path" required placeholder="/Users/me/Downloads/error.log"></label>
      <label><input type="checkbox" name="recursive" style="width:auto"> 目录</label>
      <button class="primary">下载 ↓</button>
    </form>
    <pre class="term" id="xfer-out" style="min-height:80px"></pre>`;
  for (const [form, kind] of [["#up-form", "upload"], ["#down-form", "download"]]) {
    $(form).addEventListener("submit", (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      busy(e.submitter, async () => {
        $("#xfer-out").textContent = "传输中…";
        const r = await runJob(kind, {
          serverId: state.selected.id, timeoutMs: 3_600_000,
          payload: { local_path: f.get("local_path"), remote_path: f.get("remote_path"), recursive: !!f.get("recursive") },
        });
        const { _job, ...rest } = r;
        $("#xfer-out").textContent = JSON.stringify(rest, null, 2);
      });
    });
  }
}

function renderTunnels(body) {
  body.innerHTML = `
    <form class="row" id="tun-form">
      <label>远程端口<input name="remote_port" type="number" required placeholder="3306"></label>
      <label>远程主机（可选，默认 localhost）<input name="remote_host" placeholder="10.0.0.5"></label>
      <label>本地端口（可选）<input name="local_port" type="number" placeholder="自动"></label>
      <button class="primary">启动隧道</button>
    </form>
    <p class="hint">隧道监听在运行 agent 的电脑的 127.0.0.1 上。</p>
    <div id="tun-list">加载中…</div>`;
  $("#tun-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    busy(e.submitter, async () => {
      const r = await runJob("tunnel_start", {
        serverId: state.selected.id,
        payload: { remote_port: +f.get("remote_port"), remote_host: f.get("remote_host") || null, local_port: f.get("local_port") ? +f.get("local_port") : null },
      });
      toast(r.success ? `隧道已启动：127.0.0.1:${r.local_port ?? ""}` : r.error || "启动失败");
      loadTunnelList();
    });
  });
  loadTunnelList();
}

async function loadTunnelList() {
  const el = $("#tun-list");
  try {
    const r = await runJob("tunnel_list");
    const mine = (r.tunnels || []).filter((t) => t.alias === state.selected.alias);
    el.innerHTML = mine.length
      ? `<div class="table-wrap"><table><tr><th>ID</th><th>本地</th><th>远程</th><th>状态</th><th></th></tr>${mine.map((t) => `
          <tr><td class="mono">${esc(t.tunnel_id)}</td><td class="mono">127.0.0.1:${esc(t.local_port)}</td>
          <td class="mono">${esc(t.remote_host || "localhost")}:${esc(t.remote_port)}</td><td>${esc(t.status || "")}</td>
          <td><button class="ghost danger" data-stop="${esc(t.tunnel_id)}">停止</button></td></tr>`).join("")}</table></div>`
      : `<p class="hint">该服务器没有活动隧道</p>`;
  } catch (e) { el.textContent = e.message; }
}

const JOB_LABEL = { exec: "命令", test: "测试", sync: "同步", sync_all: "全部同步", remove_local: "移除本机配置", upload: "上传", download: "下载", tunnel_start: "隧道", tunnel_stop: "停止隧道", tunnel_list: "隧道列表", local_list: "读取本机", import: "导入" };

function jobSummary(j) {
  const p = j.payload || {};
  if (j.type === "exec") return p.command;
  if (j.type === "upload") return `${p.local_path} → ${p.remote_path}`;
  if (j.type === "download") return `${p.remote_path} → ${p.local_path}`;
  if (j.type === "tunnel_start") return `${p.remote_host || "localhost"}:${p.remote_port}`;
  return "";
}

async function renderLogs(body) {
  body.innerHTML = "加载中…";
  try {
    const jobs = await api(`/api/jobs?server_id=${state.selected.id}&limit=100`);
    body.innerHTML = jobs.length
      ? `<div class="table-wrap"><table><tr><th>时间</th><th>类型</th><th>内容</th><th>结果</th><th>耗时</th><th>操作人</th></tr>${jobs.map((j) => {
          const r = j.result || {};
          const st = j.status === "done" ? `<span class="ok-text">成功</span>` : j.status === "failed" ? `<span class="err-text">失败</span>` : `<span class="muted">${j.status}</span>`;
          return `<tr><td>${fmtTime(j.created_at)}</td><td>${JOB_LABEL[j.type] || esc(j.type)}</td>
            <td class="mono" title="${esc((r.stdout || "") + (r.stderr || r.error || ""))}">${esc(jobSummary(j))}</td>
            <td>${st}${r.exit_code != null ? ` (${r.exit_code})` : ""}</td><td>${r.duration_ms ?? ""}${r.duration_ms != null ? "ms" : ""}</td>
            <td class="muted">${esc(j.created_by)}</td></tr>`;
        }).join("")}</table></div>`
      : `<p class="hint">暂无日志</p>`;
  } catch (e) { body.textContent = e.message; }
}

// ---------- 表单 ----------

function syncAuthFields() {
  const type = $("#server-form").auth_type.value;
  document.querySelectorAll("[data-auth]").forEach((el) => (el.style.display = el.dataset.auth === type ? "" : "none"));
}

function openForm(server) {
  const f = $("#server-form");
  f.reset();
  f.dataset.id = server?.id || "";
  $("#form-title").textContent = server ? `编辑 ${server.alias}` : "新增服务器";
  $("#form-error").textContent = "";
  if (server) {
    for (const k of ["alias", "hostname", "port", "username", "auth_type", "identity_file", "proxy_jump", "environment", "location", "description"]) f[k].value = server[k] ?? "";
    f.tags.value = (server.tags || []).join(", ");
  }
  f.password.placeholder = server?.has_password ? "留空则保持不变" : "";
  syncAuthFields();
  $("#server-dialog").showModal();
}

$("#server-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const btn = e.submitter;
  btn.disabled = true;
  try {
    const body = {
      alias: f.alias.value.trim(), hostname: f.hostname.value.trim(), port: +f.port.value || 22,
      username: f.username.value.trim(), auth_type: f.auth_type.value,
      identity_file: f.identity_file.value.trim() || null,
      proxy_jump: f.proxy_jump.value.trim() || null, environment: f.environment.value,
      tags: f.tags.value.split(/[,，]/).map((t) => t.trim()).filter(Boolean),
      location: f.location.value.trim(), description: f.description.value.trim(),
    };
    if (body.auth_type === "password" && f.password.value) {
      if (/[\r\n]/.test(f.password.value)) throw new Error("密码不能包含换行");
      body.password_encrypted = await encryptPassword(f.password.value);
    }
    const id = f.dataset.id;
    const r = await api(id ? `/api/servers/${id}` : "/api/servers", { method: id ? "PUT" : "POST", body });
    $("#server-dialog").close();
    state.selected = r.server;
    await loadServers();
    toast("已保存到云端，正在同步到本机…");
    const res = await waitJob(r.job.id, 60_000).catch((err) => ({ success: false, error: err.message }));
    toast(res.success ? `已${res.action === "created" ? "写入" : "更新"}本机 ~/.ssh/config` : `同步到本机失败：${res.error}`);
    loadServers();
  } catch (err) {
    $("#form-error").textContent = err.message;
  } finally {
    btn.disabled = false;
  }
});

// ---------- 事件 ----------

$("#server-form").auth_type.addEventListener("change", syncAuthFields);
document.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", () => b.closest("dialog").close()));
$("#btn-add").addEventListener("click", () => openForm(null));
$("#search").addEventListener("input", renderList);
$("#env-filter").addEventListener("click", (e) => { const env = e.target.dataset.env; if (env) { state.env = env; renderEnvFilter(); renderList(); } });
$("#server-list").addEventListener("click", (e) => {
  const li = e.target.closest("li[data-id]");
  if (!li) return;
  state.selected = state.servers.find((s) => s.id === li.dataset.id);
  renderList(); renderDetail();
});

$("#detail").addEventListener("click", async (e) => {
  const t = e.target, s = state.selected;
  if (t.dataset.tab) { state.tab = t.dataset.tab; renderDetail(); return; }
  if (t.dataset.stop) {
    busy(t, async () => { await runJob("tunnel_stop", { payload: { tunnel_id: t.dataset.stop } }); loadTunnelList(); });
    return;
  }
  if (t.id === "btn-edit") openForm(s);
  if (t.id === "btn-sync") busy(t, async () => {
    const r = await runJob("sync", { serverId: s.id });
    toast(r.success ? `已同步 ${r.alias}（${r.action}）` : `同步失败：${r.error}`);
    loadServers();
  });
  if (t.id === "btn-test") busy(t, async () => {
    if (!agentOnline()) toast("没有在线的本机 agent，任务会排队等待");
    termAppend(s.id, `<span class="info">[测试连接]</span>\n`);
    const r = await runJob("test", { serverId: s.id, timeoutMs: 120_000 });
    renderResult(s.id, r);
    toast(r.success ? `连接成功 · ${r.duration_ms}ms` : `连接失败：${r.error || r.stderr || "未知错误"}`);
    await loadServers();
  });
  if (t.id === "btn-del") {
    if (!confirm(`删除 ${s.alias}？将同时从云端和本机 ~/.ssh/config 中移除。`)) return;
    busy(t, async () => {
      await api(`/api/servers/${s.id}`, { method: "DELETE" });
      state.selected = null;
      toast("已删除");
      loadServers(); renderDetail();
    });
  }
});

$("#btn-pull").addEventListener("click", (e) => busy(e.target, async () => {
  const r = await runJob("sync_all");
  const bad = Object.entries(r.errors || {});
  toast(bad.length ? `失败 ${bad.length} 台：${bad.map(([a, err]) => `${a}(${err})`).join("，")}` : `已同步 ${(r.synced || []).length} 台到本机`);
  loadServers();
}));

$("#btn-import").addEventListener("click", (e) => busy(e.target, async () => {
  const r = await runJob("local_list");
  if (!r.success) throw new Error(r.error || "读取本机配置失败");
  const hosts = r.hosts || [];
  $("#import-list").innerHTML = hosts.length
    ? hosts.map((h) => `<label><input type="checkbox" value="${esc(h.alias)}" checked>
        <b>${esc(h.alias)}</b> <span class="hint">${esc(h.user)}@${esc(h.hostname)}:${h.port} ${esc(h.description)} ${h.has_password ? "· 含密码" : ""}</span></label>`).join("")
    : `<p class="hint">本机 ~/.ssh/config 中没有未导入的主机</p>`;
  $("#import-dialog").showModal();
}));

$("#btn-do-import").addEventListener("click", (e) => busy(e.target, async () => {
  const aliases = [...document.querySelectorAll("#import-list input:checked")].map((i) => i.value);
  if (!aliases.length) return;
  const r = await runJob("import", { payload: { aliases } });
  const bad = Object.entries(r.errors || {});
  toast(bad.length ? `导入失败：${bad.map(([a, err]) => `${a}(${err})`).join("，")}` : `已导入 ${(r.imported || []).length} 台`);
  $("#import-dialog").close();
  loadServers();
}));

loadStatus().catch((e) => toast(e.message));
loadServers().catch((e) => toast(e.message));
setInterval(() => loadStatus().catch(() => {}), 30_000);
