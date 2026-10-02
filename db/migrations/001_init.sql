-- SSH Manager schema (PostgreSQL / PlanetScale Postgres)

create table if not exists servers (
    id                 uuid primary key default gen_random_uuid(),
    alias              text not null unique check (alias ~ '^[A-Za-z0-9._-]+$'),
    hostname           text not null,
    port               integer not null default 22 check (port between 1 and 65535),
    username           text not null,
    auth_type          text not null default 'key' check (auth_type in ('key', 'password')),
    identity_file      text,
    password_encrypted text,          -- 浏览器/agent 用 agent 公钥 RSA-OAEP 加密后的密文，只有本机 agent 能解密
    proxy_jump         text,
    environment        text not null default 'development',
    tags               text[] not null default '{}',
    location           text not null default '',
    description        text not null default '',
    last_synced_at     timestamptz,
    last_connected_at  timestamptz,
    last_status        text,
    created_at         timestamptz not null default now(),
    updated_at         timestamptz not null default now()
);

-- 运行在本机、负责调用 ssh-skill 的 agent
create table if not exists agents (
    id          uuid primary key default gen_random_uuid(),
    name        text not null unique,
    hostname    text not null default '',
    version     text not null default '',
    last_seen   timestamptz not null default now(),
    created_at  timestamptz not null default now()
);

-- 全局设置，目前只存 agent 公钥（JWK）
create table if not exists settings (
    key    text primary key,
    value  jsonb not null
);

-- 任务队列：网页提交，本机 agent 领取执行并回传结果。同时作为操作日志。
create table if not exists jobs (
    id           bigserial primary key,
    type         text not null,
    server_id    uuid references servers(id) on delete set null,
    alias        text,
    agent_id     uuid references agents(id) on delete set null,
    payload      jsonb not null default '{}',
    status       text not null default 'queued' check (status in ('queued', 'running', 'done', 'failed')),
    result       jsonb,
    created_by   text not null default '',
    created_at   timestamptz not null default now(),
    started_at   timestamptz,
    finished_at  timestamptz
);
create index if not exists jobs_queue_idx on jobs (status, id) where status = 'queued';
create index if not exists jobs_server_idx on jobs (server_id, id desc);

create or replace function touch_updated_at() returns trigger
language plpgsql as $$
begin
    -- 只记录业务字段变化，同步/连接状态之类的簿记字段不刷新 updated_at
    if (to_jsonb(new) - '{updated_at,last_synced_at,last_connected_at,last_status}'::text[])
       is distinct from (to_jsonb(old) - '{updated_at,last_synced_at,last_connected_at,last_status}'::text[]) then
        new.updated_at = now();
    end if;
    return new;
end $$;

drop trigger if exists servers_touch on servers;
create trigger servers_touch before update on servers
for each row execute function touch_updated_at();
