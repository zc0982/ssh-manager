-- 云端保存的 SSH 私钥（端到端加密）
-- key_encrypted 格式：v1.<RSA-OAEP 包裹的 AES 密钥>.<IV>.<AES-256-GCM 密文>（各段 base64），
-- 只有持有 agent 私钥的本机 agent 能解密。
create table if not exists ssh_keys (
    id             uuid primary key default gen_random_uuid(),
    name           text not null unique check (name ~ '^[A-Za-z0-9._-]+$'),
    comment        text not null default '',
    key_encrypted  text not null,
    created_by     text not null default '',
    created_at     timestamptz not null default now()
);

alter table servers add column if not exists key_id uuid references ssh_keys(id) on delete restrict;

alter table ssh_keys enable row level security;
do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        revoke all on ssh_keys from anon, authenticated;
    end if;
end $$;
