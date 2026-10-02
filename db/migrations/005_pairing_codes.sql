-- 新电脑一次性配对码：只存 SHA-256 哈希；10 分钟过期；设置包只能取一次
create table if not exists pairing_codes (
    code_hash   text primary key,
    created_by  text not null default '',
    created_at  timestamptz not null default now(),
    expires_at  timestamptz not null,
    used_at     timestamptz
);

alter table pairing_codes enable row level security;
do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        revoke all on pairing_codes from anon, authenticated;
    end if;
end $$;
