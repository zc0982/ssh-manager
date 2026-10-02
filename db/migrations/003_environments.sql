-- 环境（即服务器分组）：可增删改的环境列表
create table if not exists environments (
    name         text primary key check (name ~ '^[A-Za-z0-9._-]{1,32}$'),
    color        text not null default 'magenta',
    description  text not null default '',
    sort_order   integer not null default 0,
    created_at   timestamptz not null default now()
);

-- 预置常用环境，并收录已在使用的值
insert into environments (name, color, sort_order) values
    ('production', 'magenta', 1), ('staging', 'yellow', 2), ('development', 'cyan', 3)
on conflict (name) do nothing;
insert into environments (name, sort_order)
select distinct environment, 100 from servers on conflict (name) do nothing;

-- 服务器的环境必须在列表中；重命名环境时级联更新服务器，删除仍被使用的环境会被拒绝
alter table servers drop constraint if exists servers_environment_fkey;
alter table servers add constraint servers_environment_fkey
    foreign key (environment) references environments(name) on update cascade on delete restrict;

-- 清理早期草案（独立分组表）
alter table servers drop column if exists group_id;
drop table if exists server_groups;

-- 恢复 updated_at 触发器：environment 会写进 ~/.ssh/config，变化时需要重新同步
create or replace function touch_updated_at() returns trigger
language plpgsql as $$
begin
    if (to_jsonb(new) - '{updated_at,last_synced_at,last_connected_at,last_status}'::text[])
       is distinct from (to_jsonb(old) - '{updated_at,last_synced_at,last_connected_at,last_status}'::text[]) then
        new.updated_at = now();
    end if;
    return new;
end $$;

alter table environments enable row level security;
do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        revoke all on environments from anon, authenticated;
    end if;
end $$;
