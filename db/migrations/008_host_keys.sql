-- 已确认信任的服务器主机公钥（known_hosts 行），同步时写入各电脑的 ~/.ssh/known_hosts
alter table servers add column if not exists host_keys text[] not null default '{}';
