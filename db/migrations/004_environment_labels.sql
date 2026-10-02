-- 环境的中文显示名称（仅网页展示；写入 ~/.ssh/config 的仍是 name）
alter table environments add column if not exists label text not null default ''
    check (length(label) <= 32 and label !~ '[\r\n]');

update environments set label = '生产' where name = 'production' and label = '';
update environments set label = '预发布' where name = 'staging' and label = '';
update environments set label = '开发' where name = 'development' and label = '';
