-- SSH 私钥对应的公钥（非机密，明文保存，用于显示指纹、复制到 authorized_keys、写出 .pub 文件）
alter table ssh_keys add column if not exists public_key text not null default ''
    check (length(public_key) <= 16000 and public_key !~ '[\r\n]');
alter table ssh_keys add column if not exists fingerprint text not null default '';
