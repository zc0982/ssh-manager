import assert from "node:assert/strict";
import test from "node:test";
import { sealData } from "../client/lib/crypto.ts";
import { buildSyncScript, type ExportServer } from "../client/lib/restore.ts";
import { ensureOpenSshFinalNewline } from "../client/lib/sshkey.ts";

const server: ExportServer = {
	alias: "example", hostname: "example.com", port: 22, username: "dev", auth_type: "key",
	identity_file: null, key_id: "key1", password_encrypted: null, proxy_jump: null,
	environment: "test", tags: [], location: "", description: "",
	created_at: "2026-01-01", updated_at: "2026-01-01",
};
const legacy = "-----BEGIN OPENSSH PRIVATE KEY-----\ndGVzdA==\n-----END OPENSSH PRIVATE KEY-----";

test("只补 OpenSSH 结束行缺少的换行", () => {
	const encode = (s: string) => new TextEncoder().encode(s);
	assert.deepEqual(ensureOpenSshFinalNewline(encode(legacy)), encode(legacy + "\n"));
	for (const input of [legacy + "\n", legacy + "\n\n", "-----END RSA PRIVATE KEY-----", ""]) {
		const bytes = encode(input);
		assert.equal(ensureOpenSshFinalNewline(bytes), bytes);
	}
});

test("两种同步脚本都为旧 OpenSSH 私钥补齐末尾换行", async () => {
	const pair = await crypto.subtle.generateKey(
		{ name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
		true, ["encrypt", "decrypt"],
	);
	const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
	const encrypted = await sealData(jwk, new TextEncoder().encode(legacy));
	const keys = [{ id: "key1", name: "example", key_encrypted: encrypted }];
	const expected = Buffer.from(legacy + "\n").toString("base64").match(/.{1,76}/g)!.join("\n");

	for (const platform of ["posix", "windows"] as const) {
		const { script, keyFiles } = await buildSyncScript(pair.privateKey, [server], keys, platform);
		assert.equal(keyFiles, 1);
		assert.ok(script.includes(expected), platform);
	}
});
