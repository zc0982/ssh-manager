import { bindings, defineConfig } from "cf/config";
import * as entrypoint from "./src/index.ts" with { type: "cf-worker" };

export default defineConfig({
	worker: {
		name: "ssh-manager",
		compatibilityDate: "2026-09-30",
		compatibilityFlags: ["nodejs_compat"],
		entrypoint,
		assets: { notFoundHandling: "single-page-application", runWorkerFirst: ["/api/*"] },
		env: {
			ASSETS: bindings.assets(),
			HYPERDRIVE: bindings.hyperdrive({
				id: "1239268d09dc491b8b77bd2b989ba7e8",
				dev: { connectionString: (globalThis as any).process?.env?.DEV_DATABASE_URL },
			}),
			// Cloudflare Access 配置，通过 `cf deploy --secrets-file` 上传
			ACCESS_TEAM_DOMAIN: bindings.secret(),
			ACCESS_AUD: bindings.secret(),
			ALLOWED_EMAILS: bindings.secret(),
			AGENT_CLIENT_ID: bindings.secret(),
			// 仅本地预览：SSH_MANAGER_DEV=1 cf dev 时以 .dev.vars 里的 DEV_EMAIL 登录（只对 localhost 生效）
			...((globalThis as any).process?.env?.SSH_MANAGER_DEV === "1" ? { DEV_EMAIL: bindings.secret() } : {}),
		},
	},
});
