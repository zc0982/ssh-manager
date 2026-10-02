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
				id: "HYPERDRIVE_ID",
				dev: { connectionString: (globalThis as any).process?.env?.DEV_DATABASE_URL },
			}),
			// Cloudflare Access 配置，通过 `cf deploy --secrets-file` 上传
			ACCESS_TEAM_DOMAIN: bindings.secret(),
			ACCESS_AUD: bindings.secret(),
			ALLOWED_EMAILS: bindings.secret(),
			AGENT_CLIENT_ID: bindings.secret(),
		},
	},
});
