import path from "node:path";
import { cloudflare } from "@cloudflare/vite-plugin";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
// @ts-expect-error 纯 JS 构建脚本
import { agentPyz } from "./scripts/build-agent.mjs";

export default defineConfig({
	plugins: [agentPyz(), react(), tailwindcss(), cloudflare()],
	resolve: { alias: { "@": path.resolve(import.meta.dirname, "client") } },
});
