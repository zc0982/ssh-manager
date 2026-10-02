// 把 agent/ssh_agent 打包成单文件 ssh-manager-agent.pyz（Python zipapp），供新电脑一条命令安装。
import { execFileSync } from "node:child_process";
import { cpSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

export function buildAgent(root) {
	const src = path.resolve(root, "../agent/ssh_agent");
	const out = path.resolve(root, "public/ssh-manager-agent.pyz");
	const tmp = mkdtempSync(path.join(tmpdir(), "ssh-agent-"));
	try {
		cpSync(src, path.join(tmp, "ssh_agent"), { recursive: true, filter: (p) => !p.includes("__pycache__") });
		execFileSync("python3", ["-m", "zipapp", tmp, "-m", "ssh_agent.__main__:main", "-o", out], { stdio: "inherit" });
	} finally {
		rmSync(tmp, { recursive: true, force: true });
	}
	return out;
}

/** Vite 插件：每次构建前重新打包 */
export function agentPyz() {
	return {
		name: "ssh-manager-agent-pyz",
		buildStart() {
			buildAgent(process.cwd());
		},
	};
}
