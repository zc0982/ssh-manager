import { createRemoteJWKSet, jwtVerify } from "jose";

export type Identity = { kind: "user"; email: string } | { kind: "agent"; clientId: string };

export interface AuthEnv {
	ACCESS_TEAM_DOMAIN: string; // e.g. https://myteam.cloudflareaccess.com
	ACCESS_AUD: string; // Access application AUD tag
	ALLOWED_EMAILS: string; // 逗号分隔
	AGENT_CLIENT_ID: string; // 本机 agent 使用的 Access service token client id
	DEV_EMAIL?: string; // 仅本地 cf dev 使用
}

let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;
let jwksDomain = "";

/**
 * 校验 Cloudflare Access 签发的 JWT。Access 在边缘拦截未登录请求，
 * Worker 这里再验证一次签名、aud 和身份，防止绕过 Access（如 preview URL）。
 */
export async function authenticate(request: Request, env: AuthEnv): Promise<Identity | null> {
	const url = new URL(request.url);
	if (env.DEV_EMAIL && (url.hostname === "localhost" || url.hostname === "127.0.0.1")) {
		return { kind: "user", email: env.DEV_EMAIL };
	}

	const token = request.headers.get("cf-access-jwt-assertion");
	if (!token || !env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return null;

	if (!jwks || jwksDomain !== env.ACCESS_TEAM_DOMAIN) {
		jwks = createRemoteJWKSet(new URL(`${env.ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`));
		jwksDomain = env.ACCESS_TEAM_DOMAIN;
	}
	try {
		const { payload } = await jwtVerify(token, jwks, {
			issuer: env.ACCESS_TEAM_DOMAIN,
			audience: env.ACCESS_AUD,
		});
		const allowed = env.ALLOWED_EMAILS.split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
		if (typeof payload.email === "string" && allowed.includes(payload.email.toLowerCase())) {
			return { kind: "user", email: payload.email };
		}
		if (payload.common_name && payload.common_name === env.AGENT_CLIENT_ID) {
			return { kind: "agent", clientId: String(payload.common_name) };
		}
	} catch {
		// 签名/过期/aud 不符
	}
	return null;
}
