// 环境（分组）颜色（与 Cyberpunk 主题协调）。类名写成完整字符串，方便 Tailwind 扫描。
export const ENV_COLORS: Record<string, { label: string; dot: string; badge: string }> = {
	magenta: { label: "品红", dot: "bg-fuchsia-500", badge: "border-fuchsia-500/50 text-fuchsia-300" },
	cyan: { label: "青", dot: "bg-cyan-400", badge: "border-cyan-400/50 text-cyan-300" },
	yellow: { label: "黄", dot: "bg-yellow-300", badge: "border-yellow-300/50 text-yellow-200" },
	purple: { label: "紫", dot: "bg-violet-500", badge: "border-violet-500/50 text-violet-300" },
	green: { label: "绿", dot: "bg-emerald-400", badge: "border-emerald-400/50 text-emerald-300" },
	orange: { label: "橙", dot: "bg-orange-400", badge: "border-orange-400/50 text-orange-300" },
	blue: { label: "蓝", dot: "bg-sky-500", badge: "border-sky-500/50 text-sky-300" },
	gray: { label: "灰", dot: "bg-zinc-400", badge: "border-zinc-400/50 text-zinc-300" },
};

export const colorOf = (c: string | undefined) => ENV_COLORS[c ?? ""] ?? ENV_COLORS.gray;

/** 显示名称：有中文名用中文名，否则用环境名 */
export const envLabel = (envs: { name: string; label: string }[], name: string) => envs.find((e) => e.name === name)?.label || name;
