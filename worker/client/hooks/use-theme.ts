import { useEffect, useState } from "react";

const query = () => window.matchMedia("(prefers-color-scheme: dark)");

/** 跟随系统深浅色，并同步到 <html class="dark">（shadcn 的 dark 变体） */
export function useSystemTheme(): "light" | "dark" {
	const [dark, setDark] = useState(() => query().matches);
	useEffect(() => {
		const mq = query();
		const onChange = () => setDark(mq.matches);
		mq.addEventListener("change", onChange);
		return () => mq.removeEventListener("change", onChange);
	}, []);
	useEffect(() => {
		document.documentElement.classList.toggle("dark", dark);
	}, [dark]);
	return dark ? "dark" : "light";
}
