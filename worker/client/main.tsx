import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { TooltipProvider } from "@/components/ui/tooltip";
import App from "./App";
import "./index.css";

// Cyberpunk 主题固定使用深色
document.documentElement.classList.add("dark");

createRoot(document.getElementById("root")!).render(
	<StrictMode>
		<TooltipProvider>
			<App />
		</TooltipProvider>
	</StrictMode>,
);
