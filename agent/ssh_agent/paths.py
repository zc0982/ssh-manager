"""运行方式与配置位置。

- 从仓库运行（uv run python -m ssh_agent）：配置在 agent/.env
- 以单文件 ssh-manager-agent.pyz 运行（新电脑一条命令安装）：配置在 ~/.ssh-manager/.env
"""
import os
from pathlib import Path

_here = Path(__file__).resolve()
PYZ: Path | None = next((p for p in _here.parents if p.suffix == ".pyz"), None)
REPO_ROOT = None if PYZ else _here.parent.parent

if os.getenv("SSH_MANAGER_HOME"):
    CONFIG_DIR = Path(os.path.expanduser(os.environ["SSH_MANAGER_HOME"]))
elif PYZ:
    CONFIG_DIR = Path.home() / ".ssh-manager"
else:
    CONFIG_DIR = REPO_ROOT

ENV_FILE = CONFIG_DIR / ".env"

# 单文件模式下由 uv 临时提供依赖
PYZ_DEPS = ["httpx", "cryptography", "python-dotenv"]


def run_command(uv: str, *args: str) -> list[str]:
    """启动 agent 的命令行（用于 launchd）。"""
    if PYZ:
        deps = [x for d in PYZ_DEPS for x in ("--with", d)]
        return [uv, "run", "--no-project", "--python", "3.12", *deps, "python", str(PYZ), *args]
    return [uv, "run", "--project", str(REPO_ROOT), "python", "-m", "ssh_agent", *args]
