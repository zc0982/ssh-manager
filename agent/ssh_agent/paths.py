"""配置位置：默认 agent/.env；可用环境变量 SSH_MANAGER_HOME 指定其他目录。"""
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = Path(os.path.expanduser(os.environ["SSH_MANAGER_HOME"])) if os.getenv("SSH_MANAGER_HOME") else REPO_ROOT
ENV_FILE = CONFIG_DIR / ".env"


def run_command(uv: str, *args: str) -> list[str]:
    """启动 agent 的命令行（用于 launchd）。"""
    return [uv, "run", "--project", str(REPO_ROOT), "python", "-m", "ssh_agent", *args]
