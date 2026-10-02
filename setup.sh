#!/usr/bin/env bash
# SSH Manager 本机 agent 设置脚本
#   ./setup.sh            新电脑设置向导（需要网页「新电脑」里下载的 ssh-manager-setup.json）
#   ./setup.sh backup     在旧电脑上更新云端备份（agent 私钥 + 连接凭证，用主密码加密）
#   ./setup.sh service    安装/重启开机自启的后台服务（macOS）
#   ./setup.sh status     查看后台服务状态和最近日志
set -euo pipefail
cd "$(dirname "$0")/agent"

if ! command -v uv >/dev/null 2>&1; then
  echo "需要先安装 uv：curl -LsSf https://astral.sh/uv/install.sh | sh"
  exit 1
fi

case "${1:-setup}" in
  setup)   shift || true; exec uv run python -m ssh_agent setup "$@" ;;
  backup)  exec uv run python -m ssh_agent backup-key ;;
  service) exec uv run python -m ssh_agent install-launchd ;;
  status)
    launchctl print "gui/$(id -u)/com.ssh-manager.agent" 2>/dev/null | grep -E "^\s+(state|pid) =" || echo "后台服务未安装"
    tail -n 5 "$HOME/Library/Logs/ssh-manager/agent.log" 2>/dev/null || true ;;
  *) sed -n '2,6p' "$0"; exit 1 ;;
esac
