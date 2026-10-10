#!/usr/bin/env bash
# SteamRegister 一键安装脚本（Linux/macOS）
# 用法: ./install.sh
set -euo pipefail

cd "$(dirname "$0")"

PYTHON=${PYTHON:-python3}

echo "==> 检查 Python 版本 (要求 >= 3.9)..."
"$PYTHON" -c 'import sys; assert sys.version_info >= (3,9), "需要 Python 3.9+"; print(sys.version)'

echo "==> 创建虚拟环境 .venv ..."
if [ ! -d .venv ]; then
    "$PYTHON" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

echo "==> 安装依赖 ..."
pip install --upgrade pip -q
pip install -r requirements.txt

echo "==> 初始化配置文件 ..."
[ -f config.json ] || cp config.example.json config.json && echo "已生成 config.json，请填写 clientKey / email_url 等配置"
[ -f .env ] || cp .env.example .env && echo "已生成 .env，可填入 CAPTCHA_API_KEY"

echo
echo "安装完成！运行方式："
echo "  GUI 模式   : .venv/bin/python RegistrationGUI.py"
echo "  无界面模式 : .venv/bin/python steamrg.py"
echo
echo "提示：Linux 下如缺少 tkinter，请安装系统包（Ubuntu/Debian: sudo apt install python3-tk）"
