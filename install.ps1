# SteamRegister 一键安装脚本（Windows PowerShell）
# 用法: .\install.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "==> 检查 Python ..." -ForegroundColor Cyan
python --version
python -c "import sys; assert sys.version_info >= (3,9), '需要 Python 3.9+'"

Write-Host "==> 创建虚拟环境 .venv ..." -ForegroundColor Cyan
if (-not (Test-Path .venv)) { python -m venv .venv }
& .\.venv\Scripts\Activate.ps1

Write-Host "==> 安装依赖 ..." -ForegroundColor Cyan
pip install --upgrade pip -q
pip install -r requirements.txt

Write-Host "==> 初始化配置文件 ..." -ForegroundColor Cyan
if (-not (Test-Path config.json)) { Copy-Item config.example.json config.json; Write-Host "已生成 config.json，请填写 clientKey / email_url 等配置" }
if (-not (Test-Path .env)) { Copy-Item .env.example .env; Write-Host "已生成 .env，可填入 CAPTCHA_API_KEY" }

Write-Host ""
Write-Host "安装完成！运行方式：" -ForegroundColor Green
Write-Host "  GUI 模式   : .\.venv\Scripts\python.exe RegistrationGUI.py"
Write-Host "  无界面模式 : .\.venv\Scripts\python.exe steamrg.py"
