# SteamRegister

Steam 账号自动注册工具，支持多种邮箱协议（IMAP / POP3 / Microsoft Graph / OAuth）、代理 IP 池轮换与多线程并发注册，并提供 Tkinter 图形界面。

## 项目结构

| 文件 | 说明 |
| --- | --- |
| `RegistrationGUI.py` | **程序入口（GUI 版本）**，Tkinter 图形界面，运行此文件即可 |
| `ThreadManager.py` | 线程管理器，负责读取邮箱列表、调度并发任务 |
| `SteamRegistration.py` | 核心注册逻辑（验证码识别、邮箱收信、账号保存） |
| `ProxyPool.py` | 代理 IP 池管理，支持失败重试与成功标记 |
| `steamrg.py` | 原始无界面版本，功能与 GUI 版一致 |
| `cli.py` | 命令行包装器（可指定配置/邮箱文件、线程数） |
| `config.json` | 基础配置文件（本地私有，不入库；模板见 `config.example.json`） |
| `config.example.json` | 配置模板 |
| `.env.example` | 环境变量模板（`CAPTCHA_API_KEY`） |
| `proxy_ips.txt` | 代理 IP 列表（本地私有，不入库） |
| `email_password.txt` | 邮箱账号列表（本地私有，不入库） |
| `pyproject.toml` | 包定义 / 依赖 / ruff 配置 |
| `install.sh` / `install.ps1` | Linux/macOS 与 Windows 一键安装脚本 |
| `build.spec` | PyInstaller 打包配置 |
| `tests/` | 单元测试（配置解析、凭据解析、协议合规检查） |
| `.github/workflows/ci.yml` | GitHub Actions CI（多版本测试 + lint + Release 打包） |

## 安装

要求 Python >= 3.9。

### 一键安装

```bash
# Linux / macOS
./install.sh

# Windows (PowerShell)
.\install.ps1
```

脚本会自动创建 `.venv` 虚拟环境、安装依赖，并从模板生成 `config.json` 与 `.env`。

### 手动安装

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

依赖：`beautifulsoup4`、`requests`（GUI 使用标准库 `tkinter`；Linux 下如缺失需安装系统包 `python3-tk`）。

以包方式安装（可选）：`pip install -e .[dev]`，随后可用 `steam-register` 命令启动无界面模式。

## 使用方法

### 1. 配置文件准备

所有配置文件需放在脚本同级目录下：

- `config.json` — 基础配置
- `proxy_ips.txt` — 代理 IP 列表
- `email_password.txt` — 邮箱账号列表

### 2. config.json 配置说明

```json
{
    "clientKey": "你的captcha.run token",
    "protocol": "IMAP/POP3/GRAPH/IMAP_OAUTH/POP3_OAUTH",
    "ssl": true,
    "email_url": "imap.gmx.com",
    "executornum": 10
}
```

- `clientKey`：人机验证平台 token（[captcha.run 邀请注册](https://captcha.run/sso?inviter=5888a224-d520-4c38-aa71-c8411dd62e8c)）
- `protocol`：邮箱协议类型
- `ssl`：IMAP/POP3 是否使用 SSL
- `email_url`：邮箱服务器地址，自行查找
- `executornum`：并发线程数

### 3. 代理 IP 配置

`proxy_ips.txt` 格式：

```
ip:port:username:password
```

推荐使用 [ipweb.cc](https://ipweb.cc/show/4.html) 导出的格式。

### 4. 邮箱配置

`email_password.txt` 格式：

普通邮箱：

```
email----password
```

> 微软 `IMAP_OAUTH` 和 `POP3_OAUTH` 未测试，可用性不详。

Graph API 邮箱：

```
email----password----client_id----refresh_token
```

Microsoft Graph API 参数获取方法参考：[wmemail.com](https://wmemail.com/)

### 5. 运行

```bash
# GUI 版本（推荐）
python RegistrationGUI.py

# 无界面原始版本
python steamrg.py

# CLI 包装（可指定配置/邮箱文件与线程数）
python cli.py --config config.json --emails email_password.txt --workers 3
```

密钥可通过环境变量 `CAPTCHA_API_KEY` 提供（优先于 config.json 中的 clientKey，避免明文入库）。

GUI 支持在界面中修改配置、选择邮箱/代理文件、启动/停止注册，并实时显示每个邮箱的注册状态。

### 6. 输出结果

- `accounts_succ.txt` — 注册成功的账号（格式：`账号----密码----邮箱----...`）
- `accounts_fail.txt` — 注册失败的账号
- `rgerror.txt` — 错误日志

## 开发与测试

```bash
pip install -e ".[dev]"

# 运行测试
python -m unittest discover -s tests -v    # 或 pytest tests/

# 代码检查
ruff check .

# 打包为独立 exe（Windows，GUI 版使用 build.spec；CLI 版如下）
pyinstaller --onefile --console steamrg.py
```

CI：`.github/workflows/ci.yml` 在 push / PR 时自动执行多版本 Python（3.9/3.11/3.12）语法检查与单元测试；打 `v*` 标签时自动构建 Windows exe 产物。

## 注意事项

1. 注册国家由代理 IP 决定
2. 每个线程执行前会验证邮箱可用性
3. 人机验证使用 captcha.run 平台服务
4. Steam hCaptcha 检测严格，captcha.run 提供的接口阶段性可用，详细进群了解
5. 人机验证为无感验证，ipweb 代理中部分 IP 可通过，需要频繁更换 IP 才能找到可用节点，这意味着流量成本的增加

QQ 群：961381410（captcha.run 官方群），群内有 captcha.run 提供的免费专业版

## 免责声明

本工具仅供学习研究使用，请遵守相关服务条款和法律法规。
