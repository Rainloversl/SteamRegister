# SteamRegister

Steam 账号自动注册工具，支持多种邮箱协议（IMAP / POP3 / Microsoft Graph / OAuth）、代理 IP 池轮换与多线程并发注册，并提供 Tkinter 图形界面。

## 项目结构

| 文件 | 说明 |
| --- | --- |
| `RegistrationGUI.py` | **程序入口（GUI 版本）**，Tkinter 图形界面，运行此文件即可 |
| `ThreadManager.py` | 线程管理器，负责读取邮箱列表、调度并发任务 |
| `SteamRegistration.py` | 核心注册逻辑（验证码识别、邮箱收信、账号保存） |
| `ProxyPool.py` | 代理 IP 池管理，支持失败重试与成功标记 |
| `steamrg.py` | 原始无界面版本，功能与 GUI 版一致，后续不再维护 |
| `config.json` | 基础配置文件 |
| `proxy_ips.txt` | 代理 IP 列表 |
| `email_password.txt` | 邮箱账号列表 |

## 安装

```bash
# 建议使用 Python 3.8+
pip install -r requirements.txt
```

依赖：`beautifulsoup4`、`requests`（GUI 使用标准库 `tkinter`，无需额外安装）。

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
```

GUI 支持在界面中修改配置、选择邮箱/代理文件、启动/停止注册，并实时显示每个邮箱的注册状态。

### 6. 输出结果

- `accounts_succ.txt` — 注册成功的账号（格式：`账号----密码----邮箱----...`）
- `accounts_fail.txt` — 注册失败的账号
- `rgerror.txt` — 错误日志

## 注意事项

1. 注册国家由代理 IP 决定
2. 每个线程执行前会验证邮箱可用性
3. 人机验证使用 captcha.run 平台服务
4. Steam hCaptcha 检测严格，captcha.run 提供的接口阶段性可用，详细进群了解
5. 人机验证为无感验证，ipweb 代理中部分 IP 可通过，需要频繁更换 IP 才能找到可用节点，这意味着流量成本的增加

QQ 群：961381410（captcha.run 官方群），群内有 captcha.run 提供的免费专业版

## 免责声明

本工具仅供学习研究使用，请遵守相关服务条款和法律法规。
