# SteamRegister

Steam 账号自动注册工具，支持多种邮箱协议和多线程并发注册。


## 使用方法

### 1. 配置文件准备

所有配置文件需要放在脚本同级目录下：

- config.json - 基础配置
- proxy_ips.txt - 代理IP列表
- email_password.txt - 邮箱账号列表

### 2. config.json 配置说明
```json
{
    "clientKey": "你的captcha.run token",
    "protocol": "IMAP/POP3/GRAPH",
    "ssl": true,
    "email_url": "imap.gmx.com", 邮箱服务器地址，自行查找
    "executornum": 10
}
```

- clientKey: 人机验证平台token ([captcha.run 邀请注册](https://captcha.run/sso?inviter=5888a224-d520-4c38-aa71-c8411dd62e8c))
- protocol: 邮箱协议类型
- ssl: IMAP/POP3 是否使用 SSL
- email_url: 邮箱服务器地址
- executornum: 并发线程数

### 3. 代理IP配置

proxy_ips.txt 格式:
```
ip:port:username:password
```
推荐使用 [ipweb.cc](https://ipweb.cc/show/4.html) 导出的格式

### 4. 邮箱配置

email_password.txt 格式:

普通邮箱:
```
email----password
```

Graph API邮箱:
```
email----password----client_id----refresh_token
```
Microsoft Graph API 参数获取方法参考: [wmemail.com](https://wmemail.com/)

## 注意事项

1. 注册国家由代理IP决定
2. 每个线程执行前会验证邮箱可用性
3. 人机验证使用 captcha.run 平台服务
- QQ群: 961381410 (captcha.run 官方群) 群内有captcha.run 提供的免费且专业版

## 免责声明

本工具仅供学习研究使用，请遵守相关服务条款和法律法规。

