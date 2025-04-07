# SteamRegister
steam注册机，业余写手靠ai完成，注册成本主要来源人机识别和代理ip。

注册的国家是代理ip的地址，ip池地址不对注册的国家也可能不对。

邮件收取部分，目前支持 常规imap，pop3和微软GRAPH

使用方法：
所有文件都在脚本同级目录

config.json 参数填写：
人机验证平台captcharun 邀请链接：https://captcha.run/sso?inviter=5888a224-d520-4c38-aa71-c8411dd62e8c ，QQ群:961381410 群内有平台提供免费也更专业的协议注册。
从邀请链接点注册购买谢谢， 平台主页token填入config.json 内的 clientKey
protocol 邮箱收件方式 ： IMAP ， POP3 ，GRAPH 每个线程执行前会先访问邮箱是否通畅
ssl：IMAP ，POP3 是否为ssl  大多数为true
email_url ： 邮箱协议地址  例：imap.gmx.com 
executornum： 线程数

代理ip：proxy_ips.txt  
按https://ipweb.cc/show/4.html教程 导出后修改名称为proxy_ips.txt即可，国家自行试验成功率，别的代理ip同格式也可，平台是captcharun推荐

邮箱 email_password.txt： 
按----分割即可，GRAPH 填的需要另外两个参数，方法见https://wmemail.com/ 

更新时间：2025.4.8 目前暂时可用。
