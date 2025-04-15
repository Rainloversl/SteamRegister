import base64
import imaplib
import json
import os
import poplib
import random
import re
import string
import time
import threading
from urllib.parse import urlparse, parse_qs
import requests
from bs4 import BeautifulSoup
import tkinter as tk

class SteamRegistration:
    """Steam注册处理器"""
    def __init__(self, config, proxy_pool):
        self.config = config
        self.proxy_pool = proxy_pool
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self._file_lock = threading.Lock()
        self._session_local = threading.local()
        self.email_data = None
        self.session = None
        self.proxy_info = None
        self.cookie_str = None
        self.token = None
        self.access_token = None
        self.gid = None
        self.init_id = None
        self.sessionid = None
        self.gui = None
        self.running = True
        self.BASE_HEADERS = {
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
            "Referer": "https://store.steampowered.com/join/",
            "Origin": "https://store.steampowered.com",
            "Connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "sec-ch-ua": '"Microsoft Edge";v="125"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"'
        }
        if not hasattr(self._session_local, 'session'):
            self._session_local.session = requests.Session()
            self._session_local.session.headers.update(self.BASE_HEADERS)

    def set_gui(self, gui):
        self.gui = gui
        
    def update_status(self, status, account_name=None, password=None, result=None):
        if self.gui:
            self.gui.update_status(self.email_data['email'], status, account_name, password, result)    
    
    def is_email_valid(self):
        """验证邮箱有效性"""
        try:
            protocol = self.config['protocol']
            email_url = self.config['email_url']
            use_ssl = self.config['ssl']
            email = self.email_data['email']
            password = self.email_data['password']
            if protocol == "IMAP":
                server = imaplib.IMAP4_SSL(email_url) if use_ssl else imaplib.IMAP4(email_url)
                server.login(email, password)
                server.logout()
            elif protocol == "POP3":
                server = poplib.POP3_SSL(email_url) if use_ssl else poplib.POP3(email_url)
                server.user(email)
                server.pass_(password)
                server.quit()
            elif protocol == "GRAPH":
                self._get_access_token()
                if not self.access_token:
                    raise ValueError("获取访问令牌失败")
                emails = self._graph_get_email()
                if emails is None:
                    raise ValueError("获取邮件失败")
            elif protocol == "IMAP_OAUTH":
                self._get_access_token()
                if not self.access_token:
                    raise ValueError("获取访问令牌失败")
                server = self._authenticate_oauth2()
                server.logout()
            elif protocol == "POP3_OAUTH":
                self._get_access_token()
                if not self.access_token:
                    raise ValueError("获取访问令牌失败")
                server = self._authenticate_oauth2()
                server.quit()
            else:
                raise ValueError("不支持的协议类型")
            return True
        except Exception as e:
            print(f"{email},邮箱验证失败: {e}")
            return False
            
    def _get_access_token(self):
        """获取OAuth访问令牌"""
        data = {
            'client_id': self.email_data['client_id'],
            'refresh_token': self.email_data['refresh_token'],
            'grant_type': 'refresh_token',
        }
        if self.config['protocol'] == 'GRAPH':
            data['scope'] = 'https://graph.microsoft.com/.default'
        response = requests.post(
            'https://login.microsoftonline.com/consumers/oauth2/v2.0/token', 
            data=data
        )
        if response.status_code == 200:
            result = response.json()
            access_token = result.get('access_token')
            refresh_token = result.get('refresh_token')
            if refresh_token and refresh_token != self.email_data['refresh_token']:
                self.email_data['refresh_token'] = refresh_token
                self._update_refresh_token(refresh_token)
            self.access_token = access_token

    def _authenticate_oauth2(self):
        """OAuth2认证"""
        email = self.email_data['email']
        auth_string = f"user={email}\x01auth=Bearer {self.access_token}\x01\x01"
        auth_bytes = auth_string.encode('ascii')
        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
        
        if self.config['protocol'] == "IMAP_OAUTH":
            server = imaplib.IMAP4_SSL('outlook.office365.com', 993)
            server.authenticate('XOAUTH2', lambda x: auth_string)
            return server
        elif self.config['protocol'] == "POP3_OAUTH":
            server = poplib.POP3_SSL('outlook.office365.com', 995)
            server._shortcmd('AUTH XOAUTH2')
            server._shortcmd(auth_b64)
            return server
    
    def _graph_get_email(self):
        try:
            if not self.access_token:
                return None
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }

            params = {
                '$top': 5, 
                '$select': 'subject,body,receivedDateTime,from,hasAttachments', 
                '$orderby': 'receivedDateTime desc'
            }

            response = requests.get('https://graph.microsoft.com/v1.0/me/messages', headers=headers,params=params)
            if response.status_code == 200:
                emails = response.json().get('value', [])
                return emails 
            else:
                return None
        except Exception as e:
            return None
        
    def _update_refresh_token(self, refresh_token):
        """更新refresh_token"""
        file_path = os.path.join(self.script_dir, 'email_password.txt')
        temp_path = os.path.join(self.script_dir, 'email_password.tmp')
        
        with self._file_lock:
            try:
                with open(file_path, 'r') as f, open(temp_path, 'w') as temp:
                    for line in f:
                        parts = line.strip().split('----')
                        if len(parts) == 4 and parts[0] == self.email_data['email']:
                            parts[3] = refresh_token
                            line = '----'.join(parts) + '\n'
                        temp.write(line)
                os.replace(temp_path, file_path)
            except Exception as e:
                print(f"更新refresh_token失败: {e}")
                if os.path.exists(temp_path):
                    os.remove(temp_path)

    def _setup_session(self):
        """设置代理会话"""
        if not self.proxy_info:
            raise ValueError("代理信息为空")
            
        try:
            parts = self.proxy_info.split(":")
            if len(parts) != 4:
                raise ValueError("代理格式错误")
                
            proxy_ip, proxy_port, username, password = parts
            # 验证端口是否为数字
            if not proxy_port.isdigit():
                raise ValueError("代理端口格式错误")
                
            proxy_url = f"http://{username}:{password}@{proxy_ip}:{proxy_port}"
            self.session = self._session_local.session
            self.session.proxies = {
                "http": proxy_url,
                "https": proxy_url
            }
            # 设置超时
            self.session.timeout = (10, 30)  # 连接超时10秒，读取超时30秒
        except Exception as e:
            print(f"设置代理会话失败: {e}")
            raise

    def _get_gRecaptchaResponse(self):
        """获取验证码响应"""
        proxy_ip, proxy_port, username, password = self.proxy_info.split(":")
        createTask_url = "https://api.captcha.run/v2/tasks"
        headers = {
            'Authorization': self.config['clientKey'],
            'Content-Type': 'application/json'
        }

        payload = json.dumps({
            "captchaType": "HCaptchaSteam",
            "host": proxy_ip,
            "port": proxy_port,
            "login": username,
            "password": password,
            "developer": "5888a224-d520-4c38-aa71-c8411dd62e8c" 
        })

        response = requests.post(createTask_url, headers=headers, data=payload)
        taskId = response.json()['taskId']
        return self._get_task_result(f"https://api.captcha.run/v2/tasks/{taskId}", headers)

    def _get_task_result(self, getTaskResult_url, headers):
        """获取验证码任务结果"""
        max_retries = 24
        retry_delay = 5
        for _ in range(max_retries):
            response = requests.get(getTaskResult_url, headers=headers)
            try:
                response_json = response.json()
                status = response_json.get('status')

                if status == 'Success':
                    resp = response_json.get('response')
                    return resp.get('token'), resp.get('gid')
                elif status == 'Fail':
                    return None, None
                elif status == 'Working':
                    time.sleep(retry_delay)
                    continue
            except Exception as e:
                print(f"验证码处理错误: {e}")
                time.sleep(retry_delay)
        return None, None

    def _get_init_id(self):
        """获取初始化ID"""
        headers = self.BASE_HEADERS.copy()
        headers.update({
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "cookie": self.cookie_str,
            "x-prototype-version": "1.7",
            "x-requested-with": "XMLHttpRequest"
        })
        url = "https://store.steampowered.com/join/"
        params = {"snr": "1_60_4__62"}
        
        for retry in range(3):
            try:
                response = self.session.get(url, headers=headers, params=params)
                response.raise_for_status()
                soup = BeautifulSoup(response.content, "html.parser")
                init_id = soup.find("input", {"id": "init_id"})
                if init_id and init_id.get("value"):
                    return init_id["value"]
            except Exception as e:
                print(f"获取init_id失败, 重试 {retry + 1}/3: {e}")
                time.sleep(5)
        return None

    def _ajax_verify_email(self):
        headers = self.BASE_HEADERS.copy()
        headers.update({
            "Cookie": self.cookie_str,
            "X-Requested-With": "XMLHttpRequest"
        })
        data = {
            "email": self.email_data['email'],
            "captchagid": self.gid,
            "captcha_text": self.token,
            "elang": '0',
            "init_id": self.init_id,
            "guest": "false"
        }
        
        return self.session.post(
            "https://store.steampowered.com/join/ajaxverifyemail",
            headers=headers,
            data=data
        )

    def _generate_random_account_name(self, length):
        """生成随机账户名"""
        characters = string.ascii_lowercase + string.digits
        return ''.join(random.choice(characters) for _ in range(length))

    def _generate_random_password(self, length):
        """生成随机密码"""
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(length))

    def _check_account_name_availability(self, account_name):
        """检查账户名可用性"""
        payload = {
            'accountname': account_name,
            'count': 1,
            'creationid': self.sessionid
        }
        
        try:
            response = self.session.post(
                'https://store.steampowered.com/join/checkavail/',
                data=payload,
                headers=self.BASE_HEADERS
            )
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            print(f"检查账户名失败: {e}")
            return None

    def _check_password_availability(self, account_name, password):
        """检查密码可用性"""
        payload = {
            'accountname': account_name,
            'password': password,
            'count': 1
        }
        
        try:
            response = self.session.post(
                'https://store.steampowered.com/join/checkpasswordavail/',
                data=payload,
                headers=self.BASE_HEADERS
            )
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            print(f"检查密码失败: {e}")
            return None

    def _save_account(self, account_name, password, success):
        """保存账户信息"""
        file_name = "accounts_succ.txt" if success else "accounts_fail.txt"
        file_path = os.path.join(self.script_dir, file_name)
        
        with self._file_lock:
            try:
                with open(file_path, "a", encoding='utf-8') as file:
                    if self.config['protocol'] in ["GRAPH", "IMAP_OAUTH", "POP3_OAUTH"]:
                        save_data = (f"{account_name}----{password}----{self.email_data['email']}----"
                                   f"{self.email_data['password']}----{self.email_data['client_id']}----"
                                   f"{self.email_data['refresh_token']}\n")
                    else:
                        save_data = (f"{account_name}----{password}----{self.email_data['email']}----"
                                   f"{self.email_data['password']}\n")
                    file.write(save_data)
            except Exception as e:
                print(f"保存账户信息失败: {e}")

    def _log_error(self,reason):
        self.update_status(f'{reason}',result='线程结束')
        """记录错误"""
        error_path = os.path.join(self.script_dir, 'rgerror.txt')
        with self._file_lock:
            try:
                with open(error_path, 'a', encoding='utf-8') as file:
                    # 根据协议类型保存不同格式的错误信息
                    if self.config['protocol'] in ["GRAPH", "IMAP_OAUTH", "POP3_OAUTH"]:
                        error_data = (f"{self.email_data['email']}----{self.email_data['password']}----"
                                    f"{self.email_data['client_id']}----{self.email_data['refresh_token']}\n")
                    else:
                        error_data = f"{self.email_data['email']}----{self.email_data['password']}\n"
                    file.write(error_data)
            except Exception as e:
                print(f"记录错误失败: {e}")
    
    def _ajax_check_email_verified(self):
        """检查邮箱验证状态"""
        if not self.sessionid:
            return False
    
        data = {'creationid': self.sessionid}
        url = 'https://store.steampowered.com/join/ajaxcheckemailverified'
        headers = self.BASE_HEADERS.copy()
        headers.update({
            "cookie": self.cookie_str,
        })
        
        start_time = time.time()
        verfy = False
        
        while True:
            if time.time() - start_time > 180:  # 超过3分钟退出循环
                self.update_status("邮箱验证超时")
                raise Exception("邮箱验证超时")
            response = self.session.post(url, data=data, headers=headers)
            if response.ok:
                success = response.json()
                if success['success'] == 1 or verfy:
                    # 处理账户创建
                    self.update_status("邮箱验证完成,提交注册")
                    return self._create_account()
                else:
                    print('等待邮箱验证')
                    self.update_status("等待邮箱验证")
                    if self._fetch_email_verification_url():
                        time.sleep(5)
                        verfy = True
                    time.sleep(2)
            else:
                time.sleep(5)
    
    def _fetch_email_verification_url(self):
        """获取邮箱验证链接"""
        max_attempts = 6
        attempts = 0
        href = ''
        urls = []
    
        def extract_urls_from_body(body, pattern):
            found_urls = re.findall(pattern, body)
            return [url.replace('&amp;', '&').replace("=3D", "=").replace("=\r\n", "")
                    .replace("\r\n", "").replace("=\n", "").replace("\n", "") 
                    for url in found_urls]
    
        def process_emails(emails, pattern):
            for email in emails:
                body = email.get('body', {}).get('content', '')
                urls.extend(extract_urls_from_body(body, pattern))
    
        def process_imap(mail, folder_name, pattern):
            mail.select(folder_name)
            status, messages = mail.search(None, "ALL")
            if status == "OK":
                for message_id in messages[0].split():
                    status, data = mail.fetch(message_id, "(BODY[TEXT])")
                    if status == "OK":
                        raw_email = data[0][1]
                        text_body = raw_email.decode("utf-8")
                        urls.extend(extract_urls_from_body(text_body, pattern))
    
        def process_pop3(mail, pattern):
            num_messages = len(mail.list()[1])
            for i in range(num_messages):
                raw_email = b'\n'.join(mail.retr(i + 1)[1])
                text_body = raw_email.decode("utf-8")
                urls.extend(extract_urls_from_body(text_body, pattern))
    
        while attempts < max_attempts:
            try:
                if self.config['protocol'] == "GRAPH":
                    emails = self._graph_get_email()
                    if emails:
                        process_emails(emails, r'href="(https://store\.steampowered\.com/account/newaccountverification\?[^"]+)"')
                else:
                    if self.config['protocol'] in ["IMAP", "IMAP_OAUTH"]:
                        if self.config['protocol'] == "IMAP_OAUTH":
                            self._get_access_token()
                            if not self.access_token:
                                attempts += 1
                                time.sleep(5)
                                continue
                            mail = self._authenticate_oauth2()
                        else:
                            mail = imaplib.IMAP4_SSL(self.config['email_url']) if self.config['ssl'] else imaplib.IMAP4(self.config['email_url'])
                            mail.login(self.email_data['email'], self.email_data['password'])
                            
                        # 处理所有邮件文件夹
                        process_imap(mail, "INBOX", r'https://store\.steampowered\.com/account/newaccountverification\?stoken=3D[^\r\n]*\r\n[^\r\n]*\r\n[^\r\n]*\r\n\r\n\r\n')
                        for folder_name in ['Junk', 'Trash', 'Spam', 'Junk Email']:
                            try:
                                process_imap(mail, folder_name, r'https://store\.steampowered\.com/account/newaccountverification\?stoken=3D[^\r\n]*\r\n[^\r\n]*\r\n[^\r\n]*\r\n\r\n\r\n')
                            except imaplib.IMAP4.error:
                                continue
                        mail.logout()
                        
                    elif self.config['protocol'] in ["POP3", "POP3_OAUTH"]:
                        if self.config['protocol'] == "POP3_OAUTH":
                            self._get_access_token()
                            if not self.access_token:
                                attempts += 1
                                time.sleep(5)
                                continue
                            mail = self._authenticate_oauth2()
                        else:
                            mail = poplib.POP3_SSL(self.config['email_url']) if self.config['ssl'] else poplib.POP3(self.config['email_url'])
                            mail.user(self.email_data['email'])
                            mail.pass_(self.email_data['password'])
                        process_pop3(mail, r'https://store\.steampowered\.com/account/newaccountverification\?stoken=3D[^\n]*\n[^\n]*\n[^\n]*\n\n\n')
                        mail.quit()
    
                # 检查验证链接
                for url in urls:
                    parsed_url = urlparse(url)
                    query_string = parsed_url.query
                    params = parse_qs(query_string)
                    creationid = params.get('creationid')
                    if creationid and creationid[0] == self.sessionid:
                        href = url
                        break
                        
                if href:
                    return self._verify_email_link(href)
                else:
                    print("未能匹配到邮件或链接，重新尝试")
                    attempts += 1
                    time.sleep(5)
                    
            except Exception as e:
                print(f"邮件处理错误: {e}")
                attempts += 1
                time.sleep(5)
    
            if attempts >= max_attempts:
                print("达到最大尝试次数，未能成功获取邮件或链接")
                return False
    
    def _verify_email_link(self, href):
        """验证邮箱链接"""
        headers = self.BASE_HEADERS.copy()
        headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1"
        })
        try:
            response = self.session.get(href, headers=headers)
            soup = BeautifulSoup(response.content, "html.parser")
            error_div = soup.find("div", class_="newaccount_email_verified_text error")
            
            if error_div:
                print('验证失败')
                return False
            print("验证完成")
            return True
        except Exception as e:
            print(f"验证链接访问失败: {e}")
            return False
    
    def _create_account(self):
        """创建Steam账户"""
        # 生成随机账户名和密码
        account_name = self._generate_random_account_name(random.randint(8, 12))
        
        # 检查账户名可用性
        result = self._check_account_name_availability(account_name)
        if result:
            if result['bAvailable']:
                print(f"账户名可用: {account_name}")
            else:
                print("账户名不可用")
                if 'rgSuggestions' in result and result['rgSuggestions']:
                    print("使用建议的账户名:", result['rgSuggestions'][0])
                    account_name = result['rgSuggestions'][0]
                else:
                    raise Exception("无法获取可用的账户名")
        else:
            raise Exception("账户名检查失败")
    
        # 生成并检查密码
        while True:
            password = self._generate_random_password(random.randint(8, 12))
            password_result = self._check_password_availability(account_name, password)
            if password_result and password_result['bAvailable']:
                print(f"密码可用: {password}")
                break
            print("密码不可用，重新生成")
    
        # 创建账户
        self.update_status("创建账户",account_name=account_name,password=password)
        self._create_steam_account(account_name, password)
        return True
    
    def _create_steam_account(self, account_name, password):
        """提交Steam账户创建请求"""
        data = {
            'accountname': account_name,
            'password': password,
            'count': 0,
            'lt': 1,
            'creation_sessionid': self.sessionid,
            'embedded_appid': 0,
            'guest': False
        }
        headers = self.BASE_HEADERS.copy()
        headers.update({
            "Cookie": self.cookie_str,
            "X-Requested-With": "XMLHttpRequest"
        })
        try:
            response = self.session.post(
                'https://store.steampowered.com/join/createaccount/',
                data=data,
                headers=headers
            )
            if response.ok:
                result = response.json()
                print(f'{account_name} 提交注册完成')
                self.update_status('提交注册完成',account_name=account_name,password=password,result=result['bSuccess'])
                self._save_account(account_name, password, result['bSuccess'])
            else:
                raise Exception(f'创建账户请求失败: {response.status_code}')
        except Exception as e:
            print(f'创建账户时出错: {str(e)}')
            raise
    
    def main(self, email_data, retries=30):
        """主处理函数"""
        main_retry_count = 0
        self.email_data = email_data
        if not self.is_email_valid():
            self._log_error("邮箱验证失败")
            return
        while main_retry_count < retries:
            try:
                if not self.running:
                    self.update_status("任务已停止")
                    break
                self.proxy_info = self.proxy_pool.get_proxy()
                self._setup_session()
                
                self.update_status("进行人机验证")
                self.cookie_str = "timezoneOffset=28800,0; Steam_Language=english; "
                self.token, self.gid = self._get_gRecaptchaResponse()
                if not self.gid:
                    self.update_status("人机验证失败,更换iP重试")
                    raise Exception("人机验证失败")
                self.update_status("人机验证通过")

                self.update_status("获取初始ID")    
                self.init_id = self._get_init_id()
                if not self.init_id:
                    self.update_status("多次获取init_id失败,更换iP重试")
                    raise Exception("获取init_id失败")
                self.update_status("获取初始ID完成")

                cookies = self.session.cookies.get_dict()
                self.cookie_str = '; '.join([f"{k}={v}" for k, v in cookies.items()])

                self.update_status("提交注册")
                response = self._ajax_verify_email()
                print(f'{self.email_data["email"]}提交注册结果：{response.text}')
                self.update_status(f'提交注册结果：{response.text}')
                if response.json()['success'] != 1:
                    self.update_status("人机验证未通过,更换iP重试")
                    raise Exception("人机验证未通过")
                    
                self.sessionid = response.json()['sessionid']
                self.update_status("验证邮箱")
                self._ajax_check_email_verified()
                self.session.close()
                self.proxy_pool.mark_success(self.proxy_info)
                self.proxy_info = None
                break
                
            except Exception as e:
                if not self.running:
                    self.update_status("任务已停止")
                    break
                print(f'{self.email_data["email"]},{str(e)}')
                self.session.close()
                self.proxy_pool.mark_fail(self.proxy_info)
                self.proxy_info = None
                main_retry_count += 1
                time.sleep(2)
                if main_retry_count >= retries:
                    self._log_error("最大重试次数")
            finally:
                if self.session:
                    try:
                        self.session.close()
                    except:
                        pass
                if self.proxy_info:
                    self.proxy_pool.mark_fail(self.proxy_info)
                    self.proxy_info = None
                
