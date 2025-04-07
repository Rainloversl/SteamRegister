import imaplib
import json
import os
import poplib
import queue
import random
import re
import string
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs

import requests
from bs4 import BeautifulSoup


def main(email_data, retries = 30):
    main_retry_count = 0
    email = email_data['email']
    paw = email_data['password']
    
    if not is_email_valid(email_data):
        print(f"邮箱 {email} 不可用，线程结束")
        error_path = os.path.join(script_dir, 'rgerror.txt')
        with open(error_path, 'a', encoding='utf-8') as file:
            file.write(f"{email}----{paw}\n")
        return
    
    while main_retry_count < retries:
        try:
            proxy_info = get_ip()
            proxy_ip, proxy_port, username, password = proxy_info.split(":")
            proxy_url = f"http://{username}:{password}@{proxy_ip}:{proxy_port}"
            proxies = {
                "http": proxy_url,
                "https": proxy_url
            }
            session = requests.Session()
            session.proxies = proxies
            cookie_str = "timezoneOffset=28800,0; Steam_Language=english; "
            token,gid = get_gRecaptchaResponse(proxy_ip,proxy_port,username,password)
            
            if not gid:
                raise Exception("人机验证失败")
            
            init_id = get_init_id(session,cookie_str)

            if not init_id:
                raise Exception("获取init_id失败")

            cookies = session.cookies.get_dict()
            cookie_str = '; '.join([f"{k}={v}" for k, v in cookies.items()])

            response = ajaxverifyemail(session, cookie_str, email, token, gid,init_id)
            print(response.text)
            if response.json()['success'] != 1:
                raise Exception("人机验证未通过")
            
            sessionid = response.json()['sessionid']
            ajax_retry_count = 0
            while ajax_retry_count < 3:
                try:
                    ajax_check_email_verified(sessionid, cookie_str, session, email_data)
                    break
                except Exception as e:
                    time.sleep(5)
                    ajax_retry_count += 1
            session.close()    
            success_proxy_queue.put(proxy_info)
            break
        except Exception as e:
            print(f'{email},{str(e)}')
            session.close()
            proxy_queue.put(proxy_info)
            main_retry_count += 1
            time.sleep(2)
            if main_retry_count >= retries:
                print(f"{email}线程超时")
                with open('rgerror.txt', 'a', encoding='utf-8') as file:
                    file.write(f"{email}----{paw}\n")

def is_email_valid(email_data):
    try:
        email = email_data['email']
        password = email_data['password']
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
            emails = graph_get_email(email_data)
            if emails is None:
                raise ValueError("获取邮件失败")
        else:
            raise ValueError("Unsupported protocol. Use 'IMAP', 'POP3' or 'GRAPH'.")
        return True
    except Exception as e:
        print(f"邮箱验证失败: {e}")
        return False

def ajaxverifyemail(session, cookie_str, email, token, gid, init_id):
    headers = {
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "^Cookie": cookie_str,
        "Origin": "https://store.steampowered.com",
        "Referer": "https://store.steampowered.com/join/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        "X-Requested-With": "XMLHttpRequest",
        "^sec-ch-ua": "^\\^Microsoft",
        "sec-ch-ua-mobile": "?0",
        "^sec-ch-ua-platform": "^\\^Windows^^^"
    }
    url = "https://store.steampowered.com/join/ajaxverifyemail"
    data = {
        "email": email,
        "captchagid": gid,
        "captcha_text": token,
        "elang": '0',
        "init_id": init_id,
        "guest": "false"
    }
    response = session.post(url, headers=headers, data=data)
    return response

def get_init_id(session, cookie_str):
    headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "priority": "u=0, i",
        "^sec-ch-ua": "^\\^Microsoft",
        "sec-ch-ua-mobile": "?0",
        "^sec-ch-ua-platform": "^\\^Windows^^^",
        "sec-fetch-dest": "iframe",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "cross-site",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        "Accept": "text/css,*/*;q=0.1",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Connection": "keep-alive",
        "If-Modified-Since": "Sun, 12 Apr 1970 23:39:27 GMT",
        "^If-None-Match": "^\\^rDHFC8CDRU8A^^^",
        "Sec-Fetch-Dest": "style",
        "Sec-Fetch-Mode": "no-cors",
        "Sec-Fetch-Site": "cross-site",
        "Origin": "https://store.steampowered.com",
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "cookie": cookie_str,
        "origin": "https://store.steampowered.com",
        "referer": "https://store.steampowered.com/",
        "x-prototype-version": "1.7",
        "x-requested-with": "XMLHttpRequest"
    }
    url = "https://store.steampowered.com/join/"
    params = {
        "snr": "1_60_4__62"
    }
    max_retries = 3
    retry_count = 0

    while retry_count < max_retries:
        try:
            response = session.get(url, headers=headers, params=params)
            response.raise_for_status() 
            soup = BeautifulSoup(response.content, "html.parser")
            init_id = soup.find("input", {"id": "init_id"})
            if init_id and init_id.get("value"):
                return init_id["value"]
            else:
                raise ValueError("init_id not found in the response.")
        except Exception as e:
            retry_count += 1
            if retry_count < max_retries:
                time.sleep(10)
                print("Retrying")
            else:
                raise Exception("Failed to retrieve init_id after multiple attempts.")
    return None


def get_gRecaptchaResponse(proxy_ip,proxy_port,username,password):
    createTask_url = "https://api.captcha.run/v2/tasks"
    headers = {
        'Authorization': clientKey,
        'Content-Type': 'application/json'
    }

    payload = json.dumps({
        "captchaType": "HCaptchaSteam",
        "host":proxy_ip,
        "port":proxy_port,
        "login":username,
        "password":password
    })

    response = requests.post(createTask_url, headers=headers, data=payload)
    taskId = response.json()['taskId']

    getTaskResult_url = "https://api.captcha.run/v2/tasks/"+taskId

    return get_task_result(getTaskResult_url, headers)

def get_task_result(getTaskResult_url, headers):
    max_retries = 24  # 最大重试次数
    retry_delay = 5  # 重试间隔时间（秒）

    for _ in range(max_retries):
        # 发送请求
        response = requests.get(getTaskResult_url, headers=headers)

        try:
            response_json = response.json()
            status = response_json.get('status')

            if status == 'Fail':
                return None,None
            if status == 'Success':
                resp = response.json().get('response')
                return resp.get('token'),resp.get('gid')
            elif status == 'Working':
                time.sleep(retry_delay)
                continue
            else:
                print("Unexpected status:", status)
                return None,None
        except Exception as e:
            print("Error occurred:", str(e))
            time.sleep(retry_delay)
            continue
    print("Max retries reached. Exiting.")
    return None,None

def ajax_check_email_verified(g_creationSessionID,cookie_str,session,email_data):
    if not g_creationSessionID:
        return

    data = {'creationid': g_creationSessionID}
    url = 'https://store.steampowered.com/' + 'join/ajaxcheckemailverified'
    ap_headers = {
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "^Cookie": cookie_str,
        "Origin": "https://store.steampowered.com",
        "Referer": "https://store.steampowered.com/join/?&snr=1_60_4__62",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
        "X-Requested-With": "XMLHttpRequest",
        "^sec-ch-ua": "^\\^Microsoft",
        "sec-ch-ua-mobile": "?0",
        "^sec-ch-ua-platform": "^\\^Windows^^^"
    }
    start_time = time.time()
    verfy = False
    while True:

        if time.time() - start_time > 180:  # 超过3分钟退出循环
            break
        response = session.post(url, data=data,headers=ap_headers)
        if response.ok:
            success = response.json()
            if success['success'] == 1 or verfy:
                account_name = generate_random_account_name(random.randint(8, 12))
                result = check_account_name_availability(account_name,g_creationSessionID,ap_headers,session)
                if result:
                    if result['bAvailable']:
                        print("账户名可用:"+account_name)
                    else:
                        print("账户名不可用")
                        if 'rgSuggestions' in result and result['rgSuggestions']:
                            print("建议的账户名:", result['rgSuggestions'])
                            account_name = result['rgSuggestions'][0]
                else:
                    print("无法获取账户名检测结果")
                while True:
                    password = generate_random_password(random.randint(8, 12))

                    # 检查密码可用性
                    password_result = check_password_availability(account_name, password,ap_headers,session)
                    if password_result:
                        if password_result['bAvailable']:
                            print("密码可用:", password)
                            break  # 如果密码可用，跳出循环
                        else:
                            print("密码不可用，重新生成新的密码")
                create_steam_account(account_name, password, 1, g_creationSessionID, 0, False,cookie_str,session,email_data)
                break
            else:
                print('等待邮箱验证')
                if fetch_email_verification_url(email_data, session,g_creationSessionID):
                    time.sleep(5)
                    verfy = True
                time.sleep(2)
        else:
            time.sleep(5)

def get_access_token(email_data):
    data = {
        'client_id': email_data['client_id'],
        'refresh_token': email_data['refresh_token'],
        'grant_type': 'refresh_token',
        'scope': 'https://graph.microsoft.com/.default',
    }
    response = requests.post('https://login.microsoftonline.com/consumers/oauth2/v2.0/token', data=data)
    if response.status_code == 200:
        access_token = response.json().get('access_token')
        if access_token:
            return access_token

def graph_get_email(email_data):
    try:
        access_token = get_access_token(email_data)
        if not access_token:
            return None
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        params = {
            '$top': 5,  # 限制返回数量
            '$select': 'subject,body,receivedDateTime,from,hasAttachments',  # 选择需要的字段
            '$orderby': 'receivedDateTime desc'  # 按接收时间降序排序
        }

        response = requests.get('https://graph.microsoft.com/v1.0/me/messages', headers=headers)
        if response.status_code == 200:
            emails = response.json().get('value', [])
            return emails 
        else:
            print(f"获取邮件失败: {response.status_code}")
            return None
    except Exception as e:
        return None
    
def fetch_email_verification_url(email_data, session, g_creationSessionID):
    max_attempts = 6
    attempts = 0
    href = ''
    urls = []
    
    while attempts < max_attempts:
        try:
            if protocol == "GRAPH":
                # 获取 Microsoft Graph 邮件
                emails = graph_get_email(email_data)
                if emails:
                    for email in emails:
                        body = email.get('body', {}).get('content', '')
                        # 搜索验证链接
                        url_pattern = r'href="(https://store\.steampowered\.com/account/newaccountverification\?[^"]+)"'
                        found_urls = re.findall(url_pattern, body)
                        for url in found_urls:
                            # 处理 HTML 实体编码
                            cleaned_url = url.replace('&amp;', '&')
                            urls.append(cleaned_url)
            else:
                email = email_data['email']
                password = email_data['password']
                if protocol == "IMAP":
                    mail = imaplib.IMAP4_SSL(email_url) if use_ssl else imaplib.IMAP4(email_url)
                    mail.login(email, password)
                    mail.select("INBOX")
                    # 搜索邮件
                    status, messages = mail.search(None, "ALL")
                    if status == "OK":
                        for message_id in messages[0].split():
                            # 获取邮件的纯文本正文
                            status, data = mail.fetch(message_id, "(BODY[TEXT])")
                            if status == "OK":
                                raw_email = data[0][1]
                                text_body = raw_email.decode("utf-8")
                                # 搜索链接
                                url_pattern = r'https://store.steampowered.com/account/newaccountverification\?stoken=3D[^\r\n]*\r\n[^\r\n]*\r\n[^\r\n]*\r\n\r\n\r\n'
                                found_urls = re.findall(url_pattern, text_body)
                                for url in found_urls:
                                    # 清理URL
                                    cleaned_url = url.replace("=3D", "=").replace("=\r\n", "").replace("\r\n", "")
                                    urls.append(cleaned_url)
                    junk_folder_names = ['Junk', 'Trash', 'Spam', 'Junk Email']
                    junk_name = ''
                    for folder_name in junk_folder_names:
                        try:
                            status, messages = mail.select(folder_name)
                            if status == "OK":
                                junk_name = folder_name
                                break
                        except imaplib.IMAP4.error as e:
                            continue
                    if junk_name !='':
                        mail.select(junk_name)  # 垃圾箱的名称可能有所不同，如"Trash"或"Junk Email"
                        status, messages = mail.search(None, "ALL")
                        if status == "OK":
                            for message_id in messages[0].split():
                                # 获取邮件的纯文本正文
                                status, data = mail.fetch(message_id, "(BODY[TEXT])")
                                if status == "OK":
                                    raw_email = data[0][1]
                                    text_body = raw_email.decode("utf-8")
                                    url_pattern = r'https://store.steampowered.com/account/newaccountverification\?stoken=3D[^\r\n]*\r\n[^\r\n]*\r\n[^\r\n]*\r\n\r\n\r\n'
                                    found_urls = re.findall(url_pattern, text_body)
                                    for url in found_urls:
                                        # 清理URL
                                        cleaned_url = url.replace("=3D", "=").replace("=\r\n", "").replace("\r\n", "")
                                        urls.append(cleaned_url)
                elif protocol == "POP3":
                    mail = poplib.POP3_SSL(email_url) if use_ssl else poplib.POP3(email_url)
                    mail.user(email)
                    mail.pass_(password)
                    num_messages = len(mail.list()[1])
                    for i in range(num_messages):
                        raw_email = b'\n'.join(mail.retr(i + 1)[1])
                        text_body = raw_email.decode("utf-8")
                        url_pattern = r'https://store.steampowered.com/account/newaccountverification\?stoken=3D[^\n]*\n[^\n]*\n[^\n]*\n\n\n'
                        found_urls = re.findall(url_pattern, text_body)
                        for url in found_urls:
                            cleaned_url = url.replace("=3D", "=").replace("=\n", "").replace("\n", "")
                            urls.append(cleaned_url)

            # 检查是否有正确的 URL
            for url in urls:
                parsed_url = urlparse(url)
                query_string = parsed_url.query
                params = parse_qs(query_string)
                creationid = params.get('creationid')
                if creationid and creationid[0] == g_creationSessionID:
                    href = url
                    break

            if href:
                break
            else:
                print("未能匹配到邮件或链接，重新尝试")
                attempts += 1
                time.sleep(5)
        except Exception as e:
            print(f"邮件处理错误: {e}")
            attempts += 1
            time.sleep(5)

    # 关闭连接（仅针对 IMAP 和 POP3）
    if protocol in ["IMAP", "POP3"]:
        if protocol == "IMAP":
            mail.logout()
        elif protocol == "POP3":
            mail.quit()

    if attempts == max_attempts:
        print("达到最大尝试次数，未能成功获取邮件或链接")
        return False

    if href:
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "Cache-Control": "max-age=0",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
            "^sec-ch-ua": "^\\^Microsoft",
            "sec-ch-ua-mobile": "?0",
            "^sec-ch-ua-platform": "^\\^Windows^^^",
            "Referer": "",
            "^If-None-Match": "^\\^q1xZB/G+1WQWAESmLBacgbEbWJA=^^^",
        }
        res = session.get(href, headers=headers)
        soup = BeautifulSoup(res.content, "html.parser")
        target_tag = soup.find("div", class_="newaccount_email_verified_text error")
        if target_tag:
            print('验证失败')
            return False
        else:
            print("验证完成")
            return True
    else:
        print('验证链接获取失败')
        return False



def generate_random_account_name(length):
    characters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def generate_random_password(length):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def check_account_name_availability(account_name,creation_session_id,ap_headers,session):
    base_url = 'https://store.steampowered.com/join/checkavail/' 

    payload = {
        'accountname': account_name,
        'count': 1,  
        'creationid': creation_session_id
    }
    try:
        response = session.post(base_url, data=payload,headers=ap_headers)
        if response.status_code == 200:
            result = response.json()
            return result
        else:
            print("HTTP请求失败:", response.status_code)
            return None
    except Exception as e:
        print("发生异常:", e)
        return None

def check_password_availability(account_name, password,ap_headers,session):
    base_url = 'https://store.steampowered.com/join/checkpasswordavail/' 

    payload = {
        'accountname': account_name,
        'password': password,
        'count': 1  # 这个值是递增的，表示发送的请求次数
    }

    try:
        response = session.post(base_url, data=payload,headers=ap_headers)
        if response.status_code == 200:
            result = response.json()
            return result
        else:
            print("HTTP请求失败:", response.status_code)
            return None
    except Exception as e:
        print("发生异常:", e)
        return None

def create_steam_account(accountname, pass_word, lt, g_creationSessionID, g_embeddedAppID, g_bGuest, cookie_str, session, email_data):
    iAjaxCalls = 0
    ap_headers = {
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "^Cookie": cookie_str,
        "Origin": "https://store.steampowered.com",
        "Referer": "https://store.steampowered.com/join/?&snr=1_60_4__62",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
        "X-Requested-With": "XMLHttpRequest",
        "^sec-ch-ua": "^\\^Microsoft",
        "sec-ch-ua-mobile": "?0",
        "^sec-ch-ua-platform": "^\\^Windows^^^"
    }

    data = {
        'accountname': accountname,
        'password': pass_word,
        'count': iAjaxCalls,
        'lt': lt,
        'creation_sessionid': g_creationSessionID,
        'embedded_appid': g_embeddedAppID,
        'guest': g_bGuest
    }

    url = 'https://store.steampowered.com/join/createaccount/'

    try:
        response = session.post(url, data=data, headers=ap_headers)
        if response.ok:
            result = response.json()
            print(f'{accountname},提交注册完成')
            save_to_file(accountname, pass_word, email_data, result['bSuccess'])
        else:
            print('Failed to send request. HTTP Error:', response.status_code)
    except Exception as e:
        print('An error occurred:', str(e))

def save_to_file(account_name, password, email_data, boll):
    file_name = "accounts_succ.txt" if boll else "accounts_fail.txt"
    file_path = os.path.join(script_dir, file_name)
    if protocol == "GRAPH":
        save_data = f"{account_name}----{password}----{email_data['email']}----{email_data['password']}----{email_data['client_id']}----{email_data['refresh_token']}\n"
    else:  
        save_data = f"{account_name}----{password}----{email_data['email']}----{email_data['password']}\n"
        
    with open(file_path, "a", encoding='utf-8') as file:
        file.write(save_data)

def get_ip():
    while True:
        try:
            if not success_proxy_queue.empty():
                return success_proxy_queue.get(block=True)
            if not proxy_queue.empty():
                return proxy_queue.get(block=True)
            time.sleep(5)
        except Exception as e:
            print(f"获取代理IP失败: {e}")
            time.sleep(5)

def read_config(filename):
    with open(filename, 'r') as f:
        config = json.load(f)
    return config

script_dir = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(script_dir, 'config.json')
email_password_path = os.path.join(script_dir, 'email_password.txt')
proxy_ips_path = os.path.join(script_dir, 'proxy_ips.txt')

# 创建 ThreadPoolExecutor 对象，指定最大并发数为10
config_data = read_config(config_path)
clientKey = config_data['clientKey']
email_url = config_data['email_url']
use_ssl = config_data['ssl']
executornum = config_data['executornum']
protocol = config_data['protocol']

with open(proxy_ips_path, "r") as file:
    proxy_ips = [line.strip() for line in file if line.strip()]

proxy_queue = queue.Queue()
for proxy_ip in proxy_ips:
    proxy_queue.put(proxy_ip)
success_proxy_queue = queue.Queue()

executor = ThreadPoolExecutor(max_workers=executornum)


def parse_email_credentials(email_password_str):
    parts = email_password_str.strip().split("----")
    if len(parts) == 2:
        return {
            'email': parts[0],
            'password': parts[1]
        }
    elif len(parts) == 4: 
        return {
            'email': parts[0],
            'password': parts[1],
            'client_id': parts[2],
            'refresh_token': parts[3],
        }
    else:
        raise ValueError("Invalid email credentials format")


def start_tasks():
    with open(email_password_path, "r") as file:
        for line in file:
            try:
                email_data = parse_email_credentials(line.strip())
                executor.submit(main, email_data)
            except ValueError as e:
                print(f"错误的邮箱格式: {e}")
                continue

start_tasks()
executor.shutdown(wait=True)
