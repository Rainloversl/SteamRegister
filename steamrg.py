import imaplib
import json
import queue
import random
import re
import string
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs

import requests
from bs4 import BeautifulSoup


def main(email,paw,proxy_ip,proxy_queue):
    try:
        proxy_info = proxy_ip
        # 解析代理信息
        proxy_ip, proxy_port, username, password = proxy_info.split(":")
        # 构建代理URL
        proxy_url = f"http://{username}:{password}@{proxy_ip}:{proxy_port}"
        # 设置代理
        proxies = {
            "http": proxy_url,
            "https": proxy_url
        }
        session = requests.Session()
        session.proxies = proxies
        change_ip(proxy_info)
        time.sleep(5)
        cookie_str = "timezoneOffset=28800,0; Steam_Language=english; "
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
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
            "Referer": "https://recaptcha.net/",
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
            "^cookie": cookie_str,
            "origin": "https://store.steampowered.com",
            "referer": "https://store.steampowered.com/",
            "x-prototype-version": "1.7",
            "x-requested-with": "XMLHttpRequest"
        }
        url = "https://store.steampowered.com/join/"
        params = {
            "": "",
            "snr": "1_60_4__62"
        }
        data = {
            "count": "1"
        }
        max_retries = 5
        retry_count = 0
        init_id = None
        while retry_count < max_retries:
            try:
                response = session.get(url, headers=headers, params=params, data=data)
                soup = BeautifulSoup(response.content, "html.parser")
                init_id = soup.find("input", {"id": "init_id"})["value"]
                break  # 如果成功获取了 init_id，则退出循环
            except Exception:
                print(f"打开登录界面失败:")
                retry_count += 1
                if retry_count < max_retries:
                    change_ip(proxy_info)
                    time.sleep(5)
                    print("更换ip重试")
                else:
                    print("最大重试次数，失败邮箱已加入rgerror.txt")
                    with open('rgerror.txt', 'a', encoding='utf-8') as file:
                        file.write(f"{email}----{paw}\n")
                    proxy_queue.put(proxy_info)
                    return
        cookies = response.cookies.get_dict()
        cookie_str = ''
        cookie_str += 'browserid=' + cookies.get('browserid', '') + '; '
        cookie_str += 'steamCountry=' + cookies.get('steamCountry', '') + '; '
        cookie_str += 'sessionid=' + cookies.get('sessionid', '')
        print(cookie_str)
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
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
            "Referer": "https://recaptcha.net/",
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
            "^cookie": cookie_str,
            "origin": "https://store.steampowered.com",
            "referer": "https://store.steampowered.com/",
            "x-prototype-version": "1.7",
            "x-requested-with": "XMLHttpRequest"
        }
        url = "https://store.steampowered.com/join/refreshcaptcha/"

        data = {
            "count": "1"
        }
        response = session.post(url, headers=headers, data=data)
        response_json = response.json()
        gid = response_json['gid']
        s = response_json['s']
        sitekey = response_json['sitekey']
        gRecaptchaResponse = get_gRecaptchaResponse(s, sitekey)
        if gRecaptchaResponse:
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
                "captcha_text": gRecaptchaResponse,
                "elang": '0',
                "init_id": init_id,
                "guest": "false"
            }
            response = session.post(url, headers=headers, data=data)
            if response.json()['success'] == 1:
                sessionid = response.json()['sessionid']
                print(sessionid)
                ajax_check_email_verified(sessionid,cookie_str,session,email,paw)
            else:
                with open('rgerror.txt', 'a', encoding='utf-8') as file:
                    file.write(f"{email}----{paw}\n")
            print(response.text)
            session.close()
            proxy_queue.put(proxy_info)
            return
        else:
            print('人机验证超时')
            session.close()
            proxy_queue.put(proxy_info)
            with open('rgerror.txt', 'a', encoding='utf-8') as file:
                file.write(f"{email}----{paw}\n")
            return
    except Exception as e:
        session.close()
        proxy_queue.put(proxy_info)
        with open('rgerror.txt', 'a', encoding='utf-8') as file:
            file.write(f"{email}----{paw}\n")
        return  # 结束当前调用

def read_config(filename):
    with open(filename, 'r') as f:
        config = json.load(f)
    return config

def get_gRecaptchaResponse(s, sitekey):
    createTask_url = "https://api.ez-captcha.com/createTask"
    headers = {
        'User-Agent': 'Apifox/1.0.0 (https://apifox.com)',
        'Content-Type': 'application/json'
    }

    payload = json.dumps({
        "clientKey": clientKey,
        "task": {
            "websiteURL": "https://store.steampowered.com/join",
            "websiteKey": sitekey,
            "type": "ReCaptchaV2SEnterpriseTaskProxyless",
            "isInvisible": False,
            's': s
        }
    })

    response = requests.request("POST", createTask_url, headers=headers, data=payload)
    response_json = response.json()
    taskId = response_json['taskId']

    getTaskResult_url = "https://api.ez-captcha.com/getTaskResult"

    payload = json.dumps({
        "clientKey": clientKey,
        "taskId": taskId
    })
    return get_task_result(getTaskResult_url, headers, payload)

def get_task_result(getTaskResult_url, headers, payload):
    max_retries = 12  # 最大重试次数
    retry_delay = 10  # 重试间隔时间（秒）

    for _ in range(max_retries):
        # 发送请求
        response = requests.post(getTaskResult_url, headers=headers, data=payload)

        try:
            response_json = response.json()
            errorId = response_json.get('errorId')
            status = response_json.get('status')

            if errorId == 1:
                print(response_json.get('errorDescription'))
                return None

            if status == 'ready':
                print('人机验证完成')
                return response_json.get('solution', {}).get('gRecaptchaResponse')

            elif status == 'processing':
                time.sleep(retry_delay)
                continue

            else:
                print("Unexpected status:", status)
                return None

        except Exception as e:
            print("Error occurred:", str(e))
            time.sleep(retry_delay)
            continue

    print("Max retries reached. Exiting.")
    return None

def ajax_check_email_verified(g_creationSessionID,cookie_str,session,eamil, pwd):
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
        # {
        #     "success": 36,
        #     "has_existing_account": 0,
        #     "steam_china_account": 0,
        #     "pw_account": 0,
        #     "global_account": 0,
        #     "guest": 0,
        #     "guest_refresh": null
        # }
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
                create_steam_account(account_name, password, 1, g_creationSessionID, 0, False,cookie_str,session,eamil, pwd)
                break
            else:
                print('等待邮箱验证')
                if imap_verfy_email_url(eamil, pwd, session,g_creationSessionID):
                    time.sleep(5)
                    verfy = True
                time.sleep(2)
        else:
            time.sleep(5)
def imap_verfy_email_url(email,password,session,g_creationSessionID):
    # 最大尝试次数
    max_attempts = 6
    attempts = 0
    imap_server = email_url
    username = email
    password = password
    # 选择使用的端口，143是普通IMAP，993是安全IMAP
    # True for SSL (993), False for non-SSL (143)
    imap_port = 993 if use_ssl else 143
    href = ''
    # SSL连接或普通连接
    if use_ssl:
        mail = imaplib.IMAP4_SSL(imap_server, imap_port)
    else:
        mail = imaplib.IMAP4(imap_server, imap_port)
    mail.login(username, password)
    urls = []
    while attempts < max_attempts:
        # 选择收件箱
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
        for url in urls:
            # 解析URL
            parsed_url = urlparse(url)
            # 提取查询字符串
            query_string = parsed_url.query
            # 解析查询字符串为字典
            params = parse_qs(query_string)
            creationid = params.get('creationid')
            if creationid[0] == g_creationSessionID:
                href = url
                break
        if href == "":
            print("未能匹配到邮件或链接，重新尝试")
            attempts += 1
            time.sleep(10)
        else:
            break
    mail.logout()
    if attempts == max_attempts:
        print("达到最大尝试次数，未能成功获取邮件或链接")
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
        "If-Modified-Since": "Mon, 01 Apr 2024 15:21:46 GMT"
    }
    if href != '':
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
    base_url = 'https://store.steampowered.com/join/checkavail/'  # 替换为实际的基础URL


    payload = {
        'accountname': account_name,
        'count': 1,  # 这个值是递增的，表示发送的请求次数
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
    base_url = 'https://store.steampowered.com/join/checkpasswordavail/'  # 替换为实际的基础URL

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

def create_steam_account(accountname, pass_word, lt, g_creationSessionID, g_embeddedAppID, g_bGuest,cookie_str,session,eamil, pwd):
    iAjaxCalls = 0  # 用来模拟++iAjaxCalls
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
    # 准备POST请求的参数
    data = {
        'accountname': accountname,
        'password': pass_word,
        'count': iAjaxCalls,
        'lt': lt,
        'creation_sessionid': g_creationSessionID,
        'embedded_appid': g_embeddedAppID,
        'guest': g_bGuest
    }

    url = 'https://store.steampowered.com/' + 'join/createaccount/'

    try:
        # 发送POST请求
        response = session.post(url, data=data,headers=ap_headers)
        if response.ok:
            result = response.json()
            # print(result)
            save_to_file(accountname,pass_word,eamil, pwd,result['bSuccess'])
        else:
            print('Failed to send request. HTTP Error:', response.status_code)
    except Exception as e:
        print('An error occurred:', str(e))

def save_to_file(account_name, password, email, pwd, boll):
    with open("accounts.txt", "a") as file:
        file.write(f"{account_name}----{password}----{email}----{pwd}----{boll}\n")
    with open("accounts-true.txt", "a") as file:
        if boll:
            file.write(f"{account_name}----{password}----{email}----{pwd}\n")

# 更换IP的函数
def get_ip():
    while True:
        try:
            proxy_ip = proxy_queue.get(block=True)  # 使用阻塞式获取
            return  proxy_ip
        except Exception as e:
            print(f"An error occurred while getting proxy IP: {e}")
            time.sleep(10)  # 等待一段时间后重试

def change_ip(proxy_ip):
    try:
        # 拆分代理IP的字符串
        parts = proxy_ip.split(':')
        # 获取 sessID 部分的值
        match = re.search(r"-sessID-(\w+)", parts[2])
        sessID = match.group(1)
        replaceip_url = f"http://{parts[0]}:9988/update?tunnelId=1911&sessID={sessID}&password={parts[3]}"
        res = requests.get(replaceip_url)
        if res.status_code == 200:
            # print(f"IP changed successfully to {proxy_ip}.")
            return True
        else:
            # print(f"Failed to change IP to {proxy_ip}.")
            return False
    except Exception as e:
        # print(f"An error occurred: {e}")
        return False

# 创建 ThreadPoolExecutor 对象，指定最大并发数为10
config_data = read_config('config.json')
proxy_ips = config_data['proxy_ips']
clientKey = config_data['clientKey']
email_url = config_data['email_url']
use_ssl = config_data['ssl']
executornum = config_data['executornum']

proxy_queue = queue.Queue()
for proxy_ip in proxy_ips:
    proxy_queue.put(proxy_ip)

executor = ThreadPoolExecutor(max_workers=executornum)

# 模拟任务
def task(email, password,proxy_ip,proxy_queue):
        main(email, password, proxy_ip,proxy_queue)

def start_tasks():
    with open("email_password.txt", "r") as file:
        emails_passwords = [line.strip().split("----") for line in file]
        for email, password in emails_passwords:
            proxy_ip = get_ip()
            if proxy_ip:
                executor.submit(task,email,password,proxy_ip,proxy_queue)
# 启动任务
start_tasks()
# 等待所有任务完成
executor.shutdown(wait=True)
