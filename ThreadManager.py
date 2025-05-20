from concurrent.futures import ThreadPoolExecutor
import json
import os
import threading
from ProxyPool import ProxyPool
from SteamRegistration import SteamRegistration


class ThreadManager:
    """线程管理器"""
    def __init__(self, config_path, email_file_path, proxy_file_path):
        self.config = self._load_config(config_path)
        self._validate_config()
        self.proxy_pool = ProxyPool(proxy_file_path)
        self.email_file = email_file_path
        self.executor = ThreadPoolExecutor(max_workers=self.config['executornum'])
        self._registration_local = threading.local()
        self._running = True
        self._registrations = set()
        self._registrations_lock = threading.Lock()
    
    def _validate_config(self):
        """验证配置有效性"""
        required_fields = ['protocol', 'clientKey', 'ssl', 'email_url', 'executornum']
        for field in required_fields:
            if field not in self.config:
                raise ValueError(f"配置缺少必要字段: {field}")
    
    def _load_config(self, config_path):
        """加载配置"""
        with open(config_path, 'r') as f:
            return json.load(f)
            
    def parse_email_credentials(self, line):
        """解析邮件凭据"""
        parts = line.strip().split("----")
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
                'refresh_token': parts[3]
            }
        raise ValueError("Invalid email credentials format")

    def _get_registration(self):
        """获取线程本地的SteamRegistration实例"""
        if not hasattr(self._registration_local, 'registration'):
            registration = SteamRegistration(
                self.config,
                self.proxy_pool,
            )
            self._registration_local.registration = registration
            # 将新创建的实例添加到跟踪集合
            with self._registrations_lock:
                self._registrations.add(registration)
        return self._registration_local.registration
        
    def process_email(self, email_data):
        registration = self._get_registration()
        registration.main(email_data)

    
    def stop(self):
        """停止所有任务"""
        self._running = False
        # 首先关闭线程池，不再接受新任务
        self.executor.shutdown(wait=False)

        # 遍历并停止所有注册实例
        with self._registrations_lock:
            for registration in self._registrations:
                try:
                    registration.running = False
                    if (hasattr(registration, 'session') and 
                        registration.session and 
                        not getattr(registration.session, 'closed', True)):
                        # 只有当session存在且未关闭时才进行关闭
                        registration.session.close()
                except Exception as e:
                    pass

            # 清空实例集合
            self._registrations.clear()
              
    def start(self):
        """启动处理"""
        self._running = True
        try:
            with open(self.email_file, "r") as file:
                for line in file:
                    if not self._running:
                        break
                    try:
                        email_data = self.parse_email_credentials(line.strip())
                        self.executor.submit(self.process_email, email_data)
                    except ValueError as e:
                        print(f"错误的邮箱格式: {e}")
                        continue
        finally:
            self.executor.shutdown(wait=True)

class GUIThreadManager(ThreadManager):
    def __init__(self, config_path, email_file_path, proxy_file_path, gui,completed_tasks=None):
        super().__init__(config_path, email_file_path, proxy_file_path)
        self.gui = gui
        self.completed_tasks = completed_tasks or set()

    def process_email(self, email_data):
        """处理单个邮件账号""" 
        try:
            if not self._running:  # 检查是否应该继续
                self.gui.update_status(email_data['email'], "任务已停止")
                return
            self.gui.update_status(email_data['email'], "开始验证邮箱")
            registration = self._get_registration()
            registration.set_gui(self.gui)  # 设置GUI引用
            registration.running = self._running
            registration.main(email_data)
        except Exception as e:
            self.gui.update_status(email_data['email'], f"处理失败: {e}")
    
    def start(self):
        """启动处理"""
        self._running = True
        with open(self.email_file, 'r', encoding='utf-8') as file:
            all_lines = file.readlines()  # 一次性读取所有行
        with ThreadPoolExecutor(max_workers=self.config['executornum']) as self.executor:
            for line in all_lines:
                if not self._running:
                    break
                try:
                    email_data = self.parse_email_credentials(line.strip())
                    # 跳过已完成的任务
                    if email_data['email'] not in self.completed_tasks:
                        self.executor.submit(self.process_email, email_data)
                except ValueError as e:
                    self.gui.update_status(email_data.get('email', '未知'), f"解析邮箱文件失败: {e}")