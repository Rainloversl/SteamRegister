import queue
import time

class ProxyPool:
    """代理IP池管理"""
    def __init__(self, proxy_file_path):
        self.proxy_queue = queue.Queue()
        self.success_queue = queue.Queue()
        self._load_proxies(proxy_file_path)
        
    def _load_proxies(self, file_path):
        """加载代理IP"""
        try:
            with open(file_path, "r") as file:
                proxy_ips = [line.strip() for line in file if line.strip()]
                self.proxy_count = len(proxy_ips)
                if self.proxy_count == 0:
                    raise ValueError("代理文件为空")
                for proxy in proxy_ips:
                    self.proxy_queue.put(proxy)
        except FileNotFoundError:
            raise FileNotFoundError(f"代理文件不存在: {file_path}")
        except Exception as e:
            raise Exception(f"加载代理文件失败: {str(e)}")
                
    def get_proxy(self):
        """获取代理IP"""
        max_retries = 12  # 最大等待时间60秒
        retries = 0
        
        while retries < max_retries:
            try:
                if not self.success_queue.empty():
                    return self.success_queue.get(block=False)
                
                if not self.proxy_queue.empty():
                    return self.proxy_queue.get(block=True, timeout=5)
                
                if self.proxy_count == 0:
                    raise ValueError("无可用代理")
                    
                retries += 1
                time.sleep(5)
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"获取代理失败: {e}")
                time.sleep(1)
                
        raise TimeoutError("获取代理超时")
                
    def mark_success(self, proxy):
        """标记成功的代理"""
        self.success_queue.put(proxy)
        
    def mark_fail(self, proxy):
        """标记失败的代理"""
        self.proxy_queue.put(proxy)