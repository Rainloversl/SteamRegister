import json
import os
import tkinter as tk
from tkinter import ttk
import threading
from tkinter import messagebox
from tkinter import filedialog
from ThreadManager import GUIThreadManager

class RegistrationGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Steam注册")
        self.root.geometry("800x800")
        
        # 创建主框架
        main_frame = ttk.Frame(root)
        main_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # 创建配置框架
        config_frame = ttk.LabelFrame(main_frame, text="配置信息")
        config_frame.pack(fill="x", padx=5, pady=5)
        
        # 加载默认配置
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.config_path = os.path.join(self.script_dir, 'config.json')
        self.config = self._load_config()
        
        # 创建配置输入框
        self.config_vars = {}
        self._create_config_widgets(config_frame)
        
        # 创建文件选择框架
        files_frame = ttk.LabelFrame(main_frame, text="文件选择")
        files_frame.pack(fill="x", padx=5, pady=5)
        
        # 邮箱文件选择
        self.email_path = tk.StringVar(value=os.path.join(self.script_dir, 'email_password.txt'))
        self._create_file_selector(files_frame, "邮箱文件:", self.email_path, 0)
        
        # 代理文件选择
        self.proxy_path = tk.StringVar(value=os.path.join(self.script_dir, 'proxy_ips.txt'))
        self._create_file_selector(files_frame, "代理文件:", self.proxy_path, 1)
        
        # 创建任务列表框架
        task_frame = ttk.LabelFrame(main_frame, text="任务状态")
        task_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # 创建表格
        self.tree = ttk.Treeview(task_frame, columns=("邮箱", "状态", "账户名", "密码", "结果"), show="headings")
        
        # 设置列头
        self.tree.heading("邮箱", text="邮箱")
        self.tree.heading("状态", text="状态")
        self.tree.heading("账户名", text="账户名")
        self.tree.heading("密码", text="密码")
        self.tree.heading("结果", text="结果")
        
        # 设置列宽
        self.tree.column("邮箱", width=200)
        self.tree.column("状态", width=200)
        self.tree.column("账户名", width=100)
        self.tree.column("密码", width=100)
        self.tree.column("结果", width=100)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(task_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # 布局
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # 存储线程状态
        self.thread_status = {}

        # 创建控制面板
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(side="bottom", fill="x", padx=5, pady=5)
        
        # 添加开始按钮
        self.start_button = ttk.Button(
            control_frame, 
            text="开始注册", 
            command=self.start_registration
        )
        self.start_button.pack(side="left", padx=5)
        
        # 添加停止按钮
        self.stop_button = ttk.Button(
            control_frame, 
            text="停止注册",
            command=self.stop_registration,
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)
    
    def _load_config(self):
        """加载配置文件"""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            messagebox.showerror("错误", f"加载配置文件失败: {str(e)}")
            return {}  
          
    def _create_config_widgets(self, parent):
        """创建配置输入控件"""
        config_items = [
            ("protocol", "协议类型:", ["GRAPH", "IMAP", "POP3", "IMAP_OAUTH", "POP3_OAUTH"]),
            ("clientKey", "客户端密钥:", None),
            ("ssl", "启用SSL:", ["True", "False"]),
            ("email_url", "邮箱服务器:", None),
            ("executornum", "线程数量:", None)
        ]
        
        for i, (key, label, options) in enumerate(config_items):
            ttk.Label(parent, text=label,width=10).grid(row=i, column=0, padx=5, pady=2, sticky="e")
            
            if options:
                var = tk.StringVar(value=str(self.config.get(key, "")))
                widget = ttk.Combobox(parent, textvariable=var, values=options,width=50)
            else:
                var = tk.StringVar(value=str(self.config.get(key, "")))
                widget = ttk.Entry(parent, textvariable=var, width=50)
            
            widget.grid(row=i, column=1, padx=5, pady=2, sticky="ew")
            self.config_vars[key] = var    

    def _create_file_selector(self, parent, label, var, row):
        """创建文件选择器"""
        parent.grid_columnconfigure(1, weight=1)
        ttk.Label(parent, text=label).grid(row=row, column=0, padx=5, pady=2, sticky="e")
        ttk.Entry(parent, textvariable=var).grid(row=row, column=1, padx=5, pady=2, sticky="ew")
        ttk.Button(parent, text="选择文件", 
                  command=lambda: var.set(filedialog.askopenfilename())
                  ).grid(row=row, column=2, padx=5, pady=2)        
    
    def update_status(self, email, status=None, account_name=None, password=None, result=None):
        if email not in self.thread_status:
            # 新建条目，将None替换为空字符串
            values = (
                email,
                status if status is not None else "",
                account_name if account_name is not None else "",
                password if password is not None else "",
                result if result is not None else ""
            )
            self.thread_status[email] = self.tree.insert("", "end", values=values)
        else:
            # 获取当前值
            current_values = list(self.tree.item(self.thread_status[email])['values'])
            
            # 只更新非None的值
            if status is not None:
                current_values[1] = status
            if account_name is not None:
                current_values[2] = account_name
            if password is not None:
                current_values[3] = password
            if result is not None:
                current_values[4] = result
                
            # 更新现有条目
            self.tree.item(self.thread_status[email], values=tuple(current_values))
        
        self.root.update()
    
    def get_completed_tasks(self):
        """获取已经完成的任务列表"""
        completed_tasks = set()
        for email in self.thread_status:
            values = self.tree.item(self.thread_status[email])['values']
            if values[4]:  # 检查result列是否有值
                completed_tasks.add(email)
        return completed_tasks    
    
    def _save_config(self):
        """保存配置"""
        try:
            config = {}
            for key, var in self.config_vars.items():
                value = var.get()
                if key == "executornum":
                    value = int(value)
                elif key == "ssl":
                    value = value.lower() == "true"
                config[key] = value
                
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            messagebox.showerror("错误", f"保存配置失败: {str(e)}")
    
    def _validate_inputs(self):
        """验证输入"""
        if not os.path.exists(self.email_path.get()):
            messagebox.showerror("错误", "邮箱文件不存在")
            return False
            
        if not os.path.exists(self.proxy_path.get()):
            messagebox.showerror("错误", "代理文件不存在")
            return False
            
        # 验证配置值
        for key, var in self.config_vars.items():
            if not var.get().strip():
                messagebox.showerror("错误", f"请填写 {key} 配置项")
                return False
            
        return True
    
    def start_registration(self):
        """启动注册流程"""
        try:
            if not self._validate_inputs():  # 添加输入验证
                return
                
            if not self._save_config():
                return
                
            if hasattr(self, 'manager') and self.manager:
                messagebox.showwarning("警告", "任务已在运行中")
                return
                
            self.start_button.config(state="disabled")
            self.stop_button.config(state="normal")
            
            threading.Thread(target=self._start_registration_thread, 
                        daemon=True, 
                        name="RegistrationThread").start()
        except Exception as e:
            messagebox.showerror("错误", f"启动失败: {str(e)}")
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")

    def _start_registration_thread(self):
        """在新线程中启动注册"""
        try:
            
            completed_tasks = self.get_completed_tasks()                
            
            self.manager = GUIThreadManager(
                self.config_path,
                self.email_path.get(),
                self.proxy_path.get(),
                self,
                completed_tasks
            )
            self.manager.start()
            
        except Exception as e:
            messagebox.showerror("错误", str(e))
        finally:
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")

    def stop_registration(self):
        """停止注册流程"""
        if hasattr(self, 'manager'):
            self.manager.stop() 
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    gui = RegistrationGUI(root)
    root.mainloop()