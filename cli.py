"""steamrg.py 的轻量 CLI 包装：从 config.json / email_password.txt 读取配置并启动注册流程。

用法:
    python cli.py                 # 使用默认路径
    python cli.py --config c.json --emails e.txt --workers 3
"""
import argparse
import json
import os
import sys


def main():
    parser = argparse.ArgumentParser(description="Steam 自动注册（无界面模式）")
    parser.add_argument("--config", default="config.json", help="配置文件路径")
    parser.add_argument("--emails", default="email_password.txt", help="邮箱凭据文件路径")
    parser.add_argument("--workers", type=int, default=None, help="覆盖配置中的线程数量 executornum")
    args = parser.parse_args()

    for path in (args.config, args.emails):
        if not os.path.isfile(path):
            print(f"错误: 文件不存在: {path}", file=sys.stderr)
            sys.exit(1)

    with open(args.config, "r", encoding="utf-8") as f:
        config = json.load(f)
    env_key = os.environ.get("CAPTCHA_API_KEY")
    if env_key:
        config["clientKey"] = env_key
    if args.workers:
        config["executornum"] = args.workers

    with open(args.config, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

    # 通过 runpy 以 __main__ 方式执行 steamrg，触发其注册主流程
    import runpy

    runpy.run_path(os.path.join(os.path.dirname(os.path.abspath(__file__)), "steamrg.py"), run_name="__main__")


if __name__ == "__main__":
    main()
