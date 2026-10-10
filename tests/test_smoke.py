"""冒烟测试：验证核心模块可导入、配置解析与邮箱凭据解析逻辑正确。

运行: pytest -q  （或 python -m pytest）
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import steamrg  # noqa: E402


class TestReadConfig(unittest.TestCase):
    def test_reads_json(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "config.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"clientKey": "k", "protocol": "GRAPH"}, f)
            cfg = steamrg.read_config(path)
            self.assertEqual(cfg["clientKey"], "k")

    def test_env_override(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "config.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"clientKey": "k"}, f)
            old = os.environ.get("CAPTCHA_API_KEY")
            os.environ["CAPTCHA_API_KEY"] = "env-key"
            try:
                cfg = steamrg.read_config(path)
                self.assertEqual(cfg["clientKey"], "env-key")
            finally:
                if old is None:
                    os.environ.pop("CAPTCHA_API_KEY", None)
                else:
                    os.environ["CAPTCHA_API_KEY"] = old


class TestParseEmailCredentials(unittest.TestCase):
    def test_two_fields(self):
        data = steamrg.parse_email_credentials("a@b.com----password123")
        self.assertEqual(data["email"], "a@b.com")
        self.assertEqual(data["password"], "password123")

    def test_four_fields(self):
        data = steamrg.parse_email_credentials(
            "a@b.com----pwd----client_id_x----refresh_token_y"
        )
        self.assertEqual(data["client_id"], "client_id_x")
        self.assertEqual(data["refresh_token"], "refresh_token_y")


class TestProtocolCompliance(unittest.TestCase):
    """HCaptchaSteam 协议关键约束的静态检查。"""

    def test_sitekey_fixed_in_source(self):
        src = open(
            os.path.join(os.path.dirname(steamrg.__file__), "SteamRegistration.py"),
            encoding="utf-8",
        ).read()
        self.assertIn('"siteKey": "e18a349a-46c2-46a0-87a8-74be79345c92"', src)
        self.assertIn("api.captcha-run.com/v2/tasks", src)
        # 禁止传递代理参数
        create_task_block = src.split("_get_gRecaptchaResponse")[1].split("_get_task_result")[0]
        for forbidden in ('"host"', '"port"', '"login"', '"password"'):
            self.assertNotIn(forbidden, create_task_block)


if __name__ == "__main__":
    unittest.main()
