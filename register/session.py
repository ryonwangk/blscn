# session.py
# 创建日期: 2026-05-29 09:50:00（北京时间 UTC+8）
# 更新日期: 2026-05-29 09:50:00（北京时间 UTC+8）
# 使用模型: Claude Opus 4 (claude-opus-4-7-high)
# 用途说明: BLS HTTP 会话封装

"""
BLS HTTP 会话封装
================

提供 HTTP 请求封装，处理 gzip 压缩、代理等。
"""

import gzip
from typing import Optional, Tuple

import requests
import urllib3

from .config import BASE_URL

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class BLSSession:
    """BLS 网站 HTTP 会话封装"""

    def __init__(self, proxy: Optional[dict] = None):
        """
        Args:
            proxy: 代理配置，如 {"http": "http://...", "https": "..."}
        """
        self._proxy_url: Optional[str] = None
        if proxy:
            if isinstance(proxy, dict):
                self._proxy_url = proxy.get("http", proxy.get("https", ""))
            else:
                self._proxy_url = proxy

        self.session = requests.Session()
        self.session.trust_env = False  # 禁用系统代理
        self.session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        })

        self._proxies = None
        if self._proxy_url:
            self._proxies = {"http": self._proxy_url, "https": self._proxy_url}

        # 注册流程中各步骤获取的值
        self.security_code = ""
        self.verify_token = ""
        self.captcha_id = ""
        self._reg_security_code = ""
        self.iframe_url = ""

    @property
    def reg_security_code(self) -> str:
        return self._reg_security_code

    def req(
        self,
        path: str,
        method: str = "GET",
        data: Optional[dict] = None,
        extra: Optional[dict] = None,
        timeout: int = 25,
    ) -> Tuple[int, str, dict]:
        """
        发送 HTTP 请求

        Args:
            path: 请求路径或完整 URL
            method: HTTP 方法 GET/POST
            data: POST 数据
            extra: 额外的请求头
            timeout: 超时时间（秒）

        Returns:
            (status_code, response_text, headers)
        """
        if path.startswith("http"):
            url = path
        else:
            url = BASE_URL + path

        headers = dict(self.session.headers)
        if extra:
            headers.update(extra)

        if method == "POST" and data and "Content-Type" not in headers:
            headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"

        kwargs = {
            "headers": headers,
            "timeout": timeout,
            "allow_redirects": False,
            "verify": False,
        }
        if self._proxies:
            kwargs["proxies"] = self._proxies
        if data:
            kwargs["data"] = data

        try:
            resp = self.session.request(method, url, **kwargs)
            raw = resp.content
            try:
                text = gzip.decompress(raw).decode("utf-8", errors="replace")
            except Exception:
                text = raw.decode("utf-8", errors="replace")
            return resp.status_code, text, dict(resp.headers)
        except Exception as e:
            return 0, str(e), {}
