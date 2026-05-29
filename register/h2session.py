# h2session.py
# 创建日期: 2026-05-29 10:43:00（北京时间 UTC+8）
# 更新日期: 2026-05-29 10:50:00（北京时间 UTC+8）
# 使用模型: Claude Opus 4 (claude-opus-4-7-high)
# 用途说明: BLS HTTP/2 会话封装（基于 httpx + HTTP/2）

"""
BLS HTTP/2 会话封装
==================

使用 httpx + HTTP/2 的 BLS 会话类，参考 bls_register_solver_h2.py。
启用 HTTP/2 需要设置 config.USE_HTTP2 = True。

注意：cookie 由 httpx 自动管理，不需要手动设置。
"""

import gzip
from typing import Optional, Tuple

import httpx
import urllib3

from .config import BASE_URL

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ═══════════════════════════════════════════════════════════════════════════════
# HAR 精确 Header 定义（严格按照 HAR 抓包，不多也不少）
# ═══════════════════════════════════════════════════════════════════════════════

_HAR_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
_HAR_SEC_CH_UA = '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"'
_HAR_SEC_CH_UA_MOBILE = "?0"
_HAR_SEC_CH_UA_PLATFORM = '"Windows"'
_HAR_ACCEPT_LANGUAGE = "zh-CN,zh;q=0.9,en;q=0.8"
_HAR_ACCEPT_ENCODING = "gzip, deflate, br, zstd"


def make_headers_get_register_page(referer: str = None) -> dict:
    """GET /CHN/account/RegisterUser 的 header（严格匹配 HAR）"""
    return {
        "sec-ch-ua": _HAR_SEC_CH_UA,
        "sec-ch-ua-mobile": _HAR_SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": _HAR_SEC_CH_UA_PLATFORM,
        "upgrade-insecure-requests": "1",
        "user-agent": _HAR_UA,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-dest": "document",
        "referer": referer or f"{BASE_URL}/CHN/account/login",
        "accept-encoding": _HAR_ACCEPT_ENCODING,
        "accept-language": _HAR_ACCEPT_LANGUAGE,
        "priority": "u=0, i",
    }


def make_headers_get_captcha() -> dict:
    """GET /CHN/CaptchaPublic/GenerateCaptcha 的 header（严格匹配 HAR）"""
    return {
        "sec-ch-ua": _HAR_SEC_CH_UA,
        "sec-ch-ua-mobile": _HAR_SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": _HAR_SEC_CH_UA_PLATFORM,
        "upgrade-insecure-requests": "1",
        "user-agent": _HAR_UA,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-dest": "iframe",
        "referer": f"{BASE_URL}/CHN/account/RegisterUser",
        "accept-encoding": _HAR_ACCEPT_ENCODING,
        "accept-language": _HAR_ACCEPT_LANGUAGE,
        "priority": "u=0, i",
    }


def make_headers_submit_captcha(captcha_referer: str, content_length: int) -> dict:
    """POST /CHN/CaptchaPublic/SubmitCaptcha 的 header（严格匹配 HAR）"""
    return {
        "content-length": str(content_length),
        "sec-ch-ua-platform": _HAR_SEC_CH_UA_PLATFORM,
        "x-requested-with": "XMLHttpRequest",
        "user-agent": _HAR_UA,
        "accept": "*/*",
        "sec-ch-ua": _HAR_SEC_CH_UA,
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "sec-ch-ua-mobile": _HAR_SEC_CH_UA_MOBILE,
        "origin": BASE_URL,
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
        "referer": captcha_referer,
        "accept-encoding": _HAR_ACCEPT_ENCODING,
        "accept-language": _HAR_ACCEPT_LANGUAGE,
        "priority": "u=1, i",
    }


def make_headers_send_otp(rvt: str) -> dict:
    """POST /CHN/account/SendRegisterUserVerificationCode 的 header（严格匹配 HAR）"""
    return {
        "content-length": "0",
        "requestverificationtoken": rvt,
        "sec-ch-ua-platform": _HAR_SEC_CH_UA_PLATFORM,
        "x-requested-with": "XMLHttpRequest",
        "user-agent": _HAR_UA,
        "accept": "*/*",
        "sec-ch-ua": _HAR_SEC_CH_UA,
        "sec-ch-ua-mobile": _HAR_SEC_CH_UA_MOBILE,
        "origin": BASE_URL,
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
        "referer": f"{BASE_URL}/CHN/account/RegisterUser",
        "accept-encoding": _HAR_ACCEPT_ENCODING,
        "accept-language": _HAR_ACCEPT_LANGUAGE,
        "priority": "u=1, i",
    }


def make_headers_do_register(content_length: int) -> dict:
    """POST /CHN/Account/RegisterUser 的 header（严格匹配 HAR）"""
    return {
        "content-length": str(content_length),
        "sec-ch-ua-platform": _HAR_SEC_CH_UA_PLATFORM,
        "x-requested-with": "XMLHttpRequest",
        "user-agent": _HAR_UA,
        "accept": "*/*",
        "sec-ch-ua": _HAR_SEC_CH_UA,
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "sec-ch-ua-mobile": _HAR_SEC_CH_UA_MOBILE,
        "origin": BASE_URL,
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
        "referer": f"{BASE_URL}/CHN/account/RegisterUser",
        "accept-encoding": _HAR_ACCEPT_ENCODING,
        "accept-language": _HAR_ACCEPT_LANGUAGE,
        "priority": "u=1, i",
    }


def make_headers_generic(referer: str = None) -> dict:
    """通用 GET 请求的 header"""
    return {
        "sec-ch-ua": _HAR_SEC_CH_UA,
        "sec-ch-ua-mobile": _HAR_SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": _HAR_SEC_CH_UA_PLATFORM,
        "upgrade-insecure-requests": "1",
        "user-agent": _HAR_UA,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-dest": "document",
        "referer": referer or f"{BASE_URL}/CHN/account/RegisterUser",
        "accept-encoding": _HAR_ACCEPT_ENCODING,
        "accept-language": _HAR_ACCEPT_LANGUAGE,
        "priority": "u=1, i",
    }


class BLSSessionH2:
    """BLS 网站 HTTP/2 会话封装（使用 httpx）"""

    def __init__(self, proxy: Optional[dict] = None):
        self._proxy_url: Optional[str] = None
        if proxy:
            if isinstance(proxy, dict):
                self._proxy_url = proxy.get("http", proxy.get("https", ""))
            else:
                self._proxy_url = proxy

        self.client = httpx.Client(
            http2=True,
            verify=False,
            follow_redirects=False,
            timeout=30.0,
            proxy=self._proxy_url,
        )

        self.security_code = ""
        self.verify_token = ""
        self.captcha_id = ""
        self._reg_security_code = ""
        self.iframe_url = ""

    @property
    def reg_security_code(self) -> str:
        return self._reg_security_code

    def get(self, path, headers=None, timeout=25) -> Tuple[int, str, dict]:
        """GET 请求"""
        url = BASE_URL + path
        if headers is None:
            headers = make_headers_generic()
        try:
            resp = self.client.get(url, headers=headers, timeout=timeout)
            raw = resp.content
            try:
                text = gzip.decompress(raw).decode("utf-8", errors="replace")
            except Exception:
                text = raw.decode("utf-8", errors="replace")
            return resp.status_code, text, dict(resp.headers)
        except Exception as e:
            return 0, str(e), {}

    def post(self, path, headers=None, data=None, timeout=25) -> Tuple[int, str, dict]:
        """POST 请求"""
        url = BASE_URL + path
        if headers is None:
            headers = {}
        try:
            resp = self.client.post(url, headers=headers, data=data, timeout=timeout)
            raw = resp.content
            try:
                text = gzip.decompress(raw).decode("utf-8", errors="replace")
            except Exception:
                text = raw.decode("utf-8", errors="replace")
            return resp.status_code, text, dict(resp.headers)
        except Exception as e:
            return 0, str(e), {}

    def req(
        self,
        path: str,
        method: str = "GET",
        data=None,
        extra: Optional[dict] = None,
        timeout: int = 25,
    ) -> Tuple[int, str, dict]:
        """
        统一的请求方法（兼容 HTTP/1.1 版本的接口）

        HTTP/2 模式下：
        - HAR header 优先
        - extra 作为补充，但不覆盖 HAR header 中的关键字段
        """
        if path.startswith("http"):
            url = path
        else:
            url = BASE_URL + path

        # 计算实际发送的内容
        send_data = data
        if data and isinstance(data, dict):
            from urllib.parse import urlencode
            send_data = urlencode(data)

        # HTTP/2 模式下，先应用 extra（作为基础），再应用 HAR header（覆盖）
        # 这样 HAR header 始终保持优先
        base_headers = dict(extra) if extra else {}

        # 根据路径选择正确的 HAR header
        if method == "GET":
            if "GenerateCaptcha" in path:
                har_headers = make_headers_get_captcha()
            else:
                har_headers = make_headers_get_register_page()
        else:
            har_headers = {}
            if "SendRegisterUserVerificationCode" in path:
                # OTP 发送：参数在 query string 中，无请求体
                rvt = base_headers.get("RequestVerificationToken", "")
                har_headers = make_headers_send_otp(rvt)
                send_data = None  # HAR 中是 content-length: 0
            elif "RegisterUser" in path and "Captcha" not in path:
                # 注册提交
                content_length = len(send_data) if send_data else 0
                har_headers = make_headers_do_register(content_length)
            elif "SubmitCaptcha" in path:
                # 验证码提交
                content_length = len(send_data) if send_data else 0
                iframe_url = getattr(self, 'iframe_url', '') or ""
                # iframe_url 已经是完整路径: /CHN/CaptchaPublic/GenerateCaptcha?data=...
                # referer 应该是: BASE_URL + iframe_url
                referer = BASE_URL + iframe_url
                har_headers = make_headers_submit_captcha(referer, content_length)

        # HAR header 覆盖 base_headers
        headers = {**base_headers, **har_headers}

        if method == "POST" and send_data and "Content-Type" not in headers:
            headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"

        kwargs = {"timeout": timeout}
        if send_data:
            kwargs["content"] = send_data.encode("utf-8")

        try:
            resp = self.client.request(method, url, headers=headers, **kwargs)
            raw = resp.content
            try:
                text = gzip.decompress(raw).decode("utf-8", errors="replace")
            except Exception:
                text = raw.decode("utf-8", errors="replace")
            return resp.status_code, text, dict(resp.headers)
        except Exception as e:
            return 0, str(e), {}


# 兼容性别名
BLSSession = BLSSessionH2