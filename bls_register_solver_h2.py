# bls_register_solver_h2.py
# 创建日期: 2026-05-27 10:45:00（北京时间 UTC+8）
# 更新日期: 2026-05-27 10:45:00（北京时间 UTC+8）
# 使用模型: Claude Opus 4 (claude-opus-4-7-high)
# 用途说明: BLS 中国站注册流程 - HTTP/2 版本，严格匹配 HAR 抓包 header

"""
BLS China 注册流程 — HTTP/2 版本（严格匹配 HAR header）
=======================================================
使用 httpx + HTTP/2，严格匹配 HAR 抓包中的每个请求的 header。

每个请求的 header 与 HAR 完全一致，不多也不少：
1. GET /CHN/account/RegisterUser
2. GET /CHN/CaptchaPublic/GenerateCaptcha
3. POST /CHN/CaptchaPublic/SubmitCaptcha
4. POST /CHN/account/SendRegisterUserVerificationCode
5. POST /CHN/Account/RegisterUser
"""

import sys
import os
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_parent_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), os.pardir))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

import base64
import gzip
import html as html_module
import io
import json
import random
import re
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, timedelta
from typing import Optional

import httpx
from bs4 import BeautifulSoup

from tools.mail.mailtm import MailTmClient, MailTmError

# ═══════════════════════════════════════════════════════════════════════════════
# 全局配置
# ═══════════════════════════════════════════════════════════════════════════════
TARGET_HOST = "spain.blscn.cn"
BASE_URL    = f"https://{TARGET_HOST}"

# ── 调试开关 ─────────────────────────────────────────────────────────────────
USE_REQABLE_PROXY = True
REQABLE_PROXY_HOST = "127.0.0.1"
REQABLE_PROXY_PORT = 9000
DEBUG_NO_PROXY = False

# OCR 模型路径
_ocr_model_path = os.path.join(
    os.path.dirname(__file__),
    "res",
    "ocr_model",
    "bls3_final_e37_s35000.onnx",
)
_charset_path = os.path.join(
    os.path.dirname(__file__),
    "res",
    "ocr_model",
    "bls3_meta.json",
)
_default_charset = [' ', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

# 邮件轮询参数
EMAIL_TIMEOUT        = 180.0
EMAIL_TIMEOUT_FINAL  = 300.0
EMAIL_POLL_INTERVAL  = 3.0
EMAIL_FROM_KEY       = "blscn"

# 验证码重试次数
CAPTCHA_MAX_RETRY    = 0


# ═══════════════════════════════════════════════════════════════════════════════
# HAR 精确 Header 定义（严格按照 HAR 抓包，不多也不少）
# ═══════════════════════════════════════════════════════════════════════════════

# HAR 中的基础 Header 值（所有请求共享）
_HAR_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
_HAR_SEC_CH_UA = '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"'
_HAR_SEC_CH_UA_MOBILE = "?0"
_HAR_SEC_CH_UA_PLATFORM = '"Windows"'
_HAR_ACCEPT_LANGUAGE = "zh-CN,zh;q=0.9,en;q=0.8"
_HAR_ACCEPT_ENCODING = "gzip, deflate, br, zstd"


def make_headers_get_register_page(referer: str = None) -> dict:
    """GET /CHN/account/RegisterUser 的 header（严格匹配 HAR）
    注意：cookie 由 httpx 自动管理，不需要手动设置"""
    return {
        # HTTP/2 伪头（httpx 自动处理）
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
        # cookie 由 httpx 自动管理
        "priority": "u=0, i",
    }


def make_headers_get_captcha() -> dict:
    """GET /CHN/CaptchaPublic/GenerateCaptcha 的 header（严格匹配 HAR）
    注意：cookie 由 httpx 自动管理"""
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
        "sec-fetch-dest": "iframe",  # 与 RegisterUser 不同！
        "referer": f"{BASE_URL}/CHN/account/RegisterUser",
        "accept-encoding": _HAR_ACCEPT_ENCODING,
        "accept-language": _HAR_ACCEPT_LANGUAGE,
        # cookie 由 httpx 自动管理
        "priority": "u=0, i",
    }


def make_headers_submit_captcha(captcha_referer: str, content_length: int) -> dict:
    """POST /CHN/CaptchaPublic/SubmitCaptcha 的 header（严格匹配 HAR）
    注意：cookie 由 httpx 自动管理"""
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
        # cookie 由 httpx 自动管理
        "priority": "u=1, i",
    }


def make_headers_send_otp(rvt: str) -> dict:
    """POST /CHN/account/SendRegisterUserVerificationCode 的 header（严格匹配 HAR）
    注意：cookie 由 httpx 自动管理"""
    return {
        "content-length": "0",  # 关键：无请求体！
        "requestverificationtoken": rvt,  # 注意是小写，不是 __RequestVerificationToken！
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
        # cookie 由 httpx 自动管理
        "priority": "u=1, i",
    }


def make_headers_do_register(content_length: int) -> dict:
    """POST /CHN/Account/RegisterUser 的 header（严格匹配 HAR）
    注意：cookie 由 httpx 自动管理"""
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
        # cookie 由 httpx 自动管理
        "priority": "u=1, i",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 线程安全：ONNX Session 全局单例
# ═══════════════════════════════════════════════════════════════════════════════
_onnx_sess_map: dict = {}
_onnx_lock = threading.Lock()


def _get_onnx_sess(onnx_path: str):
    if onnx_path not in _onnx_sess_map:
        with _onnx_lock:
            if onnx_path not in _onnx_sess_map:
                import onnxruntime as ort
                sess = ort.InferenceSession(onnx_path)
                inp_name = sess.get_inputs()[0].name
                _onnx_sess_map[onnx_path] = (sess, inp_name)
    return _onnx_sess_map[onnx_path]


# ═══════════════════════════════════════════════════════════════════════════════
# 随机注册信息生成器
# ═══════════════════════════════════════════════════════════════════════════════
_SURNAMES = [
    "Wang", "Li", "Zhang", "Liu", "Chen", "Yang", "Huang", "Zhao", "Wu", "Zhou",
    "Xu", "Sun", "Ma", "Zhu", "Hu", "Guo", "He", "Gao", "Lin", "Luo",
]
_FIRST_NAMES = [
    "San", "Wei", "Ming", "Hong", "Jun", "Xin", "Fang", "Li", "Xiao",
    "Hua", "Yan", "Ling", "Qiang", "Ping", "Jian", "Yong", "Gang", "Lin",
    "Jie", "Rui", "Hai", "Bin", "Chun", "Yan", "Xia", "Lin", "Tao",
]
_ISSUE_PLACES = [
    "Beijing", "Shanghai", "Guangzhou", "Shenzhen", "Chengdu", "Hangzhou",
    "Nanjing", "Wuhan", "Xian", "Chongqing", "Tianjin", "Suzhou",
]


def _generate_person_info() -> dict:
    """生成随机注册信息（符合 BLS 中国护照要求）"""
    today = date.today()

    age_years = random.randint(17, 55)
    dob = today - timedelta(days=age_years * 365 + random.randint(0, 364))
    dob = dob.replace(year=dob.year, month=random.randint(1, 12), day=random.randint(1, 28))

    age_at_issue = (today - dob).days / 365.25
    pp_validity_years = 10 if age_at_issue > 16 else 5

    days_ago = random.randint(90, 365)
    pp_issue = today - timedelta(days=days_ago)
    pp_issue = pp_issue.replace(
        year=pp_issue.year,
        month=random.randint(1, 12),
        day=min(random.randint(1, 28), _days_in_month(pp_issue.year, pp_issue.month)),
    )

    pp_expiry = pp_issue + timedelta(days=pp_validity_years * 365)
    min_expiry = today + timedelta(days=180)
    if pp_expiry < min_expiry:
        pp_expiry = min_expiry

    pp_no = f"E{random.randint(10000000, 99999999)}"

    surname   = random.choice(_SURNAMES).upper()
    first_name = random.choice(_FIRST_NAMES)
    last_name  = surname

    prefixes = ["130", "131", "132", "133", "134", "135", "136", "137", "138",
                "139", "150", "151", "152", "153", "155", "156", "157", "158",
                "159", "170", "171", "172", "173", "175", "176", "177", "178",
                "180", "181", "182", "183", "184", "185", "186", "187", "188",
                "189", "198", "199"]
    mobile = random.choice(prefixes) + str(random.randint(10000000, 99999999))

    return {
        "surname":      surname,
        "first_name":   first_name,
        "last_name":    last_name,
        "dob":          dob,
        "pp_issue":     pp_issue,
        "pp_expiry":    pp_expiry,
        "pp_no":        pp_no,
        "issue_place":  random.choice(_ISSUE_PLACES),
        "validity_years": pp_validity_years,
        "mobile":       mobile,
    }


def _days_in_month(year: int, month: int) -> int:
    """返回指定年月的天数"""
    if month == 2:
        if (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0):
            return 29
        return 28
    if month in (4, 6, 9, 11):
        return 30
    return 31


# ═══════════════════════════════════════════════════════════════════════════════
# BLS HTTP Session（H2 版本，严格匹配 HAR Header）
# ═══════════════════════════════════════════════════════════════════════════════
class BLSSessionH2:
    """BLS 网站 HTTP/2 会话封装，严格匹配 HAR Header"""

    def __init__(self, proxy=None):
        self._proxy_url = None
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

    @property
    def reg_security_code(self) -> str:
        return self._reg_security_code

    def get(self, path, headers, timeout=25):
        """GET 请求"""
        url = BASE_URL + path
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

    def post(self, path, headers, content=None, timeout=25):
        """POST 请求"""
        url = BASE_URL + path
        try:
            resp = self.client.post(url, headers=headers, content=content, timeout=timeout)
            raw = resp.content
            try:
                text = gzip.decompress(raw).decode("utf-8", errors="replace")
            except Exception:
                text = raw.decode("utf-8", errors="replace")
            return resp.status_code, text, dict(resp.headers)
        except Exception as e:
            return 0, str(e), {}


# ═══════════════════════════════════════════════════════════════════════════════
# 通用 HTML 解析
# ═══════════════════════════════════════════════════════════════════════════════
def _parse_hidden_inputs(html: str) -> dict[str, str]:
    """使用 BeautifulSoup 解析所有 input[type=hidden]"""
    soup = BeautifulSoup(html, "html.parser")
    result: dict[str, str] = {}
    for inp in soup.find_all("input", type="hidden"):
        name = inp.get("name", "") or inp.get("id", "")
        value = inp.get("value", "")
        if name:
            result[name] = value
    if "CaptchaId" not in result:
        m = re.search(r'<input[^>]+id=["\']CaptchaId["\'][^>]+value=["\']([^"\']+)["\']', html)
        if m:
            result["CaptchaId"] = m.group(1)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Step 1: 获取注册页面（严格匹配 HAR header）
# ═══════════════════════════════════════════════════════════════════════════════
def step1_get_register_page(session: BLSSessionH2, max_retry: int = 3) -> bool:
    for attempt in range(1, max_retry + 1):
        headers = make_headers_get_register_page()

        status, html, _ = session.get("/CHN/account/RegisterUser", headers)
        if status != 200:
            print(f"    [尝试 {attempt}/{max_retry}] HTTP {status}")
            if attempt < max_retry:
                time.sleep(2)
                continue
            return False

        hidden = _parse_hidden_inputs(html)
        session.security_code = hidden.get("SecurityCode", "")
        session.verify_token = hidden.get("__RequestVerificationToken", "")
        session.captcha_id = hidden.get("CaptchaId", "")

        print(f"    [Step1] hidden keys: {list(hidden.keys())}")
        print(f"    [Step1] CaptchaId from hidden: {session.captcha_id}")

        if session.security_code and session.verify_token:
            return True
        if attempt < max_retry:
            time.sleep(2)
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# Step 2: 获取验证码页面（严格匹配 HAR header）
# ═══════════════════════════════════════════════════════════════════════════════
def step2_get_captcha(session: BLSSessionH2) -> tuple[dict, str | None]:
    headers = make_headers_get_captcha()

    url = f"/CHN/CaptchaPublic/GenerateCaptcha?data={session.security_code}"
    status, html, _ = session.get(url, headers)
    if status != 200:
        return {}, None

    # 保存 captcha referer（用于 SubmitCaptcha）
    session._captcha_referer = f"{BASE_URL}/CHN/CaptchaPublic/GenerateCaptcha?data={session.security_code}"

    style_blocks = re.findall(r'<style[^>]*>(.*?)</style>', html, re.DOTALL)
    css_text = '\n'.join(style_blocks)

    class_info = {}
    for cls_name, props in re.findall(r'\.([a-z0-9]+)\{([^}]+)\}', css_text):
        left = top = z = None
        display = None
        m_left  = re.search(r'left\s*:\s*(-?\d+)px', props)
        m_top   = re.search(r'top\s*:\s*(-?\d+)px', props)
        m_z     = re.search(r'z-index\s*:\s*(\d+)', props)
        m_disp  = re.search(r'display\s*:\s*(\w+)', props)
        if m_left:  left    = int(m_left.group(1))
        if m_top:  top     = int(m_top.group(1))
        if m_z:    z       = int(m_z.group(1))
        if m_disp: display = m_disp.group(1)
        if left is not None or top is not None or z is not None or display is not None:
            class_info[cls_name] = {"left": left, "top": top, "z": z, "display": display}

    script_text = '\n'.join(style_blocks)
    for block in re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL):
        script_text += '\n' + block

    show_ids = set()
    hide_ids = set()
    for m in re.finditer(r"\$\(['\"]#?(\w+)['\"]\)\.(show|hide)\(\)", script_text):
        elem_id, action = m.group(1), m.group(2)
        (show_ids if action == 'show' else hide_ids).add(elem_id)

    soup = BeautifulSoup(html, 'html.parser')
    img_entries = []

    for img in soup.find_all('img'):
        if not img.get('class'):
            continue
        ic = img.get('class', [])
        if isinstance(ic, str):
            ic = ic.split()
        if 'captcha-img' not in ic:
            continue
        src = img.get('src', '')
        if not src.startswith('data:'):
            continue
        parent = img.parent
        while parent and parent.name != 'div':
            parent = parent.parent
        if not parent:
            continue
        div_id = parent.get('id', '')
        if not div_id:
            continue
        dc = parent.get('class', [])
        if isinstance(dc, str):
            dc = dc.split()
        img_entries.append({"id": div_id, "classes": dc, "src": src})

    if len(img_entries) < 3:
        print(f"    [WARN] BeautifulSoup 只解析出 {len(img_entries)} 个图片，使用正则备用解析...")
        img_pattern = r'<img[^>]*class="[^"]*captcha-img[^"]*"[^>]*src="(data:[^"]+)"'
        for m in re.finditer(img_pattern, html):
            src = m.group(1)
            img_pos = m.start()
            before = html[max(0, img_pos-500):img_pos]
            div_matches = list(re.finditer(r'<div[^>]*id="([a-z]+)"[^>]*>', before))
            if div_matches:
                last_div = div_matches[-1]
                div_id = last_div.group(1)
                if any(e['id'] == div_id for e in img_entries):
                    continue
                div_html = last_div.group(0)
                classes_m = re.findall(r'class="([^"]+)"', div_html)
                classes = []
                for c in classes_m:
                    classes.extend(c.split())
                img_entries.append({"id": div_id, "classes": classes, "src": src})
        print(f"    [INFO] 正则解析出 {len(img_entries)} 个图片")

    div_display = {}
    for entry in img_entries:
        div_id = entry["id"]
        classes = entry["classes"]
        div_tag_html = str(soup.find(id=div_id)) if soup.find(id=div_id) else ''
        inline_m = re.search(r'style=["\']([^"\']*display\s*:\s*(\w+)[^"\']*)["\']', div_tag_html)
        if inline_m:
            div_display[div_id] = (inline_m.group(2) != 'none')
            continue
        hidden_by_css = any(
            class_info.get(c, {}).get('display') == 'none'
            for c in classes
        )
        div_display[div_id] = not hidden_by_css

    total_img_entries = len(img_entries)
    hidden_by_display_none = sum(1 for e in img_entries if not div_display.get(e['id'], True))
    hidden_by_jquery = len(hide_ids)
    print(f"    [Step2] 图片统计: 总计={total_img_entries}, display:none={hidden_by_display_none}, jQuery隐藏={hidden_by_jquery}")

    GRID_POSITIONS = [
        (0, 0), (0, 110), (0, 220),
        (110, 0), (110, 110), (110, 220),
        (220, 0), (220, 110), (220, 220),
    ]
    position_best = {}
    position_all = {pos: [] for pos in GRID_POSITIONS}

    for entry in img_entries:
        div_id = entry["id"]
        classes = entry["classes"]

        hidden_by_css = any(
            class_info.get(c, {}).get('display') == 'none'
            for c in classes
        )
        hidden_by_js = div_id in hide_ids

        if hidden_by_css or hidden_by_js:
            continue

        left = top = z = None
        for cls in classes:
            if cls in class_info:
                info = class_info[cls]
                if info['left'] is not None: left = info['left']
                if info['top']  is not None: top  = info['top']
                if info['z'] is not None:
                    z = max(z or 0, info['z'])
        if left is None or top is None:
            continue
        key = (left, top)

        if key in position_all:
            position_all[key].append({"id": div_id, "z": z})

        if key not in position_best or (z and z > (position_best[key].get('_z') or 0)):
            position_best[key] = {"id": div_id, "src": entry["src"], "_z": z}

    print(f"    [Step2] 每个位置的图片情况:")
    for pos in GRID_POSITIONS:
        imgs = position_all.get(pos, [])
        if imgs:
            imgs.sort(key=lambda x: x['z'], reverse=True)
            best = imgs[0]
            print(f"    [Step2]   {pos}: {len(imgs)}张, 最佳={best['id']}(z={best['z']})")
        else:
            print(f"    [Step2]   {pos}: 无可见图片")

    label_entries = []
    for text_div in soup.find_all('div', class_=lambda x: x and 'box-label' in ' '.join(x) if isinstance(x, list) else ('box-label' in x if x else False)):
        text = text_div.get_text(strip=True)
        m = re.match(r'Please select all boxes with number (\d+)', text)
        if not m:
            continue
        digit = m.group(1)
        classes = text_div.get('class', [])
        if isinstance(classes, str):
            classes = classes.split()
        hidden = any(
            class_info.get(c, {}).get('display') == 'none'
            for c in classes
        )
        if hidden:
            continue
        z = 0
        for c in classes:
            if c in class_info and class_info[c].get('z') is not None:
                z = max(z, class_info[c]['z'])
        label_entries.append({"digit": digit, "z": z})

    target_digit = None
    if label_entries:
        label_entries.sort(key=lambda x: x["z"], reverse=True)
        target_digit = label_entries[0]["digit"]

    hidden = _parse_hidden_inputs(html)

    print(f"    [Step2] GenerateCaptcha hidden keys: {list(hidden.keys())}")
    print(f"    [Step2] SecurityCode (Id) length: {len(hidden.get('Id', ''))}")
    print(f"    [Step2] Captcha field length: {len(hidden.get('Captcha', ''))}")
    print(f"    [Step2] RVT length: {len(hidden.get('__RequestVerificationToken', ''))}")

    return {
        "html": html,
        "hidden": hidden,
        "position_best": position_best,
        "target_digit": target_digit,
        "class_info": class_info,
    }, target_digit


# ═══════════════════════════════════════════════════════════════════════════════
# Step 3: OCR
# ═══════════════════════════════════════════════════════════════════════════════
def _get_charset() -> list:
    if os.path.exists(_charset_path):
        for enc in ('utf-8', 'gbk', 'gb2312'):
            try:
                with open(_charset_path, 'r', encoding=enc) as f:
                    data = json.load(f)
                return data.get('charset', _default_charset)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
    return _default_charset


def decode_b64_img(src: str) -> bytes:
    if "," not in src:
        return b""
    b64 = src.split(",", 1)[1]
    b64 = b64.replace("&#x2B;", "+").replace("&#x2b;", "+")
    b64 = b64.replace("&#x3D;", "=").replace("&#x3d;", "=")
    b64 = b64.replace("&#43;", "+").replace("&#61;", "=")
    b64 = re.sub(r'&#x[0-9a-fA-F]{1,4};', '', b64)
    b64 = re.sub(r'&#\d+;', '', b64)
    b64 = re.sub(r'[^A-Za-z0-9+/=]', '', b64)
    b64 += "=" * ((4 - len(b64) % 4) % 4)
    return base64.b64decode(b64)


def _ocr_classification(raw_bytes: bytes, charset: list) -> str:
    """OCR 分类函数"""
    import numpy as np
    from PIL import Image

    pil_img = Image.open(io.BytesIO(raw_bytes)).convert("L")
    arr = np.array(pil_img, dtype=np.float32)
    arr = arr[np.newaxis, np.newaxis, :, :]

    sess, input_name = _get_onnx_sess(_ocr_model_path)
    output = sess.run(None, {input_name: arr})[0]
    preds = output.squeeze()
    if preds.ndim > 1:
        preds = preds.argmax(axis=1)

    decoded = []
    prev = -1
    for idx in preds:
        idx = int(idx)
        if idx == prev:
            continue
        if idx == 0:
            prev = idx
            continue
        if idx - 1 < len(charset):
            ch = charset[idx - 1]
            if ch and ch != ' ':
                decoded.append(ch)
        prev = idx
    return "".join(decoded).strip()


def step3_ocr(params: dict, target_digit: str | None) -> tuple[list, int]:
    position_best = params["position_best"]
    if not target_digit:
        return [], 0

    if not os.path.exists(_ocr_model_path):
        return [], 0

    charset = _get_charset()
    _get_onnx_sess(_ocr_model_path)

    sorted_positions = sorted(position_best.items(), key=lambda x: x[0])
    entries = list(sorted_positions)

    def ocr_one(pos_key, info):
        src = info["src"]
        if not src.startswith("data:"):
            return None
        raw_data = decode_b64_img(src)
        t0 = time.perf_counter()
        digit = _ocr_classification(raw_data, charset)
        ms = round((time.perf_counter() - t0) * 1000)
        match = target_digit in digit
        return {"pos": pos_key, "info": info, "digit": digit, "match": match, "ms": ms}

    results = []
    t_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=min(len(entries), 16)) as pool:
        futures = {pool.submit(ocr_one, pk, info): pk for pk, info in entries}
        for future in as_completed(futures):
            pk = futures[future]
            try:
                res = future.result()
            except Exception:
                results.append(None)
                continue
            results.append(res)

    ocr_ms = round((time.perf_counter() - t_start) * 1000)

    results.sort(key=lambda r: (r["pos"] if r else ((999, 999))))
    print(f"\n    Target: {target_digit}")
    print(f"    {'ID':<15} {'POS':<12} {'Z':<6} {'DIGIT':<8} {'MATCH'}")
    print(f"    {'-'*15} {'-'*12} {'-'*6} {'-'*8} {'-'*6}")

    for res in results:
        if res is None:
            continue
        left, top = res["pos"]
        info = res["info"]
        digit = res["digit"]
        match = res["match"]
        tag = "<- TARGET" if match else ""
        print(
            f"    {info['id']:<15} ({left:3d},{top:3d})   {info['_z']:<6} {digit!r:<8} {tag}"
        )

    selected = [res["info"]["id"] for res in results if res and res["match"]]

    print(f"\n    [DEBUG] 每个位置的最佳图片 (z-index 最高):")
    for pos_key in sorted(position_best.keys()):
        info = position_best[pos_key]
        left, top = pos_key
        print(f"    [DEBUG]   ({left},{top}): id={info['id']}, z={info['_z']}")

    random.shuffle(selected)

    print(f"\n    Selected ({len(selected)}): {selected}")
    print(f"    OCR 耗时: {ocr_ms} ms")

    return selected, ocr_ms


# ═══════════════════════════════════════════════════════════════════════════════
# Step 4: 提交验证码（严格匹配 HAR header）
# ═══════════════════════════════════════════════════════════════════════════════
def step4_submit_captcha(
    session: BLSSessionH2,
    selected_ids: list,
    hidden: dict,
) -> tuple[dict | None, str | None]:
    h_id = hidden.get("Id", "")
    h_cap = hidden.get("Captcha", "")
    print(f"    [Step4] Submitting: SelectedImages={','.join(selected_ids)} count={len(selected_ids)}")

    print(f"    [DEBUG] hidden keys: {list(hidden.keys())}")
    print(f"    [DEBUG] Captcha field length: {len(h_cap)}")

    post_data = {
        "SelectedImages": ",".join(selected_ids),
        "Id": html_module.unescape(h_id),
        "Captcha": html_module.unescape(h_cap),
        "__RequestVerificationToken": hidden.get("__RequestVerificationToken", ""),
    }

    encoded_data = urllib.parse.urlencode(post_data)
    encoded_bytes = encoded_data.encode('utf-8')
    content_length = len(encoded_bytes)

    headers = make_headers_submit_captcha(
        captcha_referer=session._captcha_referer,
        content_length=content_length,
    )

    status, resp_text, resp_headers = session.post(
        "/CHN/CaptchaPublic/SubmitCaptcha",
        headers=headers,
        content=encoded_bytes,
        timeout=30,
    )

    if not resp_text.strip().startswith("{"):
        return None, f"Non-JSON: {resp_text[:200]}"
    try:
        resp = json.loads(resp_text)
    except Exception:
        return None, f"JSON parse failed: {resp_text[:200]}"
    if resp.get("success"):
        return {
            "success": True,
            "captchaData": resp.get("captcha", ""),
            "captchaId": resp.get("captchaId", "")
        }, None
    else:
        err = resp.get("error", "Unknown")
        return None, err


# ═══════════════════════════════════════════════════════════════════════════════
# Step 5: 发送 OTP（严格匹配 HAR header）
# ═══════════════════════════════════════════════════════════════════════════════
def step5_send_otp(
    session: BLSSessionH2,
    email: str,
    mobile: str,
    captcha_data: str,
    captcha_id: str,
    max_retries: int = 2,
) -> tuple[dict, str | None]:
    """
    发送 OTP 验证码。
    严格匹配 HAR 中的请求格式：
    - content-length: 0（POST 但无请求体）
    - requestverificationtoken（小写，不是 __RequestVerificationToken）
    - 所有参数在 Query String 中
    """
    print(f"\n    [Step5] email={email}, mobile={mobile}")
    print(f"    [Step5] captchaId={captcha_id}")

    for attempt in range(1, max_retries + 1):
        from urllib.parse import unquote
        decoded_security_code = unquote(session.security_code)

        params = {
            "email": email,
            "mobile": mobile,
            "isMobileVerify": "False",
            "data": decoded_security_code,
            "captchaData": captcha_data,
            "captchaId": captcha_id,
        }

        query_string = urllib.parse.urlencode(params)
        path = f"/CHN/account/SendRegisterUserVerificationCode?{query_string}"

        headers = make_headers_send_otp(
            rvt=session.verify_token,
        )

        print(f"    [Step5] 发送查询参数:")
        for k, v in params.items():
            if k in ("data", "captchaData"):
                print(f"    [Step5]   {k}: {v[:80]}... (len={len(v)})")
            else:
                print(f"    [Step5]   {k}: {v}")

        try:
            resp = session.client.post(BASE_URL + path, headers=headers, content=b"", timeout=30)
            status = resp.status_code
            text = resp.text
        except Exception as e:
            print(f"    [Step5] 尝试 {attempt}: Connection error: {e}")
            if attempt < max_retries:
                time.sleep(2 ** attempt)
                continue
            return {}, str(e)

        if status == 429:
            print(f"    [Step5] 尝试 {attempt}: HTTP 429 Too Many Requests")
            if attempt < max_retries:
                time.sleep(3)
                continue
            return {}, "HTTP 429 Too Many Requests"

        if not text.strip().startswith("{"):
            print(f"    [Step5] 尝试 {attempt}: HTTP {status} Non-JSON ({len(text)} bytes): {text[:300]}")
            if attempt < max_retries:
                time.sleep(2 ** attempt)
                continue
            return {}, f"HTTP {status} Non-JSON: {text[:200]}"

        try:
            resp_json = json.loads(text)
        except Exception:
            print(f"    [Step5] JSON parse failed: {text[:200]}")
            return {}, "JSON parse failed"

        if resp_json.get("success"):
            session._reg_security_code = resp_json.get("securityCode", "")
            print(f"    [Step5] 成功: {json.dumps(resp_json, ensure_ascii=False)[:200]}")
            return resp_json, None

        err = resp_json.get("error", "") or resp_json.get("err", "unknown")
        if resp_json.get("captchaError"):
            print(f"    [Step5] 尝试 {attempt}: captchaError({err})")
            return {}, f"captchaError:{err}"

        print(f"    [Step5] 尝试 {attempt}: success=False ({err})")
        if attempt < max_retries:
            time.sleep(2 ** attempt)
            continue
        return {}, err

    return {}, "Max retries exceeded"


# ═══════════════════════════════════════════════════════════════════════════════
# Step 6: 等待 OTP 邮件
# ═══════════════════════════════════════════════════════════════════════════════
def step6_wait_otp_email(
    mail_client: MailTmClient,
    timeout: float = EMAIL_TIMEOUT,
) -> tuple[str | None, dict | None]:
    msg = mail_client.get_latest_message(
        from_contains=EMAIL_FROM_KEY,
        subject_contains=None,
        timeout=timeout,
        poll_interval=EMAIL_POLL_INTERVAL,
    )
    if not msg:
        return None, None

    for pat, desc in [
        (r"\b(\d{6})\b",                     "6位纯数字"),
        (r"[Cc]ode[:\s]*(\d{6})",             "Code: 6位"),
        (r"[Vv]erification[:\s]*(\d{6})",     "Verification: 6位"),
        (r"OTP[:\s]*(\d{6})",                "OTP: 6位"),
        (r"(\d{6})",                         "第一个6位"),
    ]:
        code = mail_client.extract_verification_code(msg, pattern=pat, code_length=6)
        if code:
            return code, msg

    return None, msg


# ═══════════════════════════════════════════════════════════════════════════════
# Step 7: 获取 Country ID
# ═══════════════════════════════════════════════════════════════════════════════
def step7_get_country_ids(session: BLSSessionH2) -> tuple[str, str]:
    country_id = "5e44cd63-68f0-41f2-b708-0eb3bf9f4a72"
    headers = make_headers_get_register_page()
    status, text, _ = session.get("/CHN/query/GetCountryList", headers)
    try:
        for item in json.loads(text):
            if item.get("Code") == "CHN":
                country_id = item.get("Id", country_id)
                break
    except Exception:
        pass

    passport_type_id = "0a152f62-b7b2-49ad-893e-b41b15e2bef3"
    status2, text2, _ = session.get(f"/CHN/query/GetLOVIdNameList?lovType=BLS_PASSPORT_TYPE", headers)
    try:
        items = json.loads(text2)
        if items:
            passport_type_id = items[0].get("Id", passport_type_id)
    except Exception:
        pass

    return country_id, passport_type_id


# ═══════════════════════════════════════════════════════════════════════════════
# Step 8: 完成注册（严格匹配 HAR header）
# ═══════════════════════════════════════════════════════════════════════════════
def step8_do_register(
    session: BLSSessionH2,
    email: str,
    email_otp: str,
    captcha_data: str,
    enc_email: str,
    enc_mobile: str,
    country_id: str,
    passport_type_id: str,
    person: dict,
) -> dict:
    dob_str       = person["dob"].strftime("%Y-%m-%d")
    pp_issue_str = person["pp_issue"].strftime("%Y-%m-%d")
    pp_expiry_str = person["pp_expiry"].strftime("%Y-%m-%d")

    form = [
        ("Mode",                        "register"),
        ("CaptchaParam",                ""),
        ("CaptchaData",                 captcha_data),
        ("CaptchaId",                   session.captcha_id or ""),
        ("ServerDateOfBirth",           dob_str),
        ("ServerPassportExpiryDate",    pp_expiry_str),
        ("ServerPassportIssueDate",     pp_issue_str),
        ("EncryptedEmail",              enc_email or ""),
        ("EncryptedMobile",             enc_mobile or ""),
        ("SecurityCode",               session.reg_security_code or ""),
        ("MobileVerificationEnabled",   "False"),
        ("SurName",                   person["surname"]),
        ("FirstName",                  person["first_name"]),
        ("LastName",                   person["last_name"]),
        ("DateOfBirth",                dob_str),
        ("PassportNumber",             person["pp_no"]),
        ("PassportIssueDate",          pp_issue_str),
        ("PassportExpiryDate",         pp_expiry_str),
        ("BirthCountry",               country_id),
        ("PassportType",               passport_type_id),
        ("IssuePlace",                person["issue_place"]),
        ("CountryOfResidence",         country_id),
        ("CountryCode",               "+86"),
        ("Mobile",                    ""),
        ("Email",                     email),
        ("EmailOtp",                  email_otp),
        ("__RequestVerificationToken",  session.verify_token),
    ]

    encoded_data = urllib.parse.urlencode(form)
    encoded_bytes = encoded_data.encode('utf-8')
    content_length = len(encoded_bytes)

    headers = make_headers_do_register(
        content_length=content_length,
    )

    status, text, _ = session.post(
        "/CHN/Account/RegisterUser",
        headers=headers,
        content=encoded_bytes,
        timeout=30,
    )
    try:
        return json.loads(text)
    except Exception:
        return {"raw": text}


# ═══════════════════════════════════════════════════════════════════════════════
# Step 9: 等待注册成功邮件
# ═══════════════════════════════════════════════════════════════════════════════
def step9_wait_success_email(
    mail_client: MailTmClient,
    timeout: float = EMAIL_TIMEOUT_FINAL,
) -> tuple[str | None, dict | None]:
    msg = mail_client.get_latest_message(
        from_contains=EMAIL_FROM_KEY,
        subject_contains=None,
        timeout=timeout,
        poll_interval=EMAIL_POLL_INTERVAL,
    )
    if not msg:
        return None, None

    for pat, desc in [
        (r"\b(\d{6})\b",                 "6位纯数字"),
        (r"[Pp]assword[:\s]*(\d{6})",    "Password: 6位"),
        (r"密码[:\s]*(\d{6})",           "密码: 6位"),
        (r"(\d{6})",                    "第一个6位"),
    ]:
        pwd = mail_client.extract_verification_code(msg, pattern=pat, code_length=6)
        if pwd:
            return pwd, msg

    return None, msg


# ═══════════════════════════════════════════════════════════════════════════════
# 验证码流程整合（Step 1-4）
# ═══════════════════════════════════════════════════════════════════════════════
def solve_captcha_once(session: BLSSessionH2) -> tuple[dict | None, str | None]:
    print(f"[Step2] 获取验证码图片...")
    params, target_digit = step2_get_captcha(session)
    if not params:
        return None, "Captcha page fetch failed"
    print(f"[Step2] 完成: 目标数字={target_digit}")

    print(f"[Step2->Step3] 等待 5s...")
    time.sleep(5)

    print(f"[Step3] OCR 识别...")
    selected_ids, ocr_ms = step3_ocr(params, target_digit)
    if not selected_ids:
        return None, f"OCR no match (target={target_digit})"
    print(f"[Step3] 完成: 选中 {len(selected_ids)} 个, 耗时 {ocr_ms}ms")

    print(f"[Step3->Step4] 等待 5s...")
    time.sleep(5)

    print(f"[Step4] 提交验证码...")
    result, err = step4_submit_captcha(session, selected_ids, params["hidden"])
    if result:
        new_captcha_id = result.get("captchaId", "")
        print(f"[Step4] 完成: captchaData={result.get('captchaData', '')[:30]}..., captchaId={new_captcha_id[:30] if new_captcha_id else 'N/A'}...")
        return result, None
    print(f"[Step4] 失败: {err}")
    return None, err


# ═══════════════════════════════════════════════════════════════════════════════
# 单个注册任务
# ═══════════════════════════════════════════════════════════════════════════════
def register_one_task(task_id: int, person: dict) -> dict:
    """执行一次完整的注册流程"""
    today_str = time.strftime("%Y-%m-%d %H:%M:%S")

    def log(msg: str):
        thread_name = threading.current_thread().name
        print(f"[{today_str}] [Task-{task_id}] {msg}")

    result = {
        "task_id":     task_id,
        "success":     False,
        "email":       "",
        "email_pwd":   "",
        "otp":         "",
        "account_pwd": "",
        "person":      person,
        "error":       "",
        "proxy":       "",
    }

    # ── 获取代理 ───────────────────────────────────────────────────────────
    proxy = None
    if DEBUG_NO_PROXY:
        result["proxy"] = "Direct (DEBUG_NO_PROXY)"
        log(f"[Proxy] DEBUG mode: no proxy")
    elif USE_REQABLE_PROXY:
        reqable_proxy = f"http://{REQABLE_PROXY_HOST}:{REQABLE_PROXY_PORT}"
        proxy = {"http": reqable_proxy, "https": reqable_proxy}
        result["proxy"] = reqable_proxy
        log(f"[Proxy] Using Reqable: {reqable_proxy}")
    else:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        try:
            from tools.proxies import kuaidaili
            proxy = kuaidaili.get_proxy()
            if proxy:
                result["proxy"] = proxy.get("http", "")
                log(f"[Proxy] {result['proxy']}")
        except Exception as e:
            log(f"[Proxy] Failed: {e}")

    # ── 创建临时邮箱 ───────────────────────────────────────────────────────
    mail_client = MailTmClient(proxy="", qps=8)
    try:
        email_addr, email_pwd = mail_client.create_random_account()
        result["email"]   = email_addr
        result["email_pwd"] = email_pwd
        log(f"Mail: {email_addr}")
    except MailTmError as e:
        result["error"] = f"mail.tm failed: {e}"
        log(f"X {result['error']}")
        return result

    # ── 1. 获取注册页面 ────────────────────────────────────────────────────
    bls = BLSSessionH2(proxy=proxy)
    log(f"[Step1] 获取注册页面...")
    if not step1_get_register_page(bls):
        result["error"] = "Register page fetch failed"
        log(f"X {result['error']}")
        return result
    log(f"[Step1] 完成: SecurityCode={bls.security_code[:30]}..., Token={bls.verify_token[:30]}...")

    log(f"[Step1->Step2-4] 等待 5s...")
    time.sleep(5)

    # ── 2-4. 验证码 ────────────────────────────────────────────────────────
    log(f"[Step2-4] 获取验证码...")
    captcha_data = None
    for attempt in range(0, CAPTCHA_MAX_RETRY + 1):
        capt_result, err = solve_captcha_once(bls)
        if capt_result:
            captcha_data = capt_result["captchaData"]
            break
        log(f"Captcha 尝试 {attempt}/{CAPTCHA_MAX_RETRY} 失败: {err}")
        if attempt < CAPTCHA_MAX_RETRY:
            log(f"    重试，等待 5s...")
            time.sleep(5)

    if not captcha_data:
        result["error"] = "Captcha failed"
        log(f"X {result['error']}")
        return result

    log(f"[Step2-4] 完成: CaptchaData={captcha_data[:30]}...")

    # ── 5. 发送 OTP ────────────────────────────────────────────────────────
    log(f"[Step4->Step5] 等待 5s...")
    time.sleep(5)

    for otp_retry in range(1, 3):
        log(f"[Step5] 发送 OTP (尝试 {otp_retry}/2)...")
        otp_result, err = step5_send_otp(bls, email_addr, person["mobile"], captcha_data, bls.captcha_id, max_retries=2)
        if not err and otp_result.get("success"):
            enc_email  = otp_result.get("encryptEmail", "")
            enc_mobile = otp_result.get("encryptMobile", "")
            log(f"[Step5] 完成: encryptEmail={enc_email[:30]}...")
            break
        log(f"[OTP 尝试 {otp_retry}/2] 失败: {err}")
        if otp_retry < 2:
            log("    重新获取注册页面并解题验证码...")
            if not step1_get_register_page(bls):
                result["error"] = "重试时注册页面获取失败"
                return result
            new_capt = None
            for attempt in range(1, CAPTCHA_MAX_RETRY + 1):
                capt_res, c_err = solve_captcha_once(bls)
                if capt_res:
                    new_capt = capt_res["captchaData"]
                    break
                log(f"    重试验证码尝试 {attempt}: {c_err}")
                log(f"    等待 5s...")
                time.sleep(5)
            if not new_capt:
                result["error"] = "重试验证码失败"
                return result
            captcha_data = new_capt
        else:
            result["error"] = f"OTP 发送失败: {err}"
            return result

    # ── 6. 等待 OTP 邮件 ──────────────────────────────────────────────────
    log(f"[Step5->Step6] 等待 5s...")
    time.sleep(5)
    log(f"[Step6] 等待 OTP 邮件...")
    otp_code, _ = step6_wait_otp_email(mail_client)
    if not otp_code:
        result["error"] = f"等待 OTP 邮件超时（{EMAIL_TIMEOUT}s）"
        log(f"X {result['error']}")
        return result

    result["otp"] = otp_code
    log(f"[Step6] 完成: OTP={otp_code}")

    # ── 7. 获取 Country ID ────────────────────────────────────────────────
    log(f"[Step6->Step7] 等待 5s...")
    time.sleep(5)
    log(f"[Step7] 获取国家信息...")
    country_id, passport_type_id = step7_get_country_ids(bls)
    log(f"[Step7] 完成: countryId={country_id}, passportTypeId={passport_type_id}")

    # ── 8. 完成注册 ───────────────────────────────────────────────────────
    log(f"[Step7->Step8] 等待 5s...")
    time.sleep(5)
    log(f"[Step8] 提交注册: {person['surname']} {person['first_name']}, 手机={person['mobile']}")
    reg_result = step8_do_register(
        session            = bls,
        email              = email_addr,
        email_otp          = otp_code,
        captcha_data       = captcha_data,
        enc_email          = enc_email,
        enc_mobile         = enc_mobile,
        country_id         = country_id,
        passport_type_id   = passport_type_id,
        person             = person,
    )

    if not reg_result.get("success"):
        err_msg = reg_result.get("error", "") or reg_result.get("err", "unknown")
        result["error"] = f"注册失败: {err_msg}"
        log(f"X {result['error']}")
        return result

    log(f"注册表单提交成功！")

    # ── 9. 等待注册成功邮件 ────────────────────────────────────────────────
    log(f"[Step8->Step9] 等待 5s...")
    time.sleep(5)
    log(f"[Step9] 等待注册成功邮件...")
    account_pwd, _ = step9_wait_success_email(mail_client)
    if account_pwd:
        result["account_pwd"] = account_pwd
        result["success"] = True
        log(f"[Step9] 完成: V 注册成功！账号密码: {account_pwd}")
    else:
        result["success"] = True
        result["error"] = "注册成功但未提取到账号密码"
        log(f"[Step9] 完成: ~ 注册成功，但未提取到账号密码")

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# 入口
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    print(f"""
================================================================================
  BLS China 注册 - HTTP/2 版本（严格匹配 HAR Header）
  https://spain.blscn.cn/CHN/account/RegisterUser
================================================================================
  使用 httpx + HTTP/2
  Header 与 HAR 抓包完全一致
  代理: Reqable 本地代理 (127.0.0.1:9000)
================================================================================
    """)

    if os.path.exists(_ocr_model_path):
        charset = _get_charset()
        print(f"OCR 模型: {_ocr_model_path}")
        print(f"Charset: {charset}")
    else:
        print(f"WARNING: ONNX 模型未找到: {_ocr_model_path}")

    person = _generate_person_info()
    print(f"\n注册信息:")
    print(f"  姓名: {person['surname']} {person['first_name']}")
    print(f"  手机: {person['mobile']}")
    print(f"  护照: {person['pp_no']}")
    print(f"  有效期: {person['validity_years']}年")
    print(f"  签发: {person['pp_issue']} 到期: {person['pp_expiry']}")

    result = register_one_task(task_id=1, person=person)

    print()
    if result["success"]:
        print("=" * 60)
        print(f"  V 注册成功！")
        print(f"  邮箱: {result['email']}")
        print(f"  OTP: {result['otp']}")
        print(f"  账号密码: {result['account_pwd']}")
        print(f"  代理: {result['proxy']}")
        print("=" * 60)
    else:
        print("=" * 60)
        print(f"  X 注册失败: {result['error']}")
        print("=" * 60)

    return result


if __name__ == "__main__":
    main()
