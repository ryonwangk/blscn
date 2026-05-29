# bls_register_solver.py
# 创建日期: 2026-05-26 09:50:00（北京时间 UTC+8）
# 更新日期: 2026-05-26 09:50:00（北京时间 UTC+8）
# 使用模型: Claude Opus 4 (claude-opus-4-7-high)
# 用途说明: BLS 中国站注册流程（参考登录流程 requests 模式）

"""
BLS China 注册流程 — 参考登录流程 requests 模式版
==================================================
完整流程:

  1. GET  /CHN/account/RegisterUser
     → 提取 SecurityCode、__RequestVerificationToken、CaptchaId

  2. GET  /CHN/CaptchaPublic/GenerateCaptcha?data=<security_code>
     → 解析 CSS 层叠规则，找出 9 个 grid 位置各自的可见图片
     → OCR 识别 9 张图，找目标数字对应的所有图片

  3. POST /CHN/CaptchaPublic/SubmitCaptcha
     → 提交选中的图片 ID，获得 captchaData

  4. 创建 mail.tm 临时邮箱

  5. POST /CHN/account/SendRegisterUserVerificationCode
     → 响应包含新的 SecurityCode（必须用于最终注册！）

  6. mail.tm: 轮询等待 OTP 邮件（6位纯数字）

  7. 动态获取 Country ID / PassportType ID

  8. POST /CHN/Account/RegisterUser
     → SecurityCode 必须是步骤5返回的新值！

  9. 注册成功后，mail.tm 收到账号密码邮件（6位纯数字）
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
import csv
import random
import re
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, timedelta, datetime
from typing import Optional

import requests
import urllib3
from bs4 import BeautifulSoup

from tools.mail.mailtm import MailTmClient, MailTmError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
# 全局配置
# ═══════════════════════════════════════════════════════════════════════════════
TARGET_HOST = "spain.blscn.cn"
BASE_URL    = f"https://{TARGET_HOST}"

# ═══════════════════════════════════════════════════════════════════════════════
# 代理模式配置（排他的：只能选择一种代理方式）
# ═══════════════════════════════════════════════════════════════════════════════
# 代理模式选项：
#   "reqable"    - 使用 Reqable 本地代理（127.0.0.1:9000，每分钟自动更换 IP）
#   "kuaidaili"  - 使用快代理（从 tools/proxies/kuaidaili.py 获取）
#   "none"       - 不使用代理（直连，用于本地测试）
PROXY_MODE = "kuaidaili"

# Reqable 本地代理配置
REQABLE_PROXY_HOST = "127.0.0.1"
REQABLE_PROXY_PORT = 9000

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
EMAIL_FROM_KEY       = "blsinternational"  # 邮件发件人域名部分

# 验证码重试次数
CAPTCHA_MAX_RETRY    = 0


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

    # 出生日期：17~55 岁
    age_years = random.randint(17, 55)
    dob = today - timedelta(days=age_years * 365 + random.randint(0, 364))
    dob = dob.replace(year=dob.year, month=random.randint(1, 12), day=random.randint(1, 28))

    # 护照有效期：16 周岁以上 10 年，否则 5 年
    age_at_issue = (today - dob).days / 365.25
    pp_validity_years = 10 if age_at_issue > 16 else 5

    # 护照签发日期：1年前~3个月前
    days_ago = random.randint(90, 365)
    pp_issue = today - timedelta(days=days_ago)
    pp_issue = pp_issue.replace(
        year=pp_issue.year,
        month=random.randint(1, 12),
        day=min(random.randint(1, 28), _days_in_month(pp_issue.year, pp_issue.month)),
    )

    # 护照到期日期
    pp_expiry = pp_issue + timedelta(days=pp_validity_years * 365)
    min_expiry = today + timedelta(days=180)
    if pp_expiry < min_expiry:
        pp_expiry = min_expiry

    # 护照号码：E + 8位随机数
    pp_no = f"E{random.randint(10000000, 99999999)}"

    # 姓名
    surname   = random.choice(_SURNAMES).upper()
    first_name = random.choice(_FIRST_NAMES)
    last_name  = surname

    # 手机号
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
        # 账号信息（注册成功后填充）
        "account_pwd":  "",
        # 邮箱信息（在注册过程中填充）
        "email":        "",
        "email_pwd":    "",
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
# BLS HTTP Session（参考登录流程的 requests 模式）
# ═══════════════════════════════════════════════════════════════════════════════
class BLSSession:
    """BLS 网站 HTTP 会话封装，参考登录流程使用 requests"""

    def __init__(self, proxy=None):
        self._proxy_url = None
        if proxy:
            if isinstance(proxy, dict):
                self._proxy_url = proxy.get("http", proxy.get("https", ""))
            else:
                self._proxy_url = proxy

        # 使用标准 requests.Session（参考登录流程）
        self.session = requests.Session()
        # 禁用系统代理（Windows 系统代理会干扰，Reqable 未运行时会导致连接失败）
        self.session.trust_env = False
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
        self.iframe_url = ""  # win.iframeOpenUrl，用于 Step2 验证码页面

    @property
    def reg_security_code(self) -> str:
        return self._reg_security_code

    def req(self, path, method="GET", data=None, extra=None, timeout=25):
        # 支持完整 URL 或相对路径
        if path.startswith("http"):
            url = path
        else:
            url = BASE_URL + path
        h = dict(self.session.headers)
        if extra:
            h.update(extra)
        if method == "POST" and data and "Content-Type" not in h:
            h["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"

        kwargs = {
            "headers": h,
            "timeout": timeout,
            "allow_redirects": False,
            "verify": False,  # 禁用 SSL 证书验证（参考登录流程）
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
    # 调试：检查是否有 CaptchaId
    if "CaptchaId" not in result:
        # 尝试直接搜索
        import re
        m = re.search(r'<input[^>]+id=["\']CaptchaId["\'][^>]+value=["\']([^"\']+)["\']', html)
        if m:
            result["CaptchaId"] = m.group(1)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Step 1: 获取注册页面
# ═══════════════════════════════════════════════════════════════════════════════
def step1_get_register_page(session: BLSSession, max_retry: int = 3) -> bool:
    for attempt in range(1, max_retry + 1):
        status, html, _ = session.req("/CHN/account/RegisterUser", extra={
            "Referer": f"{BASE_URL}/CHN/account/login",
            "priority": "u=0, i",
        })
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

        # 解析 win.iframeOpenUrl - 这是 Step2 验证码页面的 URL
        m_iframe = re.search(r"win\.iframeOpenUrl\s*=\s*'([^']+)'", html)
        if m_iframe:
            session.iframe_url = m_iframe.group(1)
            print(f"    [Step1] iframeOpenUrl: {session.iframe_url[:80]}...")
        else:
            session.iframe_url = None
            print(f"    [Step1] iframeOpenUrl: 未找到")

        print(f"    [Step1] hidden keys: {list(hidden.keys())}")
        print(f"    [Step1] CaptchaId from hidden: {session.captcha_id}")

        if session.security_code and session.verify_token:
            return True
        if attempt < max_retry:
            time.sleep(2)
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# Step 3: 获取验证码页面
# ═══════════════════════════════════════════════════════════════════════════════
def step3_get_captcha(session: BLSSession) -> tuple[dict, str | None]:
    # 使用 win.iframeOpenUrl（来自 Step1 页面），而不是 security_code
    captcha_url = session.iframe_url
    if not captcha_url:
        print(f"    [Step2] ERROR: iframe_url 为空")
        return {}, None

    print(f"    [Step2] captcha_url: {captcha_url[:100]}...")
    status, html, _ = session.req(captcha_url, extra={
        "Referer": BASE_URL + "/CHN/account/RegisterUser",
        "priority": "u=0, i",
    })
    if status != 200:
        return {}, None

    # 解析 CSS
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

    # 收集 show()/hide()
    script_text = '\n'.join(style_blocks)
    for block in re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL):
        script_text += '\n' + block

    show_ids = set()
    hide_ids = set()
    for m in re.finditer(r"\$\(['\"]#?(\w+)['\"]\)\.(show|hide)\(\)", script_text):
        elem_id, action = m.group(1), m.group(2)
        (show_ids if action == 'show' else hide_ids).add(elem_id)

    # 解析 img 父 div
    soup = BeautifulSoup(html, 'html.parser')
    img_entries = []

    # 首选：使用 BeautifulSoup 解析
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

    # 备用：如果 BeautifulSoup 解析结果少于 3 个，使用正则表达式
    if len(img_entries) < 3:
        print(f"    [WARN] BeautifulSoup 只解析出 {len(img_entries)} 个图片，使用正则备用解析...")
        # HTML 可能有闭合标签缺失问题，需要用更宽松的方式匹配
        # 方案：先找所有 img 标签，再往前找最近的带 id 的 div
        
        # 1. 提取所有 captcha-img 的 src 和位置
        img_pattern = r'<img[^>]*class="[^"]*captcha-img[^"]*"[^>]*src="(data:[^"]+)"'
        for m in re.finditer(img_pattern, html):
            src = m.group(1)
            img_pos = m.start()
            
            # 2. 往前找最近的带 id 的 div
            before = html[max(0, img_pos-500):img_pos]
            # 找所有 <div...id="xxx" 模式
            div_matches = list(re.finditer(r'<div[^>]*id="([a-z]+)"[^>]*>', before))
            if div_matches:
                # 取最后一个（最近的）
                last_div = div_matches[-1]
                div_id = last_div.group(1)
                
                # 检查是否已存在
                if any(e['id'] == div_id for e in img_entries):
                    continue
                
                # 提取 div 的 class
                div_html = last_div.group(0)
                classes_m = re.findall(r'class="([^"]+)"', div_html)
                classes = []
                for c in classes_m:
                    classes.extend(c.split())
                
                img_entries.append({"id": div_id, "classes": classes, "src": src})
        
        print(f"    [INFO] 正则解析出 {len(img_entries)} 个图片")

    # 确定每个 div 的 display 状态
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

    # 🔍 统计隐藏图片
    total_img_entries = len(img_entries)
    hidden_by_display_none = sum(1 for e in img_entries if not div_display.get(e['id'], True))
    hidden_by_jquery = len(hide_ids)
    print(f"    [Step2] 图片统计: 总计={total_img_entries}, display:none={hidden_by_display_none}, jQuery隐藏={hidden_by_jquery}")
    print(f"    [Step2] jQuery hide() IDs: {hide_ids}")

    # 每个 grid 位置，找 z-index 最高的可见 div
    GRID_POSITIONS = [
        (0, 0), (0, 110), (0, 220),
        (110, 0), (110, 110), (110, 220),
        (220, 0), (220, 110), (220, 220),
    ]
    position_best = {}
    
    # 🔍 调试：收集每个位置的所有图片（包括被遮挡的）
    position_all = {pos: [] for pos in GRID_POSITIONS}
    
    for entry in img_entries:
        div_id = entry["id"]
        classes = entry["classes"]

        # 检查是否被 CSS display:none 隐藏
        hidden_by_css = any(
            class_info.get(c, {}).get('display') == 'none'
            for c in classes
        )
        # 检查是否被 jQuery hide() 隐藏
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
        
        # 记录该位置所有可见图片
        if key in position_all:
            position_all[key].append({"id": div_id, "z": z})
        
        if key not in position_best or (z and z > (position_best[key].get('_z') or 0)):
            position_best[key] = {"id": div_id, "src": entry["src"], "_z": z}

    # 🔍 调试：打印每个位置的所有可见图片
    print(f"    [Step2] 每个位置的图片情况:")
    for pos in GRID_POSITIONS:
        imgs = position_all.get(pos, [])
        if imgs:
            imgs.sort(key=lambda x: x['z'], reverse=True)
            best = imgs[0]
            print(f"    [Step2]   {pos}: {len(imgs)}张, 最佳={best['id']}(z={best['z']})")
        else:
            print(f"    [Step2]   {pos}: 无可见图片")

    # 提取目标数字
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

    # 🔍 调试：确认 GenerateCaptcha 页面的 hidden 字段
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

    # 按位置顺序打印结果（参考登录流程格式）
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
        tag = "← TARGET" if match else ""
        print(
            f"    {info['id']:<15} ({left:3d},{top:3d})   {info['_z']:<6} {digit!r:<8} {tag}"
        )

    # 收集匹配的图片 ID
    selected = [res["info"]["id"] for res in results if res and res["match"]]

    random.shuffle(selected)

    print(f"\n    Selected ({len(selected)}): {selected}")
    print(f"    OCR 耗时: {ocr_ms} ms")

    return selected, ocr_ms


# ═══════════════════════════════════════════════════════════════════════════════
# Step 3: 提交验证码
# ═══════════════════════════════════════════════════════════════════════════════
def step3_submit_captcha(
    session: BLSSession,
    selected_ids: list,
    hidden: dict,
) -> tuple[dict | None, str | None]:
    h_id = hidden.get("Id", "")
    h_cap = hidden.get("Captcha", "")
    print(f"    [Step4] Submitting: SelectedImages={','.join(selected_ids)} count={len(selected_ids)}")

    # 参考 HAR：使用 __RequestVerificationToken（注意大小写）
    post_data = {
        "SelectedImages": ",".join(selected_ids),
        "Id":   html_module.unescape(h_id),
        "Captcha": html_module.unescape(h_cap),
        "__RequestVerificationToken": hidden.get("__RequestVerificationToken", ""),
        "X-Requested-With": "XMLHttpRequest",
    }
    status, resp_text, resp_headers = session.req(
        "/CHN/CaptchaPublic/SubmitCaptcha",
        method="POST",
        data=post_data,
        extra={
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": BASE_URL,
            "Referer": BASE_URL + "/CHN/CaptchaPublic/GenerateCaptcha?data=" + session.iframe_url,
            "priority": "u=1, i",
        },
        timeout=30,
    )
    if not resp_text.strip().startswith("{"):
        return None, f"非 JSON: {resp_text[:200]}"
    try:
        resp = json.loads(resp_text)
    except Exception:
        return None, f"JSON 解析失败: {resp_text[:200]}"
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
# Step 5: 发送 OTP（参考登录流程的 requests 模式）
# ═══════════════════════════════════════════════════════════════════════════════
def step5_send_otp(
    session: BLSSession,
    email: str,
    mobile: str,
    captcha_data: str,
    captcha_id: str,
    max_retries: int = 3,
) -> tuple[dict, str | None]:
    """
    发送 OTP 验证码。
    参考 HAR 中的请求格式，使用 requests 直接发送。
    """
    print(f"\n    [Step5] email={email}, mobile={mobile}")
    print(f"    [Step5] captchaId={captcha_id}")
    print(f"    [Step5] session.captcha_id={session.captcha_id}")
    print(f"    [Step5] data (len={len(session.security_code)}): {session.security_code[:50]}...")
    print(f"    [Step5] captchaData (len={len(captcha_data)}): {captcha_data[:50]}...")

    for attempt in range(1, max_retries + 1):
        # 构建查询参数 - 直接拼接到 URL 中，避免 requests 自动编码 @ 符号
        # email 中的 @ 必须保持原样，不能变成 %40
        from urllib.parse import urlencode
        query_params = {
            "email": email,
            "mobile": mobile,
            "isMobileVerify": "False",
            "data": session.security_code,
            "captchaData": captcha_data,
            "captchaId": captcha_id,
        }
        query_string = urlencode(query_params, safe="@:")

        # 参考 HAR Header：使用 RequestVerificationToken（大写 R/V/T）
        headers = {
            "Accept": "*/*",
            "RequestVerificationToken": session.verify_token,  # 注意大写
            "X-Requested-With": "XMLHttpRequest",
            "Origin": BASE_URL,
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": BASE_URL + "/CHN/account/RegisterUser",
            "priority": "u=1, i",
        }

        # 使用 requests 直接发送
        url = f"{BASE_URL}/CHN/account/SendRegisterUserVerificationCode?{query_string}"
        
        # 🔍 调试：打印实际发送的查询参数
        print(f"    [Step5] 发送的查询参数:")
        for k, v in query_params.items():
            if k in ("data", "captchaData"):
                print(f"    [Step5]   {k}: {v[:80]}... (len={len(v)})")
            else:
                print(f"    [Step5]   {k}: {v}")

        kwargs = {
            "headers": headers,
            "timeout": 30,
            "verify": False,
        }
        if session._proxies:
            kwargs["proxies"] = session._proxies

        try:
            resp = session.session.request("POST", url, **kwargs)
            status = resp.status_code
            text = resp.text
        except Exception as e:
            print(f"    [Step5] 尝试 {attempt}: 连接错误: {e}")
            if attempt < max_retries:
                time.sleep(2 ** attempt)
                continue
            return {}, str(e)

        # 处理 429
        if status == 429:
            print(f"    [Step5] 尝试 {attempt}: HTTP 429 Too Many Requests")
            if attempt < max_retries:
                time.sleep(3)
                continue
            return {}, "HTTP 429 Too Many Requests"

        # 非 JSON 响应
        if not text.strip().startswith("{"):
            print(f"    [Step5] 尝试 {attempt}: HTTP {status} 非 JSON ({len(text)} bytes): {text[:300]}")
            if attempt < max_retries:
                time.sleep(2 ** attempt)
                continue
            return {}, f"HTTP {status} 非 JSON: {text[:200]}"

        try:
            resp_json = json.loads(text)
        except Exception:
            print(f"    [Step5] JSON 解析失败: {text[:200]}")
            return {}, "JSON 解析失败"

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

    return {}, "超过最大重试次数"


# ═══════════════════════════════════════════════════════════════════════════════
# Step 6: 等待 OTP 邮件
# ═══════════════════════════════════════════════════════════════════════════════
def step6_wait_otp_email(
    mail_client: MailTmClient,
    timeout: float = EMAIL_TIMEOUT,
) -> tuple[str | None, dict | None]:
    print(f"    [Step6] 等待邮件 from 包含 '{EMAIL_FROM_KEY}'...")

    deadline = time.time() + timeout
    last_check = 0
    seen_ids: set[str] = set()

    while time.time() < deadline:
        try:
            data = mail_client.get_messages()
            messages = data.get("hydra:member", []) if isinstance(data, dict) else []
            new_msgs = [m for m in messages if m["id"] not in seen_ids]

            if new_msgs:
                print(f"    [Step6] 发现 {len(new_msgs)} 封新邮件 (共 {len(messages)} 封)")

            for msg in new_msgs:
                seen_ids.add(msg["id"])
                sender = ""
                if msg.get("from"):
                    sender = msg["from"].get("address", "")
                subject = msg.get("subject", "")

                # 检查是否匹配过滤条件
                f_ok = EMAIL_FROM_KEY.lower() in sender.lower()
                print(f"    [Step6]   邮件: from={sender}, subject={subject[:50]}, 匹配={f_ok}")

                if f_ok:
                    # 获取完整邮件
                    full_msg = mail_client.get_message(msg["id"])
                    print(f"    [Step6]   获取邮件详情成功，开始提取验证码...")

                    for pat, desc in [
                        (r"\b(\d{6})\b",                     "6位纯数字"),
                        (r"[Cc]ode[:\s]*(\d{6})",             "Code: 6位"),
                        (r"[Vv]erification[:\s]*(\d{6})",     "Verification: 6位"),
                        (r"OTP[:\s]*(\d{6})",                "OTP: 6位"),
                        (r"(\d{6})",                         "第一个6位"),
                    ]:
                        code = mail_client.extract_verification_code(full_msg, pattern=pat, code_length=6)
                        if code:
                            print(f"    [Step6]   提取成功: {code} ({desc})")
                            return code, full_msg
                    print(f"    [Step6]   提取失败，未找到验证码")

        except Exception as e:
            print(f"    [Step6]   轮询异常: {e}")

        # 轮询间隔
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        sleep_s = min(5, remaining)  # 最多等待 5 秒
        time.sleep(sleep_s)

    print(f"    [Step6] 超时，未收到邮件")
    return None, None


# ═══════════════════════════════════════════════════════════════════════════════
# Step 7: 获取 Country ID
# ═══════════════════════════════════════════════════════════════════════════════
def step2_get_country_ids(session: BLSSession) -> tuple[str, str]:
    country_id = "5e44cd63-68f0-41f2-b708-0eb3bf9f4a72"
    status, text, _ = session.req("/CHN/query/GetCountryList", extra={
        "Referer": f"{BASE_URL}/CHN/account/RegisterUser",
        "priority": "u=1, i",
    })
    try:
        for item in json.loads(text):
            if item.get("Code") == "CHN":
                country_id = item.get("Id", country_id)
                break
    except Exception:
        pass

    passport_type_id = "0a152f62-b7b2-49ad-893e-b41b15e2bef3"
    status2, text2, _ = session.req("/CHN/query/GetLOVIdNameList?lovType=BLS_PASSPORT_TYPE", extra={
        "Referer": f"{BASE_URL}/CHN/account/RegisterUser",
        "priority": "u=1, i",
    })
    try:
        items = json.loads(text2)
        if items:
            passport_type_id = items[0].get("Id", passport_type_id)
    except Exception:
        pass

    return country_id, passport_type_id


# ═══════════════════════════════════════════════════════════════════════════════
# Step 8: 完成注册
# ═══════════════════════════════════════════════════════════════════════════════
def step8_do_register(
    session: BLSSession,
    email: str,
    email_otp: str,
    captcha_data: str,
    enc_email: str,
    enc_mobile: str,
    country_id: str,
    passport_type_id: str,
    person: dict,
    mobile: str,
) -> dict:
    dob_str       = person["dob"].strftime("%Y-%m-%d")
    pp_issue_str = person["pp_issue"].strftime("%Y-%m-%d")
    pp_expiry_str = person["pp_expiry"].strftime("%Y-%m-%d")

    # 参考 HAR：使用 __RequestVerificationToken（大写 R/V/T）
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
        ("Mobile",                    mobile),
        ("Email",                     email),
        ("EmailOtp",                  email_otp),
        ("__RequestVerificationToken",  session.verify_token),
    ]

    status, text, _ = session.req(
        "/CHN/Account/RegisterUser",
        method="POST",
        data=form,
        extra={
            "RequestVerificationToken": session.verify_token,  # 大写
            "X-Requested-With":         "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": BASE_URL,
            "Referer": BASE_URL + "/CHN/account/RegisterUser",
            "priority": "u=1, i",
        },
        timeout=30,
    )
    try:
        return json.loads(text)
    except Exception:
        return {"raw": text}


# ═══════════════════════════════════════════════════════════════════════════════
# Step 9: 等待注册成功邮件（提取临时密码）
# ═══════════════════════════════════════════════════════════════════════════════
def step7_wait_success_email(
    mail_client: MailTmClient,
    timeout: float = EMAIL_TIMEOUT_FINAL,
) -> tuple[str | None, dict | None]:
    print(f"    [Step9] 等待注册成功邮件 from 包含 '{EMAIL_FROM_KEY}'...")

    deadline = time.time() + timeout
    seen_ids: set[str] = set()

    while time.time() < deadline:
        try:
            data = mail_client.get_messages()
            messages = data.get("hydra:member", []) if isinstance(data, dict) else []
            new_msgs = [m for m in messages if m["id"] not in seen_ids]

            if new_msgs:
                print(f"    [Step9] 发现 {len(new_msgs)} 封新邮件 (共 {len(messages)} 封)")

            for msg in new_msgs:
                seen_ids.add(msg["id"])
                sender = ""
                if msg.get("from"):
                    sender = msg["from"].get("address", "")
                subject = msg.get("subject", "")

                # 检查发件人
                f_ok = EMAIL_FROM_KEY.lower() in sender.lower()
                print(f"    [Step9]   邮件: from={sender}, subject={subject[:50]}, 匹配={f_ok}")

                if f_ok:
                    full_msg = mail_client.get_message(msg["id"])
                    print(f"    [Step9]   获取邮件详情成功，开始提取密码...")

                    # 提取密码：格式 "Password: 138000"（6位数字）
                    for pat, desc in [
                        (r"Password[:\s]*(\d{6})\b",    "Password: 6位"),
                        (r"密码[:\s]*(\d{6})\b",       "密码: 6位"),
                        (r"\b(\d{6})\b",               "6位纯数字"),
                        (r"(\d{5,8})",                 "5-8位数字"),
                    ]:
                        pwd = mail_client.extract_verification_code(full_msg, pattern=pat)
                        if pwd:
                            print(f"    [Step9]   提取成功: {pwd} ({desc})")
                            return pwd, full_msg
                    print(f"    [Step9]   提取失败，未找到密码")

        except Exception as e:
            print(f"    [Step9]   轮询异常: {e}")

        remaining = deadline - time.time()
        if remaining <= 0:
            break
        time.sleep(min(5, remaining))

    print(f"    [Step9] 超时，未收到注册成功邮件")
    return None, None


# ═══════════════════════════════════════════════════════════════════════════════
# step3 验证码流程整合
# ═══════════════════════════════════════════════════════════════════════════════
def solve_captcha_once(session: BLSSession) -> tuple[dict | None, str | None]:
    print(f"[Step3] 获取验证码图片...")
    params, target_digit = step3_get_captcha(session)
    if not params:
        return None, "验证码页面获取失败"
    print(f"[Step3] 完成: 目标数字={target_digit}")

    print(f"[Step3] OCR 识别...")
    selected_ids, ocr_ms = step3_ocr(params, target_digit)
    if not selected_ids:
        return None, f"OCR 未匹配到图片（target={target_digit}）"
    print(f"[Step3] 完成: 选中 {len(selected_ids)} 个, 耗时 {ocr_ms}ms")

    print(f"[Step3->Step4] 等待 5s... 模拟识别点选")
    time.sleep(5)

    print(f"[Step4] 提交验证码...")
    result, err = step3_submit_captcha(session, selected_ids, params["hidden"])
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
        "proxy_info":  "",   # 代理 IP 的详细信息（国家/省份/城市/运营商）
    }

    # ── 获取代理 ───────────────────────────────────────────────────────────
    proxy = None
    if PROXY_MODE == "none":
        result["proxy"] = "直连（PROXY_MODE=none）"
        log(f"[代理] 直连模式: 不使用代理")
    elif PROXY_MODE == "reqable":
        reqable_proxy = f"http://{REQABLE_PROXY_HOST}:{REQABLE_PROXY_PORT}"
        proxy = {"http": reqable_proxy, "https": reqable_proxy}
        result["proxy"] = reqable_proxy
        log(f"[代理] 使用 Reqable 本地代理: {reqable_proxy}")
    elif PROXY_MODE == "kuaidaili":
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        try:
            from tools.proxies import kuaidaili
            from tools.proxies.ip_info import get_ip_info, format_ip_info
            proxy = kuaidaili.get_proxy()
            if not proxy:
                result["error"] = "代理获取失败: 快代理返回 None"
                log(f"✗ {result['error']}")
                return result
            result["proxy"] = proxy.get("http", "")
            log(f"[代理] 使用快代理: {result['proxy']}")

            # 查询代理 IP 的详细信息
            log(f"[代理] 查询 IP 信息...")
            ip_info_result = get_ip_info(result["proxy"])
            if ip_info_result.get("ok"):
                result["proxy_info"] = format_ip_info(ip_info_result)
                log(f"[代理] IP 信息: {result['proxy_info']}")
            else:
                log(f"[代理] IP 信息查询失败: {ip_info_result.get('error', '未知错误')}")
                result["proxy_info"] = ""
        except Exception as e:
            result["error"] = f"代理获取失败: {e}"
            log(f"✗ {result['error']}")
            return result
    else:
        result["error"] = f"未知的 PROXY_MODE: {PROXY_MODE}"
        log(f"✗ {result['error']}")
        return result

    # ── 创建临时邮箱 ───────────────────────────────────────────────────────
    mail_client = MailTmClient(proxy="", qps=8)
    try:
        email_addr, email_pwd = mail_client.create_random_account()
        result["email"]   = email_addr
        result["email_pwd"] = email_pwd
        person["email"] = email_addr
        person["email_pwd"] = email_pwd
        log(f"邮箱: {email_addr}")
        log(f"邮箱密码: {email_pwd}")
    except MailTmError as e:
        result["error"] = f"mail.tm 创建失败: {e}"
        log(f"✗ {result['error']}")
        return result

    # ── 1. 获取注册页面 ────────────────────────────────────────────────────
    bls = BLSSession(proxy=proxy)
    log(f"[Step1] 获取注册页面...")
    if not step1_get_register_page(bls):
        result["error"] = "注册页面获取失败"
        log(f"✗ {result['error']}")
        return result
    log(f"[Step1] 完成: SecurityCode={bls.security_code[:30]}..., Token={bls.verify_token[:30]}...")

    # ── 2. 获取国家信息 ────────────────────────────────────────────────────
    log(f"[Step2] 获取国家信息...")
    country_id, passport_type_id = step2_get_country_ids(bls)
    log(f"[Step2] 完成: countryId={country_id}, passportTypeId={passport_type_id}")

    # ── 3. 验证码 ────────────────────────────────────────────────────────
    log(f"[Step2->Step3] 等待 5s... 模拟填写信息页面")
    time.sleep(5)
    log(f"[Step3] 获取验证码...")
    captcha_data = None
    for attempt in range(0, CAPTCHA_MAX_RETRY + 1):
        capt_result, err = solve_captcha_once(bls)
        if capt_result:
            captcha_data = capt_result["captchaData"]
            break
        log(f"验证码尝试 {attempt}/{CAPTCHA_MAX_RETRY} 失败: {err}")
        if attempt < CAPTCHA_MAX_RETRY:
            log(f"    重试验证码，等待 5s...")
            time.sleep(5)

    if not captcha_data:
        result["error"] = "验证码连续失败"
        log(f"✗ {result['error']}")
        return result

    log(f"[Step3] 完成: CaptchaData={captcha_data[:30]}...")

    # ── 4. 发送 OTP ────────────────────────────────────────────────────────
    log(f"[Step3->Step4] 等待 5s...")
    time.sleep(5)

    for otp_retry in range(1, 3):
        log(f"[Step4] 发送 OTP (尝试 {otp_retry}/2)...")
        # captchaId 使用 RegisterUser 页面的原始值（来自 HAR 分析）
        otp_result, err = step5_send_otp(bls, email_addr, person["mobile"], captcha_data, bls.captcha_id, max_retries=2)
        if not err and otp_result.get("success"):
            enc_email  = otp_result.get("encryptEmail", "")
            enc_mobile = otp_result.get("encryptMobile", "")
            log(f"[Step4] 完成: encryptEmail={enc_email[:30]}...")
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

    # ── 5. 等待 OTP 邮件 ──────────────────────────────────────────────────
    log(f"[Step4->Step5] 等待 5s...")
    time.sleep(5)
    log(f"[Step5] 等待 OTP 邮件...")
    otp_code, _ = step6_wait_otp_email(mail_client)
    if not otp_code:
        result["error"] = f"等待 OTP 邮件超时（{EMAIL_TIMEOUT}s）"
        log(f"✗ {result['error']}")
        return result

    result["otp"] = otp_code
    log(f"[Step5] 完成: OTP={otp_code}")

    # ── 6. 完成注册 ────────────────────────────────────────────────────────
    log(f"[Step5->Step6] 等待 3s... 模拟填写OTP")
    time.sleep(3)
    log(f"[Step6] 提交注册: {person['surname']} {person['first_name']}, 手机={person['mobile']}")
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
        mobile             = person["mobile"],
    )

    if not reg_result.get("success"):
        err_msg = reg_result.get("error", "") or reg_result.get("err", "unknown")
        result["error"] = f"注册失败: {err_msg}"
        log(f"✗ {result['error']}")
        return result

    log(f"注册表单提交成功！")

    # ── 7. 等待注册成功邮件 ────────────────────────────────────────────────
    log(f"[Step6->Step7] 等待 5s...")
    time.sleep(5)
    log(f"[Step7] 等待注册成功邮件...")
    account_pwd, _ = step7_wait_success_email(mail_client)
    if account_pwd:
        result["account_pwd"] = account_pwd
        person["account_pwd"] = account_pwd
        result["success"] = True
        log(f"[Step7] 完成: ✓ 注册成功！账号密码: {account_pwd}")
    else:
        result["success"] = True
        result["error"] = "注册成功但未提取到账号密码"
        log(f"[Step7] 完成: ⚠ 注册成功，但未提取到账号密码")

    # ── 8. 打印完整注册信息 ─────────────────────────────────────────────
    step8_print_result(person, email_addr, result)

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Step 10: 打印完整注册信息 + 保存到 CSV
# ═══════════════════════════════════════════════════════════════════════════════
CSV_FILE_PATH = "blscn_registered_accounts.csv"

def _get_csv_fieldnames() -> list:
    """CSV 列定义"""
    return [
        "注册时间", "BLS账号", "BLS密码", "邮箱", "邮箱密码",
        "姓名", "手机号", "出生日期",
        "护照号", "签发地", "签发日期", "到期日期", "有效期",
        "代理IP", "代理IP信息",
    ]

def step8_print_result(person: dict, email_addr: str, result: dict = None):
    """打印并保存注册信息到 CSV"""
    reg_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 打印到控制台
    print(f"\n{'='*70}")
    print(f"  BLS 中国站注册完成")
    print(f"{'='*70}")
    print(f"  注册时间: {reg_time}")
    print(f"{'='*70}")
    print(f"  账号信息")
    print(f"  {'-'*66}")
    print(f"  BLS 账号: {person.get('email', email_addr)}")
    print(f"  BLS 密码: {person.get('account_pwd', 'N/A')}")
    print(f"  邮箱:     {person.get('email', 'N/A')}")
    print(f"  邮箱密码: {person.get('email_pwd', 'N/A')}")
    print(f"{'='*70}")
    print(f"  个人信息")
    print(f"  {'-'*66}")
    print(f"  姓名:     {person.get('surname', '')} {person.get('first_name', '')}")
    print(f"  手机号:   {person.get('mobile', 'N/A')}")
    print(f"  出生日期: {person.get('dob', '')}")
    print(f"{'='*70}")
    print(f"  护照信息")
    print(f"  {'-'*66}")
    print(f"  护照号:   {person.get('pp_no', 'N/A')}")
    print(f"  签发地:   {person.get('issue_place', 'N/A')}")
    print(f"  签发日期: {person.get('pp_issue', 'N/A')}")
    print(f"  到期日期: {person.get('pp_expiry', 'N/A')}")
    print(f"  有效期:   {person.get('validity_years', 'N/A')} 年")
    print(f"{'='*70}")
    print(f"  代理信息")
    print(f"  {'-'*66}")
    proxy_str = result.get('proxy', '') if result else ''
    proxy_info_str = result.get('proxy_info', '') if result else ''
    # 提取 IP:端口 部分（去掉用户名密码）
    if proxy_str and '@' in proxy_str:
        proxy_ip = proxy_str.split('@')[1].rstrip('/')
    else:
        proxy_ip = proxy_str
    print(f"  代理IP:   {proxy_ip or 'N/A'}")
    print(f"  IP信息:   {proxy_info_str or 'N/A'}")
    print(f"{'='*70}")

    # 保存到 CSV
    row = {
        "注册时间": reg_time,
        "BLS账号": person.get('email', email_addr),
        "BLS密码": person.get('account_pwd', ''),
        "邮箱": person.get('email', ''),
        "邮箱密码": person.get('email_pwd', ''),
        "姓名": f"{person.get('surname', '')} {person.get('first_name', '')}",
        "手机号": person.get('mobile', ''),
        "出生日期": str(person.get('dob', '')),
        "护照号": person.get('pp_no', ''),
        "签发地": person.get('issue_place', ''),
        "签发日期": str(person.get('pp_issue', '')),
        "到期日期": str(person.get('pp_expiry', '')),
        "有效期": f"{person.get('validity_years', '')} 年",
        "代理IP": proxy_ip,
        "代理IP信息": proxy_info_str,
    }

    file_exists = os.path.exists(CSV_FILE_PATH)
    with open(CSV_FILE_PATH, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=_get_csv_fieldnames())
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

    print(f"  ✓ 已保存到: {CSV_FILE_PATH}")
    print(f"{'='*70}")


# ═══════════════════════════════════════════════════════════════════════════════
# 入口
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    print(f"""
╔══════════════════════════════════════════════════════════════════════════╗
║  BLS China 注册 — 参考登录流程 requests 模式                         ║
║  https://spain.blscn.cn/CHN/account/RegisterUser                  ║
╠══════════════════════════════════════════════════════════════════════════╣
║  使用 requests.Session（参考 bls_login_change_password.py）           ║
║  代理模式: {PROXY_MODE:<50}       ║
╚══════════════════════════════════════════════════════════════════════════╝
    """)

    if os.path.exists(_ocr_model_path):
        charset = _get_charset()
        print(f"OCR 模型: {_ocr_model_path}")
        print(f"Charset: {charset}")
    else:
        print(f"WARNING: ONNX 模型未找到: {_ocr_model_path}")

    # 生成随机注册信息
    person = _generate_person_info()
    print(f"\n注册信息:")
    print(f"  姓名: {person['surname']} {person['first_name']}")
    print(f"  手机: {person['mobile']}")
    print(f"  护照: {person['pp_no']}")
    print(f"  有效期: {person['validity_years']}年")
    print(f"  签发: {person['pp_issue']} 到期: {person['pp_expiry']}")

    # 执行注册
    result = register_one_task(task_id=1, person=person)

    print()
    if result["success"]:
        print("=" * 60)
        print(f"  ✓ 注册成功！")
        print(f"  邮箱: {result['email']}")
        print(f"  OTP: {result['otp']}")
        print(f"  账号密码: {result['account_pwd']}")
        print(f"  代理IP: {result['proxy']}")
        print(f"  IP信息: {result['proxy_info']}")
        print("=" * 60)
    else:
        print("=" * 60)
        print(f"  ✗ 注册失败: {result['error']}")
        print("=" * 60)

    return result


if __name__ == "__main__":
    main()
