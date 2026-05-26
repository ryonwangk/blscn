# -*- coding: utf-8 -*-
"""
BLS China 注册 — 快代理 + mail.tm 全自动多线程版
================================================
完整流程（参考 HAR spain.blscn.cn_wanzheng.har）:

  1. 从快代理获取代理 IP（每个线程独立）
  2. GET  /CHN/account/RegisterUser
     → 提取 SecurityCode（URL编码）、__RequestVerificationToken、CaptchaId
  3. GET  /CHN/CaptchaPublic/GenerateCaptcha?data=<security_code>
     → 解析 CSS 层叠规则，找出 9 个 grid 位置各自的可见图片
     → OCR 识别 9 张图，找目标数字对应的所有图片
  4. POST /CHN/CaptchaPublic/SubmitCaptcha
     → 提交选中的图片 ID，获得 captchaData
  5. 创建 mail.tm 临时邮箱
  6. POST /CHN/account/SendRegisterUserVerificationCode
     → 响应包含新的 SecurityCode（必须用于最终注册！）
  7. mail.tm: 轮询等待 OTP 邮件（6位纯数字）
  8. 动态获取 Country ID / PassportType ID
  9. POST /CHN/Account/RegisterUser
     → SecurityCode 必须是步骤6返回的新值！
 10. 注册成功后，mail.tm 收到账号密码邮件（6位纯数字）

验证码算法（来自 bls_solve_captcha_auto.py）:
  - CSS 随机 class 决定 div 的 position/left/top/z-index
  - 9 个 grid 位置: (0,0) (0,110) (0,220) (110,0) (110,110) (110,220)
                     (220,0) (220,110) (220,220)
  - 最终可见图 = z-index 最高且非 display:none 的 div
  - OCR 找目标数字匹配的所有图片，提交

OCR 模型: blscn/ocr_model/bls3_final_e37_s35000.onnx
         内置预处理 + CNN + LSTM + CTC + ArgMax
         charset: [' ','0'..'9']（blank=0，idx-1 映射）
         验证集准确率: 99.69%

多线程架构:
  - ThreadPoolExecutor 管理所有注册线程
  - 每个线程有独立的 proxy、BLSSession、MailTmClient
  - MAX_WORKERS 默认 1，直接改常量即可增加并行数
  - 线程之间完全隔离，无共享状态（ONNX session 是只读的，可安全共享）

护照有效期规则:
  - 出生日期 > 16周岁（today - 16年）：护照有效期 10 年
  - 出生日期 <= 16周岁：护照有效期 5 年
  - 签发日期 = 1年前随机某一天（保证护照有效期足够）
  - 到期日期 = 签发日期 + 有效期
  - 必须保证 签发日期 + 180天 <= 到期日期（BLS 校验）
"""
import sys
import os
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# 先把 tools/ 的父目录加入 sys.path（确保 from tools.mail.mailtm 能找到）
# __file__ = e:\aicodes\webreverse\blscn\bls_auto_register.py
# dirname(__file__) = e:\aicodes\webreverse\blscn
# parent = dirname(dirname(__file__)) = e:\aicodes\webreverse  ← 需要这个在 sys.path
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

import requests
from bs4 import BeautifulSoup

from curl_cffi import requests as curl_requests
from tools.mail.mailtm import MailTmClient, MailTmError
from tools.proxies import kuaidaili

# ═══════════════════════════════════════════════════════════════════════════════
# 线程安全：ONNX Session 全局单例（进程内只加载一次）
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

# ── 多线程并行数（改这里即可调整并发注册数量）───────────────────────────────
# 默认 1（单线程顺序执行）
# 例如改为 3 则同时跑 3 个注册任务
MAX_WORKERS = 1
# ──────────────────────────────────────────────────────────────────────────

# OCR 模型路径
_ocr_model_path = os.path.join(
    os.path.dirname(__file__),
    "ocr_model",
    "bls3_final_e37_s35000.onnx",
)
_charset_path = os.path.join(
    os.path.dirname(__file__),
    "ocr_model",
    "bls3_meta.json",
)
_default_charset = [' ', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

# 邮件轮询参数
EMAIL_TIMEOUT        = 180.0   # 等待 OTP 邮件的超时（秒）
EMAIL_TIMEOUT_FINAL  = 300.0   # 等待注册成功邮件的超时（秒）
EMAIL_POLL_INTERVAL  = 3.0     # 轮询间隔（秒）
EMAIL_FROM_KEY       = "blscn" # 过滤来自含此关键词的发件人

# 验证码重试次数
CAPTCHA_MAX_RETRY    = 3

# 调试开关（打印每个 HTTP 请求）
DEBUG_VERBOSE = False  # 设为 True 可看到每个请求详情
# Debug 开关：不使用代理（直连，用于本地测试或 reqable 抓包）
DEBUG_NO_PROXY = False
# Debug 开关：使用假邮箱测试 step5（跳过 mail.tm，直接用固定邮箱发请求）
DEBUG_EMAIL = ""


# ═══════════════════════════════════════════════════════════════════════════════
# 随机注册信息生成器
# ═══════════════════════════════════════════════════════════════════════════════
# 常见中国姓氏
_SURNAMES = [
    "Wang", "Li", "Zhang", "Liu", "Chen", "Yang", "Huang", "Zhao", "Wu", "Zhou",
    "Xu", "Sun", "Ma", "Zhu", "Hu", "Guo", "He", "Gao", "Lin", "Luo",
    "Zheng", "Liang", "Xie", "Wei", "Song", "Tang", "Deng", "Cai", "Feng",
    "Su", "Lu", "Han", "Cao", "Yao", "Shen", "Dong", "Cao", "Yuan", "Qiu",
]
# 常见英文名（音译或拼音首字母组合）
_FIRST_NAMES = [
    "San", "Wei", "Ming", "Hong", "Jun", "Xin", "Fang", "Li", "Xiao",
    "Hua", "Yan", "Ling", "Qiang", "Ping", "Jian", "Yong", "Gang", "Lin",
    "Jie", "Rui", "Hai", "Bin", "Chun", "Yan", "Xia", "Lin", "Tao",
    "Kai", "Zhen", "Bo", "Fei", "Yu", "Long", "Chao", "Lei", "Min",
]
# 签发地点
_ISSUE_PLACES = [
    "Beijing", "Shanghai", "Guangzhou", "Shenzhen", "Chengdu", "Hangzhou",
    "Nanjing", "Wuhan", "Xian", "Chongqing", "Tianjin", "Suzhou",
]


def _generate_person_info() -> dict:
    """
    生成随机注册信息（符合 BLS 中国护照要求）。

    返回 dict:
      surname, first_name, last_name, dob (date), pp_issue (date),
      pp_expiry (date), pp_no (str)
    """
    today = date.today()

    # ── 出生日期 ────────────────────────────────────────────────────────────
    # 随机 17~55 岁（>16周岁，满足护照有效期 10 年规则）
    age_years = random.randint(17, 55)
    dob = today - timedelta(days=age_years * 365 + random.randint(0, 364))
    dob = dob.replace(year=dob.year, month=random.randint(1, 12), day=random.randint(1, 28))

    # ── 护照有效期 ─────────────────────────────────────────────────────────
    # 16 周岁以上：10 年；16 周岁及以下：5 年
    age_at_issue = (today - dob).days / 365.25
    if age_at_issue > 16:
        pp_validity_years = 10
    else:
        pp_validity_years = 5

    # ── 护照签发日期 ───────────────────────────────────────────────────────
    # 随机 1 年前 ~ 3 个月前（保证护照至少有 3 个月有效期，且 > 180 天）
    days_ago = random.randint(90, 365)
    pp_issue = today - timedelta(days=days_ago)
    pp_issue = pp_issue.replace(
        year=pp_issue.year,
        month=random.randint(1, 12),
        day=min(random.randint(1, 28), _days_in_month(pp_issue.year, pp_issue.month)),
    )

    # ── 护照到期日期 ────────────────────────────────────────────────────────
    pp_expiry = pp_issue + timedelta(days=pp_validity_years * 365)
    # 安全修正：确保到期日期不早于今天 + 180 天
    min_expiry = today + timedelta(days=180)
    if pp_expiry < min_expiry:
        pp_expiry = min_expiry

    # ── 护照号码 ───────────────────────────────────────────────────────────
    # 格式: 1个大写字母 + 8位数字（E + 8位随机数，标准中国护照格式）
    pp_no = f"E{random.randint(10000000, 99999999)}"

    # ── 姓名 ───────────────────────────────────────────────────────────────
    surname   = random.choice(_SURNAMES).upper()
    first_name = random.choice(_FIRST_NAMES)
    last_name  = surname  # BLS 表单通常 SurName=姓，FirstName+LastName=名

    # ── 手机号 ───────────────────────────────────────────────────────────
    # 中国大陆手机号：1 + 3位号段 + 8位随机数字
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
# BLS HTTP Session
# ═══════════════════════════════════════════════════════════════════════════════
class BLSSession:
    """
    BLS 网站 HTTP 会话封装，自动管理代理、gzip 解压、统一 header。

    关键设计点（参考 HAR）:
    - 所有 POST 请求必须带 RequestVerificationToken（从页面 hidden input 获取）
    - RegisterUser 和 SendRegisterUserVerificationCode 走 /CHN/Account/...（大写A）
      而注册页面是 /CHN/account/RegisterUser（小写 a）
    - SecurityCode 每次 SendRegisterUserVerificationCode 返回新的，必须用于最终注册
    - captchaData 来自 SubmitCaptcha，captchaId 来自 RegisterUser 页面
    """

    def __init__(self, proxy=None):
        # 认证信息保持在 URL 中（http://user:pass@ip/），curl_cffi 会自动提取
        self._proxy_url = None
        if proxy:
            if isinstance(proxy, dict):
                self._proxy_url = proxy.get("http", proxy.get("https", ""))
            else:
                self._proxy_url = proxy
        else:
            self._proxy_url = None

        # 使用 curl_cffi 支持 HTTP/2 和浏览器指纹模拟
        self.session = curl_requests.Session(
            impersonate="chrome120",
            proxies={"http": self._proxy_url, "https": self._proxy_url} if self._proxy_url else None,
        )
        self.session.headers.update({
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })

        # 注册流程中各步骤获取的值
        self.security_code = ""
        self.verify_token = ""
        self.captcha_id   = ""
        self._reg_security_code = ""

    @property
    def reg_security_code(self) -> str:
        return self._reg_security_code

    def _build_proxies(self):
        return {"http": self._proxy_url, "https": self._proxy_url} if self._proxy_url else {}

    def req(self, path, method="GET", data=None, extra=None, timeout=25):
        url = BASE_URL + path
        h = dict(self.session.headers)
        if extra:
            h.update(extra)
        if method == "POST" and data and "Content-Type" not in h:
            h["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"

        kwargs = {
            "headers": h,
            "timeout": timeout,
        }
        if data:
            kwargs["data"] = data

        if DEBUG_VERBOSE:
            print(f"    >> {method} {url[:120]}")
            if h.get("RequestVerificationToken"):
                print(f"    >>   RVT: {h['RequestVerificationToken'][:40]}...")

        try:
            resp = self.session.request(method, url, **kwargs)
            raw = resp.content
            try:
                text = gzip.decompress(raw).decode("utf-8", errors="replace")
            except Exception:
                text = raw.decode("utf-8", errors="replace")
            if DEBUG_VERBOSE:
                print(f"    << HTTP {resp.status_code}  {len(raw)} bytes")
                preview = text[:300].replace('\n', ' ')
                print(f"    <<   {preview}")
            return resp.status_code, text, dict(resp.headers)
        except Exception as e:
            return 0, str(e), {}


# ═══════════════════════════════════════════════════════════════════════════════
# 通用 HTML 解析：提取所有 hidden input 的 name/id → value
# ═══════════════════════════════════════════════════════════════════════════════
def _parse_hidden_inputs(html: str) -> dict[str, str]:
    """使用 BeautifulSoup 解析所有 input[type=hidden]，返回 {name_or_id: value}。"""
    soup = BeautifulSoup(html, "html.parser")
    result: dict[str, str] = {}
    for inp in soup.find_all("input", type="hidden"):
        name = inp.get("name", "") or inp.get("id", "")
        value = inp.get("value", "")
        if name:
            result[name] = value
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Step 1: 获取注册页面
# ═══════════════════════════════════════════════════════════════════════════════
def step1_get_register_page(session: BLSSession, max_retry: int = 3) -> bool:
    for attempt in range(1, max_retry + 1):
        status, html, _ = session.req("/CHN/account/RegisterUser")
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

        if session.security_code and session.verify_token:
            return True
        if attempt < max_retry:
            time.sleep(2)
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# Step 2: 获取验证码页面
# ═══════════════════════════════════════════════════════════════════════════════
def step2_get_captcha(session: BLSSession) -> tuple[dict, str | None]:
    # session.security_code 存储时是 URL 编码形式（如 J904%2f...）
    # 直接拼接到 URL，curl_cffi 会正确编码
    url = f"/CHN/CaptchaPublic/GenerateCaptcha?data={session.security_code}"
    status, html, _ = session.req(url, extra={
        "Referer": BASE_URL + "/CHN/account/RegisterUser",
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

    # 解析 img 父 div（用 BeautifulSoup 更可靠）
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
        # 向上找最近的带 id 的 div
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

    # 确定每个 div 的 display 状态
    div_display = {}
    for entry in img_entries:
        div_id = entry["id"]
        classes = entry["classes"]
        # 从 soup 中查找该 div 的完整标签（用于检查 inline style）
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

    # 每个 grid 位置，找 z-index 最高的可见 div
    GRID_POSITIONS = [
        (0, 0), (0, 110), (0, 220),
        (110, 0), (110, 110), (110, 220),
        (220, 0), (220, 110), (220, 220),
    ]
    position_best = {}
    for entry in img_entries:
        div_id = entry["id"]
        classes = entry["classes"]
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
        if not div_display.get(div_id, True):
            continue
        key = (left, top)
        if key not in position_best or (z and z > (position_best[key].get('_z') or 0)):
            position_best[key] = {"id": div_id, "src": entry["src"], "_z": z}

    # 提取目标数字（用 BeautifulSoup 更可靠）
    label_entries = []
    soup_s2 = BeautifulSoup(html, 'html.parser')
    for text_div in soup_s2.find_all('div', class_=lambda x: x and 'box-label' in ' '.join(x) if isinstance(x, list) else ('box-label' in x if x else False)):
        text = text_div.get_text(strip=True)
        m = re.match(r'Please select all boxes with number (\d+)', text)
        if not m:
            continue
        digit = m.group(1)
        classes = text_div.get('class', [])
        if isinstance(classes, str):
            classes = classes.split()
        # 检查是否 display:none
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
        top_label = label_entries[0]
        target_digit = top_label["digit"]

    # hidden fields
    hidden = _parse_hidden_inputs(html)

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
            if res:
                print(f"    OCR [{pk}] digit={res['digit']!r} match={res['match']} id={res['info']['id']}")

    ocr_ms = round((time.perf_counter() - t_start) * 1000)
    selected = [res["info"]["id"] for res in results if res and res["match"]]
    
    # 随机打乱选择顺序，模拟人类行为，避免被检测为bot
    import random
    random.shuffle(selected)
    
    print(f"    OCR selected (shuffled): {selected}")
    return selected, ocr_ms


# ═══════════════════════════════════════════════════════════════════════════════
# Step 4: 提交验证码
# ═══════════════════════════════════════════════════════════════════════════════
def step4_submit_captcha(
    session: BLSSession,
    selected_ids: list,
    hidden: dict,
) -> tuple[dict | None, str | None]:
    h_id = hidden.get("Id", "")
    h_cap = hidden.get("Captcha", "")
    print(f"    [Step4] Submitting: SelectedImages={','.join(selected_ids)} count={len(selected_ids)}")
    print(f"    [Step4] Id (len={len(h_id)}): {h_id[:30]}...")
    print(f"    [Step4] Captcha (len={len(h_cap)}): {h_cap[:30]}...")
    post_data = {
        "SelectedImages": ",".join(selected_ids),
        "Id":   html_module.unescape(hidden.get("Id", "")),
        "Captcha": html_module.unescape(hidden.get("Captcha", "")),
        "__RequestVerificationToken": hidden.get("__RequestVerificationToken", ""),
        # HAR 成功的请求，POST body 里有 X-Requested-With
        "X-Requested-With": "XMLHttpRequest",
    }
    status, resp_text, resp_headers = session.req(
        "/CHN/CaptchaPublic/SubmitCaptcha",
        method="POST",
        data=post_data,
        extra={
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Referer": BASE_URL + "/CHN/CaptchaPublic/GenerateCaptcha?data="
                       + session.security_code,
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
        return {"success": True, "captchaData": resp.get("captcha", ""), "captchaId": resp.get("captchaId", "")}, None
    else:
        err = resp.get("error", "Unknown")
        return None, err


# ═══════════════════════════════════════════════════════════════════════════════
# Step 5: 发送 OTP（遇到429自动换代理重试）
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
    发送OTP验证码。使用 curl_cffi session 直接发送请求，
    保持与浏览器相同的TLS指纹，避免被Anti-Bot检测。
    """
    print(f"\n    [Step5] email={email}, mobile={mobile}")
    print(f"    [Step5] captchaId={captcha_id}")
    print(f"    [Step5] data (len={len(session.security_code)}): {session.security_code[:50]}...")
    print(f"    [Step5] captchaData (len={len(captcha_data)}): {captcha_data[:50]}...")

    proxy_url = session._proxy_url  # 当前代理

    for attempt in range(1, max_retries + 1):
        try:
            # 使用 curl_cffi session 直接发送请求，保持TLS指纹
            # session 已经设置了 impersonate="chrome120"，直接使用即可
            r = session.session.post(
                BASE_URL + "/CHN/account/SendRegisterUserVerificationCode",
                params={
                    "email": email,
                    "mobile": mobile,
                    "isMobileVerify": "False",
                    "data": session.security_code,
                    "captchaData": captcha_data,
                    "captchaId": captcha_id,  # 使用SubmitCaptcha返回的新值
                },
                headers={
                    "Accept": "*/*",
                    "RequestVerificationToken": session.verify_token,
                    "X-Requested-With": "XMLHttpRequest",
                    "Origin": BASE_URL,
                    "Sec-Fetch-Site": "same-origin",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Dest": "empty",
                    "Referer": BASE_URL + "/CHN/account/RegisterUser",
                },
                timeout=30,
            )
            status = r.status_code
            text = r.text
        except Exception as e:
            print(f"    [step5] 尝试 {attempt}: 连接错误: {e}")
            if attempt < max_retries:
                new_proxy = kuaidaili.get_proxy()
                if new_proxy:
                    proxy_url = new_proxy.get("http", "")
                    session._proxy_url = proxy_url
                    # 更新 session 的代理
                    session.session.proxies = {"http": proxy_url, "https": proxy_url}
                    print(f"    [step5] 换新代理: {proxy_url}")
                    time.sleep(2)
                    continue
            return {}, str(e)

        if status == 429:
            print(f"    [step5] 尝试 {attempt}: HTTP 429 Too Many Requests，换代理重试...")
            if attempt < max_retries:
                new_proxy = kuaidaili.get_proxy()
                if new_proxy:
                    proxy_url = new_proxy.get("http", "")
                    session._proxy_url = proxy_url
                    # 更新 session 的代理
                    session.session.proxies = {"http": proxy_url, "https": proxy_url}
                    print(f"    [step5] 获取新代理: {proxy_url}")
                    time.sleep(3)
                    continue
                else:
                    print(f"    [step5] 获取新代理失败")
            return {}, "HTTP 429 Too Many Requests"

        # 非 JSON 响应
        if not text.strip().startswith("{"):
            print(f"    [step5] 尝试 {attempt}: HTTP {status} 非 JSON ({len(text)} bytes): {text[:300]}")
            if attempt < max_retries:
                time.sleep(2 ** attempt)
                continue
            return {}, f"HTTP {status} 非 JSON: {text[:200]}"

        try:
            resp = r.json()
        except Exception:
            print(f"    [step5] JSON 解析失败: {text[:200]}")
            return {}, f"JSON 解析失败"

        if resp.get("success"):
            session._reg_security_code = resp.get("securityCode", "")
            print(f"    [step5] 成功: {json.dumps(resp, ensure_ascii=False)[:200]}")
            return resp, None

        err = resp.get("error", "") or resp.get("err", "unknown")
        if resp.get("captchaError"):
            print(f"    [step5] 尝试 {attempt}: captchaError({err})")
            return {}, f"captchaError:{err}"

        print(f"    [step5] 尝试 {attempt}: success=False ({err})")
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
def step7_get_country_ids(session: BLSSession) -> tuple[str, str]:
    country_id = "5e44cd63-68f0-41f2-b708-0eb3bf9f4a72"
    status, text, _ = session.req("/CHN/query/GetCountryList")
    try:
        for item in json.loads(text):
            if item.get("Code") == "CHN":
                country_id = item.get("Id", country_id)
                break
    except Exception:
        pass

    passport_type_id = "0a152f62-b7b2-49ad-893e-b41b15e2bef3"
    status2, text2, _ = session.req("/CHN/query/GetLOVIdNameList?lovType=BLS_PASSPORT_TYPE")
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

    status, text, _ = session.req(
        "/CHN/Account/RegisterUser",
        method="POST",
        data=form,
        extra={
            "RequestVerificationToken": session.verify_token,
            "X-Requested-With":         "XMLHttpRequest",
        },
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
        (r"[Pp]assword[:\s]*(\d{6})",     "Password: 6位"),
        (r"密码[:\s]*(\d{6})",           "密码: 6位"),
        (r"(\d{6})",                    "第一个6位"),
    ]:
        pwd = mail_client.extract_verification_code(msg, pattern=pat, code_length=6)
        if pwd:
            return pwd, msg

    return None, msg


# ═══════════════════════════════════════════════════════════════════════════════
# 验证码流程（Step 1-4 整合，供重试循环调用）
# ═══════════════════════════════════════════════════════════════════════════════
def solve_captcha_once(session: BLSSession) -> tuple[dict | None, str | None]:
    print(f"[Step2] 获取验证码图片...")
    params, target_digit = step2_get_captcha(session)
    if not params:
        return None, "验证码页面获取失败"
    print(f"[Step2] 完成: 目标数字={target_digit}")

    print(f"[Step2→Step3] 等待 0.5s...")
    time.sleep(0.5)

    print(f"[Step3] OCR 识别...")
    selected_ids, ocr_ms = step3_ocr(params, target_digit)
    if not selected_ids:
        return None, f"OCR 未匹配到图片（target={target_digit}）"
    print(f"[Step3] 完成: 选中 {len(selected_ids)} 个, 耗时 {ocr_ms}ms")

    print(f"[Step3→Step4] 等待 0.5s...")
    time.sleep(0.5)

    print(f"[Step4] 提交验证码...")
    result, err = step4_submit_captcha(session, selected_ids, params["hidden"])
    if result:
        # 从SubmitCaptcha响应获取新的captchaId，这个必须用于后续的SendRegister请求
        new_captcha_id = result.get("captchaId", "")
        print(f"[Step4] 完成: captchaData={result.get('captchaData', '')[:30]}..., captchaId={new_captcha_id[:30] if new_captcha_id else 'N/A'}...")
        return result, None
    print(f"[Step4] 失败: {err}")
    return None, err


# ═══════════════════════════════════════════════════════════════════════════════
# 单个注册任务（在线程池中执行）
# ═══════════════════════════════════════════════════════════════════════════════
def register_one_task(task_id: int, person: dict) -> dict:
    """
    执行一次完整的注册流程，在独立线程中运行。

    Args:
        task_id: 任务编号（用于日志标识）
        person:  随机生成的注册信息（来自 _generate_person_info）

    Returns:
        {
            "task_id":       int,
            "success":       bool,
            "email":         str,       # 临时邮箱地址
            "email_pwd":     str,       # 临时邮箱密码
            "otp":           str,       # OTP 验证码
            "account_pwd":   str,       # BLS 账号密码（6位）
            "person":        dict,      # 个人信息
            "error":         str,       # 失败原因
            "proxy":         str,       # 使用的代理 IP
        }
    """
    today_str = time.strftime("%Y-%m-%d %H:%M:%S")

    def log(msg: str):
        # 线程安全输出（加 task_id 前缀）
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

    # ── 0. 获取代理 ───────────────────────────────────────────────────────
    if DEBUG_NO_PROXY:
        proxy = None
        result["proxy"] = "直连（DEBUG_NO_PROXY）"
        log(f"[代理] DEBUG模式: 不使用代理")
    else:
        MAX_PROXY_RETRIES = 3
        proxy = None
        for attempt in range(1, MAX_PROXY_RETRIES + 1):
            proxy = kuaidaili.get_proxy()
            if not proxy:
                log(f"[代理尝试 {attempt}/{MAX_PROXY_RETRIES}] 获取失败，重试...")
                time.sleep(2)
                continue

            ip_raw = proxy.get("http", "")
            m = re.match(r'http://([^:@]+):([^@]+)@(.+)', ip_raw)
            display_ip = m.group(3) if m else ip_raw
            result["proxy"] = display_ip

            # 简单验证：用更长超时测一下 BLS 注册页面
            log(f"[代理尝试 {attempt}/{MAX_PROXY_RETRIES}] {display_ip}，验证连通性...")
            test_bls = BLSSession(proxy=proxy)
            test_status, test_text, _ = test_bls.req("/CHN/account/RegisterUser", timeout=20)
            del test_bls

            # 只要能连接上（HTTP != 0）就使用，状态码由后续步骤处理
            if test_status == 0:
                log(f"[代理尝试 {attempt}/{MAX_PROXY_RETRIES}] 连接失败(HTTP 0)，重试...")
                proxy = None
                time.sleep(3)
                continue
            log(f"代理验证通过 (HTTP {test_status}): {display_ip}")
            break

        if proxy is None:
            result["error"] = "代理获取失败（所有重试均失败）"
            log(f"✗ {result['error']}")
            return result

    # ── 0b. 创建临时邮箱 ────────────────────────────────────────────────────
    mail_client = MailTmClient(proxy="", qps=8)
    try:
        email_addr, email_pwd = mail_client.create_random_account()
        result["email"]   = email_addr
        result["email_pwd"] = email_pwd
        log(f"邮箱: {email_addr}")
    except MailTmError as e:
        result["error"] = f"mail.tm 创建失败: {e}"
        log(f"✗ {result['error']}")
        return result

    # ── 1. 获取注册页面 ─────────────────────────────────────────────────────
    bls = BLSSession(proxy=proxy)
    log(f"[Step1] 获取注册页面...")
    if not step1_get_register_page(bls):
        result["error"] = "注册页面获取失败"
        log(f"✗ {result['error']}")
        return result
    log(f"[Step1] 完成: SecurityCode={bls.security_code[:30]}..., Token={bls.verify_token[:30]}..., CaptchaId={bls.captcha_id}")

    time.sleep(1)
    log(f"[Step1→Step2] 等待 1s...")

    # ── 2-4. 验证码（支持重试）─────────────────────────────────────────────
    log(f"[Step2] 获取验证码...")
    captcha_data = None
    for attempt in range(1, CAPTCHA_MAX_RETRY + 1):
        capt_result, err = solve_captcha_once(bls)
        if capt_result:
            captcha_data = capt_result["captchaData"]
            break
        log(f"验证码尝试 {attempt}/{CAPTCHA_MAX_RETRY} 失败: {err}")
        if attempt < CAPTCHA_MAX_RETRY:
            time.sleep(2)

    if not captcha_data:
        result["error"] = "验证码连续失败"
        log(f"✗ {result['error']}")
        return result

    log(f"[Step2-4] 完成: CaptchaData={captcha_data[:30]}...")

    # ── 5. 发送 OTP（支持新鲜化重试）──────────────────────────────────────
    # CaptchaData 有时效窗口，可能在创建邮箱等步骤中过期
    # 如果返回 HTML（而非 JSON）说明已过期，需要重新拿页面+解验证码
    OTP_MAX_RETRY = 2
    enc_email = ""
    enc_mobile = ""

    # Debug 模式：使用假邮箱测试 step5
    if DEBUG_EMAIL:
        email_addr = DEBUG_EMAIL
        log(f"[Step5] DEBUG模式: 使用假邮箱 {email_addr}")

    log(f"[Step4→Step5] 等待 1s...")
    time.sleep(1)

    for otp_retry in range(1, OTP_MAX_RETRY + 1):
        log(f"[Step5] 发送 OTP (尝试 {otp_retry}/{OTP_MAX_RETRY})...")
        otp_result, err = step5_send_otp(bls, email_addr, person["mobile"], captcha_data, bls.captcha_id, max_retries=2)
        if not err and otp_result.get("success"):
            enc_email  = otp_result.get("encryptEmail", "")
            enc_mobile = otp_result.get("encryptMobile", "")
            log(f"[Step5] 完成: encryptEmail={enc_email[:30]}..., encryptMobile={enc_mobile}")
            break

        log(f"[OTP 尝试 {otp_retry}/{OTP_MAX_RETRY}] 失败: {err}")
        if otp_retry < OTP_MAX_RETRY:
            log("    重新获取注册页面并解题验证码...")
            # 重新拿页面（获得新的 SecurityCode/Token）
            if not step1_get_register_page(bls):
                result["error"] = "重试时注册页面获取失败"
                log(f"✗ {result['error']}")
                return result
            # 重新解验证码
            new_capt = None
            for attempt in range(1, CAPTCHA_MAX_RETRY + 1):
                capt_res, c_err = solve_captcha_once(bls)
                if capt_res:
                    new_capt = capt_res["captchaData"]
                    break
                log(f"    重试验证码尝试 {attempt}/{CAPTCHA_MAX_RETRY}: {c_err}")
                time.sleep(2)
            if not new_capt:
                result["error"] = "重试验证码失败"
                log(f"✗ {result['error']}")
                return result
            captcha_data = new_capt
            log(f"    新鲜 CaptchaData: {captcha_data[:30]}...")
        else:
            result["error"] = f"OTP 发送失败: {err}"
            log(f"✗ {result['error']}")
            return result

    # ── 6. 等待 OTP 邮件 ───────────────────────────────────────────────────
    if DEBUG_EMAIL:
        # Debug 模式：跳过步骤 6-9
        log(f"[Step6-9] DEBUG模式: 跳过")
        result["email"] = DEBUG_EMAIL
        result["success"] = True
        return result

    log(f"[Step5→Step6] 等待 5s...")
    time.sleep(5)
    log(f"[Step6] 等待 OTP 邮件...")
    otp_code, _ = step6_wait_otp_email(mail_client)
    if not otp_code:
        result["error"] = f"等待 OTP 邮件超时（{EMAIL_TIMEOUT}s）"
        log(f"✗ {result['error']}")
        return result

    result["otp"] = otp_code
    log(f"[Step6] 完成: OTP={otp_code}")

    # ── 7. 获取 Country ID ─────────────────────────────────────────────────
    log(f"[Step6→Step7] 等待 5s...")
    time.sleep(5)
    log(f"[Step7] 获取国家信息...")
    country_id, passport_type_id = step7_get_country_ids(bls)
    log(f"[Step7] 完成: countryId={country_id}, passportTypeId={passport_type_id}")

    # ── 8. 完成注册 ─────────────────────────────────────────────────────────
    log(f"[Step7→Step8] 等待 5s...")
    time.sleep(5)
    log(f"[Step8] 提交注册: {person['surname']} {person['first_name']}, 手机={person['mobile']}, DOB={person['dob']}")
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
        log(f"✗ {result['error']}")
        return result

    log(f"注册表单提交成功！")

    # ── 9. 等待注册成功邮件 ────────────────────────────────────────────────
    log(f"[Step8→Step9] 等待 5s...")
    time.sleep(5)
    log(f"[Step9] 等待注册成功邮件...")
    account_pwd, _ = step9_wait_success_email(mail_client)
    if account_pwd:
        result["account_pwd"] = account_pwd
        result["success"] = True
        log(f"[Step9] 完成: ✓ 注册成功！账号密码: {account_pwd}")
    else:
        result["success"] = True   # 表单已成功提交，只是没取到密码
        result["error"] = "注册成功但未提取到账号密码"
        log(f"[Step9] 完成: ⚠ 注册成功，但未提取到账号密码，请查收邮件: {email_addr}")

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# 多线程调度入口
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    print(f"""
╔══════════════════════════════════════════════════════════════════════════╗
║  BLS China 注册 — 快代理 + mail.tm 多线程版                          ║
║  https://spain.blscn.cn/CHN/account/RegisterUser                   ║
╠══════════════════════════════════════════════════════════════════════════╣
║  并行线程数: MAX_WORKERS = {MAX_WORKERS}（修改常量即可调整）                ║
║  护照规则: >16岁=10年有效, <=16岁=5年有效, 签发=1年前随机              ║
╚══════════════════════════════════════════════════════════════════════════╝
    """)

    if os.path.exists(_ocr_model_path):
        charset = _get_charset()
        print(f"OCR 模型: {_ocr_model_path}")
        print(f"Charset: {charset}")
    else:
        print(f"WARNING: ONNX 模型未找到: {_ocr_model_path}")

    # 生成所有任务（每人一个随机注册信息）
    # 当 MAX_WORKERS=1 时也走线程池（统一架构，方便扩展）
    print(f"\n生成注册任务（并行数={MAX_WORKERS}）...")

    # 每个任务生成独立随机信息
    all_persons = [_generate_person_info() for _ in range(MAX_WORKERS)]

    for i, p in enumerate(all_persons):
        print(f"  Task-{i+1}: {p['surname']} {p['first_name']} | "
              f"DOB={p['dob']} | "
              f"手机={p['mobile']} | "
              f"PP={p['pp_no']} | "
              f"有效期={p['validity_years']}年 | "
              f"签发={p['pp_issue']} 到期={p['pp_expiry']}")

    results: list[dict] = []
    t_start = time.time()

    # ThreadPoolExecutor 调度所有任务
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 提交所有任务
        futures = {
            executor.submit(register_one_task, i + 1, person): i + 1
            for i, person in enumerate(all_persons)
        }

        # 收集结果
        for future in as_completed(futures):
            task_id = futures[future]
            try:
                res = future.result()
            except Exception as e:
                res = {
                    "task_id": task_id,
                    "success": False,
                    "error": f"任务异常: {e}",
                    "email": "", "email_pwd": "", "otp": "",
                    "account_pwd": "", "person": all_persons[task_id - 1], "proxy": "",
                }
            results.append(res)
            if res["success"]:
                print(f"\n  ✓ Task-{task_id} 成功 → 账号密码: {res['account_pwd']}")
            else:
                print(f"\n  ✗ Task-{task_id} 失败 → {res['error']}")

    t_end = time.time()
    elapsed = round(t_end - t_start, 1)

    # ── 汇总报告 ──────────────────────────────────────────────────────────────
    success_count = sum(1 for r in results if r["success"])
    fail_count   = len(results) - success_count

    print("\n" + "=" * 70)
    print(f"执行完成！共 {len(results)} 个任务，成功 {success_count}，失败 {fail_count}，耗时 {elapsed}s")
    print("=" * 70)

    for r in sorted(results, key=lambda x: x["task_id"]):
        status_icon = "✓" if r["success"] else "✗"
        p = r["person"]
        pwd_info = f"账号密码={r['account_pwd']}" if r["account_pwd"] else ("成功(未取密码)" if r["success"] else f"失败:{r['error']}")
        print(f"  [{status_icon}] Task-{r['task_id']} | {p['surname']} {p['first_name']} | "
              f"邮箱={r['email']} | {pwd_info}")

    print("=" * 70)


if __name__ == "__main__":
    main()
