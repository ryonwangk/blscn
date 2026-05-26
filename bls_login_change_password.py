# -*- coding: utf-8 -*-
"""
BLS China 登录改密 — 快代理 + OCR 全自动版

完整流程:

  1. GET  /CHN/account/login
     → 从 login form 内提取所有 text input name
     → 解析 CSS display:none 类名，判断 form-group 可见性
     → visible Email* form-group = email_field
     → 提取 __RequestVerificationToken、Id

  2. POST /CHN/account/LoginSubmit
     → submittedData = {所有 text input name: value}，只有 email_field 有值
     → ResponseData JSON
     → 302 重定向到 /CHN/newcaptcha/logincaptcha?data=<security_code>

  3. GET  /CHN/newcaptcha/logincaptcha?data=<security_code>
     → 解析 CSS 层叠规则，找出 9 个 grid 位置各自的可见图片
     → OCR 识别 9 张图，找目标数字对应的所有图片
     → 提取 Step3 专属的 RVT、Id、Param

  4. POST /CHN/NewCaptcha/LoginCaptchaSubmit
     → 使用 Step3 的 RVT、Id、Param
     → ResponseData JSON 中只有密码字段有值
     → 302 重定向到 /CHN/account/changepassword?alert=True
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
from typing import Optional

from bs4 import BeautifulSoup
import requests
import urllib3

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

FIXED_EMAIL    = "turquoise5548@wshu.net"
FIXED_PASSWORD = "386929"

# OCR 配置
_ocr_model_path = os.path.join(
    os.path.dirname(__file__), "res", "ocr_model", "bls3_final_e37_s35000.onnx",
)
_charset_path = os.path.join(
    os.path.dirname(__file__), "res", "ocr_model", "bls3_meta.json",
)
_default_charset = [' ', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

# 检查 ONNX 模型是否存在
_use_onnx = os.path.exists(_ocr_model_path)
_ddddocr_inst = None  # ddddocr 实例（延迟加载）

CAPTCHA_MAX_RETRY = 1
DEBUG_VERBOSE = False
DEBUG_NO_PROXY = False
USE_REQABLE_PROXY = True  # True: 使用 127.0.0.1:9000 本地代理出口（reqable 每分钟自动更换 IP）
REQABLE_PROXY_HOST = "127.0.0.1"
REQABLE_PROXY_PORT = 9000


# ═══════════════════════════════════════════════════════════════════════════════
# BLS HTTP Session
# ═══════════════════════════════════════════════════════════════════════════════
class BLSSession:
    def __init__(self, proxy=None):
        self._proxy_url = None
        if proxy:
            if isinstance(proxy, dict):
                self._proxy_url = proxy.get("http", proxy.get("https", ""))
            else:
                self._proxy_url = proxy

        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "upgrade-insecure-requests": "1",
            "cache-control": "max-age=0",
            "priority": "u=0, i",
        })
        self._proxies = None
        if self._proxy_url:
            self._proxies = {"http": self._proxy_url, "https": self._proxy_url}

        # Step1/2 提取
        self.rvt_step1       = ""
        self.id_step1        = ""
        self.text_fields     = []  # login form 内的所有 text input name
        self.email_field     = ""  # 可见的 Email* 字段

        # 服务端返回
        self.security_code   = ""

        # Step3 页面的专属数据（用于 Step4）
        self.rvt_step3        = ""
        self.id_step3         = ""
        self.param            = ""   # Param = security_code

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
            "allow_redirects": False,
            "verify": False,  # 禁用 SSL 证书验证
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
# CSS visibility 解析
# ═══════════════════════════════════════════════════════════════════════════════
def _parse_css_display_none(html: str) -> set:
    """从 HTML 中提取 CSS display:none 的类名集合"""
    style_blocks = re.findall(r'<style[^>]*>(.*?)</style>', html, re.DOTALL)
    css_text = '\n'.join(style_blocks)
    display_none = set()
    for cls_name, props in re.findall(r'\.([a-z0-9]+)\s*\{([^}]+)\}', css_text):
        if re.search(r'display\s*:\s*none', props):
            display_none.add(cls_name)
    return display_none


# ═══════════════════════════════════════════════════════════════════════════════
# Step 1: 获取登录页面
# ═══════════════════════════════════════════════════════════════════════════════
def step1_get_login_page(session: BLSSession) -> tuple[bool, dict]:
    """
    GET /CHN/account/login
    提取 __RequestVerificationToken、Id、所有 text input name（login form 内）
    通过 CSS display:none 类名判断可见字段
    """
    status, html, _ = session.req("/CHN/account/login", timeout=25)
    if status != 200:
        return False, {}

    soup = BeautifulSoup(html, "html.parser")

    # 找 login form（action 包含 LoginSubmit）
    login_form = None
    for form in soup.find_all("form"):
        if "LoginSubmit" in (form.get("action") or ""):
            login_form = form
            break

    if not login_form:
        return False, {}

    # 提取 RVT 和 Id
    rvt_el = login_form.find("input", {"name": "__RequestVerificationToken"})
    id_el  = login_form.find("input", {"name": "Id"})

    # 解析 CSS display:none
    css_display_none = _parse_css_display_none(html)

    # 提取 login form 内的所有 text input name
    text_inputs = login_form.find_all("input", type="text")
    text_fields = [inp.get("name", "") for inp in text_inputs if inp.get("name")]

    # 找 visible Email* form-group
    form_groups = login_form.find_all("div", class_=lambda x: x and "mb-3" in (x if isinstance(x, str) else " ".join(x)))
    email_field = None

    for fg in form_groups:
        inp = fg.find("input", type="text")
        if not inp or not inp.get("name"):
            continue

        label_el = fg.find("label")
        label_text = label_el.get_text(strip=True) if label_el else ""
        if "Email" not in label_text:
            continue

        fg_classes = fg.get("class", [])
        if isinstance(fg_classes, str):
            fg_classes = fg_classes.split()

        hidden_by_css   = any(c in css_display_none for c in fg_classes)
        inline_style   = fg.get("style", "") or ""
        hidden_inline  = bool(re.search(r'display\s*:\s*none', inline_style))

        if not hidden_by_css and not hidden_inline and not email_field:
            email_field = inp.get("name", "")

    # Fallback: 用第一个 text field
    if not email_field and text_fields:
        email_field = text_fields[0]

    session.rvt_step1   = rvt_el["value"] if rvt_el else ""
    session.id_step1    = id_el["value"]  if id_el  else ""
    session.text_fields = text_fields
    session.email_field = email_field

    return session.rvt_step1 != "", {
        "html": html,
        "rvt": session.rvt_step1,
        "id": session.id_step1,
        "text_fields": text_fields,
        "email_field": email_field,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Step 2: 提交邮箱
# ═══════════════════════════════════════════════════════════════════════════════
def step2_submit_login(
    session: BLSSession,
    page_info: dict,
    email: str,
    max_retry: int = 1,
) -> bool:
    """
    POST /CHN/account/LoginSubmit
    模拟 OnSubmitVerify() 的逻辑：
    - submittedData = {所有 text input name: value}，只有 email_field 有值
    - top-level POST 中所有字段为空字符串，只有 email_field 有值
    - ResponseData = JSON.stringify(submittedData)
    """
    text_fields = page_info.get("text_fields", [])
    email_field = page_info.get("email_field", "")
    rvt         = page_info.get("rvt", "")
    id_val      = page_info.get("id", "")

    if not rvt or not email_field or not text_fields:
        return False

    for attempt in range(1, max_retry + 1):
        # 模拟 OnSubmitVerify():
        # submittedData = {name: email if name==email_field else "" for all text inputs}
        submitted_data = {name: (email if name == email_field else "") for name in text_fields}
        rd_json = json.dumps(submitted_data, separators=(",", ":"))

        post_data = {
            **{name: (email if name == email_field else "") for name in text_fields},
            "ResponseData": rd_json,
            "ReturnUrl": "",
            "Id": id_val,
            "__RequestVerificationToken": rvt,
        }

        encoded = urllib.parse.urlencode(post_data)

        status, text, headers = session.req(
            "/CHN/account/LoginSubmit",
            method="POST",
            data=encoded,
            extra={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": BASE_URL,
                "Referer": BASE_URL + "/CHN/account/login",
            },
            timeout=30,
        )

        location = headers.get("Location", "")
        if status == 302 and "newcaptcha/logincaptcha" in location:
            # 关键：从 Location 中提取 data 参数时必须保持原始 URL 编码！
            # 不能使用 parse_qs，因为它会解码 URL 参数
            # 例如 %2B 会被解码为 +，导致 Step3 请求失败
            m = re.search(r'[?&]data=([^&]+)', location)
            if m:
                session.security_code = m.group(1)
                return True

        print(f"    [尝试 {attempt}/{max_retry}] HTTP {status} Location={location}")
        if status == 200:
            print(f"    返回内容前500字符: {text[:500]}")

        if attempt < max_retry:
            time.sleep(2)
            ok, page_info = step1_get_login_page(session)
            if ok:
                text_fields = page_info.get("text_fields", [])
                email_field = page_info.get("email_field", "")
                rvt         = page_info.get("rvt", "")
                id_val      = page_info.get("id", "")

    return False


# ═══════════════════════════════════════════════════════════════════════════════
# Step 3: 获取验证码页面
# ═══════════════════════════════════════════════════════════════════════════════
def step3_get_captcha(session: BLSSession) -> tuple[dict, str | None]:
    """
    GET /CHN/newcaptcha/logincaptcha?data=<security_code>
    解析验证码图片 + 提取 Step3 专属的 RVT、Id、Param
    """
    url = f"/CHN/newcaptcha/logincaptcha?data={session.security_code}"
    status, html, headers = session.req(url, extra={
        "Referer": BASE_URL + "/CHN/account/login",
    })
    if status != 200:
        return {}, None

    soup = BeautifulSoup(html, "html.parser")

    # 提取 Step3 专属字段
    rvt_step3 = ""
    id_step3   = ""
    param      = ""

    for inp in soup.find_all("input", type="hidden"):
        name = inp.get("name", "") or inp.get("id", "")
        val  = inp.get("value", "")
        if name == "__RequestVerificationToken":
            rvt_step3 = val
        elif name == "Id":
            id_step3 = val
        elif name == "Param":
            param = val

    session.rvt_step3 = rvt_step3
    session.id_step3   = id_step3
    session.param      = param

    # ── 解析 CSS 完整规则（left/top/z-index/color/display）─────────────
    style_blocks = re.findall(r'<style[^>]*>(.*?)</style>', html, re.DOTALL)
    css_text = '\n'.join(style_blocks)

    class_info = {}   # class_name -> {left, top, z, display, color}
    for rule in re.findall(r'\.([a-z0-9]+)\s*\{([^}]+)\}', css_text):
        cls_name, props = rule
        info = {}
        m = re.search(r'left\s*:\s*(-?\d+)px', props);   info["left"]    = int(m.group(1)) if m else None
        m = re.search(r'top\s*:\s*(-?\d+)px',  props);   info["top"]     = int(m.group(1)) if m else None
        m = re.search(r'z-index\s*:\s*(\d+)',    props);   info["z"]       = int(m.group(1)) if m else None
        m = re.search(r'display\s*:\s*(\w+)',     props);   info["display"] = m.group(1)        if m else None
        m = re.search(r'color\s*:\s*([^;]+)',     props);   info["color"]   = m.group(1).strip() if m else None
        class_info[cls_name] = info

    # ── 解析 img 父 div ──────────────────────────────────────────────
    img_entries = []
    for img in soup.find_all('img'):
        if not img.get('class'):
            continue
        ic = img.get('class', [])
        if isinstance(ic, str): ic = ic.split()
        if 'captcha-img' not in ic:
            continue
        src = img.get('src', '')
        if not src.startswith('data:'):
            continue
        parent = img.parent
        while parent and parent.name != 'div':
            parent = parent.parent
        if not parent or not parent.get('id'):
            continue
        div_id  = parent.get('id', '')
        dc = parent.get('class', [])
        if isinstance(dc, str): dc = dc.split()
        img_entries.append({"id": div_id, "classes": dc, "src": src})

    # ── 收集 show()/hide() 调用（jQuery 隐藏的 div）──────────────────
    script_text = '\n'.join(style_blocks)
    for block in re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL):
        script_text += '\n' + block

    show_ids = set()
    hide_ids = set()
    for m in re.finditer(r"\$\(['\"]#?(\w+)['\"]\)\.(show|hide)\(\)", script_text):
        elem_id, action = m.group(1), m.group(2)
        if action == 'show':
            show_ids.add(elem_id)
        else:
            hide_ids.add(elem_id)

    # ── 每个 (left, top) 格子位置，取 z-index 最高的可见 div ─────────
    # 可见条件：1) CSS display!==none  2) 不在 hide_ids 中
    position_best = {}
    for entry in img_entries:
        div_id  = entry["id"]
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
                ci = class_info[cls]
                if ci.get('left') is not None: left = ci['left']
                if ci.get('top')  is not None: top  = ci['top']
                if ci.get('z')    is not None: z    = max(z or 0, ci['z'])
        if left is None or top is None:
            continue
        key = (left, top)
        if key not in position_best or (z is not None and z > (position_best[key].get('_z') or 0)):
            position_best[key] = {"id": div_id, "src": entry["src"], "_z": z or 0}

    # ── 解析目标数字：取 z-index 最高的 box-label ────────────────────
    # 注意：所有 label 都是浅色 #FFFAF0，无法用 color 区分
    # 直接取 z-index 最高的那个
    target_digit = None
    max_z = 0
    for text_div in soup.find_all('div', class_=lambda x: x and 'box-label' in ' '.join(x) if isinstance(x, list) else (x and 'box-label' in x)):
        text = text_div.get_text(strip=True)
        m = re.match(r'Please select all boxes with number (\d+)', text)
        if not m:
            continue
        digit = m.group(1)
        classes = text_div.get('class', [])
        if isinstance(classes, str): classes = classes.split()
        # 计算 z-index
        z = 0
        for c in classes:
            if c in class_info and class_info[c].get('z') is not None:
                z = max(z, class_info[c]['z'])
        if z > max_z:
            max_z = z
            target_digit = digit

    # ── 提取所有 password input 的 name（用于构建 ResponseData）───────
    # 注意：step5 中需要找 display!==none 的那个，但所有 name 都用于 ResponseData
    password_fields = [
        inp.get("name", "")
        for inp in soup.find_all("input")
        if inp.get("type") == "password" and inp.get("name")
    ]

    # ── 找出可见的密码字段（父 form-group display!==none）─────────────
    # CSS 中 form-group 类名对应 display:none 的就是隐藏的
    hidden_fg_classes = {
        c for c, ci in class_info.items()
        if ci.get('display') == 'none'
    }
    visible_pwd_field = None
    for inp in soup.find_all("input"):
        if inp.get("type") != "password" or not inp.get("name"):
            continue
        parent = inp.parent
        while parent and parent.name not in ('div', 'form'):
            parent = parent.parent
        if not parent or parent.name != 'div':
            continue
        fg_classes = parent.get('class', [])
        if isinstance(fg_classes, str): fg_classes = fg_classes.split()
        hidden = any(c in hidden_fg_classes for c in fg_classes)
        if not hidden:
            visible_pwd_field = inp.get("name", "")
            break

    # 调试信息：显示 show()/hide() 解析结果
    print(f"    CSS classes: {len(class_info)}")
    print(f"    show() calls: {len(show_ids)}, hide() calls: {len(hide_ids)}")
    print(f"    img entries: {len(img_entries)}, visible positions: {len(position_best)}")

    return {
        "html": html,
        "rvt_step3": rvt_step3,
        "id_step3": id_step3,
        "param": param,
        "position_best": position_best,
        "target_digit": target_digit,
        "class_info": class_info,
        "password_fields": password_fields,
        "visible_pwd_field": visible_pwd_field,
        "hide_ids": hide_ids,  # 用于调试
    }, target_digit


# ═══════════════════════════════════════════════════════════════════════════════
# Step 4: OCR
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


def _get_ddddocr():
    """获取 ddddocr 实例（延迟加载）"""
    global _ddddocr_inst
    if _ddddocr_inst is None:
        import ddddocr
        _ddddocr_inst = ddddocr.DdddOcr(show_ad=False, beta=True)
    return _ddddocr_inst


def _ocr_classification(raw_bytes: bytes, charset: list) -> str:
    """OCR 分类函数，优先使用 ONNX 模型，备选 ddddocr"""
    global _use_onnx

    if _use_onnx:
        try:
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
        except Exception as e:
            print(f"    ONNX OCR 失败: {e}，切换到 ddddocr")
            _use_onnx = False

    # 使用 ddddocr
    try:
        ocr = _get_ddddocr()
        result = ocr.classification(raw_bytes)
        # 提取数字
        digits = re.findall(r'\d+', result)
        return "".join(digits)
    except Exception as e:
        print(f"    ddddocr 失败: {e}")
        return ""


def step4_ocr(params: dict, target_digit: str | None) -> tuple[list, int]:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    position_best = params["position_best"]
    if not target_digit:
        return [], 0

    # 检查 OCR 可用性
    if not _use_onnx and _ddddocr_inst is None:
        try:
            _get_ddddocr()
            print("    使用 ddddocr 进行 OCR 识别")
        except ImportError:
            print("    ERROR: ONNX 模型和 ddddocr 都不可用")
            return [], 0
    elif _use_onnx:
        charset = _get_charset()
        _get_onnx_sess(_ocr_model_path)
        print("    使用 ONNX 模型进行 OCR 识别")
    else:
        print("    使用 ddddocr 进行 OCR 识别")

    sorted_positions = sorted(position_best.items(), key=lambda x: x[0])
    entries = list(sorted_positions)

    # 获取 charset（用于 ONNX 模型）
    charset = _get_charset() if _use_onnx else _default_charset

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

    # 并行执行 OCR
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

    # 按位置顺序打印结果
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
        ms = res["ms"]
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
# Step 5: 提交验证码 + 密码
# ═══════════════════════════════════════════════════════════════════════════════
def step5_submit_captcha(
    session: BLSSession,
    selected_ids: list,
    page_info: dict,
    password: str,
    max_retry: int = 3,
) -> tuple[bool, str | None]:
    """
    POST /CHN/NewCaptcha/LoginCaptchaSubmit
    使用 Step3 页面的 RVT、Id、Param
    重试时需重新获取 Step3 页面刷新 RVT
    """
    password_fields = page_info.get("password_fields", [])
    rvt_step3 = session.rvt_step3
    id_step3  = session.id_step3
    param     = session.param

    if not password_fields:
        return False, "未找到密码字段"
    if not rvt_step3:
        return False, "未找到 Step3 RVT"

    # HAR 分析: 找 display!==none 的密码字段
    # visible_pwd_field 从 step3_get_captcha 中提取
    pwd_field = page_info.get("visible_pwd_field", password_fields[8] if password_fields else "")

    for attempt in range(1, max_retry + 1):
        # Top-level: 所有密码字段，只有 pwd_field 有值
        post_data = {f: (password if f == pwd_field else "") for f in password_fields}
        # ResponseData JSON
        rd_dict = {f: (password if f == pwd_field else "") for f in password_fields}
        rd_json = json.dumps(rd_dict, separators=(",", ":"))

        # 添加其他字段
        post_data["SelectedImages"] = ",".join(selected_ids)
        post_data["Id"] = id_step3
        post_data["ReturnUrl"] = ""
        post_data["ResponseData"] = rd_json
        post_data["Param"] = param
        post_data["__RequestVerificationToken"] = rvt_step3

        encoded = urllib.parse.urlencode(post_data)

        status, text, headers = session.req(
            "/CHN/NewCaptcha/LoginCaptchaSubmit",
            method="POST",
            data=encoded,
            extra={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": BASE_URL,
                "Referer": BASE_URL + "/CHN/newcaptcha/logincaptcha?data=" + session.security_code,
            },
            timeout=30,
        )

        location = headers.get("Location", "")
        if status == 302:
            if "changepassword" in location:
                print(f"    [尝试 {attempt}] 成功！302 → {location}")
                return True, None
            else:
                print(f"    [尝试 {attempt}] 302 → {location}")
                return False, f"重定向到意外页面: {location}"
        elif status == 200:
            print(f"    [尝试 {attempt}] HTTP 200")
            if attempt < max_retry:
                time.sleep(2)
                page_info, _ = step3_get_captcha(session)
                rvt_step3 = session.rvt_step3
                id_step3  = session.id_step3
                param     = session.param
                continue
            return False, "HTTP 200，未成功重定向"
        else:
            print(f"    [尝试 {attempt}] HTTP {status} Location={location}")
            if attempt < max_retry:
                time.sleep(2)
                page_info, _ = step3_get_captcha(session)
                rvt_step3 = session.rvt_step3
                id_step3  = session.id_step3
                param     = session.param
                continue
            return False, f"HTTP {status}"

    return False, "超过最大重试次数"


# ═══════════════════════════════════════════════════════════════════════════════
# 验证码流程整合（Step 3-5）
# ═══════════════════════════════════════════════════════════════════════════════
def solve_captcha_once(session: BLSSession, password: str) -> tuple[bool, str | None, dict]:
    print(f"[Step3] 获取验证码图片...")
    page_info, target_digit = step3_get_captcha(session)
    if not page_info:
        return False, "验证码页面获取失败", {}

    password_fields = page_info.get("password_fields", [])
    print(f"[Step3] 完成: 目标数字={target_digit}, 密码字段={password_fields}")
    print(f"[Step3] Step3专属: RVT={session.rvt_step3[:30]}..., Id={session.id_step3}")

    if not password_fields:
        return False, "未找到密码字段", {}

    time.sleep(0.5)

    print(f"[Step4] OCR 识别...")
    selected_ids, ocr_ms = step4_ocr(page_info, target_digit)
    if not selected_ids:
        return False, f"OCR 未匹配到图片（target={target_digit}）", page_info
    print(f"[Step4] 完成: 选中 {len(selected_ids)} 个, 耗时 {ocr_ms}ms")

    time.sleep(0.5)

    print(f"[Step5] 提交验证码 + 密码...")
    ok, err = step5_submit_captcha(session, selected_ids, page_info, password)
    if ok:
        print(f"[Step5] 完成: ✓ 成功！")
        return True, None, page_info
    print(f"[Step5] 失败: {err}")
    return False, err, page_info


# ═══════════════════════════════════════════════════════════════════════════════
# 主登录流程
# ═══════════════════════════════════════════════════════════════════════════════
def login(email: str, password: str, proxy=None) -> dict:
    result = {
        "success": False,
        "email": email,
        "password": password,
        "error": "",
        "proxy": "",
    }

    proxy_url = None
    if proxy:
        if isinstance(proxy, dict):
            proxy_url = proxy.get("http", proxy.get("https", ""))
        else:
            proxy_url = proxy
        result["proxy"] = proxy_url

    bls = BLSSession(proxy=proxy)

    # Step 1: 获取登录页面
    print(f"[Step1] 获取登录页面...")
    ok, page_info = step1_get_login_page(bls)
    if not ok:
        result["error"] = "登录页面获取失败"
        return result

    text_fields = page_info.get("text_fields", [])
    email_field = page_info.get("email_field", "")
    print(f"[Step1] 完成: RVT={bls.rvt_step1[:30]}..., email_field={email_field}, 字段数={len(text_fields)}")

    if not text_fields:
        result["error"] = "未找到 text 字段"
        return result

    time.sleep(1)

    # Step 2: 提交邮箱
    print(f"[Step2] 提交邮箱: {email} (字段={email_field})")
    if not step2_submit_login(bls, page_info, email):
        result["error"] = "邮箱提交失败"
        return result
    print(f"[Step2] 完成: SecurityCode={bls.security_code[:30]}...")

    time.sleep(1)

    # Step 3-5: 验证码 + 密码
    last_page_info = {}
    for attempt in range(1, CAPTCHA_MAX_RETRY + 1):
        print(f"\n[验证码 尝试 {attempt}/{CAPTCHA_MAX_RETRY}]")
        ok, err, last_page_info = solve_captcha_once(bls, password)
        if ok:
            result["success"] = True
            return result
        if attempt < CAPTCHA_MAX_RETRY:
            print(f"    失败: {err}，重试...")
            time.sleep(2)

    result["error"] = f"验证码连续失败: {err}"
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# 入口
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    print(f"""
╔══════════════════════════════════════════════════════════════════════════╗
║  BLS China 登录改密 — 快代理 + OCR 全自动版                         ║
║  https://spain.blscn.cn/CHN/account/login                       ║
╠══════════════════════════════════════════════════════════════════════════╣
║  固定账号: {FIXED_EMAIL}                                   ║
║  固定密码: {FIXED_PASSWORD}                                                  ║
╚══════════════════════════════════════════════════════════════════════════╝
    """)

    if os.path.exists(_ocr_model_path):
        charset = _get_charset()
        print(f"OCR 模型: {_ocr_model_path}")
        print(f"Charset: {charset}")
    else:
        print(f"WARNING: ONNX 模型未找到: {_ocr_model_path}")

    # 获取代理
    proxy = None
    if USE_REQABLE_PROXY:
        reqable_proxy = f"http://{REQABLE_PROXY_HOST}:{REQABLE_PROXY_PORT}"
        proxy = {"http": reqable_proxy, "https": reqable_proxy}
        print(f"使用 Reqable 本地代理: {reqable_proxy} (每分钟自动更换 IP)")
    elif DEBUG_NO_PROXY:
        print("DEBUG模式: 不使用代理")
    else:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        try:
            from tools.proxies import kuaidaili
            for attempt in range(1, 4):
                proxy = kuaidaili.get_proxy()
                if not proxy:
                    print(f"[代理尝试 {attempt}/3] 获取失败，重试...")
                    time.sleep(2)
                    continue
                ip_raw = proxy.get("http", "")
                m = re.match(r'http://([^:@]+):([^@]+)@(.+)', ip_raw)
                display_ip = m.group(3) if m else ip_raw
                print(f"使用代理: {display_ip}")
                break
            if not proxy:
                print("WARNING: 无法获取代理，将直连")
        except Exception as e:
            print(f"WARNING: 代理模块加载失败: {e}，将直连")

    print()
    result = login(FIXED_EMAIL, FIXED_PASSWORD, proxy)

    print()
    if result["success"]:
        print("=" * 60)
        print(f"  ✓ 登录成功！")
        print(f"  邮箱: {result['email']}")
        print(f"  密码: {result['password']}")
        print(f"  代理: {result['proxy']}")
        print(f"  → /CHN/account/changepassword?alert=True")
        print("=" * 60)
    else:
        print("=" * 60)
        print(f"  ✗ 登录失败: {result['error']}")
        print("=" * 60)

    return result


if __name__ == "__main__":
    main()
