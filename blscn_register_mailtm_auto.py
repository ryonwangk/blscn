# -*- coding: utf-8 -*-
"""
BLS China 注册 — mail.tm 临时邮箱全自动版
==========================================
自动创建临时邮箱 → 填写 BLS 注册表单 → 等待邮件 → 提取 OTP → 完成注册

验证码算法（来自 blsfix_solve_captcha_auto.py）:
  1. GET /CHN/CaptchaPublic/GenerateCaptcha?data=<security_code>
     → HTML 里有 54 张 base64 图片和多个 box-label

  2. CSS 中每个随机 class 决定 div 的 position/left/top/z-index

  3. 9 个 grid 位置 (0,0) (0,110) (0,220)
     (110,0) (110,110) (110,220)
     (220,0) (220,110) (220,220)

  4. 最终可见图片 = 该位置所有 div 中 z-index 最高的 display:none 除外

  5. OCR 9 张可见图，找匹配数字，提交

模型: blscn/ddddocr_model/blsfix_final_e25_s6000.onnx
     预处理已内置 ONNX: 直接输入原始验证码图片即可
     charset: ['0'..'9'] (10类，纯数字)
     准确率: ~98.3%
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import base64
import gzip
import html as html_module
import io
import json
import os
import re
import threading
import time
import urllib.parse

import requests

import mailtm
from mailtm import MailTmClient, MailTmError, TokenBucket

# ═══════════════════════════════════════════════════════════════════════════════
# ONNX Session 全局单例（进程内只加载一次，线程安全）
# ═══════════════════════════════════════════════════════════════════════════════
_onnx_sess_map: dict[str, tuple] = {}   # onnx_path → (sess, input_name)
_onnx_lock = threading.Lock()


def _get_onnx_sess(onnx_path: str):
    """返回 (onnxruntime.InferenceSession, input_name)，线程安全，惰性加载。"""
    if onnx_path not in _onnx_sess_map:
        with _onnx_lock:
            if onnx_path not in _onnx_sess_map:
                import onnxruntime as ort
                sess = ort.InferenceSession(onnx_path)
                inp_name = sess.get_inputs()[0].name
                _onnx_sess_map[onnx_path] = (sess, inp_name)
    return _onnx_sess_map[onnx_path]

# ═══════════════════════════════════════════════════════════════════════════════
# 配置
# ═══════════════════════════════════════════════════════════════════════════════
# BLS 目标
TARGET_HOST   = "spain.blscn.cn"
BASE_URL      = f"https://{TARGET_HOST}"

# 代理（与 blsfix_solve_captcha_auto.py 保持一致）
PROXY_HOST    = "a963.zdtps.com"
PROXY_PORT    = 21166
PROXY_USER    = "202605201806451396"
PROXY_PASS    = "1c2nq72a"
PROXY         = f"http://{PROXY_USER}:{PROXY_PASS}@{PROXY_HOST}:{PROXY_PORT}"

# BLS 注册表单（护照信息，需根据实际情况修改）
SURNAME       = "ZHANG"
FIRST_NAME    = "San"
LAST_NAME     = ""
DOB           = "1990-01-15"
PP_NO         = "G12345678"
PP_ISSUE      = "2020-01-15"
PP_EXPIRY     = "2030-01-15"
ISSUE_PLACE   = "Beijing"

# OCR 模型路径
_ocr_model_path = os.path.join(os.path.dirname(__file__), "ddddocr_model", "blsfix_final_e25_s6000.onnx")
_charset_path   = os.path.join(os.path.dirname(__file__), "ddddocr_model", "meta.json")
_default_charset = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

# mailtm 速率限制
MAILTM_QPS    = 8

# 邮件轮询参数
EMAIL_TIMEOUT       = 180.0
EMAIL_POLL_INTERVAL = 3.0
EMAIL_SUBJECT_KEY   = ""
EMAIL_FROM_KEY      = "blscn"

# 验证码重试次数
CAPTCHA_MAX_RETRY   = 3

# 调试开关（True = 打印所有 HTTP 请求/响应详情）
DEBUG_VERBOSE       = False


# ═══════════════════════════════════════════════════════════════════════════════
# BLS HTTP Session
# ═══════════════════════════════════════════════════════════════════════════════
class BLSSession:
    def __init__(self, proxy=None):
        self._proxy = proxy or PROXY
        self._proxy_auth = None
        m = re.match(r'http://([^:@]+):([^@]+)@(.+)', self._proxy)
        if m:
            self._proxy = f"http://{m.group(3)}"
            self._proxy_auth = requests.auth.HTTPProxyAuth(m.group(1), m.group(2))
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8",
            "Accept-Encoding": "gzip, deflate",
        })
        self.security_code = ""
        self.verify_token  = ""
        self.captcha_id    = ""

    def _build_proxies(self):
        return {"http": self._proxy, "https": self._proxy} if self._proxy else {}

    def req(self, path, method="GET", data=None, extra=None, timeout=25):
        url = BASE_URL + path
        h = dict(self.session.headers)
        if extra:
            h.update(extra)
        if method == "POST" and data and "Content-Type" not in h:
            h["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
        kwargs = {
            "headers": h, "timeout": timeout, "proxies": self._build_proxies(),
        }
        if self._proxy_auth:
            kwargs["auth"] = self._proxy_auth
        if data:
            kwargs["data"] = data
        try:
            resp = self.session.request(method, url, **kwargs)
            raw = resp.content
            try:
                text = gzip.decompress(raw).decode("utf-8", errors="replace")
            except Exception:
                text = raw.decode("utf-8", errors="replace")
            if DEBUG_VERBOSE:
                print(f"    >> {method} {url[:80]}")
                print(f"    << HTTP {resp.status_code}  {len(raw)} bytes")
            return resp.status_code, text, dict(resp.headers)
        except Exception as e:
            return 0, str(e), {}


# ═══════════════════════════════════════════════════════════════════════════════
# Step 1: 获取注册页面
# ═══════════════════════════════════════════════════════════════════════════════
def step1(session: BLSSession, max_retry: int = 3) -> bool:
    for attempt in range(1, max_retry + 1):
        print(f"[1] GET /CHN/account/RegisterUser  (尝试 {attempt}/{max_retry})")
        status, html, _ = session.req("/CHN/account/RegisterUser")
        if status != 200:
            print(f"    HTTP {status}")
            if attempt < max_retry:
                print("    重试...")
                time.sleep(2)
                continue
            return False

        m = re.search(r'<input[^>]+id="SecurityCode"[^>]+value="([^"]+)"', html)
        if not m:
            m = re.search(r'<input[^>]+value="([^"]+)"[^>]+id="SecurityCode"', html)
        if m:
            session.security_code = urllib.parse.unquote(m.group(1))

        m = re.search(r'<input[^>]+name="__RequestVerificationToken"[^>]+value="([^"]+)"', html)
        if not m:
            m = re.search(r'<input[^>]+value="([^"]+)"[^>]+name="__RequestVerificationToken"', html)
        if m:
            session.verify_token = m.group(1)

        m = re.search(r'<input[^>]+id="CaptchaId"[^>]+value="([^"]+)"', html)
        if m:
            session.captcha_id = m.group(1)

        if session.security_code:
            print(f"    SecurityCode: {session.security_code[:40]}...")
            print(f"    Token: {session.verify_token[:40]}...")
            return True
        print("    SecurityCode 未找到")
        if attempt < max_retry:
            print("    重试...")
            time.sleep(2)
            continue
        return False

    return False


# ═══════════════════════════════════════════════════════════════════════════════
# Step 2: 解析验证码页面（CSS + box-label + visible images）
# ═══════════════════════════════════════════════════════════════════════════════
def step2(session: BLSSession) -> tuple[dict, str | None]:
    print("[2] GET /CHN/CaptchaPublic/GenerateCaptcha")
    url = f"/CHN/CaptchaPublic/GenerateCaptcha?data={urllib.parse.quote(session.security_code)}"
    status, html, _ = session.req(url)
    if status != 200:
        print(f"    HTTP {status}")
        return {}, None

    # ── 解析 CSS ────────────────────────────────────────────────────────────
    style_blocks = re.findall(r'<style[^>]*>(.*?)</style>', html, re.DOTALL)
    css_text = '\n'.join(style_blocks)

    class_info = {}
    for cls_name, props in re.findall(r'\.([a-z0-9]+)\{([^}]+)\}', css_text):
        left = top = z = None
        display = None
        m_left = re.search(r'left\s*:\s*(-?\d+)px', props)
        m_top  = re.search(r'top\s*:\s*(-?\d+)px', props)
        m_z    = re.search(r'z-index\s*:\s*(\d+)', props)
        m_disp = re.search(r'display\s*:\s*(\w+)', props)
        if m_left: left = int(m_left.group(1))
        if m_top:  top  = int(m_top.group(1))
        if m_z:    z    = int(m_z.group(1))
        if m_disp: display = m_disp.group(1)
        if left is not None or top is not None or z is not None or display is not None:
            class_info[cls_name] = {"left": left, "top": top, "z": z, "display": display}

    print(f"    CSS classes: {len(class_info)}, display:none: {sum(1 for v in class_info.values() if v.get('display') == 'none')}")

    # ── 收集 show()/hide() 调用 ─────────────────────────────────────────────
    script_text = '\n'.join(style_blocks)
    for block in re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL):
        script_text += '\n' + block

    show_ids = set()
    hide_ids = set()
    for m in re.finditer(r"\$\(['\"]#?(\w+)['\"]\)\.(show|hide)\(\)", script_text):
        elem_id, action = m.group(1), m.group(2)
        (show_ids if action == 'show' else hide_ids).add(elem_id)

    print(f"    show() calls: {len(show_ids)}, hide() calls: {len(hide_ids)}")

    # ── 解析 img 父 div ─────────────────────────────────────────────────────
    img_entries = []
    for m in re.finditer(
        r'<div[^>]+id="([^"]+)"[^>]*>\s*<img[^>]+class="captcha-img"[^>]+src="([^"]+)"',
        html,
    ):
        div_id, src = m.group(1), m.group(2)
        div_start = m.start()
        div_tag_start = html.rfind('<div', 0, div_start + 10)
        div_tag_end = html.find('>', div_tag_start)
        div_tag = html[div_tag_start:div_tag_end]
        cls_m = re.search(r'class="([^"]+)"', div_tag)
        classes = cls_m.group(1).split() if cls_m else []
        img_entries.append({"id": div_id, "classes": classes, "src": src})

    print(f"    img entries: {len(img_entries)}")

    # ── 确定每个 div 的 display 状态 ─────────────────────────────────────────
    div_display = {}
    for entry in img_entries:
        div_id = entry["id"]
        classes = entry["classes"]
        div_tag_start = html.find(f'id="{div_id}"')
        if div_tag_start < 0:
            div_display[div_id] = True
            continue
        div_tag_end = html.find('>', div_tag_start)
        div_tag = html[div_tag_start:div_tag_end + 1]

        inline_m = re.search(r'style=["\']([^"\']*display\s*:\s*(\w+)[^"\']*)["\']', div_tag)
        if inline_m:
            div_display[div_id] = (inline_m.group(2) != 'none')
            continue

        hidden_by_css = any(
            class_info.get(c, {}).get('display') == 'none'
            for c in classes
        )
        div_display[div_id] = not hidden_by_css

    visible_count = sum(1 for v in div_display.values() if v)
    print(f"    div visibility: {visible_count} visible, {len(div_display) - visible_count} hidden")

    # ── 对每个位置，找 z-index 最高的可见 div ────────────────────────────────
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

    print(f"    visible positions: {len(position_best)}")

    # ── 提取目标数字 ─────────────────────────────────────────────────────────
    label_entries = []
    for m in re.finditer(r"Please select all boxes with number (\d+)", html):
        digit = m.group(1)
        search_start = max(0, m.start() - 600)
        chunk = html[search_start:m.start()]
        div_tag_start = chunk.rfind('<div')
        if div_tag_start < 0:
            continue
        div_tag = chunk[div_tag_start:]
        div_tag = div_tag[:div_tag.find('>') + 1]

        cm = re.search(r"class=['\"]([^'\"]+)['\"]", div_tag)
        if not cm:
            continue
        cls_list = cm.group(1).split()

        hidden = any(class_info.get(c, {}).get('display') == 'none' for c in cls_list)
        if hidden:
            continue

        z = 0
        for c in cls_list:
            if c in class_info and class_info[c].get('z') is not None:
                z = max(z, class_info[c]['z'])

        label_entries.append({"digit": digit, "z": z})

    target_digit = None
    if label_entries:
        label_entries.sort(key=lambda x: x["z"], reverse=True)
        top_label = label_entries[0]
        target_digit = top_label["digit"]
        print(f"    box-labels: {len(label_entries)} visible, target digit: {target_digit} (z={top_label['z']})")
    else:
        print("    box-labels: 0, no target digit found")

    # ── 提取 hidden fields ───────────────────────────────────────────────────
    hidden = {}
    for inp in re.findall(r'<input[^>]+type="hidden"[^>]+>', html, re.IGNORECASE):
        name_m = re.search(r'name=["\']?([^"\'>\s]+)["\']?', inp)
        val_m  = re.search(r'value=["\']([^"\']*)["\']', inp)
        id_m   = re.search(r'id=["\']?([^"\'>\s]+)["\']?', inp)
        name = name_m.group(1) if name_m else (id_m.group(1) if id_m else "")
        if name:
            hidden[name] = val_m.group(1) if val_m else ""

    print(f"    hidden fields: {list(hidden.keys())}")

    return {
        "html": html,
        "hidden": hidden,
        "position_best": position_best,
        "target_digit": target_digit,
        "class_info": class_info,
    }, target_digit


# ═══════════════════════════════════════════════════════════════════════════════
# Step 3: OCR（使用 blsfix ONNX 模型）
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


def _ocr_classification(raw_bytes: bytes, onnx_path: str, charset: list) -> str:
    import numpy as np
    from PIL import Image

    pil_img = Image.open(io.BytesIO(raw_bytes)).convert("L")
    arr = np.array(pil_img, dtype=np.float32)
    arr = arr[np.newaxis, np.newaxis, :, :]
    arr = arr.astype(np.float32)

    sess, input_name = _get_onnx_sess(onnx_path)
    output = sess.run(None, {input_name: arr})[0]

    seq_len = output.shape[0]
    preds = output.argmax(axis=2).squeeze()

    decoded = []
    prev = -1
    for idx in preds[:seq_len]:
        idx = int(idx)
        if idx == prev:
            continue
        if idx != 0 and idx - 1 < len(charset):
            decoded.append(charset[idx - 1])
        prev = idx

    return "".join(decoded).strip()


def step3(params: dict, target_digit: str | None, ocr_model_path: str) -> tuple[list, int]:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    position_best = params["position_best"]
    if not target_digit:
        print("    No target digit found, skipping OCR")
        return [], 0

    ocr_model_path = ocr_model_path or _ocr_model_path
    if not os.path.exists(ocr_model_path):
        print(f"    ERROR: ONNX model not found at {ocr_model_path}")
        return [], 0

    charset = _get_charset()

    # 按 position 排序，保留顺序用于打印
    sorted_positions = sorted(position_best.items(), key=lambda x: x[0])
    entries = [(pos_key, info) for pos_key, info in sorted_positions]

    def ocr_one(pos_key, info):
        src = info["src"]
        if not src.startswith("data:"):
            return None
        raw_data = decode_b64_img(src)
        digit = _ocr_classification(raw_data, ocr_model_path, charset)
        match = target_digit in digit
        return {"pos": pos_key, "info": info, "digit": digit, "match": match}

    print(f"    OCR {len(entries)} visible images (target: {target_digit}):")

    results = []
    t_start = time.perf_counter()

    # 并行推理，max_workers 设为图片数量（通常 9），避免过度调度
    with ThreadPoolExecutor(max_workers=min(len(entries), 16)) as pool:
        futures = {pool.submit(ocr_one, pk, info): pk for pk, info in entries}
        for future in as_completed(futures):
            pk = futures[future]
            try:
                res = future.result()
            except Exception as e:
                print(f"    [{pk[0]},{pk[1]}] error: {e}")
                results.append(None)
                continue
            if res is None:
                results.append(None)
                continue

            left, top = res["pos"]
            info = res["info"]
            digit = res["digit"]
            match = res["match"]
            tag = " ← TARGET" if match else ""
            print(
                f"    [{info['id']:15s}] pos=({left:3d},{top:3d}) z={info['_z']:5d} "
                f"digit={digit!r:6s}{tag}"
            )
            results.append(res)

    t_end = time.perf_counter()
    ocr_ms = round((t_end - t_start) * 1000)

    selected = [
        res["info"]["id"]
        for res in results
        if res and res["match"]
    ]

    print(f"    Selected: {len(selected)} → {selected}")
    print(f"    OCR 耗时: {ocr_ms} ms (并行, {len(entries)} 图)")
    return selected, ocr_ms


# ═══════════════════════════════════════════════════════════════════════════════
# Step 4: 提交验证码
# ═══════════════════════════════════════════════════════════════════════════════
def step4(session: BLSSession, selected_ids: list, params: dict) -> tuple[dict | None, str | None]:
    hidden = params["hidden"]
    post_data = {
        "SelectedImages": ",".join(selected_ids),
        "Id": html_module.unescape(hidden.get("Id", "")),
        "Captcha": html_module.unescape(hidden.get("Captcha", "")),
        "__RequestVerificationToken": hidden.get("__RequestVerificationToken", ""),
    }

    print(f"    SelectedImages: {post_data['SelectedImages']}")

    status, resp_text, _ = session.req(
        "/CHN/CaptchaPublic/SubmitCaptcha",
        method="POST",
        data=post_data,
        extra={
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Referer": f"{BASE_URL}/CHN/CaptchaPublic/GenerateCaptcha",
        },
        timeout=30,
    )

    print(f"    HTTP {status}: {resp_text[:300]}")
    if not resp_text.strip().startswith("{"):
        return None, f"非 JSON: {resp_text[:200]}"

    try:
        resp = json.loads(resp_text)
    except Exception:
        return None, f"JSON 解析失败: {resp_text[:200]}"

    if resp.get("success"):
        return {"success": True, "captchaData": resp.get("captcha", "")}, None
    else:
        err = resp.get("error", "Unknown")
        exceeded = resp.get("exceeded", False)
        print(f"    ✗ 失败: {err} (exceeded={exceeded})")
        return None, err


# ═══════════════════════════════════════════════════════════════════════════════
# Step 5: 发送 OTP
# ═══════════════════════════════════════════════════════════════════════════════
def step5_send_otp(session: BLSSession, email: str, captcha_data: str) -> dict:
    print(f"[5] POST /CHN/account/SendRegisterUserVerificationCode  →  {email}")
    params_qs = {
        "email": email,
        "mobile": "",
        "isMobileVerify": "False",
        "data": urllib.parse.quote(session.security_code),
        "captchaData": urllib.parse.quote(captcha_data),
        "captchaId": session.captcha_id or "",
    }
    qs = urllib.parse.urlencode(params_qs)
    status, text, _ = session.req(
        f"/CHN/account/SendRegisterUserVerificationCode?{qs}", "POST", None,
        extra={
            "RequestVerificationToken": session.verify_token,
            "X-Requested-With": "XMLHttpRequest",
            "Content-Length": "0",
        }
    )
    print(f"    HTTP {status}: {text[:400]}")
    try:
        return json.loads(text)
    except:
        return {"raw": text}


# ═══════════════════════════════════════════════════════════════════════════════
# Step 6: 完成注册
# ═══════════════════════════════════════════════════════════════════════════════
def get_dropdown_ids(session: BLSSession) -> tuple:
    text = session.get_html("/CHN/query/GetCountryList") if hasattr(session, 'get_html') else ""
    if not text:
        status, text, _ = session.req("/CHN/query/GetCountryList")
    cid = "5e44cd63-68f0-41f2-b708-0eb3bf9f4a72"
    try:
        for item in json.loads(text):
            if item.get("Code") == "CHN":
                cid = item.get("Id", cid)
    except:
        pass

    status2, text2, _ = session.req("/CHN/query/GetLOVIdNameList?lovType=BLS_PASSPORT_TYPE")
    pid = "0a152f62-b7b2-49ad-893e-b41b15e2bef3"
    try:
        items = json.loads(text2)
        if items:
            pid = items[0].get("Id", pid)
    except:
        pass
    return cid, pid


def step6_register(
    session: BLSSession,
    email_otp: str,
    captcha_data: str,
    enc_email: str,
    enc_mobile: str,
    sec_code: str,
    email: str,
) -> dict:
    print("[6] POST /CHN/Account/RegisterUser")
    country_id, pp_type_id = get_dropdown_ids(session)

    form = [
        ("Mode", "register"),
        ("SurName", SURNAME), ("FirstName", FIRST_NAME), ("LastName", LAST_NAME),
        ("DateOfBirth", DOB), ("ServerDateOfBirth", DOB),
        ("PassportNumber", PP_NO),
        ("PassportIssueDate", PP_ISSUE), ("ServerPassportIssueDate", PP_ISSUE),
        ("PassportExpiryDate", PP_EXPIRY), ("ServerPassportExpiryDate", PP_EXPIRY),
        ("BirthCountry", country_id), ("PassportType", pp_type_id),
        ("IssuePlace", ISSUE_PLACE), ("CountryOfResidence", country_id),
        ("CountryCode", "+86"), ("Mobile", ""), ("Email", email),
        ("EmailOtp", email_otp),
        ("CaptchaParam", ""), ("CaptchaData", captcha_data),
        ("CaptchaId", session.captcha_id or ""),
        ("EncryptedEmail", enc_email or ""), ("EncryptedMobile", enc_mobile or ""),
        ("SecurityCode", sec_code or ""), ("MobileVerificationEnabled", "False"),
    ]

    status, text, _ = session.req("/CHN/Account/RegisterUser", "POST", form,
        extra={"RequestVerificationToken": session.verify_token,
               "X-Requested-With": "XMLHttpRequest"})
    print(f"    HTTP {status}: {text[:400]}")
    try:
        return json.loads(text)
    except:
        return {"raw": text}


# ═══════════════════════════════════════════════════════════════════════════════
# 主流程
# ═══════════════════════════════════════════════════════════════════════════════
def solve_captcha_once(session: BLSSession, ocr_model_path: str) -> tuple[dict | None, str | None]:
    params, target_digit = step2(session)
    if not params:
        return None, "验证码页面获取失败"

    selected_ids, ocr_ms = step3(params, target_digit, ocr_model_path)
    if not selected_ids:
        return None, f"OCR 未匹配到任何图片（target={target_digit}）"

    result, err = step4(session, selected_ids, params)
    if result:
        return result, None
    return None, err


def main():
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║  BLS China 注册 — mail.tm 临时邮箱全自动版                             ║
║  https://spain.blscn.cn/CHN/account/RegisterUser                       ║
╠══════════════════════════════════════════════════════════════════════╣
║  OTP 邮件将通过 mail.tm 临时邮箱自动接收并提取验证码               ║
║  验证码算法: CSS z-index 层叠 + ONNX OCR（blsfix 模型）           ║
╚══════════════════════════════════════════════════════════════════════╝
    """)

    ocr_model_path = _ocr_model_path
    if os.path.exists(ocr_model_path):
        charset = _get_charset()
        print(f"OCR 模型: {ocr_model_path}")
        print(f"Charset: {charset}")
    else:
        print(f"WARNING: ONNX 模型未找到: {ocr_model_path}")
        print("请确保 blscn/ddddocr_model/blsfix_final_e25_s6000.onnx 存在")

    # ── 0. mailtm: 创建临时邮箱 ─────────────────────────────────────────────
    print("\n[0] mailtm: 创建临时邮箱账户...")
    mailtm_client = MailTmClient(proxy=PROXY, qps=MAILTM_QPS)
    try:
        email_addr, email_pwd = mailtm_client.create_random_account()
        print(f"    邮箱地址: {email_addr}")
        print(f"    邮箱密码: {email_pwd}")
    except MailTmError as e:
        print(f"    mailtm 创建失败: {e}")
        return

    # ── 1. BLS: 注册页面 ─────────────────────────────────────────────────────
    print("\n[1] BLS: 获取注册页面...")
    bls = BLSSession(proxy=PROXY)
    if not step1(bls):
        print("Step 1 失败，退出")
        return

    # ── 2-4. 验证码（支持重试）────────────────────────────────────────────────
    captcha_data = None
    for attempt in range(1, CAPTCHA_MAX_RETRY + 1):
        print(f"\n[2-4] 验证码尝试 {attempt}/{CAPTCHA_MAX_RETRY}...")
        result, err = solve_captcha_once(bls, ocr_model_path)
        if result:
            captcha_data = result["captchaData"]
            print(f"\n    CaptchaData: {captcha_data[:50]}...")
            break
        print(f"    验证码失败: {err}")
        if attempt < CAPTCHA_MAX_RETRY:
            print("    重新获取验证码页面...")
            time.sleep(2)

    if not captcha_data:
        print("\n验证码连续失败，请检查 ONNX 模型或手动处理")
        return

    # ── 5. 发送 OTP ──────────────────────────────────────────────────────────
    print(f"\n[5] 发送 OTP 到 {email_addr}...")
    otp_result = step5_send_otp(bls, email_addr, captcha_data)
    if not otp_result.get("success"):
        print(f"    OTP 发送失败: {otp_result.get('error', otp_result.get('err', 'unknown'))}")
        return

    print(f"    OTP 已发送")
    enc_email  = otp_result.get("encryptEmail", "")
    enc_mobile = otp_result.get("encryptMobile", "")
    sec_code   = otp_result.get("securityCode", "")

    # ── 6. mailtm: 等待邮件 ───────────────────────────────────────────────────
    print(f"\n[6] mailtm: 轮询等待邮件（from 含 '{EMAIL_FROM_KEY}'，超时 {EMAIL_TIMEOUT}s）...")
    msg = mailtm_client.get_latest_message(
        subject_contains=EMAIL_SUBJECT_KEY or None,
        from_contains=EMAIL_FROM_KEY,
        timeout=EMAIL_TIMEOUT,
        poll_interval=EMAIL_POLL_INTERVAL,
    )

    if not msg:
        print(f"    超时（{EMAIL_TIMEOUT}s）未收到邮件")
        print(f"    请手动查收: {email_addr}")
        return

    print(f"    收到邮件: {msg.get('subject', '')}")
    print(f"    发件人: {msg.get('from', {}).get('address', '')}")

    code = None
    for pat, desc in [
        (r"\b(\d{6})\b",               "6位纯数字"),
        (r"[Cc]ode[:\s]*(\d{6})",      "Code: 6位"),
        (r"[Vv]erification[:\s]*(\d+)", "Verification: N位"),
        (None, None),
    ]:
        code = mailtm_client.extract_verification_code(msg, pattern=pat, code_length=6)
        if code:
            print(f"    提取验证码（{desc}）: {code}")
            break

    if not code:
        print("    自动提取失败，打印邮件内容片段:")
        for key in ("intro", "html", "text"):
            val = msg.get(key, "")
            if val:
                snippet = (val[0] if isinstance(val, list) else val)[:400]
                print(f"      [{key}]: {snippet}")
        print(f"\n    请手动查收: {email_addr}")
        return

    # ── 7. 完成注册 ──────────────────────────────────────────────────────────
    result = step6_register(bls, code, captcha_data, enc_email, enc_mobile, sec_code, email_addr)
    print(f"\n注册结果: {json.dumps(result, ensure_ascii=False, indent=2)}")
    if result.get("success"):
        print("\n[OK] 注册成功!")
    else:
        print(f"\n[FAIL] 注册失败: {result.get('error', result.get('err', 'unknown'))}")


if __name__ == "__main__":
    main()
