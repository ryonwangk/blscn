# steps.py
# 创建日期: 2026-05-29 09:55:00（北京时间 UTC+8）
# 更新日期: 2026-05-29 10:08:00（北京时间 UTC+8）
# 使用模型: Claude Opus 4 (claude-opus-4-7-high)
# 用途说明: BLS 注册流程的各个步骤

"""
BLS 注册流程步骤
================

包含注册流程中的每个具体步骤：
- Step1: 获取注册页面
- Step2: 获取国家信息、验证码页面
- Step3: OCR 识别验证码
- Step4: 提交验证码
- Step5: 发送 OTP
- Step6: 等待 OTP 邮件
- Step7: 提交注册
- Step8: 等待注册成功邮件
"""

import html as html_module
import json
import re
import sys
import time

# 确保 stdout 支持 UTF-8
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from typing import Optional, Tuple

import requests
from bs4 import BeautifulSoup

from .config import BASE_URL, EMAIL_FROM_KEY, EMAIL_TIMEOUT, EMAIL_TIMEOUT_FINAL
from .session import BLSSession


# ═══════════════════════════════════════════════════════════════════════════════
# 工具函数
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
    # 备用：直接搜索 CaptchaId
    if "CaptchaId" not in result:
        m = re.search(r'<input[^>]+id=["\']CaptchaId["\'][^>]+value=["\']([^"\']+)["\']', html)
        if m:
            result["CaptchaId"] = m.group(1)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Step 1: 获取注册页面
# ═══════════════════════════════════════════════════════════════════════════════

def step1_get_register_page(session: BLSSession, max_retry: int = 3) -> bool:
    """获取注册页面，提取 SecurityCode、Token、CaptchaId"""
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
# Step 2: 获取验证码页面（CSS 解析）
# ═══════════════════════════════════════════════════════════════════════════════

def step2_get_captcha(session: BLSSession) -> Tuple[dict, Optional[str]]:
    """
    获取验证码页面，解析 CSS 层叠规则

    Returns:
        (params dict, target_digit)
    """
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

    # 备用：正则解析
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

    # 统计隐藏图片
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

        if key not in position_best or (z and z > (position_best[key].get('_z') or 0)):
            position_best[key] = {"id": div_id, "src": entry["src"], "_z": z}

    # 打印每个位置的情况
    print(f"    [Step2] 每个位置的图片情况:")
    for pos in GRID_POSITIONS:
        imgs = [e for e in img_entries if e.get('classes')]
        filtered = []
        for e in img_entries:
            classes = e.get('classes', [])
            left2 = top2 = z2 = None
            for c in classes:
                if c in class_info:
                    info = class_info[c]
                    if info['left'] is not None: left2 = info['left']
                    if info['top']  is not None: top2 = info['top']
                    if info['z'] is not None:
                        z2 = max(z2 or 0, info['z'])
            if left2 == pos[0] and top2 == pos[1]:
                filtered.append({"id": e['id'], "z": z2 or 0})

        if filtered:
            filtered.sort(key=lambda x: x['z'], reverse=True)
            best = filtered[0]
            print(f"    [Step2]   {pos}: {len(filtered)}张, 最佳={best['id']}(z={best['z']})")
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
# Step 3: 提交验证码
# ═══════════════════════════════════════════════════════════════════════════════

def step3_submit_captcha(
    session: BLSSession,
    selected_ids: list,
    hidden: dict,
) -> Tuple[Optional[dict], Optional[str]]:
    """提交选中的验证码图片"""
    h_id = hidden.get("Id", "")
    h_cap = hidden.get("Captcha", "")
    print(f"    [Step4] Submitting: SelectedImages={','.join(selected_ids)} count={len(selected_ids)}")

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
# Step 4: 发送 OTP
# ═══════════════════════════════════════════════════════════════════════════════

def step4_send_otp(
    session: BLSSession,
    email: str,
    mobile: str,
    captcha_data: str,
    captcha_id: str,
    max_retries: int = 3,
) -> Tuple[dict, Optional[str]]:
    """发送 OTP 验证码"""
    print(f"\n    [Step5] email={email}, mobile={mobile}")
    print(f"    [Step5] captchaId={captcha_id}")
    print(f"    [Step5] session.captcha_id={session.captcha_id}")
    print(f"    [Step5] data (len={len(session.security_code)}): {session.security_code[:50]}...")
    print(f"    [Step5] captchaData (len={len(captcha_data)}): {captcha_data[:50]}...")

    for attempt in range(1, max_retries + 1):
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

        headers = {
            "Accept": "*/*",
            "RequestVerificationToken": session.verify_token,
            "X-Requested-With": "XMLHttpRequest",
            "Origin": BASE_URL,
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": BASE_URL + "/CHN/account/RegisterUser",
            "priority": "u=1, i",
        }

        url = f"{BASE_URL}/CHN/account/SendRegisterUserVerificationCode?{query_string}"

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

        if status == 429:
            print(f"    [Step5] 尝试 {attempt}: HTTP 429 Too Many Requests")
            if attempt < max_retries:
                time.sleep(3)
                continue
            return {}, "HTTP 429 Too Many Requests"

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
# Step 5: 获取国家信息
# ═══════════════════════════════════════════════════════════════════════════════

def step5_get_country_ids(session: BLSSession) -> Tuple[str, str]:
    """获取国家 ID 和护照类型 ID"""
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
# Step 6: 提交注册
# ═══════════════════════════════════════════════════════════════════════════════

def step6_do_register(
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
    """提交注册表单"""
    # 支持 date 对象或字符串格式的日期
    def to_date_str(val):
        if hasattr(val, 'strftime'):
            return val.strftime("%Y-%m-%d")
        return str(val)

    dob_str        = to_date_str(person["dob"])
    pp_issue_str   = to_date_str(person["pp_issue"])
    pp_expiry_str  = to_date_str(person["pp_expiry"])

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
            "RequestVerificationToken": session.verify_token,
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
# Step 7: 等待 OTP 邮件
# ═══════════════════════════════════════════════════════════════════════════════

def step7_wait_otp_email(
    mail_client,
    timeout: float = EMAIL_TIMEOUT,
) -> Tuple[Optional[str], Optional[dict]]:
    """等待 OTP 验证码邮件"""
    print(f"    [Step6] 等待邮件 from 包含 '{EMAIL_FROM_KEY}'...")

    deadline = time.time() + timeout
    last_check = 0
    seen_ids: set = set()

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

                f_ok = EMAIL_FROM_KEY.lower() in sender.lower()
                print(f"    [Step6]   邮件: from={sender}, subject={subject[:50]}, 匹配={f_ok}")

                if f_ok:
                    full_msg = mail_client.get_message(msg["id"])
                    print(f"    [Step6]   获取邮件详情成功，开始提取验证码...")

                    for pat, desc in [
                        (r"\b(\d{6})\b",                     "6位纯数字"),
                        (r"[Cc]ode[:\s]*(\d{6})",             "Code: 6位"),
                        (r"[Vv]erification[:\s]*(\d{6})",    "Verification: 6位"),
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

        remaining = deadline - time.time()
        if remaining <= 0:
            break
        time.sleep(min(5, remaining))

    print(f"    [Step6] 超时，未收到邮件")
    return None, None


# ═══════════════════════════════════════════════════════════════════════════════
# Step 8: 等待注册成功邮件
# ═══════════════════════════════════════════════════════════════════════════════

def step8_wait_success_email(
    mail_client,
    timeout: float = EMAIL_TIMEOUT_FINAL,
) -> Tuple[Optional[str], Optional[dict]]:
    """等待注册成功邮件，提取临时密码"""
    print(f"    [Step9] 等待注册成功邮件 from 包含 '{EMAIL_FROM_KEY}'...")

    deadline = time.time() + timeout
    seen_ids: set = set()

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

                f_ok = EMAIL_FROM_KEY.lower() in sender.lower()
                print(f"    [Step9]   邮件: from={sender}, subject={subject[:50]}, 匹配={f_ok}")

                if f_ok:
                    full_msg = mail_client.get_message(msg["id"])
                    print(f"    [Step9]   获取邮件详情成功，开始提取密码...")

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
