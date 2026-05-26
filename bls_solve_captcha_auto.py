# -*- coding: utf-8 -*-
"""
BLS China 验证码求解器

算法核心:
1. GET /CHN/CaptchaPublic/GenerateCaptcha?data=<security_code>
   → HTML 里有 54 张 base64 图片和多个 box-label

2. CSS 中每个随机 class 决定 div 的 position/left/top/z-index

3. 9 个 grid 位置 (0,0) (0,110) (0,220)
   (110,0) (110,110) (110,220)
   (220,0) (220,110) (220,220)

4. 最终可见图片 = 该位置所有 div 中 z-index 最高的 display:none 除外

5. OCR 9 张可见图，找匹配数字，提交

模型: blscn/ocr_model/bls3_final_e37_s35000.onnx
     内置预处理 + CNN + LSTM + CTC + ArgMax
     charset: [' ','0','1','2','3','4','5','6','7','8','9']（blank=0，charset[idx-1]）
     验证集准确率: 99.69%
     ONNX session 全局单例，9 张图并行推理
"""
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import base64, gzip, json, os, re, threading, time, urllib.parse, requests

# ONNX Session 全局单例（进程内只加载一次，线程安全）
_onnx_sess_map: dict = {}   # onnx_path → (sess, input_name)
_onnx_lock = threading.Lock()


def _get_onnx_sess(onnx_path: str):
    """返回 (InferenceSession, input_name)，线程安全，惰性加载。"""
    if onnx_path not in _onnx_sess_map:
        with _onnx_lock:
            if onnx_path not in _onnx_sess_map:
                import onnxruntime as ort
                sess = ort.InferenceSession(onnx_path)
                inp_name = sess.get_inputs()[0].name
                _onnx_sess_map[onnx_path] = (sess, inp_name)
    return _onnx_sess_map[onnx_path]

# kuaidaili 代理模块
_tools_dir = os.path.join(os.path.dirname(__file__), '..', 'tools')
if _tools_dir not in sys.path:
    sys.path.insert(0, _tools_dir)
from proxies import kuaidaili

# ─────────────────────────────────────────────────────────────────
# 配置
# ─────────────────────────────────────────────────────────────────
TARGET_HOST = "spain.blscn.cn"
BASE_URL    = f"https://{TARGET_HOST}"

# 模型路径
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

# 默认 charset（当 JSON 不存在时）
_default_charset = [' ', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']


# ─────────────────────────────────────────────────────────────────
# HTTP Session
# ─────────────────────────────────────────────────────────────────

class BLSSession:
    def __init__(self, proxy=None):
        self._proxy = proxy   # 保存原始值供外部查看
        self._proxy_auth = None
        if proxy:
            if isinstance(proxy, dict):
                # kuaidaili.get_proxy() 返回 {"http": "...", "https": "..."}
                self._proxy_url = proxy.get("http", proxy.get("https", ""))
            else:
                # 字符串格式 http://user:pass@host:port
                self._proxy_url = proxy
                m = re.match(r'http://([^:@]+):([^@]+)@(.+)', proxy)
                if m:
                    self._proxy_url = f"http://{m.group(3)}"
                    self._proxy_auth = requests.auth.HTTPProxyAuth(m.group(1), m.group(2))
        else:
            self._proxy_url = None
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                         "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept": "*/*",
        })
        self.security_code = ""
        self.verify_token = ""

    def _build_proxies(self):
        return {"http": self._proxy_url, "https": self._proxy_url} if self._proxy_url else {}

    def req(self, path, method="GET", data=None, extra=None, timeout=20):
        url = BASE_URL + path
        h = dict(self.session.headers)
        if extra:
            h.update(extra)
        if method == "POST" and data:
            if "Content-Type" not in h:
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
            return resp.status_code, text, dict(resp.headers)
        except Exception as e:
            return 0, str(e), {}


# ─────────────────────────────────────────────────────────────────
# Step 1: 获取注册页面 → SecurityCode
# ─────────────────────────────────────────────────────────────────

def step1(session):
    status, html, _ = session.req("/CHN/account/RegisterUser")
    if status != 200:
        return False, f"HTTP {status}"

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

    return bool(session.security_code), None


# ─────────────────────────────────────────────────────────────────
# Step 2: 获取验证码页面，解析完整结构
# ─────────────────────────────────────────────────────────────────

def step2(session):
    url = f"/CHN/CaptchaPublic/GenerateCaptcha?data={urllib.parse.quote(session.security_code)}"
    print(f"验证码链接URL: {BASE_URL + url}")
    status, html, _ = session.req(url)
    if status != 200:
        return None, f"HTTP {status}"

    # ── 解析 CSS ──
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

    print(f"  CSS classes: {len(class_info)}")
    disp_none_count = sum(1 for v in class_info.values() if v.get('display') == 'none')
    print(f"  CSS display:none classes: {disp_none_count}")

    # ── 收集 show()/hide() 调用 ──
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

    print(f"  show() calls: {len(show_ids)}, hide() calls: {len(hide_ids)}")

    # ── 解析 box-label ──
    label_to_digit = {}
    for m in re.finditer(
        r"<div[^>]+class=['\"][^'\"]*box-label[^'\"]*['\"][^>]*id=['\"]([^'\"]+)['\"][^>]*>([^<]+)</div>",
        html,
    ):
        div_id, text = m.group(1), m.group(2)
        digit_m = re.search(r'number (\d+)', text)
        if digit_m:
            label_to_digit[div_id] = digit_m.group(1)

    if not label_to_digit:
        for m in re.finditer(
            r"<div[^>]+id=['\"]([^'\"]+)['\"][^>]*class=['\"][^'\"]*box-label[^'\"]*['\"][^>]*>([^<]+)</div>",
            html,
        ):
            div_id, text = m.group(1), m.group(2)
            digit_m = re.search(r'number (\d+)', text)
            if digit_m:
                label_to_digit[div_id] = digit_m.group(1)

    print(f"  box-labels: {len(label_to_digit)}")

    # ── 解析 img 父 div ──
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

    print(f"  img entries: {len(img_entries)}")

    # ── 确定每个 div 的 display 状态 ──
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
    hidden_count = sum(1 for v in div_display.values() if not v)
    print(f"  div visibility: {visible_count} visible, {hidden_count} hidden")

    # ── 对每个位置，找 z-index 最高的可见 div ──
    GRID_POSITIONS = [
        (0,0),(0,110),(0,220),
        (110,0),(110,110),(110,220),
        (220,0),(220,110),(220,220),
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
                if info['top'] is not None: top  = info['top']
                if info['z'] is not None:
                    z = max(z or 0, info['z'])

        if left is None or top is None:
            continue

        key = (left, top)
        is_visible = div_display.get(div_id, True)
        if not is_visible:
            continue

        if key not in position_best or (z and z > (position_best[key].get('_z') or 0)):
            position_best[key] = {
                "id": div_id,
                "src": entry["src"],
                "_z": z,
            }

    print(f"  visible positions: {len(position_best)}")

    # ── 提取目标数字 ──
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

        hidden = any(
            class_info.get(c, {}).get('display') == 'none'
            for c in cls_list
        )
        if hidden:
            continue

        z = 0
        for c in cls_list:
            if c in class_info and class_info[c].get('z') is not None:
                z = max(z, class_info[c]['z'])

        label_entries.append({"digit": digit, "z": z})

    if not label_entries:
        target_digit = None
        print(f"  box-labels: 0, no target digit")
    else:
        label_entries.sort(key=lambda x: x["z"], reverse=True)
        top_label = label_entries[0]
        target_digit = top_label["digit"]
        print(f"  box-labels: {len(label_entries)} visible")
        print(f"  target digit: {target_digit} (z={top_label['z']})")

    # ── 提取 hidden fields ──
    hidden = {}
    for inp in re.findall(r'<input[^>]+type="hidden"[^>]+>', html, re.IGNORECASE):
        name_m = re.search(r'name=["\']?([^"\'>\s]+)["\']?', inp)
        val_m  = re.search(r'value=["\']([^"\']*)["\']', inp)
        id_m   = re.search(r'id=["\']?([^"\'>\s]+)["\']?', inp)
        name = name_m.group(1) if name_m else (id_m.group(1) if id_m else "")
        if name:
            hidden[name] = val_m.group(1) if val_m else ""

    print(f"  hidden fields: {list(hidden.keys())}")

    return {
        "html": html,
        "hidden": hidden,
        "position_best": position_best,
        "target_digit": target_digit,
        "class_info": class_info,
    }, target_digit, None


# ─────────────────────────────────────────────────────────────────
# Step 3: OCR（bls3_final_e37_s35000.onnx）
# ─────────────────────────────────────────────────────────────────

def _get_charset():
    """从 bls3_meta.json 加载 charset，否则使用默认值"""
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
    """解码 base64 图片，处理 HTML 实体编码"""
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
    """
    bls3_final_e37_s35000.onnx：内置预处理 + CNN + LSTM + CTC + ArgMax。
    输入原图（任意高度，0-255），模型内部完成 invert/resize64/normalize。
    输出直接是 charset 索引序列（ArgMax 内置）。

    charset: [' ','0','1','2','3','4','5','6','7','8','9']
    blank=0，idx=1→'0'，idx=2→'1'，...，需要 charset[idx-1]
    """
    import numpy as np
    from PIL import Image
    import io

    # 直接传原图（灰度），预处理由模型内部完成
    pil_img = Image.open(io.BytesIO(raw_bytes)).convert("L")
    arr = np.array(pil_img, dtype=np.float32)
    arr = arr[np.newaxis, np.newaxis, :, :]

    # 使用全局单例 session
    sess, input_name = _get_onnx_sess(_ocr_model_path)
    output = sess.run(None, {input_name: arr})[0]

    preds = output.squeeze() if output.ndim > 1 else output

    # CTC collapse + charset 映射
    decoded = []
    prev = -1
    for idx in preds:
        idx = int(idx)
        if idx == prev:
            continue        # CTC collapse: 跳过连续重复
        if idx == 0:
            prev = idx
            continue        # CTC blank: 跳过
        if idx - 1 < len(charset):
            ch = charset[idx - 1]
            if ch and ch != ' ':
                decoded.append(ch)
        prev = idx

    return "".join(decoded).strip()


def step3(params, target_digit: str):
    from concurrent.futures import ThreadPoolExecutor, as_completed

    position_best = params["position_best"]
    if not target_digit:
        print("  No target digit found")
        return [], 0

    if not os.path.exists(_ocr_model_path):
        print(f"  ERROR: model not found at {_ocr_model_path}")
        return [], 0

    charset = _get_charset()
    sorted_positions = sorted(position_best.items(), key=lambda x: x[0])
    entries = [(pk, info) for pk, info in sorted_positions]

    # 预热 ONNX session（首次推理有冷启动开销，单独计时）
    _get_onnx_sess(_ocr_model_path)  # 确保 session 已加载（不计入图片耗时）

    def ocr_one(pk, info):
        src = info["src"]
        if not src.startswith("data:"):
            return None
        raw_data = decode_b64_img(src)
        t0 = time.perf_counter()
        digit = _ocr_classification(raw_data, charset)
        ms = round((time.perf_counter() - t0) * 1000)
        match = target_digit in digit
        return {"pos": pk, "info": info, "digit": digit, "match": match, "ms": ms}

    print(f"\n  OCR {len(entries)} visible images (target: {target_digit}):")

    results = []
    t_start = time.perf_counter()

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
            results.append(res)

    t_end = time.perf_counter()
    total_ms = round((t_end - t_start) * 1000)

    # 按位置顺序打印
    results.sort(key=lambda r: (r["pos"] if r else ((999, 999))))
    for res in results:
        if res is None:
            continue
        left, top = res["pos"]
        info = res["info"]
        digit = res["digit"]
        match = res["match"]
        ms = res["ms"]
        tag = " ← TARGET" if match else ""
        print(
            f"    [{info['id']:15s}] pos=({left:3d},{top:3d}) z={info['_z']:5d} "
            f"digit={digit!r:6s}{tag}  (+{ms} ms)"
        )

    selected = [res["info"]["id"] for res in results if res and res["match"]]
    print(f"\n  Selected: {len(selected)} → {selected}")
    print(f"  OCR 耗时: {total_ms} ms (并行, {len(entries)} 图)")
    return selected, total_ms


# ─────────────────────────────────────────────────────────────────
# Step 4: 提交验证码
# ─────────────────────────────────────────────────────────────────

def step4(session, selected_ids, hidden):
    import html as html_module

    post_data = {
        "SelectedImages": ",".join(selected_ids),
        "Id": html_module.unescape(hidden.get("Id", "")),
        "Captcha": html_module.unescape(hidden.get("Captcha", "")),
        "__RequestVerificationToken": hidden.get("__RequestVerificationToken", ""),
    }

    print(f"\n  >>> [STEP4] 提交验证码数据:")
    print(f"  POST URL: {BASE_URL}/CHN/CaptchaPublic/SubmitCaptcha")
    print(f"  SelectedImages: {post_data['SelectedImages']}")
    print(f"  Id: {post_data['Id']}")
    print(f"  Captcha: {post_data['Captcha']}")
    print(f"  __RequestVerificationToken: {post_data['__RequestVerificationToken']}")

    status, resp_text, hdr = session.req(
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

    print(f"  HTTP {status}: {resp_text[:300]}")

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
        print(f"  ✗ 失败: {err} (exceeded={exceeded})")
        return None, err


# ─────────────────────────────────────────────────────────────────
# 主函数
# ─────────────────────────────────────────────────────────────────

def solve_captcha(proxy=None, max_retry=1):
    print("=" * 60)
    print("BLS China 验证码求解器（bls3_final_e37 ONNX 模型）")
    print(f"Model: {_ocr_model_path}")
    charset = _get_charset()
    print(f"Charset: {charset}")
    print("=" * 60)

    for attempt in range(1, max_retry + 1):
        print(f"\n── 尝试 {attempt}/{max_retry} ──")

        # 每次重试从快代理获取新 IP
        if proxy is None:
            proxy = kuaidaili.get_proxy()
            print(f"  [代理] 从快代理获取新 IP: {proxy.get('http', 'N/A').split('@')[1] if proxy else '获取失败'}")

        session = BLSSession(proxy=proxy)

        print("\n[1/4] 获取注册页面...")
        ok, err = step1(session)
        if not ok:
            return {"success": False, "error": f"注册页面失败: {err}"}
        print(f"  SecurityCode: {session.security_code[:40]}...")

        print("\n[2/4] 获取验证码页面...")
        params, target_digit, err = step2(session)
        if not params:
            return {"success": False, "error": f"验证码页面失败: {err}"}

        print("\n[3/4] OCR 识别...")
        selected_ids, ocr_ms = step3(params, target_digit)
        if not selected_ids:
            print("  没有匹配到图片，重试...")
            time.sleep(2)
            continue

        print("\n[4/4] 提交验证码...")
        result, err = step4(session, selected_ids, params["hidden"])

        if result:
            return {
                "success":      True,
                "captchaData": result["captchaData"],
                "captchaId":   params["hidden"].get("Id", ""),
                "token":       params["hidden"].get("__RequestVerificationToken", ""),
                "securityCode": session.security_code,
                "session":     session,
                "ocr_ms":      ocr_ms,
            }

        print(f"  失败: {err}，重试...")
        time.sleep(2)

    return {"success": False, "error": "超过最大重试次数"}


if __name__ == "__main__":
    print("从快代理获取代理 IP...")
    proxy = kuaidaili.get_proxy()
    print(f"代理: {proxy.get('http', 'N/A')}")
    result = solve_captcha(proxy=proxy)
    if result["success"]:
        print(f"\n最终结果:")
        print(f"  CaptchaData: {result['captchaData'][:60]}...")
        print(f"  CaptchaId:   {result.get('captchaId','')[:40]}...")
        print(f"  OCR 耗时:    {result.get('ocr_ms', 0)} ms")
    else:
        print(f"\n失败: {result['error']}")
