# ocr.py
# 创建日期: 2026-05-29 09:52:00（北京时间 UTC+8）
# 更新日期: 2026-05-29 10:08:00（北京时间 UTC+8）
# 使用模型: Claude Opus 4 (claude-opus-4-7-high)
# 用途说明: OCR 数字识别模块

"""
OCR 识别模块
============

使用 ONNX 模型识别验证码图片中的数字。
"""

import base64
import io
import json
import os
import random
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# 确保 stdout 支持 UTF-8
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import numpy as np
from PIL import Image

from .config import OCR_MODEL_PATH, OCR_META_PATH, DEFAULT_CHARSET


# ═══════════════════════════════════════════════════════════════════════════════
# 线程安全：ONNX Session 全局单例
# ═══════════════════════════════════════════════════════════════════════════════
_onnx_sess_map: dict = {}
_onnx_lock = threading.Lock()


def _get_onnx_sess(onnx_path: str):
    """获取或创建 ONNX Session（线程安全）"""
    if onnx_path not in _onnx_sess_map:
        with _onnx_lock:
            if onnx_path not in _onnx_sess_map:
                import onnxruntime as ort
                sess = ort.InferenceSession(onnx_path)
                _onnx_sess_map[onnx_path] = sess
    return _onnx_sess_map[onnx_path]


# ═══════════════════════════════════════════════════════════════════════════════
# 工具函数
# ═══════════════════════════════════════════════════════════════════════════════

def get_charset() -> list:
    """获取字符集（公共接口）"""
    return _get_charset()


def _get_charset() -> list:
    """获取字符集"""
    if os.path.exists(OCR_META_PATH):
        for enc in ('utf-8', 'gbk', 'gb2312'):
            try:
                with open(OCR_META_PATH, 'r', encoding=enc) as f:
                    data = json.load(f)
                return data.get('charset', DEFAULT_CHARSET)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
    return DEFAULT_CHARSET


def decode_b64_img(src: str) -> bytes:
    """解码 Base64 图片数据"""
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


# ═══════════════════════════════════════════════════════════════════════════════
# OCR 核心
# ═══════════════════════════════════════════════════════════════════════════════

def _ocr_classification(raw_bytes: bytes, charset: list) -> str:
    """
    使用 ONNX 模型对图片进行分类识别

    Args:
        raw_bytes: 图片二进制数据
        charset: 字符集

    Returns:
        识别的数字字符串
    """
    pil_img = Image.open(io.BytesIO(raw_bytes)).convert("L")
    arr = np.array(pil_img, dtype=np.float32)
    arr = arr[np.newaxis, np.newaxis, :, :]

    sess = _get_onnx_sess(OCR_MODEL_PATH)
    input_name = sess.get_inputs()[0].name
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


def ocr_images(
    position_best: dict,
    target_digit: Optional[str],
) -> tuple[list[str], int]:
    """
    并行 OCR 识别所有验证码图片

    Args:
        position_best: 位置到最佳图片的映射 {(left, top): {"id": str, "src": str, "_z": int}}
        target_digit: 目标数字

    Returns:
        (选中的图片ID列表, OCR耗时ms)
    """
    if not target_digit:
        return [], 0

    if not os.path.exists(OCR_MODEL_PATH):
        return [], 0

    charset = _get_charset()
    _get_onnx_sess(OCR_MODEL_PATH)

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

    # 并行识别（OCR 图片数量较少，使用 16 线程）
    max_workers = min(len(entries), 16)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(ocr_one, pk, info): pk for pk, info in entries}
        for future in as_completed(futures):
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
