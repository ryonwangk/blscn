# register.py
# 创建日期: 2026-05-29 09:58:00（北京时间 UTC+8）
# 更新日期: 2026-05-29 10:08:00（北京时间 UTC+8）
# 使用模型: Claude Opus 4 (claude-opus-4-7-high)
# 用途说明: BLS 注册主流程整合

"""
BLS 注册主流程
==============

整合所有步骤，执行完整的注册流程。
"""

import os
import sys
import threading
import time
from datetime import datetime
from typing import Optional

# 确保 stdout 支持 UTF-8
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# 添加父目录到 sys.path
_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_grand_parent = os.path.dirname(_parent_dir)
if _grand_parent not in sys.path:
    sys.path.insert(0, _grand_parent)

from tools.mail.mailtm import MailTmClient, MailTmError

from .config import (
    BASE_URL, CAPTCHA_MAX_RETRY, CSV_FILE_PATH, EMAIL_FROM_KEY,
    PROXY_MODE, REQABLE_PROXY_HOST, REQABLE_PROXY_PORT,
)
from .models import RegisterResult, PersonInfo
from .session import BLSSession
from .steps import (
    step1_get_register_page,
    step2_get_captcha,
    step3_submit_captcha,
    step4_send_otp,
    step5_get_country_ids,
    step6_do_register,
    step7_wait_otp_email,
    step8_wait_success_email,
)
from .ocr import ocr_images


# ═══════════════════════════════════════════════════════════════════════════════
# 代理获取
# ═══════════════════════════════════════════════════════════════════════════════

def get_proxy_info(ip_port: str) -> tuple[Optional[str], Optional[str]]:
    """
    获取代理 IP 的详细信息

    Args:
        ip_port: 代理 URL 或 IP:端口 字符串

    Returns:
        (proxy_info_str, error_str)
    """
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    try:
        from tools.proxies.ip_info import get_ip_info, format_ip_info

        # 从 URL 中提取 IP:端口（处理带认证的 URL）
        # 格式: http://user:pass@1.2.3.4:8080 或 1.2.3.4:8080
        clean_ip = ip_port
        if "@" in ip_port:
            clean_ip = ip_port.split("@")[-1]
        clean_ip = clean_ip.rstrip("/")

        info = get_ip_info(clean_ip)
        if info.get("ok"):
            return format_ip_info(info), None
        return "", info.get("error", "未知错误")
    except Exception as e:
        return None, str(e)


def get_proxy() -> tuple[Optional[dict], str]:
    """
    获取代理配置

    Returns:
        (proxy_dict, proxy_url_str) 或 (None, error_str)
    """
    if PROXY_MODE == "none":
        return None, "直连"

    elif PROXY_MODE == "reqable":
        reqable_proxy = f"http://{REQABLE_PROXY_HOST}:{REQABLE_PROXY_PORT}"
        proxy = {"http": reqable_proxy, "https": reqable_proxy}
        return proxy, reqable_proxy

    elif PROXY_MODE == "kuaidaili":
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
        try:
            from tools.proxies import kuaidaili
            proxy = kuaidaili.get_proxy()
            if not proxy:
                return None, "快代理返回 None"
            return proxy, proxy.get("http", "")
        except Exception as e:
            return None, str(e)

    return None, f"未知的 PROXY_MODE: {PROXY_MODE}"


# ═══════════════════════════════════════════════════════════════════════════════
# 注册主流程
# ═══════════════════════════════════════════════════════════════════════════════

def solve_captcha_once(session: BLSSession) -> tuple[Optional[dict], Optional[str]]:
    """执行一次验证码识别+提交"""
    print(f"[Step3] 获取验证码图片...")
    params, target_digit = step2_get_captcha(session)
    if not params:
        return None, "验证码页面获取失败"
    print(f"[Step3] 完成: 目标数字={target_digit}")

    print(f"[Step3] OCR 识别...")
    selected_ids, ocr_ms = ocr_images(params["position_best"], target_digit)
    if not selected_ids:
        return None, f"OCR 未匹配到图片（target={target_digit}）"
    print(f"[Step3] 完成: 选中 {len(selected_ids)} 个, 耗时 {ocr_ms}ms")

    print(f"[Step3->Step4] 等待 5s... 模拟识别点选")
    time.sleep(5)

    print(f"[Step4] 提交验证码...")
    result, err = step3_submit_captcha(session, selected_ids, params["hidden"])
    if result:
        print(f"[Step4] 完成: captchaData={result.get('captchaData', '')[:30]}..., captchaId={result.get('captchaId', '')[:30] if result.get('captchaId') else 'N/A'}...")
        return result, None
    print(f"[Step4] 失败: {err}")
    return None, err


def register_one_task(task_id: int, person: PersonInfo) -> RegisterResult:
    """
    执行一次完整的注册流程

    Args:
        task_id: 任务 ID
        person: 人物信息

    Returns:
        RegisterResult: 注册结果
    """
    today_str = time.strftime("%Y-%m-%d %H:%M:%S")

    def log(msg: str):
        thread_name = threading.current_thread().name
        print(f"[{today_str}] [Task-{task_id}] {msg}")

    result = RegisterResult(task_id=task_id, person=person)

    # ── 获取代理 ───────────────────────────────────────────────────────────
    proxy, proxy_str = get_proxy()
    if proxy_str == "直连":
        result.proxy = "直连"
        log("[代理] 直连模式")
    elif proxy is None:
        result.error = f"代理获取失败: {proxy_str}"
        log(f"✗ {result.error}")
        return result
    else:
        result.proxy = proxy_str
        log(f"[代理] 使用代理: {result.proxy}")

        # 查询代理 IP 信息
        log("[代理] 查询 IP 信息...")
        ip_info, ip_err = get_proxy_info(proxy_str)
        if ip_info:
            result.proxy_info = ip_info
            log(f"[代理] IP 信息: {result.proxy_info}")
        else:
            log(f"[代理] IP 信息查询失败: {ip_err}")

    # ── 创建临时邮箱 ───────────────────────────────────────────────────────
    mail_client = MailTmClient(proxy="", qps=8)
    try:
        email_addr, email_pwd = mail_client.create_random_account()
        result.email = email_addr
        result.email_pwd = email_pwd
        person.email = email_addr
        person.email_pwd = email_pwd
        log(f"邮箱: {email_addr}")
        log(f"邮箱密码: {email_pwd}")
    except MailTmError as e:
        result.error = f"mail.tm 创建失败: {e}"
        log(f"✗ {result.error}")
        return result

    # ── Step 1: 获取注册页面 ───────────────────────────────────────────────
    bls = BLSSession(proxy=proxy)
    log("[Step1] 获取注册页面...")
    if not step1_get_register_page(bls):
        result.error = "注册页面获取失败"
        log(f"✗ {result.error}")
        return result
    log(f"[Step1] 完成: SecurityCode={bls.security_code[:30]}..., Token={bls.verify_token[:30]}...")

    # ── Step 2: 获取国家信息 ───────────────────────────────────────────────
    log("[Step2] 获取国家信息...")
    country_id, passport_type_id = step5_get_country_ids(bls)
    log(f"[Step2] 完成: countryId={country_id}, passportTypeId={passport_type_id}")

    # ── Step 3: 验证码 ─────────────────────────────────────────────────────
    log("[Step2->Step3] 等待 5s... 模拟填写信息页面")
    time.sleep(5)

    captcha_result = None
    captcha_error = None
    retry_count = 0

    for attempt in range(CAPTCHA_MAX_RETRY + 1):
        captcha_result, captcha_error = solve_captcha_once(bls)
        if captcha_result:
            break
        retry_count += 1
        if attempt < CAPTCHA_MAX_RETRY:
            log(f"[Step3] 验证码尝试 {attempt + 1}/{CAPTCHA_MAX_RETRY + 1} 失败: {captcha_error}，重试...")
            time.sleep(3)

    if not captcha_result:
        result.error = f"验证码失败: {captcha_error}"
        log(f"✗ {result.error}")
        return result

    captcha_data = captcha_result.get("captchaData", "")
    new_captcha_id = captcha_result.get("captchaId", "")
    result.otp = new_captcha_id

    log(f"[Step3] 完成: CaptchaData={captcha_data[:30]}...")

    # ── Step 4: 发送 OTP ─────────────────────────────────────────────────
    log("[Step3->Step4] 等待 5s...")
    time.sleep(5)

    log(f"[Step4] 发送 OTP (尝试 1/2)...")
    enc_email, enc_mobile = "", ""
    for retry in range(2):
        otp_resp, otp_err = step4_send_otp(
            bls,
            result.email,
            person.mobile,
            captcha_data,
            bls.captcha_id,  # 必须使用 Step1 获取的原始 captcha_id，不是验证码提交后的 new_captcha_id
        )
        if otp_resp.get("success"):
            enc_email = otp_resp.get("encryptEmail", "")
            enc_mobile = otp_resp.get("encryptMobile", "")
            log(f"[Step4] 完成: encryptEmail={enc_email[:30]}...")
            break
        if retry == 0:
            log(f"[Step4] 发送 OTP 失败: {otp_err}，重试...")
            time.sleep(2)

    if not enc_email:
        result.error = f"OTP 发送失败: {otp_err}"
        log(f"✗ {result.error}")
        return result

    # ── Step 5: 等待 OTP 邮件 ─────────────────────────────────────────────
    log("[Step4->Step5] 等待 5s...")
    time.sleep(5)

    log("[Step5] 等待 OTP 邮件...")
    otp_code, _ = step7_wait_otp_email(mail_client)
    if not otp_code:
        result.error = "等待 OTP 超时"
        log(f"✗ {result.error}")
        return result
    result.otp = otp_code
    log(f"[Step5] 完成: OTP={otp_code}")

    # ── Step 6: 提交注册 ─────────────────────────────────────────────────
    log("[Step5->Step6] 等待 3s... 模拟填写OTP")
    time.sleep(3)

    person_dict = person.to_dict()
    log(f"[Step6] 提交注册: {person.surname} {person.first_name}, 手机={person.mobile}")
    reg_resp = step6_do_register(
        bls,
        result.email,
        otp_code,
        captcha_data,
        enc_email,
        enc_mobile,
        country_id,
        passport_type_id,
        person_dict,
        person.mobile,
    )
    if reg_resp.get("success"):
        log("[Step6] 注册表单提交成功！")
    else:
        result.error = f"注册失败: {reg_resp}"
        log(f"✗ {result.error}")
        return result

    # ── Step 7: 等待注册成功邮件 ──────────────────────────────────────────
    log("[Step6->Step7] 等待 5s...")
    time.sleep(5)

    log("[Step7] 等待注册成功邮件...")
    account_pwd, _ = step8_wait_success_email(mail_client)
    if not account_pwd:
        result.error = "等待注册成功邮件超时"
        log(f"✗ {result.error}")
        return result

    result.success = True
    result.account_pwd = account_pwd
    person.account_pwd = account_pwd
    log(f"[Step7] 完成: ✓ 注册成功！账号密码: {account_pwd}")

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# 结果保存
# ═══════════════════════════════════════════════════════════════════════════════

def save_result(result: RegisterResult):
    """保存注册结果到 CSV（只有成功的才保存）"""
    person = result.person
    if not person or not result.success:
        return

    csv_exists = os.path.exists(CSV_FILE_PATH)
    try:
        with open(CSV_FILE_PATH, "a", newline="", encoding="utf-8-sig") as f:
            import csv as csv_module
            writer = csv_module.writer(f)
            if not csv_exists:
                writer.writerow([
                    "注册时间", "BLS账号", "BLS密码", "邮箱", "邮箱密码",
                    "姓名", "手机号", "出生日期", "护照号", "签发地",
                    "签发日期", "到期日期", "有效期", "代理IP", "IP信息",
                ])

            # 提取代理 IP 部分（去除用户名密码）
            proxy_ip = result.proxy
            if "@" in proxy_ip and not proxy_ip.startswith("直连"):
                proxy_ip = proxy_ip.split("@")[-1].rstrip("/")

            writer.writerow([
                time.strftime("%Y-%m-%d %H:%M:%S"),
                result.email,
                result.account_pwd,
                result.email,
                result.email_pwd,
                f"{person.surname} {person.first_name}",
                person.mobile,
                person.dob,
                person.pp_no,
                person.issue_place,
                person.pp_issue,
                person.pp_expiry,
                person.validity_years,
                proxy_ip,
                result.proxy_info,
            ])
        print(f"    [完成] 已保存到: {CSV_FILE_PATH}")
    except Exception as e:
        print(f"    [错误] 保存 CSV 失败: {e}")


def print_result(result: RegisterResult):
    """打印注册结果"""
    person = result.person
    print()
    if result.success:
        print("=" * 60)
        print(f"  ✓ 注册成功！")
        print(f"  邮箱: {result.email}")
        print(f"  OTP: {result.otp}")
        print(f"  账号密码: {result.account_pwd}")
        print(f"  代理IP: {result.proxy}")
        print(f"  IP信息: {result.proxy_info}")
        print("=" * 60)
    else:
        print("=" * 60)
        print(f"  ✗ 注册失败: {result.error}")
        print("=" * 60)
