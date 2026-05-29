# models.py
# 创建日期: 2026-05-29 09:48:00（北京时间 UTC+8）
# 更新日期: 2026-05-29 09:48:00（北京时间 UTC+8）
# 使用模型: Claude Opus 4 (claude-opus-4-7-high)
# 用途说明: BLS 注册数据模型

"""
BLS 注册数据模型
==============

包含注册任务结果、人物信息等数据结构。
"""

import random
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Optional


# ═══════════════════════════════════════════════════════════════════════════════
# 随机信息生成数据
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
_MOBILE_PREFIXES = [
    "130", "131", "132", "133", "134", "135", "136", "137", "138",
    "139", "150", "151", "152", "153", "155", "156", "157", "158",
    "159", "170", "171", "172", "173", "175", "176", "177", "178",
    "180", "181", "182", "183", "184", "185", "186", "187", "188",
    "189", "198", "199",
]


# ═══════════════════════════════════════════════════════════════════════════════
# 数据模型
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class PersonInfo:
    """人物信息"""
    surname: str
    first_name: str
    last_name: str
    dob: date
    pp_issue: date
    pp_expiry: date
    pp_no: str
    issue_place: str
    validity_years: int
    mobile: str
    email: str = ""
    email_pwd: str = ""
    account_pwd: str = ""

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "surname": self.surname,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "dob": str(self.dob),
            "pp_issue": str(self.pp_issue),
            "pp_expiry": str(self.pp_expiry),
            "pp_no": self.pp_no,
            "issue_place": self.issue_place,
            "validity_years": self.validity_years,
            "mobile": self.mobile,
            "email": self.email,
            "email_pwd": self.email_pwd,
            "account_pwd": self.account_pwd,
        }

    @classmethod
    def random(cls) -> "PersonInfo":
        """生成随机人物信息"""
        return generate_person()


@dataclass
class RegisterResult:
    """注册任务结果"""
    task_id: int
    success: bool = False
    email: str = ""
    email_pwd: str = ""
    otp: str = ""
    account_pwd: str = ""
    person: Optional[PersonInfo] = None
    error: str = ""
    proxy: str = ""
    proxy_info: str = ""

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "task_id": self.task_id,
            "success": self.success,
            "email": self.email,
            "email_pwd": self.email_pwd,
            "otp": self.otp,
            "account_pwd": self.account_pwd,
            "person": self.person.to_dict() if self.person else {},
            "error": self.error,
            "proxy": self.proxy,
            "proxy_info": self.proxy_info,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# 工具函数
# ═══════════════════════════════════════════════════════════════════════════════

def _days_in_month(year: int, month: int) -> int:
    """返回指定年月的天数"""
    if month == 2:
        if (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0):
            return 29
        return 28
    if month in (4, 6, 9, 11):
        return 30
    return 31


def generate_person() -> PersonInfo:
    """
    生成随机注册信息（符合 BLS 中国护照要求）

    Returns:
        PersonInfo: 人物信息对象
    """
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
    surname = random.choice(_SURNAMES).upper()
    first_name = random.choice(_FIRST_NAMES)

    # 手机号
    mobile = random.choice(_MOBILE_PREFIXES) + str(random.randint(10000000, 99999999))

    return PersonInfo(
        surname=surname,
        first_name=first_name,
        last_name=surname,
        dob=dob,
        pp_issue=pp_issue,
        pp_expiry=pp_expiry,
        pp_no=pp_no,
        issue_place=random.choice(_ISSUE_PLACES),
        validity_years=pp_validity_years,
        mobile=mobile,
    )
