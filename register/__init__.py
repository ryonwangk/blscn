# __init__.py
# 创建日期: 2026-05-29 10:05:00（北京时间 UTC+8）
# 更新日期: 2026-05-29 10:05:00（北京时间 UTC+8）
# 使用模型: Claude Opus 4 (claude-opus-4-7-high)
# 用途说明: BLS 注册模块导出

"""
BLS 注册模块
============

模块结构：
- config.py: 配置项
- models.py: 数据模型
- session.py: HTTP 会话
- steps.py: 注册步骤
- ocr.py: OCR 识别
- register.py: 注册主流程
- runner.py: 多线程运行器
- main.py: 命令行入口

Usage:
    # 命令行运行
    python -m blscn.register.main --tasks 3

    # 代码调用
    from blscn.register import run_single, run_registration

    # 单线程
    result = run_single()

    # 多线程
    results = run_registration(task_count=5)
"""

# 只导出配置和模型，避免循环导入
from .config import (
    MAX_PARALLEL_TASKS,
    PROXY_MODE,
    BASE_URL,
    TARGET_HOST,
)
from .models import PersonInfo, RegisterResult

__all__ = [
    # 配置
    "MAX_PARALLEL_TASKS",
    "PROXY_MODE",
    "BASE_URL",
    "TARGET_HOST",
    # 模型
    "PersonInfo",
    "RegisterResult",
]


def run_single():
    """单线程执行一次注册"""
    from .runner import run_single as _run_single
    return _run_single()


def run_registration(task_count: int = MAX_PARALLEL_TASKS):
    """多线程并行执行注册"""
    from .runner import run_registration as _run_registration
    return _run_registration(task_count=task_count)


def register_one_task(task_id: int, person: PersonInfo):
    """执行单个注册任务"""
    from .register import register_one_task as _register_one_task
    return _register_one_task(task_id, person)


def save_result(result: RegisterResult):
    """保存注册结果"""
    from .register import save_result as _save_result
    return _save_result(result)


def print_result(result: RegisterResult):
    """打印注册结果"""
    from .register import print_result as _print_result
    return _print_result(result)
