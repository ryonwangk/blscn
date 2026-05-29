# bls_register.py
# 创建日期: 2026-05-29 10:12:00（北京时间 UTC+8）
# 更新日期: 2026-05-29 10:12:00（北京时间 UTC+8）
# 使用模型: Claude Opus 4 (claude-opus-4-7-high)
# 用途说明: BLS 注册入口脚本（调用 register 模块）

"""
BLS 注册入口脚本
================

Usage:
    # 单线程（默认）
    python blscn/bls_register.py

    # 指定并行数
    python blscn/bls_register.py --tasks 3
"""

import sys
import os

# 添加父目录到 sys.path
_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

from blscn.register.runner import run_registration, run_single
from blscn.register.config import MAX_PARALLEL_TASKS


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="BLS China 注册工具")
    parser.add_argument(
        "--tasks", "-t",
        type=int,
        default=MAX_PARALLEL_TASKS,
        help=f"并行任务数（默认: {MAX_PARALLEL_TASKS}）",
    )
    args = parser.parse_args()

    if args.tasks <= 1:
        run_single()
    else:
        run_registration(task_count=args.tasks)
