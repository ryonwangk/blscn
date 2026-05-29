# main.py
# 创建日期: 2026-05-29 10:02:00（北京时间 UTC+8）
# 更新日期: 2026-05-29 10:02:00（北京时间 UTC+8）
# 使用模型: Claude Opus 4 (claude-opus-4-7-high)
# 用途说明: BLS 注册命令行入口

"""
BLS 注册入口
============

支持单线程和多线程并行注册。

Usage:
    # 单线程（默认）
    python -m blscn.register.main

    # 指定并行数
    python -m blscn.register.main --tasks 3

    # 或直接运行
    python blscn/register/main.py --tasks 5
"""

import argparse
import os
import sys

# 确保模块路径正确
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from blscn.register.config import MAX_PARALLEL_TASKS, PROXY_MODE, OCR_MODEL_PATH
from blscn.register.models import PersonInfo
from blscn.register.runner import run_registration, run_single
from blscn.register.ocr import get_charset


def print_banner(task_count: int):
    """打印横幅"""
    print(f"""
╔══════════════════════════════════════════════════════════════════════════╗
║  BLS China 注册 — 多线程并行模式                                    ║
║  https://spain.blscn.cn/CHN/account/RegisterUser                  ║
╠══════════════════════════════════════════════════════════════════════════╣
║  并行任务数: {task_count:<50}   ║
║  代理模式: {PROXY_MODE:<51}   ║
╚══════════════════════════════════════════════════════════════════════════╝
    """)


def main():
    """主入口"""
    parser = argparse.ArgumentParser(description="BLS China 注册工具")
    parser.add_argument(
        "--tasks", "-t",
        type=int,
        default=MAX_PARALLEL_TASKS,
        help=f"并行任务数（默认: {MAX_PARALLEL_TASKS}）",
    )
    args = parser.parse_args()

    task_count = args.tasks

    # 打印横幅
    print_banner(task_count)

    # 检查 OCR 模型
    if os.path.exists(OCR_MODEL_PATH):
        charset = get_charset()
        print(f"OCR 模型: {OCR_MODEL_PATH}")
        print(f"Charset: {charset}")
    else:
        print(f"WARNING: ONNX 模型未找到: {OCR_MODEL_PATH}")

    # 根据任务数选择执行方式
    if task_count <= 1:
        print("\n执行模式: 单线程\n")
        run_single()
    else:
        print(f"\n执行模式: {task_count} 线程并行\n")
        run_registration(task_count=task_count)


if __name__ == "__main__":
    main()
