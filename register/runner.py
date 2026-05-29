# runner.py
# 创建日期: 2026-05-29 10:00:00（北京时间 UTC+8）
# 更新日期: 2026-05-29 10:08:00（北京时间 UTC+8）
# 使用模型: Claude Opus 4 (claude-opus-4-7-high)
# 用途说明: 多线程并行注册运行器

"""
多线程并行注册运行器
====================

支持多线程并行执行多个注册任务。
"""

import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

# 确保 stdout 支持 UTF-8
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# 添加父目录到 sys.path
_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

from blscn.register.config import MAX_PARALLEL_TASKS
from blscn.register.models import PersonInfo, RegisterResult
from blscn.register.register import register_one_task, save_result, print_result


# ═══════════════════════════════════════════════════════════════════════════════
# 多线程运行器
# ═══════════════════════════════════════════════════════════════════════════════

def run_registration(
    task_count: int = MAX_PARALLEL_TASKS,
    progress_callback: Optional[Callable[[int, int, RegisterResult], None]] = None,
) -> list[RegisterResult]:
    """
    多线程并行执行注册任务

    Args:
        task_count: 并行任务数
        progress_callback: 进度回调函数 (completed, total, result)

    Returns:
        注册结果列表
    """
    results: list[RegisterResult] = []
    results_lock = threading.Lock()
    completed_count = 0
    count_lock = threading.Lock()

    def run_one_task(task_id: int, person: PersonInfo) -> RegisterResult:
        """执行单个任务"""
        result = register_one_task(task_id, person)
        
        # 更新进度
        nonlocal completed_count
        with count_lock:
            completed_count += 1
            current = completed_count
        
        # 保存结果
        save_result(result)
        
        # 回调
        if progress_callback:
            progress_callback(current, task_count, result)
        
        return result

    # 生成任务列表
    tasks = []
    for i in range(1, task_count + 1):
        person = PersonInfo.random()
        tasks.append((i, person))

    print(f"\n{'='*60}")
    print(f"  启动 {task_count} 个并行注册任务")
    print(f"{'='*60}\n")

    start_time = time.time()

    # 使用线程池执行
    with ThreadPoolExecutor(max_workers=task_count) as executor:
        futures = {
            executor.submit(run_one_task, task_id, person): (task_id, person)
            for task_id, person in tasks
        }

        for future in as_completed(futures):
            task_id, person = futures[future]
            try:
                result = future.result()
                with results_lock:
                    results.append(result)
            except Exception as e:
                print(f"[Task-{task_id}] 执行异常: {e}")
                results.append(RegisterResult(
                    task_id=task_id,
                    person=person,
                    success=False,
                    error=str(e),
                ))

    elapsed = time.time() - start_time

    # 统计结果
    success_count = sum(1 for r in results if r.success)
    fail_count = task_count - success_count

    print(f"\n{'='*60}")
    print(f"  注册任务完成")
    print(f"{'='*60}")
    print(f"  总任务数: {task_count}")
    print(f"  成功: {success_count}")
    print(f"  失败: {fail_count}")
    print(f"  总耗时: {elapsed:.1f} 秒")
    print(f"{'='*60}\n")

    return results


def run_single() -> RegisterResult:
    """单线程执行一次注册"""
    person = PersonInfo.random()
    result = register_one_task(task_id=1, person=person)
    save_result(result)
    print_result(result)
    return result
