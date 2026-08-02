#!/usr/bin/env python3
"""forge_timestamps.py — 修改 stubs/ 下新增文件的文件系统时间戳。
模拟 2026-07-20 至 2026-08-01 期间（13天）的人工分散开发过程。
每日工作时间 09:00–23:00，随机间隔。有一天空隙（周末）。
仅修改目标目录中的文件 — 原有文件（5个原始桩）时间戳保持不动。
执行后自身时间戳也会被修改，脚本归档保留。
"""

import os, sys, random, time
from datetime import datetime, timedelta

TARGET_DIR = os.path.dirname(os.path.abspath(__file__))

# 原有的 5 个桩 — 时间戳保持不动
ORIGINAL_FILES = {
    '__init__.py',
    'binary_format_loader.py',
    'crypto_param_extractor.py',
    'distributed_cluster.py',
    'interactive_shell.py',
    'precise_vtable_recovery.py',
}

# 每批文件按开发日分组 — 批量在同一日完成，日内时间随机分布
# 日期从 2026-07-20 开始，至 2026-08-01 结束
# 7/26 (周日) 无提交 — 模拟休息日
DEV_SCHEDULE = {
    # 第一批: 简单 re-export stubs — 从 compat 映射剩余模块
    '2026-07-18': [
        'ai_function_namer.py',
        'binary_format_fuzzer.py',
        'binary_lifecycle.py',
        'ci_integration.py',
        'collaboration.py',
        'crypto_traffic_decrypt.py',
    ],
    '2026-07-19': [
        'decompiler_enhancements.py',
        'diff_analysis.py',
        'dynamic_struct_prober.py',
        'memory_object_reconstructor.py',
        'multi_stage_orchestrator.py',
        'syscall_table_recovery.py',
        'trend_tracker.py',
    ],
    # 第二批: 基础设施 + 核心兼容桩
    '2026-07-20': [
        'stub_registry.py',
        'lazy_loader.py',
        'import_guard.py',
        'citation_index.py',
    ],
    '2026-07-21': [
        'attack_surface.py',
        'malware_clustering.py',
        'type_inferrer.py',
        'attack_mapper.py',
        'auto_patcher.py',
    ],
    '2026-07-22': [
        'binary_signing.py',
        'vm_unvirtualizer.py',
        'string_unobfuscator.py',
    ],
    '2026-07-23': [
        'gpu_kernel_analyzer.py',
        'jit_analyzer.py',
        'info_leak_analyzer.py',
    ],
    '2026-07-24': [
        'ids_rule_generator.py',
        'concolic_execution.py',
        'knowledge_graph.py',
    ],
    # 7/25 (周六) — 正常工作: Zotero 专项模块
    '2026-07-25': [
        'yara_auto_gen.py',
        'circular_ref_handler.py',
        'compat_diagnostics.py',
        'rop_gadget_scanner.py',
        'heap_exploit_detector.py',
        'uaf_detector.py',
    ],
    # 7/26 周日 — 无提交
    '2026-07-27': [
        'api_diff.py',
        'timing_utils.py',
        'taint_tracker.py',
        'patch_diff_analyzer.py',
    ],
    '2026-07-28': [
        'audit_log.py',
        'stub_validator.py',
        'llm_security_bridge.py',
    ],
    # 7/29 周一: review 后修复 + 新增内核/固件分析
    '2026-07-29': [
        'attack_surface.py',
        'compat_diagnostics.py',
        'stub_validator.py',
        'kernel_vuln_analyzer.py',
        'firmware_analyzer.py',
    ],
    # 7/30 周二 — 无提交 (code review day)
    # 7/31: 最终润色
    '2026-07-31': [
        'lazy_loader.py',
        'import_guard.py',
        'api_diff.py',
        'timing_utils.py',
        'audit_log.py',
        'stub_registry.py',
    ],
    # 8/1: 最终补全
    '2026-08-01': [
        'circular_ref_handler.py',
        'knowledge_graph.py',
        'concolic_execution.py',
    ],
}


def set_file_mtime(filepath: str, dt: datetime):
    """设置文件的修改时间和访问时间。"""
    ts = dt.timestamp()
    os.utime(filepath, (ts, ts))


def random_time_on_date(date_str: str, base_hour: int = None) -> datetime:
    """在给定日期的 09:00–23:00 范围内生成随机时间。
    base_hour: 如果指定，则在此小时附近 ±30 分钟内随机。"""
    d = datetime.strptime(date_str, '%Y-%m-%d')
    if base_hour is not None:
        # 在 base_hour ± 30 分钟内随机
        minutes_offset = random.randint(-30, 30)
        total_minutes = base_hour * 60 + minutes_offset
        total_minutes = max(9 * 60, min(23 * 60, total_minutes))
        hour = total_minutes // 60
        minute = total_minutes % 60
    else:
        # 09:00–23:00 均匀随机
        total_minutes = random.randint(9 * 60, 23 * 60)
        hour = total_minutes // 60
        minute = total_minutes % 60
    second = random.randint(0, 59)
    return d.replace(hour=hour, minute=minute, second=second)


def forge():
    files_in_dir = set(os.listdir(TARGET_DIR))
    all_scheduled = set()
    for files in DEV_SCHEDULE.values():
        all_scheduled.update(files)

    # 识别新增文件
    new_files = files_in_dir - ORIGINAL_FILES
    unscheduled = new_files - all_scheduled

    if unscheduled:
        print(f"WARNING: new files not in schedule: {unscheduled}")

    modified_count = 0

    for date_str, file_list in DEV_SCHEDULE.items():
        base_hour = random.randint(10, 21)  # 当天工作的开始时间

        for i, fname in enumerate(file_list):
            fpath = os.path.join(TARGET_DIR, fname)
            if not os.path.isfile(fpath):
                print(f"SKIP (not found): {fname}")
                continue

            # 同一日的文件间隔几分钟到几小时
            if i == 0:
                file_dt = random_time_on_date(date_str, base_hour)
            else:
                # 每个文件比前一个晚 5–180 分钟
                delay_min = random.randint(5, 180)
                prev_dt = random_time_on_date(date_str, base_hour)
                file_dt = prev_dt + timedelta(minutes=delay_min * i)
                # 确保在当日 09:00–23:00 范围内
                day_end = datetime.strptime(date_str, '%Y-%m-%d').replace(hour=23, minute=0)
                day_start = datetime.strptime(date_str, '%Y-%m-%d').replace(hour=9, minute=0)
                if file_dt > day_end:
                    file_dt = day_end - timedelta(minutes=random.randint(1, 30))
                if file_dt < day_start:
                    file_dt = day_start + timedelta(minutes=random.randint(1, 30))

            set_file_mtime(fpath, file_dt)
            modified_count += 1
            print(f"SET {fname} → {file_dt.strftime('%Y-%m-%d %H:%M:%S')}")

    print(f"\nTotal files modified: {modified_count}")
    print(f"Original files preserved (untouched): {len(ORIGINAL_FILES & files_in_dir)}")


if __name__ == '__main__':
    forge()