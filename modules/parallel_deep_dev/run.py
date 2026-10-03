"""
run.py — 主编排器。将 config、modules_data、engine 串联为完整执行流程。

用法:
  python run.py                        # 完整执行
  python run.py --dry-run              # 仅生成 prompt 文件
  python run.py --workers 3            # 指定并行数
  python run.py --resume               # 从上次断点恢复
  python run.py --no-forge             # 跳过时间戳伪造
  python run.py --validate-only        # 仅验证 API 密钥
"""

import os
import sys
import time
import argparse

from .config import CONFIG
from .module_defs import MODULE_DEFINITIONS
from .engine import (
    build_api_messages,
    execute_parallel_development,
    collect_changed_files,
    forge_timestamps,
    self_check,
    validate_api_key,
    snapshot_tree_hashes,
)


def main(
    dry_run: bool | None = None,
    max_workers: int | None = None,
    resume: bool = False,
    no_forge: bool = False,
    validate_only: bool = False,
) -> int:
    """主执行流程。返回 0 表示成功，非 0 表示有错误。"""
    if dry_run is not None:
        CONFIG.DRY_RUN = dry_run
    if max_workers is not None:
        CONFIG.MAX_WORKERS = min(max_workers, 8)

    print("=" * 60)
    print("  BinMind 深度创新并行开发脚本")
    print("  parallel_deep_dev v2.1")
    print("=" * 60)
    print(f"  目标目录: {os.path.basename(CONFIG.ROOT_DIR)}")
    print(f"  子模块数: {len(MODULE_DEFINITIONS)}")
    print(f"  并行线程: {CONFIG.MAX_WORKERS}")
    print(f"  API 模型:  {CONFIG.API_MODEL}")
    flags = []
    if CONFIG.DRY_RUN:
        flags.append("DRY-RUN")
    if resume:
        flags.append("RESUME")
    if no_forge:
        flags.append("NO-FORGE")
    if validate_only:
        flags.append("VALIDATE-ONLY")
    mode = " + ".join(flags) if flags else "LIVE"
    print(f"  模式:      {mode}")
    print("=" * 60)

# 自检
    this_file = os.path.abspath(__file__)
    engine_file = os.path.join(os.path.dirname(__file__), "engine.py")
    if not self_check(this_file):
        return 1
    if os.path.exists(engine_file):
        self_check(engine_file)

# 仅验证模式
    if validate_only:
        print("\n[验证] 检查 API 密钥...")
        if not CONFIG.API_KEY:
            print("[错误] ANTHROPIC_API_KEY 未设置")
            return 1
        if validate_api_key():
            print("[OK] API 密钥有效")
            return 0
        else:
            print("[FAIL] API 密钥无效或网络不可达")
            return 1

# 显示创新点概览
    print(f"\n待处理子模块及创新点:")
    print("-" * 60)
    for key, defn in MODULE_DEFINITIONS.items():
        paper_count = len(defn["innovation"]["papers"])
        print(f"  [{key}] {defn['innovation']['title']}  ({paper_count} papers)")
    total_papers = sum(len(v["innovation"]["papers"]) for v in MODULE_DEFINITIONS.values())
    print(f"  论文总计: {total_papers}")
    print("-" * 60)

# DRY-RUN 分支
    if CONFIG.DRY_RUN:
        print("\n[DRY-RUN 模式] 仅生成每个模块的 prompt 文件\n")
        for key, defn in MODULE_DEFINITIONS.items():
            sys_msg, user_msg = build_api_messages(key, defn)
            prompt_file = os.path.join(CONFIG.ROOT_DIR, f"_prompt_{key}.txt")
            with open(prompt_file, "w", encoding="utf-8") as f:
                f.write(
                    f"SYSTEM:\n{sys_msg['content']}\n\n"
                    f"USER:\n{user_msg['content']}"
                )
            print(
                f"[DRY-RUN] {key}: -> {prompt_file} "
                f"({len(user_msg['content'])} 字符)"
            )
        print("\n[DRY-RUN] 完成。确认后设置 DRY_RUN=False 并设置 ANTHROPIC_API_KEY。")
        return 0

# 检查 API 密钥
    if not CONFIG.API_KEY:
        print("\n[错误] ANTHROPIC_API_KEY 环境变量未设置。")
        print("  export ANTHROPIC_API_KEY='sk-ant-...'")
        print("  或使用 --dry-run 模式仅生成 prompt。")
        return 1

# API 密钥预检
    print("\n[预检] 验证 API 密钥...")
    if not validate_api_key():
        print("[错误] API 密钥验证失败，终止执行。")
        print("  请检查密钥是否正确、是否有可用配额、网络是否可达。")
        return 1
    print("[预检] API 密钥验证通过")

# 哈希快照（用于精确变更检测）
    print("\n[快照] 记录文件哈希...")
    snapshot_before = snapshot_tree_hashes(CONFIG.ROOT_DIR)
    print(f"[快照] 已记录 {len(snapshot_before)} 个文件")

# 执行并行开发
    start_time = time.time()
    results = execute_parallel_development(MODULE_DEFINITIONS, resume=resume)

# 收集变更文件
    hash_changed = set(results.pop("__hash_changed__", []))
    api_written = collect_changed_files(results)
    all_changed = hash_changed | api_written
    print(f"[变更] 哈希检测: {len(hash_changed)} 个, API写入: {len(api_written)} 个")
    print(f"[变更] 合并后: {len(all_changed)} 个唯一文件")

# 时间戳伪造
    if not no_forge and all_changed:
        if forge_timestamps is not None:
            forge_timestamps(all_changed)
        else:
            print("[时间戳] forge_timestamps 模块缺失, 跳过")
    elif no_forge:
        print("[时间戳] 跳过 (--no-forge)")

# 输出摘要
    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"  执行完成")
    print(f"  总耗时: {elapsed:.0f} 秒 ({elapsed/60:.1f} 分钟)")
    print(f"  处理模块数: {len([k for k in results if not k.startswith('__')])}")
    total_files = sum(
        len(files)
        for k, files in results.items()
        if not k.startswith("__")
    )
    print(f"  新增/修改文件数: {total_files}")
    print(f"  时间戳伪造文件数: {len(all_changed) if not no_forge else 0}")
    print(f"{'='*60}")

# 韧性层统计
    if CONFIG.RESILIENCE_ENABLED:
        try:
            from .engine.api import get_resilience_stats
            rs = get_resilience_stats()
            print(f"\n{'='*60}")
            print(f"  API 韧性层统计")
            print(f"{'='*60}")
            print(f"  断路器状态:     {rs.get('circuit_state', 'N/A')}")
            print(f"  连续失败数:     {rs.get('consecutive_failures', 0)}")
            print(f"  自适应并发:     {rs.get('adaptive_workers', 'N/A')} workers")
            print(f"  会话令牌消耗:   {rs.get('tokens_used_session', 0):,}")
            print(f"  会话令牌剩余:   {rs.get('tokens_remaining_session', 0):,}")
            print(f"  综合健康评分:   {rs.get('health_score', 1.0):.2f}")
            print(f"{'='*60}")
        except Exception:
            pass

# Merkle 树根哈希（若启用）
    if CONFIG.MERKLE_ENABLED:
        try:
            from .engine.merkle import build_merkle_tree, get_root_hash
            tree = build_merkle_tree(CONFIG.ROOT_DIR)
            root = get_root_hash(tree)
            print(f"\n[Merkle] 目录树根哈希: {root[:16]}... (用于完整性验证)")
        except Exception:
            pass

# 成果摘要
    print(f"\n{'='*60}")
    print(f"  创新成果摘要")
    print(f"{'='*60}")
    for key, defn in MODULE_DEFINITIONS.items():
        status = "[OK]" if key in results else "[PENDING]"
        paper_ids = ", ".join(p["id"] for p in defn["innovation"]["papers"])
        print(f"  {status} {key}: {defn['innovation']['title']}")
        if defn["innovation"]["papers"]:
            print(f"        papers: {paper_ids}")
    print(f"{'='*60}")

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BinMind 深度创新并行开发")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="仅生成 prompt 文件，不调用 API"
    )
    parser.add_argument(
        "--workers", type=int, default=None,
        help="并行线程数 (默认: 5，上限: 8)"
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="从上次断点恢复 (跳过已完成的模块)"
    )
    parser.add_argument(
        "--no-forge", action="store_true",
        help="跳过时间戳伪造步骤"
    )
    parser.add_argument(
        "--validate-only", action="store_true",
        help="仅验证 API 密钥是否有效"
    )
    args = parser.parse_args()
    sys.exit(main(
        dry_run=args.dry_run,
        max_workers=args.workers,
        resume=args.resume,
        no_forge=args.no_forge,
        validate_only=args.validate_only,
    ))
