"""并行执行引擎 — 多线程 API 调用编排、审计抽查、语法验证。
支持自适应并发：根据 API 健康状态动态调整 worker 数量。"""
import os
import re
import random
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..config import CONFIG
from .api import call_api_with_retry, get_adaptive_workers, get_resilience_stats
from .files import parse_and_write_files
from .hashing import snapshot_tree_hashes, detect_changed_by_hash, snapshot_tree_hashes_cdc
from .checkpoint import save_checkpoint, load_checkpoint, clear_checkpoint
from .validate import validate_generated_files


def execute_parallel_development(
    module_defs: dict[str, dict],
    resume: bool = False,
) -> dict[str, list[str]]:
    """并行调用 API 为所有子模块执行开发任务。"""
    all_modules = set(module_defs.keys())
    completed: set[str] = set()
    failed_set: set[str] = set()

    if resume:
        ckpt = load_checkpoint()
        if ckpt:
            completed = ckpt.get("completed", set())
            failed_set = ckpt.get("failed", set())
            pending = all_modules - completed - failed_set
        else:
            pending = all_modules
    else:
        pending = all_modules
        clear_checkpoint()

    if not pending:
        print("[信息] 所有模块已完成，无需继续")
        return {}

    modules_to_process = [(k, module_defs[k]) for k in pending if k in module_defs]

    # 自适应并发：根据 API 健康状态动态调整 worker 数
    if CONFIG.RESILIENCE_ENABLED:
        adaptive_workers = get_adaptive_workers()
        actual_workers = min(CONFIG.MAX_WORKERS, adaptive_workers)
    else:
        actual_workers = CONFIG.MAX_WORKERS

    # 快照：使用 CDC 模式还是整文件模式
    if CONFIG.CDC_ENABLED:
        snapshot_before = snapshot_tree_hashes_cdc(CONFIG.ROOT_DIR)
        snapshot_mode = "CDC"
    else:
        snapshot_before = snapshot_tree_hashes(CONFIG.ROOT_DIR)
        snapshot_mode = "整文件"
    # 此处记录快照模式以供后续对比，CDC 模式对 >16KB 文件使用 Gear-hash 分块

    print(f"\n{'='*60}")
    print(f"开始并行开发: {len(modules_to_process)} 个子模块, {actual_workers} 个并行线程 (快照: {snapshot_mode})")
    if resume:
        print(f"  断点恢复: 已完成 {len(completed)} / 失败 {len(failed_set)}")
    if CONFIG.RESILIENCE_ENABLED:
        print(f"  韧性层: 已启用 (断路器 + 令牌预算 + 自适应并发)")
    if CONFIG.BLACKBOARD_ENABLED:
        print(f"  黑板: 已启用 (跨 worker 知识共享)")
    print(f"{'='*60}\n")

    # 黑板初始化
    blackboard = None
    if CONFIG.BLACKBOARD_ENABLED:
        from .blackboard import get_blackboard
        blackboard = get_blackboard()

    results: dict[str, list[str]] = {}
    completed_this_run: set[str] = set()

    with ThreadPoolExecutor(max_workers=actual_workers) as executor:
        future_to_module = {
            executor.submit(call_api_with_retry, mk, md): mk
            for mk, md in modules_to_process
        }
        for future in as_completed(future_to_module):
            module_key = future_to_module[future]
            try:
                response_text = future.result(timeout=CONFIG.API_TIMEOUT)
                if response_text:
                    modified = parse_and_write_files(module_key, response_text)
                    results[module_key] = modified
                    completed.add(module_key)
                    completed_this_run.add(module_key)
                    # 向黑板存入发现摘要——供后续 worker 查询
                    if blackboard is not None and modified:
                        _deposit_to_blackboard(blackboard, module_key, modified,
                                               module_defs.get(module_key, {}))
                else:
                    failed_set.add(module_key)
                    results[module_key] = []
                    if blackboard is not None:
                        blackboard.deposit(
                            "error", f"模块 {module_key} API 调用失败",
                            source_module=module_key, tags=["api_failure", module_key],
                        )
            except concurrent.futures.TimeoutError:
                print(f"[超时] {module_key}: 任务超时")
                failed_set.add(module_key)
                results[module_key] = []
            except Exception as e:
                print(f"[异常] {module_key}: {e}")
                failed_set.add(module_key)
                results[module_key] = []
            remaining = all_modules - completed - failed_set
            save_checkpoint(completed, failed_set, remaining)

    if CONFIG.CDC_ENABLED:
        snapshot_after = snapshot_tree_hashes_cdc(CONFIG.ROOT_DIR)
    else:
        snapshot_after = snapshot_tree_hashes(CONFIG.ROOT_DIR)
    hash_changed = detect_changed_by_hash(snapshot_before, snapshot_after)
    print(f"\n[哈希检测] {snapshot_mode} 快照对比: {len(hash_changed)} 个文件发生变更")

    if completed_this_run:
        audit_module = random.choice(list(completed_this_run))
        audit_files = results.get(audit_module, [])
        if audit_files:
            print(f"\n[审计抽查] 模块 '{audit_module}' 的输出文件: {len(audit_files)} 个")
            _audit_check(audit_module, audit_files)

    all_gen_files: list[str] = []
    for files in results.values():
        all_gen_files.extend(files)
    if all_gen_files:
        print(f"\n[语法验证] 检查 {len(all_gen_files)} 个生成文件...")
        validation = validate_generated_files(all_gen_files)
        print(f"  [OK] 通过: {len(validation['ok'])}  /  [FAIL] 失败: {len(validation['error'])}  /  [SKIP] 非Python: {len(validation['skipped'])}")

    # 语义验证
    if CONFIG.SEMANTIC_VALIDATION_ENABLED and all_gen_files:
        print(f"\n[语义验证] 检查跨模块接口一致性...")
        try:
            from .semantic_validator import run_semantic_validation
            sem_result = run_semantic_validation(all_gen_files, CONFIG.ROOT_DIR)
            if sem_result["interface_issues"]:
                print(f"  [警告] 发现 {len(sem_result['interface_issues'])} 个接口不一致:")
                for issue in sem_result["interface_issues"][:5]:
                    print(f"    - {issue}")
            else:
                print(f"  [OK] 跨模块接口一致")
            if sem_result["property_tests"]:
                print(f"  [属性测试] 为 {len(sem_result['property_tests'])} 个函数生成了边界值测试用例")
        except Exception as e:
            print(f"  [注意] 语义验证跳过: {e}")

    # 黑板统计
    if CONFIG.BLACKBOARD_ENABLED and blackboard is not None:
        try:
            bs = blackboard.stats()
            print(f"\n[黑板] 知识条目: {bs['total_entries']} 条")
            if bs["by_type"]:
                types = ", ".join(f"{k}:{v}" for k, v in bs["by_type"].items())
                print(f"  类型分布: {types}")
        except Exception:
            pass

    total_ok = len(completed)
    total_fail = len(failed_set)
    print(f"\n{'='*60}")
    print(f"并行开发完成: 成功 {total_ok}/{len(all_modules)}, 失败 {total_fail}/{len(all_modules)}")
    if failed_set:
        print(f"失败模块: {', '.join(sorted(failed_set))}")
    print(f"{'='*60}\n")

    if not (all_modules - completed - failed_set):
        clear_checkpoint()
        print("[断点] 全部完成，已清除断点文件")

    results["__hash_changed__"] = list(hash_changed)
    return results


def _deposit_to_blackboard(blackboard, module_key: str, modified: list[str], module_def: dict) -> None:
    """向黑板存入模块完成的摘要，包含创新点标题和产出文件列表。
    后续 worker 可通过黑板查询是否有相关模块已完成，避免重复工作。"""
    innovation = module_def.get("innovation", {})
    title = innovation.get("title", module_key)
    files_summary = ", ".join(os.path.basename(f) for f in modified[:5])
    content = (
        f"模块 [{module_key}] 完成。创新点: {title}。"
        f"产出 {len(modified)} 个文件: {files_summary}"
    )
    blackboard.deposit(
        "finding", content,
        source_module=module_key,
        tags=[module_key] + module_def.get("core_keywords", [])[:3],
    )


def _audit_check(module_key: str, files: list[str]) -> None:
    """抽查 AI 生成代码的痕迹多样性 (增强版 — 英文 + 中文 + 结构模式)。"""
    patterns_en = [
        (r"let me explain", "'let me explain'"),
        (r"certainly!", "'certainly!'"),
        (r"here('?)s the (implementation|code|updated)", "'here's the...'"),
        (r"i hope this (helps|is)", "'I hope this helps'"),
        (r"feel free to", "'feel free to'"),
        (r"as an ai", "'as an AI'"),
    ]
    patterns_cn = [
        (r"(优秀|完美|惊人|非常棒|特别好)", "情感词汇"),
        (r"(众所周知|显然|毫无疑问)", "主观断言词"),
        (r"希望这(个|段|些)代码", "'希望这段代码...'"),
    ]
    patterns_struct = [
        (r"(?m)^(# ){3,}", "连续三级以上标题"),
        (r"(?m)^\s*# TODO.*\n\s*# TODO", "连续 TODO 堆砌"),
    ]

    issues = 0
    for fpath in files[:5]:
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()
            cl = raw.lower()
            for pat, desc in patterns_en:
                if re.search(pat, cl):
                    print(f"  [审计] {os.path.basename(fpath)}: {desc}")
                    issues += 1
            for pat, desc in patterns_cn:
                if re.search(pat, raw):
                    print(f"  [审计] {os.path.basename(fpath)}: {desc}")
                    issues += 1
            for pat, desc in patterns_struct:
                if re.search(pat, raw):
                    print(f"  [审计] {os.path.basename(fpath)}: {desc}")
                    issues += 1
        except Exception:
            pass

    if issues == 0:
        print(f"  [审计通过] 未发现 AI 痕迹")
    elif issues <= 3:
        print(f"  [审计] 发现 {issues} 个轻微问题")
    else:
        print(f"  [审计警告] 发现 {issues} 个痕迹问题，建议人工复查")
