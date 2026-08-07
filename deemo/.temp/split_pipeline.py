"""拆分 pipeline.py: 增强块提取到 pipeline_enh1..6.py, 主文件保留 run_pipeline + run_pipeline_enhanced 骨架."""
import re
from pathlib import Path

SRC = Path(__file__).parent.parent / "core" / "pipeline.py"
lines = SRC.read_text(encoding="utf-8").splitlines(keepends=True)

# 定位增强块起始行 (在 run_pipeline_enhanced 内, 以 "    # --- (" 开头)
block_starts = []
enh_start = None
return_idx = None
for i, line in enumerate(lines):
    if "def run_pipeline_enhanced" in line:
        enh_start = i
    if enh_start is not None and i > enh_start:
        if re.match(r'    # --- \([a-z]', line):
            block_starts.append(i)
        if line.strip() == "return result" and return_idx is None:
            return_idx = i

# 按每组约9个块分6组
chunks = 6
per_chunk = (len(block_starts) + chunks - 1) // chunks
groups = []
for g in range(chunks):
    si = g * per_chunk
    ei = min((g + 1) * per_chunk, len(block_starts))
    if si >= len(block_starts):
        break
    start_line = block_starts[si]
    end_line = block_starts[ei] if ei < len(block_starts) else return_idx
    groups.append((g + 1, start_line, end_line))

TEMPLATE = '''"""Pipeline 增强层第 {n} 组 — 从 pipeline.py 拆分.

包含 {block_count} 个可选增强模块, 每个通过 try/except ImportError 独立激活.
"""
import logging

logger = logging.getLogger(__name__)


def _apply_enh{n}(result, binary_path, binfo, binary_hash, kwargs):
    """应用第 {n} 组增强模块."""
{body}'''

for n, start, end in groups:
    body_lines = lines[start:end]
    # 去掉末尾空行和 return result
    while body_lines and (body_lines[-1].strip() == "" or "return result" in body_lines[-1]):
        body_lines.pop()
    # 原始代码在 run_pipeline_enhanced 内缩进4空格, 作为新函数体缩进4空格正好
    body = "".join(body_lines)
    # enh1 第一个块引用 sym_result, 需在函数体顶部定义
    if n == 1:
        body = '    sym_result = result.get("symbolic_execution")\n' + body
    block_count = sum(1 for l in body_lines if re.match(r'    # --- \(', l))
    content = TEMPLATE.format(n=n, body=body, block_count=block_count)
    out = SRC.parent / f"pipeline_enh{n}.py"
    out.write_text(content, encoding="utf-8")
    print(f"pipeline_enh{n}.py: {content.count(chr(10))+1} lines, {block_count} blocks")

# 重写 pipeline.py
new_pipeline = '''"""Central analysis pipeline.

Orchestrates binary loading, decompilation, static analysis, symbolic
execution, crash analysis, and reporting. Each stage can fail independently
without killing the whole run. Enhancement layers split into pipeline_enh1..6.py.
"""

import hashlib
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from config import (
    MAX_FUNCTIONS, MAX_PARALLEL, ENABLE_SYMBOLIC,
    ENABLE_CRYPTO_SCAN, ENABLE_TAINTRACK, ENABLE_UNPACK,
    SUBPROCESS_TIMEOUT, ensure_dirs,
)
from core.binary_info import get_binary_info, validate_binary
from core.decompiler import list_functions, decompile_function, ai_analyze_function
from core.symexec import run_symbolic, check_angr, find_buffer_overflow
from core.crash_analysis import load_crash_file, analyze_crash_for_exploit
from core.exploit_gen import generate_exploit
from core.report import write_report
from core.vuln_db import init_db, start_run, finish_run, save_finding
from core.hooks import get_hook_manager
from core.pipeline_enh1 import _apply_enh1
from core.pipeline_enh2 import _apply_enh2
from core.pipeline_enh3 import _apply_enh3
from core.pipeline_enh4 import _apply_enh4
from core.pipeline_enh5 import _apply_enh5
from core.pipeline_enh6 import _apply_enh6

logger = logging.getLogger(__name__)


def _hash_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def run_pipeline(
    binary_path: str,
    crash_path: Optional[str] = None,
    functions: Optional[List[str]] = None,
    max_funcs: int = None,
    include_lib: bool = False,
    parallel: bool = False,
    output_format: str = "markdown",
    hooks_dir: Optional[str] = None,
    decompiler: str = "auto",
    **kwargs
) -> Dict[str, Any]:
    """Execute the full analysis pipeline on a binary."""
    start_time = time.time()
    ensure_dirs()
    init_db()

    if max_funcs is None:
        max_funcs = MAX_FUNCTIONS

    hook_mgr = get_hook_manager()
    if hooks_dir:
        hook_mgr.load_dir(hooks_dir)

    ctx = {"binary_path": binary_path, "status": "init"}
    ctx = hook_mgr.run("pre_unpack", ctx)
    if ctx.get("status") == "abort":
        return {"error": "aborted by pre_unpack hook"}

    if not validate_binary(binary_path):
        return {"error": f"Unsupported or missing file: {binary_path}"}

    binfo = get_binary_info(binary_path)
    binary_hash = _hash_file(binary_path)
    run_id = start_run(binary_path)

    logger.info("Binary: %s | %s %d-bit | size=%d",
                binfo["filename"], binfo["arch"], binfo["bits"], binfo["size"])

    if ENABLE_UNPACK:
        ctx = hook_mgr.run("pre_decompile", ctx)

    all_funcs = list_functions(binary_path)
    logger.info("Found %d functions", len(all_funcs))

    if functions:
        target_funcs = [f for f in functions if f in all_funcs]
        if not target_funcs:
            target_funcs = functions
    else:
        priority = ("main", "vuln", "win", "get_flag", "read_input",
                    "process", "parse", "handle", "init")
        target_funcs = [f for f in priority if f in all_funcs]
        if not target_funcs:
            target_funcs = all_funcs[:max_funcs]

    target_funcs = target_funcs[:max_funcs]
    logger.info("Analyzing %d functions", len(target_funcs))

    ctx = hook_mgr.run("pre_analysis", ctx)
    decomp_results = []

    def _analyze_one(func_name):
        r = decompile_function(binary_path, func_name, decompiler)
        if r["pseudocode"].strip():
            ai = ai_analyze_function(func_name, r["pseudocode"], binfo)
            return ai
        return {"function": func_name, "vulnerabilities": [],
                "pseudocode": r.get("pseudocode", "")}

    if parallel and len(target_funcs) > 1:
        max_workers = min(MAX_PARALLEL, len(target_funcs))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_analyze_one, n): n for n in target_funcs}
            for fut in as_completed(futures):
                try:
                    decomp_results.append(fut.result())
                except Exception as err:
                    logger.error("Analysis worker failed: %s", err)
    else:
        for name in target_funcs:
            try:
                decomp_results.append(_analyze_one(name))
            except Exception as err:
                logger.error("Analysis of %s failed: %s", name, err)

    ctx = hook_mgr.run("post_analysis", ctx)

    sym_result = None
    if ENABLE_SYMBOLIC and check_angr():
        logger.info("Running symbolic execution...")
        sym_result = run_symbolic(binary_path)

    crash_data = None
    crash_analysis = None
    if crash_path and os.path.isfile(crash_path):
        crash_data = load_crash_file(crash_path)
        if crash_data:
            crash_analysis = analyze_crash_for_exploit(crash_data)

    if ENABLE_CRYPTO_SCAN:
        try:
            from plugins.crypto_scan import scan_crypto
            crypto = scan_crypto(binary_path)
            logger.info("Crypto scan: %d constants found", len(crypto))
        except ImportError:
            logger.debug("optional plugin not available")

    all_vulns = []
    for r in decomp_results:
        analysis = r.get("analysis", r)
        for v in analysis.get("vulnerabilities", []):
            all_vulns.append(v)
            try:
                save_finding(
                    run_id, binary_path, binary_hash,
                    r.get("function_name", r.get("function", "?")),
                    v.get("type", "?"), v.get("severity", "Unknown"),
                    v.get("cwe", ""), v.get("description", ""),
                )
            except Exception:
                pass

    exploit_result = None
    if crash_analysis and crash_analysis.get("exploitable"):
        exploit_result = generate_exploit(binfo, crash_data)

    ctx = hook_mgr.run("pre_report", ctx)
    reports = write_report(decomp_results, binfo, crash_analysis, output_format)
    ctx = hook_mgr.run("post_report", ctx)

    elapsed = time.time() - start_time
    finish_run(run_id, "completed", f"{len(all_vulns)} vulns in {elapsed:.1f}s")

    logger.info("Pipeline done in %.1fs | %d functions | %d vulns",
                elapsed, len(target_funcs), len(all_vulns))

    return {
        "reports": reports,
        "decomp_analysis": decomp_results,
        "crash_analysis": crash_analysis,
        "crash_data": crash_data,
        "symbolic_execution": sym_result,
        "exploit_result": exploit_result,
        "binary_info": binfo,
        "elapsed": elapsed,
        "total_vulns": len(all_vulns),
    }


def run_pipeline_enhanced(binary_path: str, **kwargs) -> Dict[str, Any]:
    """Enhanced pipeline: 50+ optional enhancement layers.

    API-compatible with run_pipeline. All enhancements use try/except ImportError
    and silently degrade to standard pipeline if unavailable.
    """
    result = run_pipeline(binary_path, **kwargs)
    if "error" in result:
        return result

    binfo = result.get("binary_info", {})
    binary_hash = _hash_file(binary_path)

    _apply_enh1(result, binary_path, binfo, binary_hash, kwargs)
    _apply_enh2(result, binary_path, binfo, binary_hash, kwargs)
    _apply_enh3(result, binary_path, binfo, binary_hash, kwargs)
    _apply_enh4(result, binary_path, binfo, binary_hash, kwargs)
    _apply_enh5(result, binary_path, binfo, binary_hash, kwargs)
    _apply_enh6(result, binary_path, binfo, binary_hash, kwargs)

    return result
'''

SRC.write_text(new_pipeline, encoding="utf-8")
print(f"\npipeline.py: {new_pipeline.count(chr(10))+1} lines (was 1691)")
