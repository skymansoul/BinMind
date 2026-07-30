"""
Central analysis pipeline. Orchestrates binary loading, decompilation,
static analysis, symbolic execution, crash analysis, and reporting.
Each stage can fail independently without killing the whole run.
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

logger = logging.getLogger(__name__)


def _hash_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ''


def run_pipeline(
    binary_path: str,
    crash_path: Optional[str] = None,
    functions: Optional[List[str]] = None,
    max_funcs: int = None,
    include_lib: bool = False,
    parallel: bool = False,
    output_format: str = 'markdown',
    hooks_dir: Optional[str] = None,
    decompiler: str = 'auto',
    **kwargs
) -> Dict[str, Any]:
    """
    Execute the full analysis pipeline on a binary.

    Returns a dict with keys: reports, decomp_analysis, crash_analysis,
    symbolic_execution, exploit_result, similar_vulnerabilities.
    """
    start_time = time.time()
    ensure_dirs()
    init_db()

    if max_funcs is None:
        max_funcs = MAX_FUNCTIONS

    hook_mgr = get_hook_manager()
    if hooks_dir:
        hook_mgr.load_dir(hooks_dir)

    ctx = {'binary_path': binary_path, 'status': 'init'}
    ctx = hook_mgr.run('pre_unpack', ctx)
    if ctx.get('status') == 'abort':
        return {'error': 'aborted by pre_unpack hook'}

    # --- validate ---
    if not validate_binary(binary_path):
        return {'error': f'Unsupported or missing file: {binary_path}'}

    binfo = get_binary_info(binary_path)
    binary_hash = _hash_file(binary_path)
    run_id = start_run(binary_path)

    logger.info("Binary: %s | %s %d-bit | size=%d",
                binfo['filename'], binfo['arch'], binfo['bits'], binfo['size'])

    # --- unpacking ---
    if ENABLE_UNPACK:
        ctx = hook_mgr.run('pre_decompile', ctx)

    # --- function discovery ---
    all_funcs = list_functions(binary_path)
    logger.info("Found %d functions", len(all_funcs))

    if functions:
        target_funcs = [f for f in functions if f in all_funcs]
        if not target_funcs:
            target_funcs = functions
    else:
        # prefer user-facing functions
        priority = ('main', 'vuln', 'win', 'get_flag', 'read_input',
                    'process', 'parse', 'handle', 'init')
        target_funcs = [f for f in priority if f in all_funcs]
        if not target_funcs:
            target_funcs = all_funcs[:max_funcs]

    target_funcs = target_funcs[:max_funcs]
    logger.info("Analyzing %d functions", len(target_funcs))

    # --- decompile + AI analyze ---
    ctx = hook_mgr.run('pre_analysis', ctx)
    decomp_results = []

    def _analyze_one(func_name):
        r = decompile_function(binary_path, func_name, decompiler)
        if r['pseudocode'].strip():
            ai = ai_analyze_function(func_name, r['pseudocode'], binfo)
            return ai
        return {'function': func_name, 'vulnerabilities': [],
                'pseudocode': r.get('pseudocode', '')}

    if parallel and len(target_funcs) > 1:
        max_workers = min(MAX_PARALLEL, len(target_funcs))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_analyze_one, n): n for n in target_funcs}
            for fut in as_completed(futures):
                try:
                    decomp_results.append(fut.result())
                except Exception as e:
                    logger.error("Analysis worker failed: %s", e)
    else:
        for name in target_funcs:
            try:
                decomp_results.append(_analyze_one(name))
            except Exception as e:
                logger.error("Analysis of %s failed: %s", name, e)

    ctx = hook_mgr.run('post_analysis', ctx)

    # --- symbolic execution ---
    sym_result = None
    if ENABLE_SYMBOLIC and check_angr():
        logger.info("Running symbolic execution...")
        sym_result = run_symbolic(binary_path)

    # --- crash analysis ---
    crash_data = None
    crash_analysis = None
    if crash_path and os.path.isfile(crash_path):
        crash_data = load_crash_file(crash_path)
        if crash_data:
            crash_analysis = analyze_crash_for_exploit(crash_data)

    # --- crypto scan ---
    if ENABLE_CRYPTO_SCAN:
        try:
            from plugins.crypto_scan import scan_crypto
            crypto = scan_crypto(binary_path)
            logger.info("Crypto scan: %d constants found", len(crypto))
        except ImportError:
            pass

    # --- save findings ---
    all_vulns = []
    for r in decomp_results:
        analysis = r.get('analysis', r)
        for v in analysis.get('vulnerabilities', []):
            all_vulns.append(v)
            try:
                save_finding(
                    run_id, binary_path, binary_hash,
                    r.get('function_name', r.get('function', '?')),
                    v.get('type', '?'), v.get('severity', 'Unknown'),
                    v.get('cwe', ''), v.get('description', ''),
                )
            except Exception:
                pass

    # --- exploit generation ---
    exploit_result = None
    if crAsh_analysis and crash_analysis.get('exploitable'):
        exploit_result = generate_exploit(binfo, crash_data)

    # --- report ---
    ctx = hook_mgr.run('pre_report', ctx)
    reports = write_report(decomp_results, binfo, crash_analysis, output_format)
    ctx = hook_mgr.run('post_report', ctx)

    # --- wrap up ---
    elapsed = time.time() - start_time
    finish_run(run_id, 'completed',
               f'{len(all_vulns)} vulns in {elapsed:.1f}s')

    logger.info("Pipeline done in %.1fs | %d functions | %d vulns",
                elapsed, len(target_funcs), len(all_vulns))

    return {
        'reports': reports,
        'decomp_analysis': decomp_results,
        'crash_analysis': crash_analysis,
        'crash_data': crash_data,
        'symbolic_execution': sym_result,
        'exploit_result': exploit_result,
        'binary_info': binfo,
        'elapsed': elapsed,
        'total_vulns': len(all_vulns),
    }
