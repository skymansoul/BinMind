# 沙箱执行验证 - 对 core.exploit_executor 的薄封装
# MinGW 环境下不提供真沙箱; 语法级验证由 heap_overflow_src_verifier 完成
# 实际 exploit 执行委托给 exploit_executor.execute_exploit (subprocess/docker/dry-run)
"""沙箱执行入口 - 委托至 exploit_executor。

保留 run_sandbox_validation 接口以兼容旧调用方;
内部转发到 core.exploit_executor.execute_exploit, 不再是静默 stub。
"""
import logging
import os
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)


def run_sandbox_validation(files, blackboard=None, **kw) -> List[Dict[str, Any]]:
    """对 files 中每个 exploit 脚本做 dry-run 语法检查, 返回结果列表。

    files: 脚本路径列表或单个路径字符串。
    无脚本时返回空列表; 单个脚本失败时返回含 error 的单元素列表。
    """
    from core.exploit_executor import execute_exploit

    if not files:
        return []

    if isinstance(files, str):
        files = [files]

    results: List[Dict[str, Any]] = []
    for script_path in files:
        if not isinstance(script_path, str) or not os.path.isfile(script_path):
            results.append({'script': str(script_path), 'error': 'file not found'})
            continue
        # dry-run 仅做语法检查, 不实际执行
        res = execute_exploit(
            script_path=script_path,
            target_binary=kw.get('target_binary', ''),
            sandbox='dry-run',
            timeout=kw.get('timeout', 10),
        )
        res['script'] = script_path
        results.append(res)

    return results
