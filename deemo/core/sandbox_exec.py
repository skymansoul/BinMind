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

# 全局安全开关: 默认禁用真实执行, 仅允许 dry-run 语法检查
ENABLE_EXPLOIT_EXEC = False

# 白名单目录: 只有这些目录下的目标二进制才允许执行
# 空列表表示禁止任何真实执行
_ALLOWED_EXEC_DIRS: List[str] = []


def set_exploit_exec_enabled(enabled: bool, allowed_dirs: Optional[List[str]] = None) -> None:
    """显式开启真实执行; 可选指定白名单目录。"""
    global ENABLE_EXPLOIT_EXEC, _ALLOWED_EXEC_DIRS
    ENABLE_EXPLOIT_EXEC = bool(enabled)
    if allowed_dirs is not None:
        _ALLOWED_EXEC_DIRS = [os.path.realpath(d) for d in allowed_dirs]


def _is_target_allowed(target_binary: str) -> bool:
    """白名单校验: 目标二进制必须位于允许的目录之下。"""
    if not target_binary:
        return False
    if not _ALLOWED_EXEC_DIRS:
        return False
    real = os.path.realpath(target_binary)
    return any(real.startswith(d + os.sep) or real == d for d in _ALLOWED_EXEC_DIRS)


def run_sandbox_validation(files, blackboard=None, **kw) -> List[Dict[str, Any]]:
    """对 files 中每个 exploit 脚本做 dry-run 语法检查, 返回结果列表。

    files: 脚本路径列表或单个路径字符串。
    无脚本时返回空列表; 单个脚本失败时返回含 error 的单元素列表。
    安全策略: 默认仅 dry-run; 真实执行需显式调用 set_exploit_exec_enabled(True)。
    """
    from core.exploit_executor import execute_exploit

    if not files:
        return []

    if isinstance(files, str):
        files = [files]

    # 安全策略: 非白名单目标或全局开关关闭时, 强制降级为 dry-run
    requested_sandbox = kw.get('sandbox', 'dry-run')
    target_binary = kw.get('target_binary', '')
    if requested_sandbox != 'dry-run':
        if not ENABLE_EXPLOIT_EXEC:
            _log.warning("真实执行被全局开关阻止, 降级为 dry-run: %s", target_binary)
            requested_sandbox = 'dry-run'
        elif not _is_target_allowed(target_binary):
            _log.warning("目标二进制不在白名单目录, 降级为 dry-run: %s", target_binary)
            requested_sandbox = 'dry-run'

    results: List[Dict[str, Any]] = []
    for script_path in files:
        if not isinstance(script_path, str) or not os.path.isfile(script_path):
            results.append({'script': str(script_path), 'error': 'file not found'})
            continue
        # dry-run 仅做语法检查, 不实际执行
        res = execute_exploit(
            script_path=script_path,
            target_binary=target_binary,
            sandbox=requested_sandbox,
            timeout=kw.get('timeout', 10),
        )
        res['script'] = script_path
        results.append(res)

    return results
