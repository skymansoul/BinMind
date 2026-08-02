# 2026-07-28
# Environment variable fuzzing — 枚举 + 变异 + crash 检测
# 策略：收集目标进程使用的所有环境变量 → 对每个变量应用变异策略
# → 运行目标 → 检查是否崩溃。
import os
import subprocess
import time
import hashlib
from typing import List, Dict, Any, Optional, Tuple


# ================================================
def collect_env_variables(target_path: str) -> Dict[str, str]:
    """收集目标二进制使用的环境变量。
    通过 strace/dtrace 或二进制字符串分析。
    """
    _vars = {}
    # 尝试通过二进制中的 getenv 调用找到引用
    try:
        with open(target_path, "rb") as _f:
            _data = _f.read()
        _getenv_patterns = [
            b"getenv", b"secure_getenv", b"environ",
            b"HOME=", b"PATH=", b"USER=", b"LANG=", b"TMPDIR=",
            b"LD_PRELOAD", b"LD_LIBRARY_PATH", b"DYLD_",
        ]
        for _pat in _getenv_patterns:
            if _pat in _data:
                _vars[_pat.decode(errors="replace")] = os.environ.get(
                    _pat.decode(errors="replace"), "")
    except (OSError, IOError):
        pass
    # 填充通用变量
    for _key in ["HOME", "PATH", "USER", "SHELL", "LANG", "TMPDIR", "TEMP", "TERM"]:
        if _key in os.environ:
            _vars[_key] = os.environ[_key]
    return _vars


def generate_env_mutations(base: Dict[str, str]) -> List[Dict[str, str]]:
    """生成环境变量变异列表。

    策略：
    - empty: 空字符串
    - long: 10KB 'A' 填充
    - fmt: %s%n%x 格式字符串
    - path_traversal: ../../../etc/passwd
    - null_byte: \x00 注入
    - special: 换行、制表符、引号
    - numeric: 超范围值
    """
    _mutations = []
    _strategies = [
        ("", "empty"),
        ("A" * 10240, "long"),
        ("%s" * 100, "fmt_%s"),
        ("%n" * 100, "fmt_%n"),
        ("%x" * 100, "fmt_%x"),
        ("../../../etc/passwd", "path_traversal"),
        ("A\x00B\x00C", "null_byte"),
        ("\n\r\t\"'\\", "special_chars"),
        ("-1", "negative"),
        ("99999999999999999999", "overflow"),
    ]

    for _key, _orig_val in base.items():
        for _val, _name in _strategies:
            _m = dict(base)
            _m[_key] = _val
            _mutations.append(_m)

        # 随机大写变体
        _m = dict(base)
        _m[_key] = _orig_val.upper()
        _mutations.append(_m)

    return _mutations


def fuzz_env(target_path: str,
             env_vars: Dict[str, str],
             timeout: float = 5.0) -> List[Dict[str, Any]]:
    """对环境变量进行 fuzz。对每个变异，启动目标进程并检测 crash。

    Returns: [{mutation: dict, exit_code: int, crashed: bool, output: str}, ...]
    """
    import tempfile
    _results = []
    _mutations = generate_env_mutations(env_vars)
    _base_env = dict(os.environ)

    for _mutation in _mutations:
        _env = dict(_base_env)
        for _k, _v in _mutation.items():
            _env[_k] = _v

        try:
            _r = subprocess.run(
                [target_path],
                env=_env,
                timeout=timeout,
                capture_output=True,
            )
            _crashed = _r.returncode < 0 or _r.returncode >= 128  # signal
            _results.append({
                "mutation": str(_mutation),
                "exit_code": _r.returncode,
                "crashed": _crashed,
                "stdout": _r.stdout[:500].decode(errors="replace"),
                "stderr": _r.stderr[:500].decode(errors="replace"),
            })
        except subprocess.TimeoutExpired:
            _results.append({
                "mutation": str(_mutation),
                "exit_code": -1,
                "crashed": False,
                "stdout": "",
                "stderr": "Timeout",
            })
        except Exception as _e:
            _results.append({
                "mutation": str(_mutation),
                "exit_code": -2,
                "crashed": True,
                "stdout": "",
                "stderr": str(_e),
            })

    return _results


def env_fuzz_summary(results: List[Dict[str, Any]]) -> str:
    """格式化的 env fuzz 摘要。"""
    _crashes = [_r for _r in results if _r.get("crashed")]
    _timeouts = [_r for _r in results if _r.get("exit_code") == -1]
    _lines = [
        "Environment Variable Fuzzing Summary",
        f"Total mutations: {len(results)}",
        f"Crashes: {len(_crashes)}",
        f"Timeouts: {len(_timeouts)}",
        f"Clean exits: {len(results) - len(_crashes) - len(_timeouts)}",
        "",
    ]
    if _crashes:
        _lines.append("Crash mutations:")
        for _c in _crashes[:10]:
            _lines.append(f"  exit={_c['exit_code']} | {_c['mutation'][:100]}")
    return "\n".join(_lines)
