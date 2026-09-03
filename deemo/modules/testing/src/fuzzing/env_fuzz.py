"""环境变量模糊测试——枚举 getenv 引用 -> 对每个变量生成 10 种变异"""
import os
import subprocess
import logging
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)


def _signal_name(code: int) -> str:
    """信号编号映射为可读名称"""
    sigs = {1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL",
            5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE",
            9: "SIGKILL", 10: "SIGUSR1", 11: "SIGSEGV", 12: "SIGUSR2",
            13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM", 16: "SIGSTKFLT",
            17: "SIGCHLD", 18: "SIGCONT", 19: "SIGSTOP"}
    return sigs.get(code, f"SIG({code})")


def collect_env_variables(target_path: str) -> Dict[str, str]:
    """二进制字符串中扫描 getenv 引用，收集目标使用的环境变量"""
    _vars = {}
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
    for _key in ["HOME", "PATH", "USER", "SHELL", "LANG", "TMPDIR", "TEMP", "TERM"]:
        if _key in os.environ:
            _vars[_key] = os.environ[_key]
    return _vars


def generate_env_mutations(base: Dict[str, str]) -> List[Dict[str, str]]:
    """生成环境变量变异——空值/长字符串/格式串/路径遍历/null 注入/特殊字符/溢出"""
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

        _m = dict(base)
        _m[_key] = _orig_val.upper()
        _mutations.append(_m)

    return _mutations


def fuzz_env(target_path: str,
             env_vars: Dict[str, str],
             timeout: float = 5.0) -> List[Dict[str, Any]]:
    """环境变量模糊测试——每组变异启动目标，记录崩溃信号"""
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
            _crashed = _r.returncode < 0 or _r.returncode >= 128
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
    """env fuzz 结果摘要"""
    _crashes = [_r for _r in results if _r.get("crashed")]
    _timeouts = [_r for _r in results if _r.get("exit_code") == -1]
    _lines = [
        "环境变量模糊测试摘要",
        f"总变异次数: {len(results)}",
        f"崩溃: {len(_crashes)}",
        f"超时: {len(_timeouts)}",
        f"正常退出: {len(results) - len(_crashes) - len(_timeouts)}",
        "",
    ]
    if _crashes:
        _lines.append("崩溃变异:")
        for _c in _crashes[:10]:
            _lines.append(f"  exit={_c['exit_code']} | {_c['mutation'][:100]}")
    return "\n".join(_lines)


class RuntimeEnvironmentVariableFuzzer:
    """运行时环境变量与命令行参数模糊测试——启动阶段漏洞检测"""

    def __init__(self):
        self.fuzz_cases: List[Dict[str, Any]] = []
        self.test_results: List[Dict[str, Any]] = []
        self.found_vulnerabilities: List[Dict[str, Any]] = []
        self._generate_fuzz_cases()

    def _generate_fuzz_cases(self):
        """构建环境变量与命令行参数模糊测试用例集"""
        env_fuzz_cases = [
            {'name': 'PATH', 'value': '/very/long/path/' * 100},
            {'name': 'HOME', 'value': '/nonexistent'},
            {'name': 'LD_LIBRARY_PATH', 'value': '/malicious/lib'},
            {'name': 'LANG', 'value': 'invalid_lang'},
            {'name': 'TERM', 'value': 'invalid_term'},
            {'name': 'SHELL', 'value': '/bin/nonexistent'},
            {'name': 'USER', 'value': ''},
            {'name': 'PWD', 'value': '/very/deep/path/' * 50},
            {'name': 'LD_PRELOAD', 'value': '/tmp/evil.so'},
            {'name': 'PYTHONPATH', 'value': '/malicious/py'},
            {'name': 'IFS', 'value': '\t\n'},
            {'name': 'TMPDIR', 'value': '/nonexistent/' * 20},
        ]

        arg_fuzz_cases = [
            ['--help', '--invalid'],
            ['-x' * 100],
            ['', ''],
            ['--config=/nonexistent'],
            ['--debug', '--verbose', '--invalid'],
            ['-%s' * 50],
            ['--format=%n%n%n'],
            ['-' + '\x00' * 4],
        ]

        self.fuzz_cases = [
            {'type': 'environment', 'cases': env_fuzz_cases},
            {'type': 'arguments', 'cases': arg_fuzz_cases}
        ]

    def fuzz_environment_variables(self, binary_path: str) -> List[Dict[str, Any]]:
        """环境变量模糊测试——信号终止记录为漏洞"""
        results = []

        for case in self.fuzz_cases[0]['cases']:
            env = {case['name']: case['value']}

            try:
                process = subprocess.Popen(
                    [binary_path],
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10
                )

                stdout, stderr = process.communicate(timeout=10)

                result = {
                    'case': case,
                    'return_code': process.returncode,
                    'stdout': stdout.decode('utf-8', errors='replace')[:500],
                    'stderr': stderr.decode('utf-8', errors='replace')[:500],
                    'crashed': process.returncode != 0
                }

                results.append(result)

                if process.returncode < 0:
                    self.found_vulnerabilities.append({
                        'type': 'environment_crash',
                        'env_var': case['name'],
                        'value': case['value'],
                        'signal': -process.returncode,
                        'signal_name': _signal_name(-process.returncode),
                    })

            except subprocess.TimeoutExpired:
                results.append({
                    'case': case,
                    'error': 'timeout'
                })
            except Exception as e:
                results.append({
                    'case': case,
                    'error': str(e)
                })

        self.test_results.extend(results)
        return results

    def fuzz_command_line_arguments(self, binary_path: str) -> List[Dict[str, Any]]:
        """命令行参数模糊测试"""
        results = []

        for args in self.fuzz_cases[1]['cases']:
            try:
                process = subprocess.Popen(
                    [binary_path] + args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10
                )

                stdout, stderr = process.communicate(timeout=10)

                result = {
                    'arguments': args,
                    'return_code': process.returncode,
                    'stdout': stdout.decode('utf-8', errors='replace')[:500],
                    'stderr': stderr.decode('utf-8', errors='replace')[:500],
                    'crashed': process.returncode != 0
                }

                results.append(result)

            except subprocess.TimeoutExpired:
                results.append({
                    'arguments': args,
                    'error': 'timeout'
                })
            except Exception as e:
                results.append({
                    'arguments': args,
                    'error': str(e)
                })

        self.test_results.extend(results)
        return results

    def generate_fuzz_report(self) -> str:
        """模糊测试报告"""
        report = '# 环境变量与参数模糊测试报告\n\n'

        report += '## 测试统计\n'
        report += f'- 测试用例总数: {len(self.test_results)}\n'
        report += f'- 发现的漏洞数: {len(self.found_vulnerabilities)}\n\n'

        if self.found_vulnerabilities:
            report += '## 发现的漏洞\n'
            for vuln in self.found_vulnerabilities:
                report += f'- 类型: {vuln["type"]}\n'
                if 'env_var' in vuln:
                    report += f'  环境变量: {vuln["env_var"]}\n'
                report += f'  信号: {vuln.get("signal", "N/A")}\n'
                if 'signal_name' in vuln:
                    report += f'  信号名: {vuln["signal_name"]}\n'

        return report
