"""
回归测试 — 扫描调度模块

负责:
  - 对已编译样本调度 BinMind + angr + Ghidra 扫描
  - 超时控制、错误隔离、结果暂存
  - 每个样本独立扫描，单个失败不影响其他

创建: 2026-06-15
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@dataclass
class ToolResult:
    """单个工具对一个样本的扫描结果."""
    tool_name: str          # 'binmind' | 'angr' | 'ghidra'
    sample_name: str
    binary_path: str
    verdict: str = ""       # OVERFLOW | SAFE | ERROR | TIMEOUT | SKIP
    confidence: float = 0.0
    elapsed_ms: float = 0.0
    error: str = ""
    raw_output: str = ""
    findings: List[Dict] = field(default_factory=list)


@dataclass
class ScanReport:
    """一个样本的完整扫描报告（含所有工具结果）."""
    sample_name: str
    binary_path: str
    results: List[ToolResult] = field(default_factory=list)
    total_elapsed_ms: float = 0.0

    @property
    def binmind_result(self) -> Optional[ToolResult]:
        for r in self.results:
            if r.tool_name == 'binmind':
                return r
        return None

    @property
    def passed_tools(self) -> List[str]:
        return [r.tool_name for r in self.results if r.verdict not in ('ERROR', 'TIMEOUT', 'SKIP')]


class ScanScheduler:
    """扫描调度器 — 对样本清单执行多工具扫描."""

    DEFAULT_TIMEOUT_S = 30  # 单样本单工具超时
    DEFAULT_GLOBAL_TIMEOUT_S = 600  # 全部扫描总超时

    def __init__(
        self,
        timeout_s: int = 0,
        global_timeout_s: int = 0,
        enable_angr: bool = True,
        enable_ghidra: bool = True,
        verbose: bool = False,
    ):
        self.timeout_s = timeout_s or self.DEFAULT_TIMEOUT_S
        self.global_timeout_s = global_timeout_s or self.DEFAULT_GLOBAL_TIMEOUT_S
        self.enable_angr = enable_angr
        self.enable_ghidra = enable_ghidra
        self.verbose = verbose
        self._reports: List[ScanReport] = []

    def scan_all(self, manifest: List[Any]) -> List[ScanReport]:
        """对清单中所有已编译样本执行扫描."""
        compiled = [m for m in manifest if m.binary_path and os.path.isfile(m.binary_path)]
        if self.verbose:
            print(f'[scan] {len(compiled)}/{len(manifest)} samples have binaries')

        t_start = time.perf_counter()
        self._reports = []

        for m in compiled:
            elapsed = time.perf_counter() - t_start
            if elapsed > self.global_timeout_s:
                print(f'[scan] global timeout ({self.global_timeout_s}s), stopping at {m.name}')
                break

            report = self._scan_one_sample(m)
            self._reports.append(report)

            if self.verbose:
                tools_ok = len(report.passed_tools)
                print(f'[scan] {m.name}: {tools_ok} tools passed')

        return self._reports

    # 工具注册表: {name: (script_relpath, args_template, timeout_padding, parser)}
    _TOOL_REGISTRY = {
        'binmind': (
            ['eval', 'run_benchmark.py'],
            ['--single', '{binary}', '--json'], 0, '_parse_binmind_json',
        ),
        'angr': (
            ['eval', 'angr_explorer.py'],
            ['--binary', '{binary}', '--timeout', '{timeout}'], 5, '_parse_tool_json',
        ),
        'ghidra': (
            ['eval', 'ghidra_headless.py'],
            ['--binary', '{binary}', '--timeout', '{timeout}'], 10, '_parse_tool_json',
        ),
    }

    def _scan_one_sample(self, m: Any) -> ScanReport:
        """扫描单个样本 — BinMind 必执行，angr/ghidra 可选."""
        report = ScanReport(sample_name=m.name, binary_path=m.binary_path)
        enabled = {'binmind': True, 'angr': self.enable_angr, 'ghidra': self.enable_ghidra}
        for tool, ok in enabled.items():
            if not ok:
                continue
            t0 = time.perf_counter()
            r = self._run_tool(tool, m)
            r.elapsed_ms = (time.perf_counter() - t0) * 1000
            report.results.append(r)
        report.total_elapsed_ms = sum(r.elapsed_ms for r in report.results)
        return report

    def _run_tool(self, tool_name: str, m: Any) -> ToolResult:
        """执行外部工具 — 统一的 subprocess 调用 + 结果解析."""
        result = ToolResult(tool_name=tool_name, sample_name=m.name,
                            binary_path=m.binary_path)
        script_parts, args_tmpl, pad, parser_name = self._TOOL_REGISTRY[tool_name]
        script = os.path.join(PROJECT_ROOT, *script_parts)

        # BinMind 回退: 尝试 CLI 入口
        if tool_name == 'binmind' and not os.path.isfile(script):
            script = os.path.join(PROJECT_ROOT, 'binmind_cli.py')

        if not os.path.isfile(script):
            result.verdict = 'SKIP'
            result.error = f'{tool_name} entry not found'
            return result

        args = [a.format(binary=m.binary_path, timeout=str(self.timeout_s))
                for a in args_tmpl]
        try:
            proc = subprocess.run(
                [sys.executable, script] + args,
                capture_output=True, text=True, timeout=self.timeout_s + pad,
                cwd=PROJECT_ROOT,
            )
            result.raw_output = proc.stdout[:2000]
            parser = getattr(self, parser_name)
            parsed = parser(proc.stdout)
            result.verdict = parsed.get('verdict', 'ERROR')
            result.confidence = parsed.get('confidence', 0.0)
            result.findings = parsed.get('findings', [])
            if proc.returncode != 0 and not parsed:
                result.verdict = 'ERROR'
                result.error = proc.stderr[:200]
        except subprocess.TimeoutExpired:
            result.verdict = 'TIMEOUT'
            result.error = f'timeout ({self.timeout_s}s)'
        except Exception as e:
            result.verdict = 'ERROR'
            result.error = str(e)[:200]
        return result

    @staticmethod
    def _parse_binmind_json(stdout: str) -> Dict:
        """从 stdout 中提取 BinMind JSON 输出."""
        if not stdout.strip():
            return {}
        # BinMind 输出可能在多行中，搜索 JSON 块
        for line in stdout.split('\n'):
            line = line.strip()
            if line.startswith('{') and ('verdict' in line or 'overflow' in line):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        # 回退: 尝试解析整个输出
        try:
            return json.loads(stdout.strip())
        except json.JSONDecodeError:
            return {}

    @staticmethod
    def _parse_tool_json(stdout: str) -> Dict:
        """从 stdout 中提取通用工具 JSON 输出."""
        if not stdout.strip():
            return {}
        for line in stdout.split('\n'):
            line = line.strip()
            if line.startswith('{'):
                try:
                    data = json.loads(line)
                    if 'verdict' in data or 'overflow' in data:
                        return data
                except json.JSONDecodeError:
                    continue
        try:
            return json.loads(stdout.strip())
        except json.JSONDecodeError:
            return {}

    @property
    def reports(self) -> List[ScanReport]:
        return self._reports

    def summary(self) -> Dict:
        """扫描汇总."""
        total = len(self._reports)
        tools = {}
        for report in self._reports:
            for r in report.results:
                if r.tool_name not in tools:
                    tools[r.tool_name] = {'total': 0, 'ok': 0, 'timeout': 0,
                                          'error': 0, 'skip': 0}
                tools[r.tool_name]['total'] += 1
                if r.verdict in ('OVERFLOW', 'SAFE'):
                    tools[r.tool_name]['ok'] += 1
                elif r.verdict == 'TIMEOUT':
                    tools[r.tool_name]['timeout'] += 1
                elif r.verdict == 'ERROR':
                    tools[r.tool_name]['error'] += 1
                else:
                    tools[r.tool_name]['skip'] += 1

        return {
            'samples_scanned': total,
            'tools': tools,
            'total_elapsed_ms': round(
                sum(r.total_elapsed_ms for r in self._reports), 1),
        }


__all__ = ['ToolResult', 'ScanReport', 'ScanScheduler', 'PROJECT_ROOT']
