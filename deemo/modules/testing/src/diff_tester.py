# 差分测试核心 — 多引擎输出比对 + Oracle共识判定
# 核心思想: 多个引擎处理同一输入，输出不一致处标记为差异。
# Oracle机制: 多数票（>=50%引擎输出一致），不要求100%共识。
from dataclasses import dataclass, field
from typing import List, Dict, Any, Callable, Optional, Tuple
import hashlib
import json
import time
from collections import defaultdict
import uuid


@dataclass
class TestCase:
    id: str
    input_data: bytes
    expected_output: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


@dataclass
class DiffResult:
    test_case: TestCase
    engine_outputs: Dict[str, Any]  # engine_name -> output
    diff_type: str                  # NONE | CONSENSUS_FAIL | ENGINE_MISMATCH | CRASH | TIMEOUT
    differences: List[Dict[str, Any]] = field(default_factory=list)
    oracle_output: Any = None
    diverging_engines: List[str] = field(default_factory=list)
    duration_ms: float = 0.0


class OracleComparator:
    """多引擎输出比对，多数票决定oracle。

    若>=50%参与计算的引擎结果一致，视为oracle。
    """
    @staticmethod
    def compare(results: Dict[str, Any]) -> Tuple[Optional[Any], List[str], Dict[str, List[str]]]:
        """比较输出。返回 (oracle_output, diverging_engines, groups)。

        多数票判定: 严格超过半数 (>50%) 才认可 oracle。
        平局/无多数时 oracle 为 None，全部引擎计入 diverging。
        """
        if not results:
            return None, [], {}

        # 按输出哈希分组
        _groups: Dict[str, List[str]] = defaultdict(list)
        for _engine, _output in results.items():
            _h = OracleComparator._hash_output(_output)
            _groups[_h].append(_engine)

        # 按组大小排序
        _sorted_groups = sorted(_groups.values(), key=len, reverse=True)
        _total = len(results)
        _largest = _sorted_groups[0] if _sorted_groups else []

        if len(_largest) > _total * 0.5:
            # 存在多数共识 oracle
            _oracle_hash = None
            for _h, _engines in _groups.items():
                if _engines == _largest:
                    _oracle_hash = _h
                    break
            _oracle = None
            # 定位实际输出
            for _e, _o in results.items():
                if OracleComparator._hash_output(_o) == _oracle_hash:
                    _oracle = _o
                    break
            _diverging = [_e for _e in results if _e not in _largest]
            return _oracle, _diverging, dict(_groups)
        else:
            return None, list(results.keys()), dict(_groups)

    @staticmethod
    def determine_oracle(outputs: Dict[str, Any]) -> Optional[Any]:
        """严格多数: >50%才返回oracle。"""
        _oracle, _div, _ = OracleComparator.compare(outputs)
        return _oracle

    @staticmethod
    def find_differences(results: Dict[str, Any],
                         oracle: Any) -> List[Dict[str, Any]]:
        """定位各引擎与oracle不一致的具体差异。"""
        _diffs = []
        _oracle_hash = OracleComparator._hash_output(oracle) if oracle is not None else None
        for _engine, _output in results.items():
            if OracleComparator._hash_output(_output) != _oracle_hash:
                _diffs.append({
                    "engine": _engine,
                    "expected": oracle,
                    "actual": _output,
                    "expected_hash": _oracle_hash,
                    "actual_hash": OracleComparator._hash_output(_output),
                    "output_preview": str(_output)[:200],
                })
        return _diffs

    @staticmethod
    def _hash_output(output: Any) -> str:
        """对任意输出做哈希用于比较。"""
        if isinstance(output, (bytes, bytearray)):
            return hashlib.sha256(output).hexdigest()
        if isinstance(output, str):
            return hashlib.sha256(output.encode()).hexdigest()
        if isinstance(output, dict):
            _s = json.dumps(output, sort_keys=True, default=str)
            return hashlib.sha256(_s.encode()).hexdigest()
        return hashlib.sha256(str(output).encode()).hexdigest()


def _compare_results(engine_results: Dict[str, Any]) -> str:
    """内部比较: 先快检崩溃，再比对输出内容。

    返回 diff_type: NONE | ENGINE_MISMATCH | CRASH | TIMEOUT | CONSENSUS_FAIL
    """
    _h_grouped = defaultdict(list)
    for _e, _r in engine_results.items():
        # 崩溃防护: 检测异常对象
        if _r is None:
            return "CRASH"
        if isinstance(_r, Exception):
            return "CRASH"
        _h = OracleComparator._hash_output(_r)
        _h_grouped[_h].append(_e)

    if len(_h_grouped) == 1:
        return "NONE"
    elif len(_h_grouped) == len(engine_results):
        return "CONSENSUS_FAIL"
    else:
        return "ENGINE_MISMATCH"


class DifferentialTester:
    """差分测试器 — 注册多个引擎，对比输出差异。

    使用方法:
        dt = DifferentialTester()
        dt.add_engine("native", native_run_func)
        dt.add_engine("qemu", qemu_run_func)
        results = dt.run_tests(test_cases)
    """

    def __init__(self):
        self._engines: Dict[str, Callable[[bytes], Any]] = {}
        self._engine_meta: Dict[str, Dict] = {}
        self._comparator = OracleComparator()
        self._results: List[DiffResult] = []
        self._stats: Dict[str, Dict] = defaultdict(lambda: {"pass": 0, "fail": 0, "crash": 0, "timeout": 0})

# 引擎管理
    def add_engine(self, name: str, run_func: Callable[[bytes], Any],
                   meta: Dict = None):
        self._engines[name] = run_func
        self._engine_meta[name] = meta or {}

    def remove_engine(self, name: str):
        self._engines.pop(name, None)
        self._engine_meta.pop(name, None)

    def list_engines(self) -> List[str]:
        return list(self._engines.keys())

# 测试执行
    def run_tests(self, test_cases: List[TestCase]) -> List[DiffResult]:
        self._results = []
        for _tc in test_cases:
            _dr = self.run_single(_tc)
            self._results.append(_dr)
        return self._results

    def run_single(self, test_case: TestCase) -> DiffResult:
        """在全部引擎上执行单个测试用例。"""
        _outputs = {}
        _crashes = []
        _t0 = time.perf_counter()

        for _name, _func in self._engines.items():
            try:
                _out = _func(test_case.input_data)
                _outputs[_name] = _out
            except Exception as _e:
                _crashes.append(_name)
                _outputs[_name] = _e

        _dt = time.perf_counter() - _t0
        _diff_type = _compare_results(_outputs)

        _oracle, _diverging, _groups = self._comparator.compare(_outputs)
        _diffs = self._comparator.find_differences(_outputs, _oracle) if _oracle else []

        # 更新统计
        for _name in self._engines:
            if _name in _crashes:
                self._stats[_name]["crash"] += 1
            elif _name in _diverging:
                self._stats[_name]["fail"] += 1
            else:
                self._stats[_name]["pass"] += 1

        return DiffResult(
            test_case=test_case,
            engine_outputs=_outputs,
            diff_type=_diff_type,
            differences=_diffs,
            oracle_output=_oracle,
            diverging_engines=_diverging,
            duration_ms=_dt * 1000,
        )

# 结果
    def results_summary(self) -> Dict[str, Any]:
        _pass = sum(1 for _r in self._results if _r.diff_type == "NONE")
        return {
            "total": len(self._results),
            "pass": _pass,
            "fail": len(self._results) - _pass,
            "engines": dict(self._stats),
        }

    def by_engine_summary(self) -> Dict[str, Dict]:
        return dict(self._stats)


def generate_report(results: List[DiffResult]) -> str:
    """差分测试结果文本摘要。"""
    _lines = ["=" * 60, "Differential Testing Report", "=" * 60]

    _by_type = defaultdict(list)
    for _r in results:
        _by_type[_r.diff_type].append(_r)

    for _dt in ("NONE", "ENGINE_MISMATCH", "CONSENSUS_FAIL", "CRASH"):
        _group = _by_type.get(_dt, [])
        _lines.append(f"\n[{_dt}] ({len(_group)} cases)")
        for _dr in _group[:5]:  # 仅展示前5条
            _lines.append(f"  - {_dr.test_case.id}: {', '.join(_dr.diverging_engines or ['none'])}")
        if len(_group) > 5:
            _lines.append(f"  ... and {len(_group) - 5} more")

    _lines.append(f"\nTotal: {len(results)} cases across {len(results[0].engine_outputs) if results else 0} engines")
    return "\n".join(_lines)
