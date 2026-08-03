"""模糊测试、协议分析——Fuzzer 集成、并发测试、覆盖率追踪、网络协议逆向"""
from typing import Dict, Any, List, Set, Optional, Tuple
import logging
import re
import os
import json
import subprocess
import datetime
import hashlib
import time
import threading
import socket
import math
import sqlite3
import struct
from collections import defaultdict, Counter, deque
from collections import OrderedDict
from pathlib import Path

_CACHE_SALT = 0x9e3779b9
_STALE_LIMIT = 3600

logger = logging.getLogger(__name__)


# ==================== 工具函数 ====================
def _bkdr_hash(s: str) -> int:
    h = 0
    for ch in s:
        h = ((h << 5) + h) + ord(ch)
        h &= 0xFFFFFFFF
    return h


def _signal_name(code: int) -> str:
    sigs = {1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL",
            5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE",
            9: "SIGKILL", 10: "SIGUSR1", 11: "SIGSEGV", 12: "SIGUSR2",
            13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM", 16: "SIGSTKFLT",
            17: "SIGCHLD", 18: "SIGCONT", 19: "SIGSTOP"}
    return sigs.get(code, f"SIG({code})")


from modules.testing.src.fuzzing.fuzzer import FuzzerIntegration
from modules.testing.src.fuzzing.protocol import ProtocolFormatReverseEngineer
from modules.testing.src.fuzzing.concurrency import ConcurrencyVulnerabilityDetector
from modules.testing.src.fuzzing.vuln_search import VulnerabilityDatabaseFullTextSearch
from modules.testing.src.fuzzing.input_infer import ConstraintBasedInputStructureInferer
from modules.testing.src.fuzzing.coverage import BinaryFuzzingCoverageRealtimeStats
from modules.testing.src.fuzzing.env_fuzz import RuntimeEnvironmentVariableFuzzer
from modules.testing.src.fuzzing.fs_check import FirmwareFileSystemIntegrityChecker
from modules.testing.src.fuzzing.net_diff import NetworkServiceResponseDiffAnalyzer
from modules.testing.src.fuzzing.complexity import CodeComplexityGuidedResourceAllocator
from modules.testing.src.fuzzing.multi_fuzz import MultiModeFuzzingCoordinator


# ==================== 崩溃可利用性分类器 ====================
class CrashExploitabilityClassifier:
    """信号 + 错误消息 + 栈帧信息推断内存破坏类型"""

    def classify(self, signal_num: int, error_msg: str,
                 stack_frames: Optional[List[str]] = None) -> Dict[str, Any]:
        sig_name = _signal_name(signal_num)
        msg_lower = error_msg.lower()
        frames = stack_frames or []

        corruption_type = "unknown"
        confidence = 0.0
        indicators: List[str] = []

        if signal_num == 11:
            if "double free" in msg_lower or "invalid pointer" in msg_lower:
                corruption_type = "double_free"
                confidence = 0.75
                indicators.append("glibc_double_free_msg")
            elif "use after free" in msg_lower or "uaf" in msg_lower:
                corruption_type = "use_after_free"
                confidence = 0.80
                indicators.append("explicit_uaf_msg")
            elif "stack" in msg_lower or "stack smashing" in msg_lower:
                corruption_type = "stack_buffer_overflow"
                confidence = 0.85
                indicators.append("stack_smash_detected")
            elif any("free" in fn.lower() for fn in frames[:3]):
                corruption_type = "use_after_free"
                confidence = 0.55
                indicators.append("crash_in_free_path")
            elif any("malloc" in fn.lower() or "calloc" in fn.lower()
                     or "realloc" in fn.lower() for fn in frames[:3]):
                corruption_type = "heap_buffer_overflow"
                confidence = 0.50
                indicators.append("crash_in_alloc_path")
            elif "null" in msg_lower or "nullptr" in msg_lower:
                corruption_type = "null_deref"
                confidence = 0.70
                indicators.append("null_deref_msg")
            else:
                corruption_type = "heap_buffer_overflow"
                confidence = 0.35
                indicators.append("sigsegv_default")
        elif signal_num == 6:
            if "assert" in msg_lower:
                corruption_type = "assertion_failure"
                confidence = 0.40
                indicators.append("assert_triggered")
            elif "corruption" in msg_lower:
                corruption_type = "heap_corruption"
                confidence = 0.65
                indicators.append("heap_corruption_abort")
            else:
                corruption_type = "abort_signal"
                confidence = 0.25
        elif signal_num == 8:
            corruption_type = "integer_overflow"
            confidence = 0.45
            indicators.append("sigfpe_arith")
        elif signal_num == 4:
            corruption_type = "code_execution"
            confidence = 0.70
            indicators.append("sigill_bad_insn")
        elif signal_num == 7:
            corruption_type = "misaligned_access"
            confidence = 0.50
            indicators.append("sigbus_align")

        return {
            "signal": sig_name,
            "corruption_type": corruption_type,
            "confidence": round(confidence, 2),
            "indicators": indicators,
            "exploitable": confidence >= 0.40,
        }


# ==================== Fuzzer 健康监控 ====================
class FuzzerHealthMonitor:
    """实时监控 fuzzer 运行指标——停滞检测 + 退化检测"""

    def __init__(self, window_seconds: float = 600.0):
        self._window = window_seconds
        self._samples: Dict[str, List[Tuple[float, Dict[str, Any]]]] = \
            defaultdict(list)
        self._lock = threading.Lock()

    def record(self, engine: str, exec_count: int,
               edge_count: int, crash_count: int) -> None:
        now = time.time()
        with self._lock:
            self._samples[engine].append((now, {
                'exec': exec_count, 'edges': edge_count,
                'crashes': crash_count}))
            cutoff = now - self._window
            self._samples[engine] = [
                (t, s) for t, s in self._samples[engine] if t >= cutoff]

    def stats(self, engine: str) -> Dict[str, Any]:
        with self._lock:
            entries = self._samples.get(engine, [])
        if len(entries) < 2:
            return {"engine": engine, "samples": len(entries),
                    "status": "warming"}
        first_t, first_s = entries[0]
        last_t, last_s = entries[-1]
        elapsed = max(0.1, last_t - first_t)
        exec_rate = (last_s['exec'] - first_s['exec']) / elapsed
        edge_delta = last_s['edges'] - first_s['edges']
        crash_delta = last_s['crashes'] - first_s['crashes']
        edge_rate = edge_delta / elapsed if elapsed > 0 else 0.0
        is_stalled = (edge_delta == 0 and elapsed > self._window / 2)
        return {
            "engine": engine,
            "samples": len(entries),
            "window_s": round(elapsed, 1),
            "exec_per_sec": round(exec_rate, 1),
            "edge_growth_rate": round(edge_rate, 3),
            "new_crashes": crash_delta,
            "status": "stalled" if is_stalled else "running",
        }

    def all_stats(self) -> Dict[str, Any]:
        return {
            eng: self.stats(eng)
            for eng in list(self._samples.keys())
        }


# ==================== Sanitizer Harness 生成器 ====================
class SanitizerHarnessGenerator:
    """目标二进制 sanitizer 编译命令与 harness 骨架生成"""

    SANITIZER_FLAGS = {
        'asan': '-fsanitize=address -fno-omit-frame-pointer -g',
        'msan': '-fsanitize=memory -fno-omit-frame-pointer -g',
        'ubsan': '-fsanitize=undefined -fno-omit-frame-pointer -g',
        'tsan': '-fsanitize=thread -fno-omit-frame-pointer -g',
        'all': '-fsanitize=address,undefined -fno-omit-frame-pointer -g',
    }

    def generate_cmake(self, target_name: str,
                       sanitizers: List[str],
                       source_files: List[str]) -> str:
        flags = ' '.join(
            self.SANITIZER_FLAGS[s]
            for s in sanitizers if s in self.SANITIZER_FLAGS)
        sources = ' '.join(source_files)
        return f"""# {target_name} sanitizer 构建配置
cmake_minimum_required(VERSION 3.16)
project({target_name}_sanitized)

set(CMAKE_C_FLAGS "${{CMAKE_C_FLAGS}} {flags}")
set(CMAKE_CXX_FLAGS "${{CMAKE_CXX_FLAGS}} {flags}")
set(CMAKE_EXE_LINKER_FLAGS "${{CMAKE_EXE_LINKER_FLAGS}} {flags}")

add_executable({target_name}_fuzz {sources})
target_link_libraries({target_name}_fuzz PRIVATE ${{FUZZ_LIBS}})
"""

    def generate_libfuzzer_driver(self, target_func: str,
                                  input_struct: str = "const uint8_t*") -> str:
        return f'''
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern int {target_func}({input_struct} data, size_t len);

// Sanitizer 感知入口——越界/未定义行为时立即中断
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size == 0) return 0;
    return {target_func}(data, size);
}}
'''

    def analyze_crash_for_sanitizer_recommendation(
            self, classification: Dict[str, Any]) -> List[str]:
        """崩溃分类 -> 最适合的 sanitizer 推荐"""
        ct = classification.get('corruption_type', 'unknown')
        recs = ['asan']
        if ct in ('use_after_free', 'double_free', 'heap_buffer_overflow',
                   'heap_corruption'):
            recs.append('msan')
        if ct in ('integer_overflow', 'misaligned_access'):
            recs.append('ubsan')
        if ct == 'code_execution':
            recs.extend(['asan', 'ubsan'])
        return recs


# ==================== ICS/SCADA 协议模糊测试模板 ====================
class ICSProtocolFuzzTemplates:
    """工控协议专用变异模板库——Modbus, CAN 等"""

    MODBUS_HEADER = b'\x00\x01\x00\x00\x00\x06\x01'

    @staticmethod
    def modbus_read_coils(unit_id: int = 1,
                          start_addr: int = 0,
                          count: int = 10) -> bytes:
        header = bytearray(ICSProtocolFuzzTemplates.MODBUS_HEADER)
        header[6] = unit_id
        func = bytes([0x01])
        addr = struct.pack('>H', start_addr)
        cnt = struct.pack('>H', count)
        pdu_len = 1 + len(addr) + len(cnt)
        header[4:6] = struct.pack('>H', pdu_len)
        return bytes(header) + func + addr + cnt

    @staticmethod
    def modbus_mutants(base_pdu: bytes) -> List[bytes]:
        """Modbus PDU 结构保持变异——长度不匹配/功能码高位置位/事务ID归零/单元扫描"""
        if len(base_pdu) < 4:
            return [base_pdu]
        mutants = []
        buf = bytearray(base_pdu)
        mismatch = bytearray(buf)
        mismatch[4:6] = struct.pack('>H', 0xFFFF)
        mutants.append(bytes(mismatch))
        func_high = bytearray(buf)
        if len(func_high) > 7:
            func_high[7] |= 0x80
        mutants.append(bytes(func_high))
        zero_tid = bytearray(buf)
        zero_tid[0:2] = b'\x00\x00'
        mutants.append(bytes(zero_tid))
        for uid in (0, 127, 247, 255):
            unit_scan = bytearray(buf)
            unit_scan[6] = uid
            mutants.append(bytes(unit_scan))
        return mutants

    @staticmethod
    def can_frame(arb_id: int = 0x7DF,
                  data: bytes = b'\x02\x01\x0D') -> bytes:
        dlc = min(8, len(data))
        padded = data[:dlc].ljust(dlc, b'\x00')
        return struct.pack('<IB8s', arb_id & 0x7FF, dlc, padded)

    @staticmethod
    def can_mutants(base_frame: bytes) -> List[bytes]:
        """CAN 帧变异——DLC 超限/仲裁 ID 遍历"""
        if len(base_frame) < 13:
            return [base_frame]
        mutants = []
        oversized = bytearray(base_frame)
        oversized[4] = 15
        mutants.append(bytes(oversized))
        for test_id in (0x000, 0x7FF, 0x123):
            alt_id = bytearray(base_frame)
            alt_id[0:4] = struct.pack('<I', test_id & 0x7FF)
            mutants.append(bytes(alt_id))
        return mutants


# ==================== 诊断引导反馈循环 ====================
class DiagnosisGuidedFeedback:
    """崩溃诊断 -> 变异热点调整——信号类型 x 偏移权重矩阵"""

    def __init__(self):
        self._signal_hotspots: Dict[int, Dict[int, float]] = defaultdict(
            lambda: defaultdict(float))

    def record_crash(self, signal_num: int, mutated_offset: int,
                     corruption_type: str) -> None:
        """记录一次崩溃——信号 x 偏移权重点增量"""
        weight = 0.5
        if corruption_type in ('stack_buffer_overflow', 'code_execution'):
            weight = 1.5
        elif corruption_type in ('use_after_free', 'double_free'):
            weight = 1.0
        self._signal_hotspots[signal_num][mutated_offset] += weight

    def recommend_offsets(self, signal_num: int, top_k: int = 8) -> List[int]:
        """该信号类型下历史最热门偏移列表"""
        hotspots = self._signal_hotspots.get(signal_num, {})
        ranked = sorted(hotspots.items(), key=lambda x: -x[1])[:top_k]
        return [offset for offset, _ in ranked]

    def decay_all(self, factor: float = 0.9) -> None:
        for sig in self._signal_hotspots:
            for off in list(self._signal_hotspots[sig].keys()):
                self._signal_hotspots[sig][off] *= factor
                if self._signal_hotspots[sig][off] < 0.05:
                    del self._signal_hotspots[sig][off]


# ==================== 二进制提升等价性验证 ====================
class BinaryLiftingVerifier:
    """二进制提升前后行为一致性验证——原生执行 vs IR 执行结果比较"""

    def __init__(self):
        self._oracle_results: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def verify_round_trip(self, native_output: bytes,
                          lifted_output: bytes) -> Dict[str, Any]:
        """原生输出与提升后输出逐字节比较"""
        match = native_output == lifted_output
        result = {
            'match': match,
            'native_len': len(native_output),
            'lifted_len': len(lifted_output),
        }
        if not match:
            for i, (nb, lb) in enumerate(zip(native_output, lifted_output)):
                if nb != lb:
                    result['first_diff_offset'] = i
                    result['native_byte'] = nb
                    result['lifted_byte'] = lb
                    break
            if len(native_output) != len(lifted_output):
                result['size_mismatch'] = True
        return result

    def record_oracle(self, input_hash: str, native_result: Dict[str, Any],
                      lifted_result: Dict[str, Any]) -> None:
        self._oracle_results[input_hash].append({
            'native': native_result, 'lifted': lifted_result,
        })

    def oracle_pass_rate(self) -> float:
        if not self._oracle_results:
            return 1.0
        passed = 0
        for entries in self._oracle_results.values():
            for e in entries:
                if e['native'].get('output') == e['lifted'].get('output'):
                    passed += 1
        total = sum(len(e) for e in self._oracle_results.values())
        return passed / total if total > 0 else 0.0


# ==================== Patch-Delta 聚焦 Fuzzing ====================
class PatchDeltaFuzzer:
    """定向模糊测试调度器——补丁变更函数优先分配 fuzz 预算"""

    def __init__(self):
        self._changed_addrs: Set[int] = set()
        self._affected_paths: Dict[int, List[int]] = defaultdict(list)

    def load_diff(self, changed_function_addrs: List[int]) -> None:
        self._changed_addrs = set(changed_function_addrs)

    def is_hot(self, func_addr: int) -> bool:
        return func_addr in self._changed_addrs

    def prioritize_seeds(self, seeds: List[Tuple[bytes, Set[int]]]
                         ) -> List[Tuple[bytes, float]]:
        """种子优先排序——覆盖变更函数多的权重高"""
        if not self._changed_addrs:
            return [(s, 1.0) for s, _ in seeds]
        weighted = []
        for data, covered in seeds:
            hit_count = len(covered & self._changed_addrs)
            weight = 1.0 + hit_count * 2.0
            weighted.append((data, weight))
        return weighted

    def generate_regression_corpus(self, original_crashes: List[bytes],
                                   output_dir: str) -> int:
        """原始崩溃集 -> 去重回归测试语料"""
        os.makedirs(output_dir, exist_ok=True)
        count = 0
        for i, crash in enumerate(original_crashes):
            h = hashlib.sha256(crash).hexdigest()[:8]
            path = os.path.join(output_dir, f"regress_{h}.bin")
            if not os.path.exists(path):
                with open(path, 'wb') as fh:
                    fh.write(crash)
                count += 1
        return count


# ==================== 二进制 -> Fuzz Driver 生成器 ====================
class FuzzDriverGenerator:
    """从导出表推断 API 签名——纯静态分析驱动模板填充"""

    def __init__(self):
        self._known_apis: Dict[str, Dict[str, Any]] = {
            'parse': {'arg_count': 2, 'arg_types': ['const uint8_t*', 'size_t'],
                      'return': 'int'},
            'decode': {'arg_count': 2, 'arg_types': ['const uint8_t*', 'size_t'],
                       'return': 'int'},
            'process': {'arg_count': 2, 'arg_types': ['const uint8_t*', 'size_t'],
                        'return': 'int'},
            'read': {'arg_count': 2, 'arg_types': ['const uint8_t*', 'size_t'],
                     'return': 'int'},
        }

    def generate_from_exports(self, exported_funcs: List[Dict[str, Any]],
                              target_name: str = "auto_fuzz") -> str:
        """导出函数列表 -> 多目标 LibFuzzer harness"""
        if not exported_funcs:
            return self._empty_harness(target_name)

        parts = [
            '#include <stdint.h>',
            '#include <stddef.h>',
            '#include <stdlib.h>',
            '',
        ]
        for func in exported_funcs:
            fname = func.get('name', 'unknown_func')
            fname_safe = re.sub(r'[^a-zA-Z0-9_]', '_', fname)
            parts.append(
                f'extern int {fname_safe}(const uint8_t *data, size_t len);')

        parts.append('')
        parts.append(
            'extern "C" int LLVMFuzzerTestOneInput'
            '(const uint8_t *data, size_t size) {')
        parts.append('    if (size < 4) return 0;')
        parts.append('')

        for func in exported_funcs:
            fname_safe = re.sub(
                r'[^a-zA-Z0-9_]', '_', func.get('name', 'unknown_func'))
            offset = exported_funcs.index(func) * 2
            parts.append(
                f'    {fname_safe}(data + {offset}, '
                f'size > {offset} ? size - {offset} : 0);')

        parts.append('    return 0;')
        parts.append('}')
        return '\n'.join(parts)

    @staticmethod
    def _empty_harness(name: str) -> str:
        return f'''
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    (void)data; (void)size;
    return 0;
}}
'''.strip()


# ==================== Oracle 构造工具包 ====================
class OracleConstructor:
    """历史发现中提取并实例化测试 Oracle——不变量学习 + 违例检测"""

    def __init__(self):
        self._invariants: List[Dict[str, Any]] = []
        self._violations: List[Dict[str, Any]] = []

    def learn_from_diff(self, diff: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """一次差异中提取可泛化的不变量"""
        evidence = diff.get('evidence', {})
        invariant = None
        if 'size_difference' in evidence:
            invariant = {
                'type': 'output_size_consistency',
                'description': '同一输入在两二进制上的输出长度应一致',
                'check': lambda a_out, b_out: len(a_out) == len(b_out),
            }
        elif 'crash_signal' in evidence:
            invariant = {
                'type': 'no_crash_divergence',
                'description': '若 A 不崩溃则 B 也不应崩溃',
                'check': lambda a_crashed, b_crashed: a_crashed == b_crashed,
            }
        if invariant:
            self._invariants.append(invariant)
        return invariant

    def validate(self, result_a, result_b) -> List[Dict[str, Any]]:
        """对一对结果执行全部已知不变量检查"""
        violations = []
        for inv in self._invariants:
            try:
                if inv['type'] == 'output_size_consistency':
                    if not inv['check'](result_a.stdout, result_b.stdout):
                        violations.append({
                            'invariant': inv['type'],
                            'detail': f"size {len(result_a.stdout)} vs "
                            f"{len(result_b.stdout)}",
                        })
                elif inv['type'] == 'no_crash_divergence':
                    if not inv['check'](result_a.crashed, result_b.crashed):
                        violations.append({
                            'invariant': inv['type'],
                            'detail': f"A crashed={result_a.crashed} "
                            f"B crashed={result_b.crashed}",
                        })
            except Exception:
                pass
        self._violations.extend(violations)
        return violations

    @property
    def invariant_count(self) -> int:
        return len(self._invariants)


# ==================== 关系化执行追踪比较 ====================
class RelationalTraceComparer:
    """两二进制同输入时的基本块轨迹比较——相似度 + 分歧点"""

    def __init__(self):
        self._divergence_points: List[Dict[str, Any]] = []

    def compare_block_traces(
            self, trace_a: List[int], trace_b: List[int]) -> Dict[str, Any]:
        """基本块地址序列比较——首个分歧点 + 整体相似度"""
        if not trace_a and not trace_b:
            return {'similarity': 1.0, 'first_divergence': None}

        max_len = max(len(trace_a), len(trace_b))
        common = 0
        first_div = None
        for i in range(max_len):
            ba = trace_a[i] if i < len(trace_a) else None
            bb = trace_b[i] if i < len(trace_b) else None
            if ba == bb:
                common += 1
            elif first_div is None:
                first_div = {
                    'step': i,
                    'addr_a': hex(ba) if ba else 'EOF',
                    'addr_b': hex(bb) if bb else 'EOF',
                }
        similarity = common / max_len if max_len > 0 else 1.0
        return {
            'similarity': round(similarity, 3),
            'first_divergence': first_div,
            'len_a': len(trace_a),
            'len_b': len(trace_b),
        }

    def find_all_divergences(
            self, trace_a: List[int],
            trace_b: List[int]) -> List[Dict[str, Any]]:
        max_len = max(len(trace_a), len(trace_b))
        divs = []
        for i in range(max_len):
            ba = trace_a[i] if i < len(trace_a) else None
            bb = trace_b[i] if i < len(trace_b) else None
            if ba != bb:
                divs.append({
                    'step': i,
                    'addr_a': hex(ba) if ba else 'EOF',
                    'addr_b': hex(bb) if bb else 'EOF',
                })
        return divs


# ==================== 密码学弱点检测器 ====================
class CryptoWeaknessDetector:
    """二进制密码学反模式扫描——硬编码密钥/弱PRNG/ECB/弱哈希/固定盐值"""

    _WEAK_PATTERNS = [
        (re.compile(rb'md5|MD5'), '弱哈希算法 MD5'),
        (re.compile(rb'ecb|ECB'), 'ECB 分组模式（非语义安全）'),
        (re.compile(rb'DES\b|des_cbc|des_ecb'), 'DES 单密钥（56-bit 可暴力破解）'),
        (re.compile(rb'RC4|arcfour'), 'RC4 流密码（已知偏差攻击）'),
    ]

    _HARDCODED_PATTERNS = [
        re.compile(rb'(?:key|Key|KEY)\s*[=:]\s*"(?:[^"]{4,64})"'),
        re.compile(rb'(?:secret|Secret)\s*[=:]\s*"(?:[^"]{4,128})"'),
        re.compile(rb'(?:passwd|password)\s*[=:]\s*"(?:[^"]{3,64})"'),
    ]

    _WEAK_PRNG = [
        re.compile(rb'\brand\b\s*\(\)'),
        re.compile(rb'\bsrand\b\s*\('),
        re.compile(rb'\brand48\b\s*\('),
        re.compile(rb'\blcong48\b\s*\('),
        re.compile(rb'\bmrand48\b\s*\('),
    ]

    def scan_strings(self, strings: List[str]) -> List[Dict[str, Any]]:
        findings = []
        for s in strings:
            s_bytes = s.encode('utf-8', errors='replace')
            for pat, desc in self._WEAK_PATTERNS:
                if pat.search(s_bytes):
                    findings.append({
                        'type': 'weak_crypto', 'detail': desc,
                        'evidence': s[:120]})
                    break
        return findings

    def scan_hardcoded_keys(self, source_lines: List[str]) -> List[Dict[str, Any]]:
        findings = []
        for line in source_lines:
            line_bytes = line.encode('utf-8', errors='replace')
            for pat in self._HARDCODED_PATTERNS:
                m = pat.search(line_bytes)
                if m:
                    findings.append({
                        'type': 'hardcoded_secret',
                        'detail': '源代码中检测到硬编码密钥/密码',
                        'evidence': line.strip()[:150]})
                    break
        return findings

    def scan_binary(self, raw_bytes: bytes) -> List[Dict[str, Any]]:
        findings = []
        for pat in self._WEAK_PRNG:
            for m in pat.finditer(raw_bytes):
                findings.append({
                    'type': 'weak_prng',
                    'detail': '使用非密码学安全的随机数生成器',
                    'offset': m.start()})
                if len(findings) >= 8:
                    break
        key_patterns = [
            (re.compile(rb'(?:key|Key)[\x00-\x20]*[:=][\x00-\x20]*'
                        rb'(?:[\x20-\x7E]{8,64})'), '疑似硬编码密钥'),
            (re.compile(rb'(?:pass|pwd)[\x00-\x20]*[:=][\x00-\x20]*'
                        rb'(?:[\x20-\x7E]{4,32})'), '疑似硬编码密码'),
        ]
        for pat, desc in key_patterns:
            for m in pat.finditer(raw_bytes):
                findings.append({
                    'type': 'hardcoded_secret_in_binary',
                    'detail': desc,
                    'offset': m.start()})
        return findings


# ==================== 反分析/反调试检测器 ====================
class AntiAnalysisDetector:
    """二进制反分析技术特征检测——ptrace/时间反调试/VM检测/代码混淆"""

    _ANTI_DEBUG_SIGS = [
        (re.compile(rb'ptrace\b.*PTRACE_TRACEME'), 'ptrace 反调试自检'),
        (re.compile(rb'\bgetppid\b\s*\(\)'), '父进程检测（getppid）'),
        (re.compile(rb'\bint\s*0x80\b.*\x1a'), 'INT 0x80 异常触发'),
        (re.compile(rb'\bsysctl\b.*kern\.proc'), 'sysctl 进程检测'),
    ]

    _ANTI_VM_SIGS = [
        (re.compile(rb'VMware|VMWARE|vmware'), 'VMware 字符串检测'),
        (re.compile(rb'VirtualBox|VBOX|vbox'), 'VirtualBox 字符串检测'),
        (re.compile(rb'QEMU|qemu'), 'QEMU 字符串检测'),
        (re.compile(rb'cpuid.*\x01\x00\x00\x00'), 'CPUID hypervisor 位检测'),
    ]

    _OBFUSCATION_SIGNS = [
        (re.compile(rb'(?:push|pop)\s+(?:eax|ebx|ecx|edx|rax|rbx|rcx|rdx)'
                    rb'\s*\n\s*(?:push|pop)'), '栈混淆（push/pop 对）'),
        (re.compile(rb'jmp\s+\$'), '无限循环（反反汇编）'),
    ]

    def scan(self, raw_bytes: bytes,
             strings: Optional[List[str]] = None) -> Dict[str, Any]:
        report: Dict[str, List[Dict[str, Any]]] = {
            'anti_debug': [], 'anti_vm': [], 'obfuscation': []}

        for pat, desc in self._ANTI_DEBUG_SIGS:
            for m in pat.finditer(raw_bytes):
                report['anti_debug'].append({
                    'technique': desc, 'offset': m.start()})
                if len(report['anti_debug']) >= 6:
                    break

        for pat, desc in self._ANTI_VM_SIGS:
            for m in pat.finditer(raw_bytes):
                report['anti_vm'].append({
                    'technique': desc, 'offset': m.start()})

        for pat, desc in self._OBFUSCATION_SIGNS:
            for m in pat.finditer(raw_bytes):
                report['obfuscation'].append({
                    'technique': desc, 'offset': m.start()})

        total = sum(len(v) for v in report.values())
        report['summary'] = {
            'total_findings': total,
            'protected': total >= 3,
            'risk_level': (
                'high' if total >= 6
                else 'medium' if total >= 3
                else 'low'),
        }
        return report


# ==================== 漏洞可达性分析器 ====================
class VulnerabilityReachabilityAnalyzer:
    """调用图遍历判定漏洞函数是否可被攻击面触及——BFS/DFS 双模"""

    def __init__(self):
        self._edges: Dict[str, Set[str]] = defaultdict(set)
        self._attack_surface: Set[str] = set()

    def add_edge(self, caller: str, callee: str) -> None:
        self._edges[caller].add(callee)

    def mark_attack_surface(self, funcs: List[str]) -> None:
        self._attack_surface.update(funcs)

    def reachable_from_surface(self, target: str,
                                max_depth: int = 10) -> Dict[str, Any]:
        """反向 BFS——从 target 回溯到攻击面入口"""
        if target in self._attack_surface:
            return {'reachable': True, 'depth': 0, 'direct_entry': True}

        reverse: Dict[str, Set[str]] = defaultdict(set)
        for caller, callees in self._edges.items():
            for callee in callees:
                reverse[callee].add(caller)

        visited: Set[str] = {target}
        queue = deque([(target, 0)])
        path_to: Dict[str, Optional[str]] = {target: None}
        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for caller in reverse.get(current, set()):
                if caller in visited:
                    continue
                visited.add(caller)
                path_to[caller] = current
                if caller in self._attack_surface:
                    path = [caller]
                    node = current
                    while node is not None:
                        path.append(node)
                        node = path_to.get(node)
                    return {
                        'reachable': True,
                        'depth': depth + 1,
                        'entry': caller,
                        'call_chain': path,
                    }
                queue.append((caller, depth + 1))
        return {
            'reachable': False,
            'searched_depth': max_depth,
            'functions_visited': len(visited),
        }

    def reachability_heatmap(self,
                              cve_list: List[Dict[str, Any]]
                              ) -> Dict[str, Any]:
        """CVE 列表批量可达性分析"""
        reachable = []
        unreachable_count = 0
        for cve in cve_list:
            funcs = cve.get('affected_functions', [])
            for func in funcs:
                result = self.reachable_from_surface(func)
                if result.get('reachable'):
                    reachable.append({
                        'cve': cve.get('id', 'unknown'),
                        'function': func,
                        'depth': result.get('depth'),
                        'call_chain': result.get('call_chain', []),
                    })
                    break
            else:
                unreachable_count += 1
        return {
            'total_cves': len(cve_list),
            'reachable': len(reachable),
            'unreachable': unreachable_count,
            'reachable_details': reachable,
            'fp_reduction_pct': round(
                unreachable_count / max(1, len(cve_list)) * 100, 1),
        }


# ==================== PE 熵分析器 ====================
class PEEntropyAnalyzer:
    """PE 二进制节区熵分析与加壳检测——香农熵 + overlay 检测"""

    def __init__(self):
        self._section_entropy: Dict[str, float] = {}
        self._overall_entropy: float = 0.0

    def compute_entropy(self, data: bytes) -> float:
        """香农熵 [0, 8]"""
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        ent = 0.0
        n = len(data)
        for cnt in freq:
            if cnt > 0:
                p = cnt / n
                ent -= p * math.log2(p)
        return ent

    def analyze_sections(self, sections: Dict[str, bytes]) -> Dict[str, Any]:
        """分析所有节区熵值——加壳判定规则"""
        self._section_entropy = {}
        for name, data in sections.items():
            ent = round(self.compute_entropy(data), 2)
            self._section_entropy[name] = ent

        high_entropy = {k: v for k, v in self._section_entropy.items()
                        if v >= 7.0}
        low_entropy = {k: v for k, v in self._section_entropy.items()
                       if v <= 3.0}

        has_packer_section = any(
            name.lower() in ('.upx', '.aspack', '.petite', '.mpress',
                             '.vmp', '.themida', '.enigma')
            for name in self._section_entropy)

        is_packed = (
            has_packer_section
            or (len(high_entropy) >= 2)
            or (len(high_entropy) >= 1 and len(low_entropy) >= 1
                and self._section_entropy.get('.text', 0) >= 6.5))

        return {
            'sections': self._section_entropy,
            'high_entropy_sections': list(high_entropy.keys()),
            'low_entropy_sections': list(low_entropy.keys()),
            'overall_max_entropy': round(
                max(self._section_entropy.values())
                if self._section_entropy else 0, 2),
            'is_packed': is_packed,
            'packer_section_detected': has_packer_section,
            'confidence': (
                'high' if has_packer_section
                else 'medium' if is_packed
                else 'low'),
        }

    def overlay_detection(self, pe_raw: bytes,
                           section_end: int) -> bool:
        """PE 尾部附加数据检测——常见于捆绑包/下载器"""
        return len(pe_raw) > section_end + 256


# ==================== 漏洞缓解检测器 ====================
class ExploitMitigationDetector:
    """二进制安全缓解措施检测与缺口评估——NX/Canary/PIE/RELRO/CFI/CET/PAC"""

    MITIGATION_CHECKS = {
        'nx': {'name': 'NX/DEP', 'risk_if_missing': 'critical',
               'desc': '栈/堆不可执行'},
        'canary': {'name': 'Stack Canary', 'risk_if_missing': 'high',
                   'desc': '栈溢出检测'},
        'pie': {'name': 'PIE/ASLR', 'risk_if_missing': 'high',
                'desc': '地址空间随机化'},
        'full_relro': {'name': 'Full RELRO', 'risk_if_missing': 'medium',
                       'desc': 'GOT 只读保护'},
        'fortify': {'name': 'FORTIFY_SOURCE', 'risk_if_missing': 'medium',
                    'desc': '编译期缓冲区溢出检测'},
        'cfi': {'name': 'Control Flow Integrity',
                'risk_if_missing': 'critical',
                'desc': '间接调用/跳转目标验证'},
        'shadow_stack': {'name': 'Shadow Stack',
                         'risk_if_missing': 'high',
                         'desc': '返回地址完整性保护'},
        'cet': {'name': 'Intel CET', 'risk_if_missing': 'high',
                'desc': 'IBT + Shadow Stack 硬件强制'},
        'pac': {'name': 'ARM PAC', 'risk_if_missing': 'high',
                'desc': '指针认证码'},
    }

    def __init__(self):
        self._findings: Dict[str, bool] = {}

    def detect_from_binary(self, raw_bytes: bytes,
                           elf_sections: Optional[List[str]] = None
                           ) -> Dict[str, Any]:
        """ELF 节头和标志推断启用的缓解措施"""
        present = {}
        missing = {}

        if elf_sections:
            sections_str = ' '.join(elf_sections).lower()
            present['nx'] = 'gnu_stack' in sections_str
        else:
            present['nx'] = b'GNU_STACK' in raw_bytes

        present['canary'] = (
            b'__stack_chk_fail' in raw_bytes
            or b'__stack_chk_guard' in raw_bytes)

        present['pie'] = raw_bytes[16:18] == b'\x03\x00' if len(
            raw_bytes) > 18 else False

        present['full_relro'] = (
            b'BIND_NOW' in raw_bytes
            or b'DT_BIND_NOW' in raw_bytes)

        present['fortify'] = b'__sprintf_chk' in raw_bytes

        present['cfi'] = (
            b'__cfi_check' in raw_bytes
            or b'__cfi_slowpath' in raw_bytes)

        present['shadow_stack'] = b'cetcompat' in raw_bytes.lower()

        present['cet'] = b'ibt' in raw_bytes.lower()

        present['pac'] = (
            b'paciasp' in raw_bytes or b'autiasp' in raw_bytes)

        for check, info in self.MITIGATION_CHECKS.items():
            if present.get(check, False):
                present[check] = True
            else:
                missing[check] = info

        critical_missing = sum(
            1 for c in missing
            if self.MITIGATION_CHECKS[c]['risk_if_missing'] == 'critical')
        high_missing = sum(
            1 for c in missing
            if self.MITIGATION_CHECKS[c]['risk_if_missing'] == 'high')
        overall_risk = (
            'critical' if critical_missing >= 1
            else 'high' if high_missing >= 2
            else 'medium' if missing
            else 'low')

        return {
            'present': {k: self.MITIGATION_CHECKS[k]['name']
                        for k, v in present.items() if v},
            'missing': {k: v['name'] for k, v in missing.items()},
            'missing_risk_details': missing,
            'mitigation_score': round(
                len(present) / len(self.MITIGATION_CHECKS), 2),
            'overall_risk': overall_risk,
        }

    def hardening_recommendations(self) -> List[str]:
        """缺失缓解措施的加固建议"""
        recs = []
        for check, info in self.MITIGATION_CHECKS.items():
            if check not in self._findings or not self._findings[check]:
                recs.append(
                    f"[{info['risk_if_missing'].upper()}] "
                    f"缺少 {info['name']}: {info['desc']}")
        return recs


# ==================== MMIO 访问建模器 ====================
class MMIOAccessModeler:
    """固件 MMIO 外设寄存器分类与建模——T0-T3 四类分类体系"""

    REG_TYPES = {'T0': 'readonly_status', 'T1': 'readonly_constant',
                 'T2': 'write_ignored', 'T3': 'write_affects_behavior'}

    def __init__(self):
        self._registers: Dict[int, Dict[str, Any]] = {}

    def classify_register(self, addr: int, observed_reads: List[int],
                           write_effects: List[bool]) -> str:
        """observed_reads + write_effects -> T0-T3 分类"""
        unique_reads = set(observed_reads)
        if len(unique_reads) > 1 and not any(write_effects):
            reg_type = 'T0'
        elif len(unique_reads) == 1 and not any(write_effects):
            reg_type = 'T1'
        elif not any(write_effects):
            reg_type = 'T2'
        else:
            reg_type = 'T3'
        self._registers[addr] = {
            'type': reg_type,
            'description': self.REG_TYPES[reg_type],
            'observed_values': sorted(unique_reads)[:8],
        }
        return reg_type

    def get_fuzzable_registers(self) -> List[int]:
        """返回所有 T3 寄存器地址——写入可改变行为"""
        return sorted(
            addr for addr, info in self._registers.items()
            if info['type'] == 'T3')

    def model_response(self, addr: int,
                        write_value: int) -> Optional[int]:
        """模拟 MMIO 读取——T0/T1 返回观测值，T2/T3 返回 0"""
        info = self._registers.get(addr)
        if info is None:
            return None
        if info['type'] in ('T0', 'T1'):
            vals = info.get('observed_values', [0])
            return vals[0] if vals else 0
        return 0

    def generate_mmio_fuzz_inputs(self, count: int = 16) -> List[bytes]:
        """为所有 T3 寄存器生成 fuzz 输入序列"""
        t3_addrs = self.get_fuzzable_registers()
        if not t3_addrs:
            return []
        inputs = []
        for _ in range(count):
            seq = bytearray()
            for addr in t3_addrs:
                seq.extend(struct.pack('<II', addr,
                            random.randint(0, 0xFFFFFFFF)))
            inputs.append(bytes(seq))
        return inputs

    def register_summary(self) -> Dict[str, Any]:
        counts = Counter(
            info['type'] for info in self._registers.values())
        return {
            'total_registers': len(self._registers),
            'by_type': dict(counts),
            'fuzzable_count': counts.get('T3', 0),
        }


# ==================== 依赖图传播器 ====================
class DependencyGraphPropagator:
    """组件依赖图中漏洞影响的传递闭包分析——BFS + DFS 双模"""

    def __init__(self):
        self._deps: Dict[str, Set[str]] = defaultdict(set)
        self._vulns: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def add_dependency(self, component: str,
                        depends_on: str) -> None:
        self._deps[component].add(depends_on)

    def add_vulnerability(self, component: str,
                           cve_id: str, severity: str = 'unknown') -> None:
        self._vulns[component].append({
            'cve': cve_id, 'severity': severity})

    def propagate(self, root_component: str) -> Dict[str, Any]:
        """从 root 出发遍历传递依赖汇总影响到的全部 CVE"""
        visited: Set[str] = set()
        queue = deque([root_component])
        transitive_vulns: List[Dict[str, Any]] = []
        dep_chain: Dict[str, List[str]] = defaultdict(list)

        while queue:
            comp = queue.popleft()
            if comp in visited:
                continue
            visited.add(comp)
            for vuln in self._vulns.get(comp, []):
                transitive_vulns.append({
                    'component': comp,
                    'cve': vuln['cve'],
                    'severity': vuln['severity'],
                })
            for dep in self._deps.get(comp, set()):
                if dep not in visited:
                    dep_chain[dep] = dep_chain.get(comp, []) + [comp]
                    queue.append(dep)

        seen_cves = set()
        unique_vulns = []
        for v in transitive_vulns:
            if v['cve'] not in seen_cves:
                seen_cves.add(v['cve'])
                unique_vulns.append(v)

        criticals = [v for v in unique_vulns
                     if v['severity'] in ('critical', 'high')]
        return {
            'root': root_component,
            'transitive_deps_count': len(visited) - 1,
            'total_vulnerabilities': len(unique_vulns),
            'critical_high_count': len(criticals),
            'vulnerabilities': unique_vulns,
            'risk_level': (
                'critical' if len(criticals) >= 3
                else 'high' if len(criticals) >= 1
                else 'medium' if len(unique_vulns) >= 3
                else 'low'),
        }

    def find_riskiest_paths(self, root: str,
                             top_k: int = 5) -> List[Dict[str, Any]]:
        """返回风险最高的 K 条传递依赖路径"""
        visited = set()
        all_paths = []

        def dfs(comp: str, path: List[str],
                accumulated_risk: float) -> None:
            if comp in visited:
                return
            visited.add(comp)
            current_path = path + [comp]
            node_risk = sum(
                {'critical': 1.0, 'high': 0.7, 'medium': 0.4,
                 'low': 0.1, 'unknown': 0.2}.get(
                     v['severity'], 0.2)
                for v in self._vulns.get(comp, []))
            total_risk = accumulated_risk + node_risk
            if node_risk > 0:
                all_paths.append({
                    'path': list(current_path),
                    'length': len(current_path),
                    'risk_score': round(total_risk, 2),
                })
            for dep in self._deps.get(comp, set()):
                dfs(dep, current_path, total_risk)

        dfs(root, [], 0.0)
        all_paths.sort(key=lambda p: -p['risk_score'])
        return all_paths[:top_k]
