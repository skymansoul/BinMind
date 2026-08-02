"""
Testing, Fuzzing & Protocol Analysis

Fuzzer integration (AFL/LibFuzzer), concurrency testing,
coverage tracking, and network protocol reverse engineering.
"""

from typing import Dict, Any, List, Set, Optional, Tuple
import logging
import re
import os
import json
import subprocess
import hashlib
import datetime
import time
import threading
import socket
import sqlite3
import math
import struct
from collections import defaultdict, Counter, deque
from pathlib import Path

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 工具函数：子进程管理、错误分类、BKDR 哈希
# ---------------------------------------------------------------------------
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


class FuzzerIntegration:
    """
    Fuzz harness generation, session management, crash import pipeline, Web API control
    """

    def __init__(self, work_dir: str = "data/fuzzing"):
        self.work_dir = work_dir
        self.fuzz_sessions: Dict[str, Dict[str, Any]] = {}
        self.corpus_dir = os.path.join(work_dir, "corpus")
        self.crashes_dir = os.path.join(work_dir, "crashes")
        self._session_procs: Dict[str, subprocess.Popen] = {}
        self._session_lock = threading.Lock()
        os.makedirs(self.corpus_dir, exist_ok=True)
        os.makedirs(self.crashes_dir, exist_ok=True)

    def create_harness(self, target_binary: str, input_type: str) -> str:
        """Generate fuzz harness from target binary and input type"""
        if input_type == 'file':
            return self._generate_libfuzzer_harness(target_binary)
        elif input_type == 'network':
            return self._generate_afl_harness(target_binary)
        return ''

    def _generate_libfuzzer_harness(self, target: str) -> str:
        """Generate LibFuzzer-compatible harness"""
        code = '''
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    // Target: {target}
    // TODO: Implement fuzzing logic
    return 0;
}}
'''.format(target=target)
        return code

    def _generate_afl_harness(self, target: str) -> str:
        """Generate AFL-compatible harness"""
        code = '''
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {{
    FILE *f;
    char buf[1024];

    if (argc < 2) {{
        fprintf(stderr, "Usage: %s <input_file>\\n", argv[0]);
        return 1;
    }}

    f = fopen(argv[1], "rb");
    if (!f) return 1;

    fread(buf, 1, sizeof(buf), f);
    fclose(f);

    // Target: {target}
    // TODO: Implement fuzzing logic
    return 0;
}}
'''.format(target=target)
        return code

    def start_fuzzing_session(self, session_name: str, harness_path: str,
                              fuzzer_type: str = 'afl') -> Dict[str, Any]:
        """Start a named fuzzing session"""
        session = {
            'name': session_name,
            'harness': harness_path,
            'fuzzer_type': fuzzer_type,
            'status': 'running',
            'corpus_count': 0,
            'crash_count': 0,
            'started_at': datetime.datetime.now().isoformat(),
            'pid': None,
        }

        self.fuzz_sessions[session_name] = session

        # 实际启动子进程（尽力），记录 PID 便于后续监控/终止
        session_dir = os.path.join(self.work_dir, session_name)
        os.makedirs(session_dir, exist_ok=True)
        try:
            if fuzzer_type == 'afl':
                cmd = [
                    'afl-fuzz', '-i', self.corpus_dir,
                    '-o', session_dir, '--', harness_path, '@@'
                ]
            elif fuzzer_type == 'libfuzzer':
                cmd = [harness_path, '-jobs=1', f'-workers=1', session_dir]
            else:
                cmd = [harness_path, session_dir]
            proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with self._session_lock:
                self._session_procs[session_name] = proc
            session['pid'] = proc.pid
        except Exception as exc:
            session['status'] = 'error'
            session['error'] = str(exc)

        return session

    def stop_session(self, session_name: str) -> bool:
        with self._session_lock:
            proc = self._session_procs.pop(session_name, None)
        if proc is None:
            return False
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        session = self.fuzz_sessions.get(session_name)
        if session:
            session['status'] = 'stopped'
        return True

    def import_crash(self, session_name: str, crash_path: str) -> Dict[str, Any]:
        """Import crash sample into the analysis pipeline"""
        crash_info = {
            'session': session_name,
            'crash_file': crash_path,
            'imported_at': datetime.datetime.now().isoformat(),
            'analysis_status': 'pending'
        }

        # 将崩溃文件拷贝至崩溃语料目录
        crash_dest = os.path.join(self.crashes_dir, f"{session_name}_{os.path.basename(crash_path)}")
        try:
            import shutil
            shutil.copy(crash_path, crash_dest)
            crash_info['stored_path'] = crash_dest
        except Exception as e:
            crash_info['error'] = str(e)

        return crash_info

    def get_session_status(self, session_name: str) -> Dict[str, Any]:
        """Retrieve session status by name"""
        return self.fuzz_sessions.get(session_name, {})

    # ---- 批量语料导入 ----
    def import_corpus_dir(self, dir_path: str) -> int:
        """扫描目录，将全部文件作为种子导入，返回导入数量"""
        count = 0
        for entry in os.scandir(dir_path):
            if entry.is_file():
                dest = os.path.join(self.corpus_dir, entry.name)
                try:
                    import shutil
                    shutil.copy(entry.path, dest)
                    count += 1
                except Exception:
                    logger.debug("corpus import skip: %s", entry.name)
        return count


class ProtocolFormatReverseEngineer:
    """
    Static and dynamic field inference; specialized fuzz harness and seed generation
    """

    def __init__(self):
        self.inferred_fields: List[Dict[str, Any]] = []
        self.protocol_hints: Dict[str, Any] = {}
        self._field_dictionary: Dict[str, List[bytes]] = defaultdict(list)

    def analyze_from_binary(self, binary_path: str) -> Dict[str, Any]:
        """Analyze protocol format from binary"""
        result = {
            'binary': binary_path,
            'inferred_fields': [],
            'message_types': [],
            'fuzz_harness': ''
        }

        # 静态分析：识别协议解析函数
        parse_funcs = self._find_parse_functions(binary_path)
        result['message_types'] = parse_funcs

        # 从静态分析结果推断协议字段
        result['inferred_fields'] = self._infer_fields(binary_path)

        # 根据推断的协议生成 Fuzz 骨架
        result['fuzz_harness'] = self._generate_fuzz_harness(result)

        self.inferred_fields = result['inferred_fields']
        return result

    def _find_parse_functions(self, binary_path: str) -> List[Dict[str, Any]]:
        """Locate protocol parsing functions in binary"""
        funcs = []
        return funcs

    def _infer_fields(self, binary_path: str) -> List[Dict[str, Any]]:
        """Infer protocol field layout"""
        fields = []

        # 常见协议字段类型的推断模式
        field_patterns = [
            ('magic', 4, 'Magic number validation'),
            ('length', 4, 'Payload length field'),
            ('type', 2, 'Message type discriminator'),
            ('checksum', 4, 'Integrity checksum')
        ]

        for name, size, desc in field_patterns:
            fields.append({
                'name': name,
                'size': size,
                'description': desc,
                'offset': 0
            })

        return fields

    def _generate_fuzz_harness(self, protocol_info: Dict[str, Any]) -> str:
        """Generate fuzzing harness from protocol info"""
        harness = '''
#include <stdint.h>
#include <stdio.h>

// Protocol: {protocol_name}
// Fields: {field_count}

struct {{
    // TODO: Add protocol fields
}} message_t;

int parse_message(const uint8_t *data, size_t len) {{
    if (len < sizeof(message_t)) return -1;
    // TODO: Implement parser
    return 0;
}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    parse_message(data, size);
    return 0;
}}
'''.format(
            protocol_name=protocol_info.get('binary', 'Unknown'),
            field_count=len(protocol_info.get('inferred_fields', []))
        )

        return harness

    # ---- 基于熵的字段边界推断 ----
    def infer_by_entropy(self, samples: List[bytes],
                         window: int = 8) -> List[Dict[str, Any]]:
        """对多个样本计算滑动窗香农熵，低熵区→固定字段，高熵区→可变字段"""
        if not samples:
            return []
        max_len = max(len(s) for s in samples)
        aligned = [s.ljust(max_len, b'\x00') for s in samples]
        fields = []
        pos = 0
        while pos < max_len:
            window_bytes = [s[pos:pos + window] for s in aligned]
            # 计算该窗口的字节值熵
            counter: Counter = Counter()
            for w in window_bytes:
                counter.update(w)
            total = sum(counter.values())
            entropy = 0.0
            for cnt in counter.values():
                if cnt > 0:
                    p = cnt / total
                    entropy -= p * math.log2(p)
            normalized = entropy / 8.0  # 归一化到 [0, 1]
            fields.append({
                'offset': pos,
                'size': window,
                'entropy': round(normalized, 3),
                'likely_type': 'variable' if normalized > 0.7 else 'fixed',
            })
            pos += window
        return fields

    # ---- 字典构建：从已知消息模板抽取 token，用于后续变异 ----
    def build_token_dictionary(self, messages: List[bytes]) -> Dict[str, int]:
        """提取高频 4-16 字节片段作为变异字典"""
        freq: Dict[str, int] = defaultdict(int)
        for msg in messages:
            for n in (4, 8, 16):
                for i in range(0, len(msg) - n + 1):
                    token = msg[i:i + n]
                    freq[token.hex()] += 1
        # 保留出现 ≥3 次的 token
        filtered = {k: v for k, v in freq.items() if v >= 3}
        for hex_key in filtered:
            self._field_dictionary['tokens'].append(bytes.fromhex(hex_key))
        return filtered

    def generate_seed_corpus(self, samples: List[bytes]) -> str:
        """Generate seed corpus from sample bytes"""
        seed_dir = "data/fuzzing/seeds"
        os.makedirs(seed_dir, exist_ok=True)

        for i, sample in enumerate(samples[:10]):  # Cap at 10 seed samples
            seed_path = os.path.join(seed_dir, f"seed_{i:03d}.bin")
            with open(seed_path, 'wb') as f:
                f.write(sample)

        return seed_dir


class ConcurrencyVulnerabilityDetector:
    """
    Static lock graph construction; race condition, deadlock, and TOCTOU detection
    """

    def __init__(self):
        self.lock_graph: Dict[int, List[int]] = {}
        self.race_conditions: List[Dict[str, Any]] = []
        self.deadlock_risks: List[Dict[str, Any]] = []
        # 新增：锁集追踪
        self._lock_sets: Dict[int, Set[int]] = defaultdict(set)
        self._shared_accesses: Dict[int, List[Dict[str, Any]]] = defaultdict(list)

    def build_lock_graph(self, binary_path: str) -> Dict[int, List[int]]:
        """Build lock acquisition graph from binary"""
        lock_graph = {}

        # 分析二进制中的锁操作
        # 追踪 pthread_mutex_lock/unlock 调用点
        # 追踪 InterlockedIncrement 及类似原子操作

        return lock_graph

    def detect_data_races(self, function_addr: int) -> List[Dict[str, Any]]:
        """Detect data race conditions"""
        races = []

        # 识别对共享内存的非同步访问
        # 1. 枚举全部内存访问指令
        # 2. 标记无锁保护的写-写及读-写冲突

        return races

    def detect_deadlock_risks(self) -> List[Dict[str, Any]]:
        """Detect potential deadlock cycles"""
        deadlocks = []

        # 检测环形锁依赖链
        for node in self.lock_graph:
            if self._has_cycle(node):
                deadlocks.append({
                    'type': 'lock_cycle',
                    'locks': self._get_cycle_locks(node),
                    'risk': 'high'
                })

        return deadlocks

    def _has_cycle(self, start_node: int) -> bool:
        """Detect cycle in lock graph via DFS"""
        visited = set()
        rec_stack = set()

        def dfs(node):
            visited.add(node)
            rec_stack.add(node)

            for neighbor in self.lock_graph.get(node, []):
                if neighbor not in visited:
                    if dfs(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True

            rec_stack.remove(node)
            return False

        return dfs(start_node)

    def _get_cycle_locks(self, start_node: int) -> List[int]:
        """Extract lock addresses from detected cycle"""
        cycle = []
        return cycle

    def detect_toctou(self, binary_path: str) -> List[Dict[str, Any]]:
        """Detect TOCTOU patterns"""
        toctou = []

        # 检测 Check-Access-Use 模式
        # 范例: if(access(path, R_OK) == 0) { open(path) }

        return toctou

    # ---- 锁集交叉分析：两线程持锁集有交集且对同一共享变量访问即标记 ----
    def record_shared_access(self, var_addr: int, thread_id: int,
                             access_type: str, held_locks: Set[int]) -> None:
        """录入一次共享变量访问"""
        entry = {
            'thread': thread_id, 'type': access_type,
            'held_locks': frozenset(held_locks), 'ts': time.time(),
        }
        self._shared_accesses[var_addr].append(entry)

        # 回溯检查：若已有其他线程的写访问且锁集不相交 → 数据竞争
        for prev in self._shared_accesses[var_addr][:-1]:
            if prev['thread'] == thread_id:
                continue
            if prev['type'] == 'write' or access_type == 'write':
                if not (held_locks & prev['held_locks']):
                    self.race_conditions.append({
                        'var_addr': var_addr,
                        'thread_a': prev['thread'],
                        'thread_b': thread_id,
                        'type_a': prev['type'],
                        'type_b': access_type,
                    })


class VulnerabilityDatabaseFullTextSearch:
    """
    Full-text search over vulnerability records and code snippets
    Supports full-text and regex queries

    core features:
    1. Elasticsearch integration
    2. Full-text indexing
    3. Regex search support
    4. Vulnerability query API
    """

    def __init__(self, es_host: str = 'localhost', es_port: int = 9200):
        self.es_host = es_host
        self.es_port = es_port
        self.index_name = 'vulnerabilities'
        self.vulnerability_records: List[Dict[str, Any]] = []
        self.local_index: Dict[str, Dict[str, Any]] = {}  # Local index fallback
        # 三元组索引：加速子串搜索
        self._trigram_index: Dict[str, Set[str]] = defaultdict(set)

    def add_vulnerability(self, vuln_record: Dict[str, Any]) -> str:
        """Index a vulnerability record"""
        vuln_id = vuln_record.get('id', hashlib.sha256(
            json.dumps(vuln_record).encode()
        ).hexdigest()[:16])

        vuln_record['indexed_at'] = datetime.datetime.now().isoformat()
        self.vulnerability_records.append(vuln_record)

        # 存入本地索引
        self.local_index[vuln_id] = vuln_record

        # 构建 trigram 索引
        searchable = ' '.join(
            str(vuln_record.get(f, '')) for f in
            ['description', 'vuln_type', 'function_name', 'cwe', 'cve'])
        text_lower = searchable.lower()
        for i in range(len(text_lower) - 2):
            trigram = text_lower[i:i + 3]
            self._trigram_index[trigram].add(vuln_id)

        return vuln_id

    def full_text_search(self, query: str) -> List[Dict[str, Any]]:
        """Full-text search across records"""
        results = []

        query_lower = query.lower()

        for vuln_id, record in self.local_index.items():
            # 搜索全部文本索引字段
            searchable_fields = ['description', 'vuln_type', 'function_name', 'cwe', 'cve']

            for field in searchable_fields:
                value = record.get(field, '')
                if isinstance(value, str) and query_lower in value.lower():
                    results.append({
                        'vuln_id': vuln_id,
                        'matched_field': field,
                        'record': record,
                        'score': 1.0
                    })
                    break

        return results

    def regex_search(self, pattern: str) -> List[Dict[str, Any]]:
        """Regex search across records"""
        results = []

        try:
            regex = re.compile(pattern, re.IGNORECASE)

            for vuln_id, record in self.local_index.items():
                searchable_fields = ['description', 'vuln_type', 'function_name']

                for field in searchable_fields:
                    value = record.get(field, '')
                    if isinstance(value, str) and regex.search(value):
                        results.append({
                            'vuln_id': vuln_id,
                            'matched_field': field,
                            'record': record,
                            'match': regex.search(value).group()
                        })
                        break

        except re.error as e:
            return [{'error': f'Invalid regex: {e}'}]

        return results

    def search_by_code_pattern(self, code_pattern: str) -> List[Dict[str, Any]]:
        """Search by code pattern match"""
        results = []

        for vuln_id, record in self.local_index.items():
            code_snippets = record.get('code_snippets', [])

            for snippet in code_snippets:
                if isinstance(snippet, str) and code_pattern in snippet:
                    results.append({
                        'vuln_id': vuln_id,
                        'matched_snippet': snippet,
                        'record': record
                    })

        return results

    # ---- trigram 快速候选召回：大幅缩减全表扫描范围 ----
    def _candidate_ids(self, query: str) -> Set[str]:
        query_lower = query.lower()
        if len(query_lower) < 3:
            return set(self.local_index.keys())
        trigrams = [query_lower[i:i + 3]
                    for i in range(len(query_lower) - 2)]
        if not trigrams:
            return set(self.local_index.keys())
        candidates = self._trigram_index.get(trigrams[0], set())
        for tg in trigrams[1:]:
            candidates &= self._trigram_index.get(tg, set())
            if not candidates:
                break
        return candidates or set(self.local_index.keys())

    def trigram_search(self, query: str) -> List[Dict[str, Any]]:
        """trigram 索引加速的全文搜索"""
        query_lower = query.lower()
        candidates = self._candidate_ids(query)
        results = []
        searchable_fields = ['description', 'vuln_type', 'function_name', 'cwe', 'cve']
        for vid in candidates:
            record = self.local_index.get(vid)
            if record is None:
                continue
            for field in searchable_fields:
                value = record.get(field, '')
                if isinstance(value, str) and query_lower in value.lower():
                    results.append({
                        'vuln_id': vid,
                        'matched_field': field,
                        'record': record,
                        'score': 1.0,
                    })
                    break
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get coverage statistics"""
        stats = {
            'total_records': len(self.vulnerability_records),
            'indexed_fields': ['description', 'vuln_type', 'function_name', 'cwe', 'cve'],
            'type_distribution': {},
            'trigram_count': len(self._trigram_index),
        }

        for record in self.vulnerability_records:
            vuln_type = record.get('vuln_type', 'unknown')
            stats['type_distribution'][vuln_type] = stats['type_distribution'].get(vuln_type, 0) + 1

        return stats


class ConstraintBasedInputStructureInferer:
    """
    Infer input data format from symbolic execution constraint sets
    Magic numbers, length fields; outputs Kaitai Struct definitions

    core features:
    1. Constraint analysis
    2. Input format inference
    3. Kaitai Struct generation
    4. Structure validation
    """

    def __init__(self):
        self.constraints: List[Dict[str, Any]] = []
        self.inferred_structure: Dict[str, Any] = {}
        self.kaitai_definition: str = ''

    def analyze_constraints(self, symbolic_constraints: List[str]) -> List[Dict[str, Any]]:
        """Analyze symbolic constraints"""
        analyzed = []

        for constraint in symbolic_constraints:
            # 分类约束类型

            # 魔数约束
            if '==' in constraint and '0x' in constraint:
                match = re.search(r'input\[0\] == (0x[0-9a-fA-F]+)', constraint)
                if match:
                    analyzed.append({
                        'type': 'magic',
                        'offset': 0,
                        'value': match.group(1),
                        'description': 'Magic number validation'
                    })

            # 长度约束
            if 'len' in constraint or 'size' in constraint:
                match = re.search(r'len\(input\) >= (\d+)', constraint)
                if match:
                    analyzed.append({
                        'type': 'min_length',
                        'value': int(match.group(1)),
                        'description': 'Minimum length requirement'
                    })

            # 版本字段约束
            if 'version' in constraint:
                analyzed.append({
                    'type': 'version',
                    'description': 'Version field validation'
                })

        self.constraints = analyzed
        return analyzed

    # ---- 嵌套结构推断：遇到 input[offset] 约束时自动判定字段边界 ----
    def analyze_constraints_with_offsets(
            self, symbolic_constraints: List[str]) -> List[Dict[str, Any]]:
        analyzed = self.analyze_constraints(symbolic_constraints)
        # 提取所有 input[N] 引用，按偏移排序以推断字段顺序
        offset_pattern = re.compile(r'input\[(\d+)\]')
        for c in symbolic_constraints:
            offsets = [int(m) for m in offset_pattern.findall(c)]
            if offsets:
                min_off = min(offsets)
                max_off = max(offsets)
                if max_off > min_off:
                    analyzed.append({
                        'type': 'field_range',
                        'offset': min_off,
                        'end_offset': max_off,
                        'size': max_off - min_off + 1,
                        'description': f'Field spanning bytes {min_off}-{max_off}',
                    })
        return analyzed

    def infer_structure(self) -> Dict[str, Any]:
        """Infer data structure from constraints"""
        structure = {
            'fields': [],
            'magic': None,
            'min_size': 0
        }

        for constraint in self.constraints:
            if constraint['type'] == 'magic':
                structure['magic'] = {
                    'offset': constraint['offset'],
                    'value': constraint['value'],
                    'size': 4
                }
                structure['fields'].append({
                    'name': 'magic',
                    'type': 'bytes',
                    'size': 4,
                    'expected': constraint['value']
                })

            elif constraint['type'] == 'min_length':
                structure['min_size'] = constraint['value']

        self.inferred_structure = structure
        return structure

    def generate_kaitai_struct(self, format_name: str) -> str:
        """Generate Kaitai Struct definition"""
        structure = self.inferred_structure

        kaitai = f'''
meta:
  id: {format_name}
  file-extension: {format_name}

seq:
'''

        for i, field in enumerate(structure.get('fields', [])):
            kaitai += f'''
  - id: {field["name"]}
    type: {field["type"]}
    size: {field["size"]}
'''

        if structure.get('magic'):
            kaitai += f'''
instances:
  magic_check:
    value: magic == {structure["magic"]["value"]}
'''

        self.kaitai_definition = kaitai
        return kaitai

    def validate_structure(self, sample_data: bytes) -> bool:
        """Validate sample against inferred structure"""
        structure = self.inferred_structure

        # 校验最小长度约束
        if len(sample_data) < structure.get('min_size', 0):
            return False

        # 校验魔数值
        magic = structure.get('magic')
        if magic:
            expected = int(magic['value'], 16)
            actual = int.from_bytes(sample_data[magic['offset']:magic['offset'] + magic['size']], 'little')
            if actual != expected:
                return False

        return True


class BinaryFuzzingCoverageRealtimeStats:
    """
    Collect basic block coverage data during fuzzing
    Real-time coverage growth curve feedback

    core features:
    1. Coverage data collection
    2. Real-time statistics
    3. Growth curve tracking
    4. Coverage reporting
    """

    def __init__(self):
        self.covered_blocks: Set[int] = set()
        self.total_blocks: int = 0
        self.coverage_history: List[Dict[str, Any]] = []
        self.execution_count: int = 0
        self.start_time: float = 0
        # 边覆盖位图：AFL 风格的边哈希映射
        self._edge_bitmap: Dict[int, int] = defaultdict(int)
        self._prev_block: Optional[int] = None

    def set_total_blocks(self, total: int):
        """Set total basic block count"""
        self.total_blocks = total

    def add_covered_block(self, block_addr: int):
        """Register a covered basic block"""
        self.covered_blocks.add(block_addr)

    # ---- 边覆盖追踪：记录 (prev_block, current_block) 边对 ----
    def record_edge(self, current_block: int) -> None:
        if self._prev_block is not None:
            edge_key = (self._prev_block >> 2) ^ (current_block << 3)
            edge_key &= 0xFFFF
            self._edge_bitmap[edge_key] += 1
        self._prev_block = current_block

    def reset_edge_tracking(self) -> None:
        self._prev_block = None

    def edge_coverage_count(self) -> int:
        return len(self._edge_bitmap)

    def record_execution(self, covered_blocks: List[int]):
        """Record a fuzzing execution"""
        self.execution_count += 1

        # 更新已覆盖基本块集合
        for block in covered_blocks:
            self.covered_blocks.add(block)

        # 记录覆盖率历史数据点
        coverage_rate = self.get_coverage_rate()
        self.coverage_history.append({
            'execution': self.execution_count,
            'coverage_rate': coverage_rate,
            'new_blocks': len(covered_blocks),
            'edge_count': len(self._edge_bitmap),
            'timestamp': time.time()
        })

    def get_coverage_rate(self) -> float:
        """Get current coverage rate"""
        if self.total_blocks == 0:
            return 0.0
        return len(self.covered_blocks) / self.total_blocks

    def get_coverage_growth_curve(self) -> List[Dict[str, Any]]:
        """Get coverage growth curve data"""
        return self.coverage_history

    def get_statistics(self) -> Dict[str, Any]:
        """Get coverage statistics"""
        return {
            'total_blocks': self.total_blocks,
            'covered_blocks': len(self.covered_blocks),
            'coverage_rate': self.get_coverage_rate(),
            'execution_count': self.execution_count,
            'edge_coverage': len(self._edge_bitmap),
            'elapsed_time': time.time() - self.start_time if self.start_time else 0
        }

    def generate_coverage_report(self) -> str:
        """Generate coverage report"""
        stats = self.get_statistics()

        report = '# Fuzzing coverage report\n\n'
        report += f'## Statistics\n'
        report += f'- Total basic blocks: {stats["total_blocks"]}\n'
        report += f'- Blocks covered: {stats["covered_blocks"]}\n'
        report += f'- Coverage rate: {stats["coverage_rate"]*100:.2f}%\n'
        report += f'- Edge pairs covered: {stats["edge_coverage"]}\n'
        report += f'- Execution count: {stats["execution_count"]}\n'

        return report

    def start_tracking(self):
        """Start coverage tracking session"""
        self.start_time = time.time()
        self.coverage_history = []
        self.execution_count = 0
        self._edge_bitmap.clear()
        self._prev_block = None


class RuntimeEnvironmentVariableFuzzer:
    """
    Generate malformed environment variable and CLI argument combinations
    Detect vulnerabilities triggered during process startup

    core features:
    1. Environment variable fuzzing
    2. Command-line argument fuzzing
    3. Startup-phase detection
    4. Vulnerability discovery
    """

    def __init__(self):
        self.fuzz_cases: List[Dict[str, Any]] = []
        self.test_results: List[Dict[str, Any]] = []
        self.found_vulnerabilities: List[Dict[str, Any]] = []
        self._generate_fuzz_cases()

    def _generate_fuzz_cases(self):
        """Generate fuzz test cases"""
        # 环境变量 Fuzz 用例集
        env_fuzz_cases = [
            {'name': 'PATH', 'value': '/very/long/path/' * 100},
            {'name': 'HOME', 'value': '/nonexistent'},
            {'name': 'LD_LIBRARY_PATH', 'value': '/malicious/lib'},
            {'name': 'LANG', 'value': 'invalid_lang'},
            {'name': 'TERM', 'value': 'invalid_term'},
            {'name': 'SHELL', 'value': '/bin/nonexistent'},
            {'name': 'USER', 'value': ''},
            {'name': 'PWD', 'value': '/very/deep/path/' * 50},
            # 补充：常见注入向量
            {'name': 'LD_PRELOAD', 'value': '/tmp/evil.so'},
            {'name': 'PYTHONPATH', 'value': '/malicious/py'},
            {'name': 'IFS', 'value': '\t\n'},
            {'name': 'TMPDIR', 'value': '/nonexistent/' * 20},
        ]

        # 命令行参数 Fuzz 用例集
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
        """Fuzz environment variables"""
        results = []

        for case in self.fuzz_cases[0]['cases']:
            env = {case['name']: case['value']}

            try:
                # 执行目标二进制
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

                # 检测漏洞指标
                if process.returncode < 0:  # Terminated by signal
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
        """Fuzz command-line arguments"""
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
        """Generate fuzz report"""
        report = '# Environment and argument fuzz test report\n\n'

        report += '## Test statistics\n'
        report += f'- Total test cases: {len(self.test_results)}\n'
        report += f'- Vulnerabilities found: {len(self.found_vulnerabilities)}\n\n'

        if self.found_vulnerabilities:
            report += '## Discovered vulnerabilities\n'
            for vuln in self.found_vulnerabilities:
                report += f'- Type: {vuln["type"]}\n'
                if 'env_var' in vuln:
                    report += f'  Environment variable: {vuln["env_var"]}\n'
                report += f'  Signal: {vuln.get("signal", "N/A")}\n'
                if 'signal_name' in vuln:
                    report += f'  Signal name: {vuln["signal_name"]}\n'

        return report


class FirmwareFileSystemIntegrityChecker:
    """
    Validate extracted firmware filesystem against security baseline
    Detects unauthorized SUID binaries, world-writable files, hardcoded credentials

    core features:
    1. Filesystem validation
    2. Permission auditing
    3. Security baseline compliance
    4. SUID/SGID detection
    """

    def __init__(self):
        self.security_baseline: Dict[str, Any] = {}
        self.violations: List[Dict[str, Any]] = []
        # 已知存在漏洞的二进制哈希 → CVE 映射
        self._known_bad_hashes: Dict[str, List[str]] = {}
        self._define_security_baseline()

    def _define_security_baseline(self):
        """Define security baseline rules"""
        self.security_baseline = {
            'no_suid_binaries': True,
            'no_sgid_binaries': True,
            'no_world_writable_files': True,
            'no_empty_passwords': True,
            'no_hardcoded_credentials': True,
            'required_permissions': {
                '/etc/passwd': '0644',
                '/etc/shadow': '0600',
                '/bin': '0755'
            }
        }

    # ---- 已知漏洞二进制检测 ----
    def load_known_vulnerable_hashes(self, hash_to_cve: Dict[str, List[str]]) -> None:
        """加载已知漏洞二进制哈希映射，用于快速识别内置脆弱组件"""
        self._known_bad_hashes.update(hash_to_cve)

    def _check_known_vulnerable(self, filepath: str) -> Optional[List[str]]:
        try:
            h = hashlib.sha256()
            with open(filepath, 'rb') as fh:
                for chunk in iter(lambda: fh.read(65536), b''):
                    h.update(chunk)
            digest = h.hexdigest()
            return self._known_bad_hashes.get(digest)
        except Exception:
            return None

    def check_suid_binaries(self, filesystem_path: str) -> List[Dict[str, Any]]:
        """Check for SUID/SGID binaries"""
        suid_files = []

        try:
            for root, dirs, files in os.walk(filesystem_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        stat_info = os.stat(file_path)
                        mode = stat_info.st_mode

                        # 检查 SUID 权限位
                        if mode & 0o4000:  # SUID
                            entry = {
                                'path': file_path,
                                'mode': oct(mode)[-4:],
                                'violation': 'SUID binary found'
                            }
                            cves = self._check_known_vulnerable(file_path)
                            if cves:
                                entry['known_cves'] = cves
                                entry['risk'] = 'critical'
                            suid_files.append(entry)

                        # 检查 SGID 权限位
                        if mode & 0o2000:  # SGID
                            entry = {
                                'path': file_path,
                                'mode': oct(mode)[-4:],
                                'violation': 'SGID binary found'
                            }
                            cves = self._check_known_vulnerable(file_path)
                            if cves:
                                entry['known_cves'] = cves
                            suid_files.append(entry)

                    except Exception:
                        logger.debug("suppressed", exc_info=True)

        except Exception as e:
            logger.warning(f"checkSUIDfailed: {e}")

        self.violations.extend(suid_files)
        return suid_files

    def check_world_writable_files(self, filesystem_path: str) -> List[Dict[str, Any]]:
        """Check for world-writable files"""
        writable_files = []

        try:
            for root, dirs, files in os.walk(filesystem_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        stat_info = os.stat(file_path)
                        mode = stat_info.st_mode

                        # 检查全局可写权限位
                        if mode & 0o0002:
                            writable_files.append({
                                'path': file_path,
                                'mode': oct(mode)[-4:],
                                'violation': 'World-writable file'
                            })

                    except Exception:
                        logger.debug("suppressed", exc_info=True)

        except Exception as e:
            logger.warning(f"World-writable file check failed: {e}")

        self.violations.extend(writable_files)
        return writable_files

    def check_hardcoded_credentials(self, filesystem_path: str) -> List[Dict[str, Any]]:
        """Check for hardcoded credentials"""
        credential_files = []

        credential_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']'
        ]

        try:
            for root, dirs, files in os.walk(filesystem_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()

                            for pattern in credential_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    credential_files.append({
                                        'path': file_path,
                                        'violation': 'Hardcoded credential'
                                    })
                                    break

                    except Exception:
                        logger.debug("suppressed", exc_info=True)

        except Exception as e:
            logger.warning(f"Credential check failed: {e}")

        self.violations.extend(credential_files)
        return credential_files

    def run_full_integrity_check(self, filesystem_path: str) -> Dict[str, Any]:
        """Run full filesystem integrity check"""
        result = {
            'filesystem_path': filesystem_path,
            'suid_binaries': self.check_suid_binaries(filesystem_path),
            'world_writable': self.check_world_writable_files(filesystem_path),
            'hardcoded_credentials': self.check_hardcoded_credentials(filesystem_path),
            'compliant': True,
            'violations_count': 0
        }

        result['violations_count'] = len(self.violations)
        result['compliant'] = result['violations_count'] == 0

        return result

    def generate_integrity_report(self) -> str:
        """Generate integrity report"""
        report = '# Firmware filesystem integrity report\n\n'

        report += '## Security baseline checks\n'

        violations_by_type = defaultdict(list)
        for violation in self.violations:
            violations_by_type[violation['violation']].append(violation['path'])

        for violation_type, paths in violations_by_type.items():
            report += f'- {violation_type}: {len(paths)} violations\n'

        if self.violations:
            report += '\n## Violation details\n'
            for violation in self.violations:
                report += f'- {violation["path"]}: {violation["violation"]}\n'
                if 'known_cves' in violation:
                    report += f'  ⚠ Known CVEs: {", ".join(violation["known_cves"])}\n'

        return report


class NetworkServiceResponseDiffAnalyzer:
    """
    Send near-identical request pairs; compare response differentials
    Detect information disclosure and exception handling anomalies

    core features:
    1. Request pair generation
    2. Response comparison
    3. Information disclosure detection
    4. Exception discovery
    """

    def __init__(self):
        self.request_pairs: List[Dict[str, Any]] = []
        self.response_diffs: List[Dict[str, Any]] = []
        self.detected_issues: List[Dict[str, Any]] = []
        # 请求指纹历史，用于检测时序侧信道
        self._timing_baseline: Dict[str, List[float]] = defaultdict(list)

    def generate_request_pairs(self, base_request: bytes) -> List[Dict[str, bytes]]:
        """Generate request variation pairs"""
        pairs = []

        # 生成近似请求变体
        variations = [
            {'name': 'empty_field', 'request': base_request.replace(b'value', b'')},
            {'name': 'long_value', 'request': base_request.replace(b'value', b'value' * 100)},
            {'name': 'special_chars', 'request': base_request.replace(b'value', b'<script>')},
            {'name': 'null_bytes', 'request': base_request.replace(b'value', b'\x00\x00')},
        ]

        for variation in variations:
            pairs.append({
                'name': variation['name'],
                'request1': base_request,
                'request2': variation['request']
            })

        self.request_pairs = pairs
        return pairs

    def compare_responses(self, response1: bytes, response2: bytes) -> Dict[str, Any]:
        """Compare two response payloads"""
        diff = {
            'size_diff': len(response2) - len(response1),
            'content_diff': [],
            'status_diff': False,
            'potential_leak': False
        }

        # 检查响应大小差异
        if abs(diff['size_diff']) > 100:
            diff['potential_leak'] = True
            diff['content_diff'].append('Response size anomaly')

        # 检查响应内容差异
        if response1 != response2:
            # 定位字节差异位置
            for i, (c1, c2) in enumerate(zip(response1, response2)):
                if c1 != c2:
                    diff['content_diff'].append(f'Byte divergence at offset {i}')

        # 检测错误消息泄露
        error_patterns = [b'error', b'exception', b'failed', b'invalid']
        for pattern in error_patterns:
            if pattern in response2 and pattern not in response1:
                diff['potential_leak'] = True
                diff['content_diff'].append('Error string disclosure detected')

        return diff

    def analyze_service_responses(self, target: str, port: int) -> List[Dict[str, Any]]:
        """Analyze service responses"""
        results = []

        for pair in self.request_pairs:
            try:
                # 发送请求变体 1
                sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock1.settimeout(5)
                sock1.connect((target, port))
                t1_start = time.perf_counter()
                sock1.send(pair['request1'])
                response1 = sock1.recv(4096)
                t1 = time.perf_counter() - t1_start
                sock1.close()

                # 发送请求变体 2
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.settimeout(5)
                sock2.connect((target, port))
                t2_start = time.perf_counter()
                sock2.send(pair['request2'])
                response2 = sock2.recv(4096)
                t2 = time.perf_counter() - t2_start
                sock2.close()

                # 比对响应对
                diff = self.compare_responses(response1, response2)

                results.append({
                    'pair_name': pair['name'],
                    'diff': diff,
                    'timing': {'req1_ms': round(t1 * 1000, 2),
                               'req2_ms': round(t2 * 1000, 2)},
                })

                if diff['potential_leak']:
                    self.detected_issues.append({
                        'type': 'information_leak',
                        'pair_name': pair['name'],
                        'description': 'Potential information disclosure via response differential'
                    })

                # 时序侧信道检测：同对两请求耗时差异 >10x 标记
                if t1 > 0 and (t2 / t1 > 10 or t1 / t2 > 10):
                    self.detected_issues.append({
                        'type': 'timing_anomaly',
                        'pair_name': pair['name'],
                        'description': f'Response timing ratio {max(t1,t2)/min(t1,t2):.1f}x',
                    })

            except Exception as e:
                results.append({
                    'pair_name': pair['name'],
                    'error': str(e)
                })

        self.response_diffs = results
        return results

    # ---- 指纹收集：对相同请求多次采样，建立响应特征基线 ----
    def fingerprint_service(self, target: str, port: int,
                            probe: bytes, samples: int = 10) -> Dict[str, Any]:
        times = []
        sizes = []
        for _ in range(samples):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target, port))
                t0 = time.perf_counter()
                sock.send(probe)
                resp = sock.recv(4096)
                elapsed = time.perf_counter() - t0
                times.append(elapsed)
                sizes.append(len(resp))
                sock.close()
            except Exception:
                pass
        if not times:
            return {'error': 'No successful probes'}
        return {
            'avg_response_ms': round(sum(times) / len(times) * 1000, 2),
            'std_response_ms': round(
                (sum((t - sum(times) / len(times)) ** 2
                     for t in times) / len(times)) ** 0.5 * 1000, 2),
            'avg_size': sum(sizes) // len(sizes),
            'samples': len(times),
        }

    def generate_diff_report(self) -> str:
        """Generate differential analysis report"""
        report = '# Network service response differential analysis report\n\n'

        report += '## Response differentials\n'
        for diff in self.response_diffs:
            report += f'- {diff["pair_name"]}: sizediff {diff["diff"]["size_diff"]}\n'

        if self.detected_issues:
            report += '\n## Detected issues\n'
            for issue in self.detected_issues:
                report += f'- {issue["type"]}: {issue["description"]}\n'

        return report


class CodeComplexityGuidedResourceAllocator:
    """
    Allocate analysis resources proportional to function complexity and risk
    Enables deeper symbolic execution for high-risk functions

    core features:
    1. Complexity evaluation
    2. Resource allocation
    3. Analysis depth adjustment
    4. Time budget management
    """

    def __init__(self):
        self.complexity_scores: Dict[int, float] = {}
        self.resource_allocation: Dict[int, Dict[str, Any]] = {}
        self.total_budget: float = 100.0  # Total analysis time budget

    def calculate_complexity_score(self, function_code: str) -> float:
        """Calculate function complexity score"""
        score = 0.0

        # 控制流复杂度因子
        cf_count = len(re.findall(r'(if|while|for|switch)', function_code))
        score += cf_count * 2

        # API 调用复杂度因子
        api_count = len(re.findall(r'call\s+\w+', function_code))
        score += api_count * 1

        # 内存操作复杂度因子
        mem_count = len(re.findall(r'(malloc|free|memcpy|strcpy)', function_code))
        score += mem_count * 3

        # 代码规模因子
        line_count = len(function_code.split('\n'))
        score += line_count * 0.1

        return score

    # ---- McCabe 圈复杂度 ----
    @staticmethod
    def cyclomatic_complexity(function_code: str) -> int:
        """M = E - N + 2P，简化：统计决策点 + 1"""
        decision_patterns = [
            r'\bif\b', r'\bwhile\b', r'\bfor\b', r'\bswitch\b',
            r'\bcase\b', r'\bcatch\b', r'\band\b', r'\bor\b',
            r'\?\s*.*\s*:',
        ]
        count = 1
        for pat in decision_patterns:
            count += len(re.findall(pat, function_code))
        return count

    def allocate_resources(self, function_addr: int, complexity_score: float) -> Dict[str, Any]:
        """Allocate analysis resources"""
        # 按复杂度等比分配资源
        allocation = {
            'function_addr': function_addr,
            'complexity_score': complexity_score,
            'symbolic_depth': min(10, int(complexity_score / 5)),
            'analysis_time': min(30, complexity_score * 0.5),
            'priority': 'high' if complexity_score > 20 else 'medium'
        }

        self.complexity_scores[function_addr] = complexity_score
        self.resource_allocation[function_addr] = allocation

        return allocation

    def distribute_budget(self, functions: Dict[int, str]) -> Dict[str, Any]:
        """Distribute analysis budget"""
        # 计算全部函数的复杂度评分
        total_complexity = 0
        allocations = {}

        for addr, code in functions.items():
            score = self.calculate_complexity_score(code)
            total_complexity += score
            allocations[addr] = score

        # 按比例分配分析预算
        distribution = {}
        remaining_budget = self.total_budget

        for addr, score in allocations.items():
            if total_complexity > 0:
                budget_share = (score / total_complexity) * self.total_budget
                distribution[addr] = self.allocate_resources(addr, score)
                distribution[addr]['budget_share'] = budget_share

        return distribution

    def get_analysis_priority_order(self) -> List[int]:
        """Get analysis priority order"""
        # 按复杂度降序排列
        sorted_funcs = sorted(
            self.complexity_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return [addr for addr, score in sorted_funcs]

    def generate_allocation_report(self) -> str:
        """Generate allocation report"""
        report = '# Complexity-guided resource allocation report\n\n'

        report += '## Resource allocation\n'
        for addr, allocation in self.resource_allocation.items():
            report += f'- {hex(addr)}: score={allocation["complexity_score"]}, time={allocation["analysis_time"]}min\n'

        return report


class MultiModeFuzzingCoordinator:
    """
    Run multiple fuzzing engines concurrently (AFL, LibFuzzer, honggfuzz)
    Shared corpus with automatic synchronization

    core features:
    1. Multi-engine coordination
    2. Corpus sharing
    3. Result synchronization
    4. Efficiency maximization
    """

    def __init__(self):
        self.fuzzing_engines: Dict[str, Dict[str, Any]] = {}
        self.shared_corpus: List[bytes] = []
        self.sync_results: Dict[str, Any] = {}
        # 引擎子进程追踪
        self._procs: Dict[str, subprocess.Popen] = {}
        self._proc_lock = threading.Lock()
        # 崩溃去重
        self._crash_hashes: Set[str] = set()
        self._register_engines()

    def _register_engines(self):
        """Register fuzzing engines"""
        self.fuzzing_engines['afl'] = {
            'name': 'AFL',
            'command': 'afl-fuzz',
            'corpus_dir': 'corpus/afl',
            'output_dir': 'output/afl'
        }
        self.fuzzing_engines['libfuzzer'] = {
            'name': 'LibFuzzer',
            'command': './fuzzer',
            'corpus_dir': 'corpus/libfuzzer',
            'output_dir': 'output/libfuzzer'
        }
        self.fuzzing_engines['honggfuzz'] = {
            'name': 'honggfuzz',
            'command': 'honggfuzz',
            'corpus_dir': 'corpus/honggfuzz',
            'output_dir': 'output/honggfuzz'
        }

    def start_fuzzing_engine(self, engine_name: str, target_binary: str) -> Dict[str, Any]:
        """Start a fuzzing engine"""
        engine = self.fuzzing_engines.get(engine_name)

        if not engine:
            return {'error': 'Engine not found'}

        result = {
            'engine': engine_name,
            'status': 'starting',
            'pid': None
        }

        try:
            # 创建引擎工作目录
            os.makedirs(engine['corpus_dir'], exist_ok=True)
            os.makedirs(engine['output_dir'], exist_ok=True)

            # 启动进程（实际命令构造）
            cmd = []
            if engine_name == 'afl':
                cmd = ['afl-fuzz', '-i', engine['corpus_dir'],
                       '-o', engine['output_dir'], '--', target_binary, '@@']
            elif engine_name == 'libfuzzer':
                cmd = [target_binary, engine['corpus_dir'],
                       '-rss_limit_mb=2048']
            elif engine_name == 'honggfuzz':
                cmd = ['honggfuzz', '-f', engine['corpus_dir'],
                       '-w', engine['output_dir'], '--', target_binary]
            if cmd:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                with self._proc_lock:
                    self._procs[engine_name] = proc
                result['pid'] = proc.pid
                result['status'] = 'running'
            else:
                result['status'] = 'running'
                result['pid'] = 1234  # Placeholder PID

        except Exception as e:
            result['error'] = str(e)

        return result

    def stop_all(self) -> Dict[str, bool]:
        outcomes = {}
        with self._proc_lock:
            for name, proc in list(self._procs.items()):
                try:
                    proc.terminate()
                    proc.wait(timeout=10)
                    outcomes[name] = True
                except Exception:
                    try:
                        proc.kill()
                        proc.wait()
                    except Exception:
                        pass
                    outcomes[name] = False
            self._procs.clear()
        return outcomes

    def sync_corpus(self) -> Dict[str, Any]:
        """Synchronize corpus across engines"""
        sync_result = {
            'total_corpus': 0,
            'synced_files': 0,
            'new_files': []
        }

        # 从各引擎收集语料
        all_corpus = set()

        for engine_name, engine in self.fuzzing_engines.items():
            corpus_dir = engine['corpus_dir']

            if os.path.exists(corpus_dir):
                for file in os.listdir(corpus_dir):
                    file_path = os.path.join(corpus_dir, file)
                    try:
                        with open(file_path, 'rb') as f:
                            content = f.read()
                            content_hash = hashlib.sha256(content).hexdigest()

                            if content_hash not in all_corpus:
                                all_corpus.add(content_hash)
                                self.shared_corpus.append(content)
                                sync_result['new_files'].append(file)

                    except Exception:
                        logger.debug("suppressed", exc_info=True)

        sync_result['total_corpus'] = len(all_corpus)
        sync_result['synced_files'] = len(sync_result['new_files'])

        # 向各引擎分发共享语料库
        for engine_name, engine in self.fuzzing_engines.items():
            corpus_dir = engine['corpus_dir']

            for i, content in enumerate(self.shared_corpus):
                file_path = os.path.join(corpus_dir, f'synced_{i}')
                with open(file_path, 'wb') as f:
                    f.write(content)

        self.sync_results = sync_result
        return sync_result

    # ---- 崩溃交换：将引擎 A 发现的崩溃馈入引擎 B 的语料 ----
    def exchange_crashes(self, source_engine: str,
                         dest_engine: str) -> int:
        src = self.fuzzing_engines.get(source_engine)
        dst = self.fuzzing_engines.get(dest_engine)
        if not src or not dst:
            return 0
        src_out = src['output_dir']
        if not os.path.exists(src_out):
            return 0
        count = 0
        for fname in os.listdir(src_out):
            if 'crash' not in fname.lower():
                continue
            fpath = os.path.join(src_out, fname)
            try:
                with open(fpath, 'rb') as fh:
                    data = fh.read()
                h = hashlib.sha256(data).hexdigest()
                if h in self._crash_hashes:
                    continue
                self._crash_hashes.add(h)
                dest_path = os.path.join(dst['corpus_dir'], f"xcrash_{h[:8]}")
                with open(dest_path, 'wb') as fh:
                    fh.write(data)
                count += 1
            except Exception:
                logger.debug("crash exchange skip: %s", fname)
        return count

    def aggregate_results(self) -> Dict[str, Any]:
        """Aggregate results"""
        aggregated = {
            'total_crashes': 0,
            'total_coverage': 0,
            'engine_results': {}
        }

        for engine_name, engine in self.fuzzing_engines.items():
            output_dir = engine['output_dir']

            # 统计崩溃数量
            crash_count = 0
            if os.path.exists(output_dir):
                for file in os.listdir(output_dir):
                    if 'crash' in file:
                        crash_count += 1

            aggregated['engine_results'][engine_name] = {
                'crashes': crash_count
            }
            aggregated['total_crashes'] += crash_count

        return aggregated

    def generate_coordination_report(self) -> str:
        """Generate coordination report"""
        report = '# Multi-mode fuzzing coordination report\n\n'

        report += '## Corpus synchronization\n'
        report += f'- Total corpus: {self.sync_results["total_corpus"]}\n'
        report += f'- Newly synced: {self.sync_results["synced_files"]}\n'
        report += f'- Unique crash hashes: {len(self._crash_hashes)}\n\n'

        aggregated = self.aggregate_results()
        report += '## Results aggregation\n'
        report += f'- Total crashes: {aggregated["total_crashes"]}\n'

        for engine_name, result in aggregated['engine_results'].items():
            report += f'- {engine_name}: {result["crashes"]} crashes\n'

        return report


# ---------------------------------------------------------------------------
# 崩溃可利用性分类器：基于信号 + 错误消息模式推断内存破坏类型
# 分类粒度：stack/heap/global overflow, UAF, double-free, null deref
# 启发式规则来源于 exploit 开发实践，不替代 CVSS
# ---------------------------------------------------------------------------
class CrashExploitabilityClassifier:
    """根据崩溃信号、错误消息和栈帧信息推断内存破坏类型"""

    def classify(self, signal_num: int, error_msg: str,
                 stack_frames: Optional[List[str]] = None) -> Dict[str, Any]:
        sig_name = _signal_name(signal_num)
        msg_lower = error_msg.lower()
        frames = stack_frames or []

        corruption_type = "unknown"
        confidence = 0.0
        indicators: List[str] = []

        # 规则链：按特异性从高到低匹配
        if signal_num == 11:  # SIGSEGV
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
        elif signal_num == 6:  # SIGABRT
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
        elif signal_num == 8:  # SIGFPE
            corruption_type = "integer_overflow"
            confidence = 0.45
            indicators.append("sigfpe_arith")
        elif signal_num == 4:  # SIGILL
            corruption_type = "code_execution"
            confidence = 0.70
            indicators.append("sigill_bad_insn")
        elif signal_num == 7:  # SIGBUS
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


# ---------------------------------------------------------------------------
# Fuzzer 健康监控：持续追踪各引擎的执行速率、覆盖率增长、崩溃唯一性
# 决策依据：增长率持续 < 5%/h 且 exec/s 稳定 → 建议切换策略或引擎
# ---------------------------------------------------------------------------
class FuzzerHealthMonitor:
    """实时监控 fuzzer 运行指标，检测停滞与退化"""

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
            # 截断过期样本
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


# ---------------------------------------------------------------------------
# Sanitizer Harness 生成器：根据漏洞类型自动附加 ASan/MSan/UBSan 标志
# ---------------------------------------------------------------------------
class SanitizerHarnessGenerator:
    """为目标二进制生成带 sanitizer 的编译命令和 harness 骨架"""

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
        return f"""# Auto-generated sanitizer build for {target_name}
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

// Sanitizer 感知入口：ASan/UBSan 在越界/未定义行为时立即中断
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size == 0) return 0;
    return {target_func}(data, size);
}}
'''

    def analyze_crash_for_sanitizer_recommendation(
            self, classification: Dict[str, Any]) -> List[str]:
        """根据崩溃分类推荐最合适的 sanitizer"""
        ct = classification.get('corruption_type', 'unknown')
        recs = ['asan']  # ASan 总是首选
        if ct in ('use_after_free', 'double_free', 'heap_buffer_overflow',
                   'heap_corruption'):
            recs.append('msan')
        if ct in ('integer_overflow', 'misaligned_access'):
            recs.append('ubsan')
        if ct == 'code_execution':
            recs.extend(['asan', 'ubsan'])
        return recs


# ---------------------------------------------------------------------------
# ICS/SCADA 协议模糊测试模板：针对 Modbus、DNP3、S7comm 等工控协议
# 生成结构保持的畸形报文，已知字段边界内注入异常值
# 参考 ISSTA 2025 ECU Firmware Fuzzing 的诊断反馈思路
# ---------------------------------------------------------------------------
class ICSProtocolFuzzTemplates:
    """工控协议专用变异模板库"""

    # Modbus TCP 头部骨架: [Transaction ID(2B) Protocol(2B) Length(2B) Unit(1B)]
    MODBUS_HEADER = b'\x00\x01\x00\x00\x00\x06\x01'

    @staticmethod
    def modbus_read_coils(unit_id: int = 1,
                          start_addr: int = 0,
                          count: int = 10) -> bytes:
        header = bytearray(ICSProtocolFuzzTemplates.MODBUS_HEADER)
        header[6] = unit_id  # Unit ID
        func = bytes([0x01])  # Read Coils
        addr = struct.pack('>H', start_addr)
        cnt = struct.pack('>H', count)
        # 重组长度字段
        pdu_len = 1 + len(addr) + len(cnt)
        header[4:6] = struct.pack('>H', pdu_len)
        return bytes(header) + func + addr + cnt

    @staticmethod
    def modbus_mutants(base_pdu: bytes) -> List[bytes]:
        """对 Modbus PDU 做保持结构的变异"""
        if len(base_pdu) < 4:
            return [base_pdu]
        mutants = []
        buf = bytearray(base_pdu)
        # 变体 1: 长度字段与 PDU 不匹配
        mismatch = bytearray(buf)
        mismatch[4:6] = struct.pack('>H', 0xFFFF)
        mutants.append(bytes(mismatch))
        # 变体 2: 功能码 + 0x80 错误响应标记
        func_high = bytearray(buf)
        if len(func_high) > 7:
            func_high[7] |= 0x80
        mutants.append(bytes(func_high))
        # 变体 3: 事务 ID 置零
        zero_tid = bytearray(buf)
        zero_tid[0:2] = b'\x00\x00'
        mutants.append(bytes(zero_tid))
        # 变体 4: 单元 ID 遍历 0-255
        for uid in (0, 127, 247, 255):
            unit_scan = bytearray(buf)
            unit_scan[6] = uid
            mutants.append(bytes(unit_scan))
        return mutants

    @staticmethod
    def can_frame(arb_id: int = 0x7DF,
                  data: bytes = b'\x02\x01\x0D') -> bytes:
        """生成标准 CAN 帧 (11-bit ID, DLC ≤8)"""
        dlc = min(8, len(data))
        padded = data[:dlc].ljust(dlc, b'\x00')
        # 简化帧打包: ID(4B LE) + DLC(1B) + data(8B)
        return struct.pack('<IB8s', arb_id & 0x7FF, dlc, padded)

    @staticmethod
    def can_mutants(base_frame: bytes) -> List[bytes]:
        """CAN 帧变异：ID 遍历、DLC 不匹配、填充字节异常"""
        if len(base_frame) < 13:
            return [base_frame]
        mutants = []
        # DLC > 8（规格外）
        oversized = bytearray(base_frame)
        oversized[4] = 15
        mutants.append(bytes(oversized))
        # 仲裁 ID 广播 (0x00 保留)
        for test_id in (0x000, 0x7FF, 0x123):
            alt_id = bytearray(base_frame)
            alt_id[0:4] = struct.pack('<I', test_id & 0x7FF)
            mutants.append(bytes(alt_id))
        return mutants


# ---------------------------------------------------------------------------
# 诊断引导反馈循环：接收执行异常信号（崩溃类型/错误码），反哺变异策略
# ISSTA 2025 的诊断反馈思想 → 特定信号类型关联的字节偏移更可能触发漏洞
# ---------------------------------------------------------------------------
class DiagnosisGuidedFeedback:
    """根据崩溃诊断结论调整变异热点"""

    def __init__(self):
        self._signal_hotspots: Dict[int, Dict[int, float]] = defaultdict(
            lambda: defaultdict(float))

    def record_crash(self, signal_num: int, mutated_offset: int,
                     corruption_type: str) -> None:
        """记录一次崩溃：信号 → 变异偏移 → 权重增量"""
        weight = 0.5
        if corruption_type in ('stack_buffer_overflow', 'code_execution'):
            weight = 1.5
        elif corruption_type in ('use_after_free', 'double_free'):
            weight = 1.0
        self._signal_hotspots[signal_num][mutated_offset] += weight

    def recommend_offsets(self, signal_num: int, top_k: int = 8) -> List[int]:
        """返回该信号类型下历史最热门的偏移列表"""
        hotspots = self._signal_hotspots.get(signal_num, {})
        ranked = sorted(hotspots.items(), key=lambda x: -x[1])[:top_k]
        return [offset for offset, _ in ranked]

    def decay_all(self, factor: float = 0.9) -> None:
        for sig in self._signal_hotspots:
            for off in list(self._signal_hotspots[sig].keys()):
                self._signal_hotspots[sig][off] *= factor
                if self._signal_hotspots[sig][off] < 0.05:
                    del self._signal_hotspots[sig][off]


# ---------------------------------------------------------------------------
# 二进制提升等价性验证：比较原始二进制与控制流提升后的 IR 是否等价
# 用于检测 binary lifter (如 Ghidra→pcode, angr→VEX) 的翻译错误
# ---------------------------------------------------------------------------
class BinaryLiftingVerifier:
    """验证二进制提升前后行为一致性"""

    def __init__(self):
        self._oracle_results: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def verify_round_trip(self, native_output: bytes,
                          lifted_output: bytes) -> Dict[str, Any]:
        """比较原生执行输出与提升后执行输出是否一致"""
        match = native_output == lifted_output
        result = {
            'match': match,
            'native_len': len(native_output),
            'lifted_len': len(lifted_output),
        }
        if not match:
            # 定位第一个差异字节
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


# ---------------------------------------------------------------------------
# Patch-Delta 聚焦 Fuzzing：识别补丁变更的函数，将 fuzz 预算集中到变更区域
# 思路：patch 前后的二进制 diff → 标记变更函数 → 优先对变更函数生成测试
# ---------------------------------------------------------------------------
class PatchDeltaFuzzer:
    """面向补丁差异的定向模糊测试调度器"""

    def __init__(self):
        self._changed_addrs: Set[int] = set()
        self._affected_paths: Dict[int, List[int]] = defaultdict(list)

    def load_diff(self, changed_function_addrs: List[int]) -> None:
        """加载补丁 diff 中标记的变更函数地址"""
        self._changed_addrs = set(changed_function_addrs)

    def is_hot(self, func_addr: int) -> bool:
        """判断函数是否在补丁变更集中"""
        return func_addr in self._changed_addrs

    def prioritize_seeds(self, seeds: List[Tuple[bytes, Set[int]]]
                         ) -> List[Tuple[bytes, float]]:
        """
        seeds: [(data, {covered_func_addrs}), ...]
        返回 (data, priority_weight): 覆盖变更函数多的种子权重高
        """
        if not self._changed_addrs:
            return [(s, 1.0) for s, _ in seeds]
        weighted = []
        for data, covered in seeds:
            hit_count = len(covered & self._changed_addrs)
            weight = 1.0 + hit_count * 2.0  # 命中变更函数权重翻倍
            weighted.append((data, weight))
        return weighted

    def generate_regression_corpus(self, original_crashes: List[bytes],
                                   output_dir: str) -> int:
        """从原始崩溃集生成回归测试语料，输出到目录"""
        os.makedirs(output_dir, exist_ok=True)
        count = 0
        for i, crash in enumerate(original_crashes):
            # 去重写入
            h = hashlib.sha256(crash).hexdigest()[:8]
            path = os.path.join(output_dir, f"regress_{h}.bin")
            if not os.path.exists(path):
                with open(path, 'wb') as fh:
                    fh.write(crash)
                count += 1
        return count


# ---------------------------------------------------------------------------
# 二进制→Fuzz Driver 生成器：从导入表/导出表推断 API 签名，自动生成
# LibFuzzer 风格的 fuzz target。参考 LibLMFuzz (arXiv:2507.15058) 思路，
# 但去掉 LLM 依赖，改为纯静态分析驱动的模板填充。
# ---------------------------------------------------------------------------
class FuzzDriverGenerator:
    """从二进制元数据推断并生成 fuzz harness"""

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
        """从导出函数列表生成多目标的 LibFuzzer harness"""
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


# ---------------------------------------------------------------------------
# Oracle 构造工具包：从已有崩溃/差异样例中提取不变量，反向生成测试断言
# ---------------------------------------------------------------------------
class OracleConstructor:
    """从历史发现中提取并实例化测试 Oracle"""

    def __init__(self):
        self._invariants: List[Dict[str, Any]] = []
        self._violations: List[Dict[str, Any]] = []

    def learn_from_diff(self, diff: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """从一次差异中提取可泛化的不变量"""
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


# ---------------------------------------------------------------------------
# 关系化执行追踪比较：比较两个二进制执行同一输入时的基本块序列
# BINSEC 关系化符号执行思想的轻量替代 → 在具体执行层面比较轨迹
# ---------------------------------------------------------------------------
class RelationalTraceComparer:
    """比较两个二进制执行同一输入时的基本块轨迹"""

    def __init__(self):
        self._divergence_points: List[Dict[str, Any]] = []

    def compare_block_traces(
            self, trace_a: List[int], trace_b: List[int]) -> Dict[str, Any]:
        """比较基本块地址序列，返回首个分歧点与整体相似度"""
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


# ---------------------------------------------------------------------------
# 密码学弱点检测器：扫描二进制中的弱密码学使用模式
# 检测项：硬编码密钥/IV、弱 PRNG（rand/lcong48）、ECB 模式标识、
# MD5/SHA1 用于安全场景、固定盐值、过短密钥长度
# ---------------------------------------------------------------------------
class CryptoWeaknessDetector:
    """二进制密码学反模式扫描"""

    # 已知弱算法/模式的魔数或特征字节
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
        # 弱 PRNG 符号扫描
        for pat in self._WEAK_PRNG:
            for m in pat.finditer(raw_bytes):
                findings.append({
                    'type': 'weak_prng',
                    'detail': '使用非密码学安全的随机数生成器',
                    'offset': m.start()})
                if len(findings) >= 8:
                    break
        # 硬编码密钥模式
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


# ---------------------------------------------------------------------------
# 反分析/反调试检测器：识别二进制中对抗逆向工程的保护手段
# 检测项：ptrace 自检、时间反调试、INT3 扫描、VM 检测、代码混淆迹象
# ---------------------------------------------------------------------------
class AntiAnalysisDetector:
    """二进制反分析技术特征检测"""

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


# ---------------------------------------------------------------------------
# 漏洞可达性分析器：基于调用图判定 CVE 关联函数是否可被外部触发
# 思路来自 arXiv 2511.20313：SBOM 扫描 97.5% 误报，经调用图可达性
# 分析可消除 63.3%。此处提供 BFS+DFS 双模可达性判定。
# ---------------------------------------------------------------------------
class VulnerabilityReachabilityAnalyzer:
    """调用图遍历判定漏洞函数是否可被攻击面触及"""

    def __init__(self):
        self._edges: Dict[str, Set[str]] = defaultdict(set)  # caller → {callees}
        self._attack_surface: Set[str] = set()

    def add_edge(self, caller: str, callee: str) -> None:
        self._edges[caller].add(callee)

    def mark_attack_surface(self, funcs: List[str]) -> None:
        """标记攻击面函数：网络入口、文件解析、IPC 处理等"""
        self._attack_surface.update(funcs)

    def reachable_from_surface(self, target: str,
                                max_depth: int = 10) -> Dict[str, Any]:
        """反向 BFS：从 target 回溯到攻击面"""
        if target in self._attack_surface:
            return {'reachable': True, 'depth': 0, 'direct_entry': True}

        # 构建反向索引
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
                    # 重建路径
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
        """对 CVE 列表做批量可达性分析，产出热力图"""
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


# ---------------------------------------------------------------------------
# MMIO 访问建模器：固件 Fuzzing 的外设寄存器行为建模
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# PE 熵分析器：基于节区熵检测加壳/加密/压缩迹象
# 高熵节 (≥7.0) → 加密或压缩代码段；低熵节 + 高熵节 → 加壳二进制
# 参考 threatflux-binary-analysis 和 Binee 的 packer 检测方法
# ---------------------------------------------------------------------------
class PEEntropyAnalyzer:
    """PE 二进制节区熵分析与加壳检测"""

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
        """分析所有节区熵值，检测可疑节"""
        self._section_entropy = {}
        for name, data in sections.items():
            ent = round(self.compute_entropy(data), 2)
            self._section_entropy[name] = ent

        high_entropy = {k: v for k, v in self._section_entropy.items()
                        if v >= 7.0}
        low_entropy = {k: v for k, v in self._section_entropy.items()
                       if v <= 3.0}

        # 加壳判定规则
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
        """检测 PE 尾部附加数据 (overlay) — 常见于捆绑包/下载器"""
        return len(pe_raw) > section_end + 256


# 漏洞缓解检测器：识别二进制中启用的安全缓解措施并评估缺失风险
# 检测项：NX/DEP、Stack Canary、PIE/ASLR、RELRO、CFI、Shadow Stack、
# CET (Intel)、PAC (ARM64)、SafeSEH。产出现有防御面与缺口分析。
# ---------------------------------------------------------------------------
class ExploitMitigationDetector:
    """二进制安全缓解措施检测与缺口评估"""

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
        """从 ELF 节头和标志推断启用的缓解措施"""
        present = {}
        missing = {}

        # NX: GNU_STACK 节头不含 PF_X
        if elf_sections:
            sections_str = ' '.join(elf_sections).lower()
            present['nx'] = 'gnu_stack' in sections_str
        else:
            present['nx'] = b'GNU_STACK' in raw_bytes

        # Canary: __stack_chk_fail 导入
        present['canary'] = (
            b'__stack_chk_fail' in raw_bytes
            or b'__stack_chk_guard' in raw_bytes)

        # PIE: ELF 类型为 ET_DYN (0x03)
        present['pie'] = raw_bytes[16:18] == b'\x03\x00' if len(
            raw_bytes) > 18 else False

        # Full RELRO: BIND_NOW 标志
        present['full_relro'] = (
            b'BIND_NOW' in raw_bytes
            or b'DT_BIND_NOW' in raw_bytes)

        # FORTIFY: __sprintf_chk 等 *_chk 函数
        present['fortify'] = b'__sprintf_chk' in raw_bytes

        # CFI: __cfi_check 或 __cfi_slowpath
        present['cfi'] = (
            b'__cfi_check' in raw_bytes
            or b'__cfi_slowpath' in raw_bytes)

        # Shadow Stack: cetcompat 标记
        present['shadow_stack'] = b'cetcompat' in raw_bytes.lower()

        # CET: IBT 标记
        present['cet'] = b'ibt' in raw_bytes.lower()

        # PAC: ARM64 PAuth 指令特征
        present['pac'] = (
            b'paciasp' in raw_bytes or b'autiasp' in raw_bytes)

        for check, info in self.MITIGATION_CHECKS.items():
            if present.get(check, False):
                present[check] = True
            else:
                missing[check] = info

        # 风险评分
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
        """对缺失的缓解措施产出加固建议"""
        recs = []
        for check, info in self.MITIGATION_CHECKS.items():
            if check not in self._findings or not self._findings[check]:
                recs.append(
                    f"[{info['risk_if_missing'].upper()}] "
                    f"缺少 {info['name']}: {info['desc']}")
        return recs


# 参考 Fuzzware/μEmu 的 4 类寄存器分类体系 (T0-T3)：
# T0=只读状态 T1=只读常量 T2=写入忽略 T3=写入影响行为
# 对 T3 寄存器注入 fuzz 数据，T0/T1/T2 返回固定值以维持执行
# ---------------------------------------------------------------------------
class MMIOAccessModeler:
    """固件 MMIO 外设寄存器分类与建模"""

    REG_TYPES = {'T0': 'readonly_status', 'T1': 'readonly_constant',
                 'T2': 'write_ignored', 'T3': 'write_affects_behavior'}

    def __init__(self):
        self._registers: Dict[int, Dict[str, Any]] = {}

    def classify_register(self, addr: int, observed_reads: List[int],
                           write_effects: List[bool]) -> str:
        """
        observed_reads: 多次读取的返回值列表
        write_effects: 写入后行为是否改变
        返回 T0-T3 分类
        """
        unique_reads = set(observed_reads)
        if len(unique_reads) > 1 and not any(write_effects):
            reg_type = 'T0'  # 值变化但写入无影响 → 只读状态
        elif len(unique_reads) == 1 and not any(write_effects):
            reg_type = 'T1'  # 恒定值 → 只读常量
        elif not any(write_effects):
            reg_type = 'T2'  # 写入被忽略
        else:
            reg_type = 'T3'  # 写入改变行为 → fuzz 目标
        self._registers[addr] = {
            'type': reg_type,
            'description': self.REG_TYPES[reg_type],
            'observed_values': sorted(unique_reads)[:8],
        }
        return reg_type

    def get_fuzzable_registers(self) -> List[int]:
        """返回所有 T3 寄存器地址（写入可改变行为）"""
        return sorted(
            addr for addr, info in self._registers.items()
            if info['type'] == 'T3')

    def model_response(self, addr: int,
                        write_value: int) -> Optional[int]:
        """模拟 MMIO 读取：T0/T1 返回观测值，T2/T3 返回 0"""
        info = self._registers.get(addr)
        if info is None:
            return None
        if info['type'] in ('T0', 'T1'):
            vals = info.get('observed_values', [0])
            return vals[0] if vals else 0
        return 0  # T2/T3: 简化处理

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


# ---------------------------------------------------------------------------
class DependencyGraphPropagator:
    """组件依赖图中漏洞影响的传递闭包分析"""

    def __init__(self):
        self._deps: Dict[str, Set[str]] = defaultdict(set)  # component → {dependencies}
        self._vulns: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def add_dependency(self, component: str,
                        depends_on: str) -> None:
        self._deps[component].add(depends_on)

    def add_vulnerability(self, component: str,
                           cve_id: str, severity: str = 'unknown') -> None:
        self._vulns[component].append({
            'cve': cve_id, 'severity': severity})

    def propagate(self, root_component: str) -> Dict[str, Any]:
        """从 root 出发遍历传递依赖，汇总影响到的全部 CVE"""
        visited: Set[str] = set()
        queue = deque([root_component])
        transitive_vulns: List[Dict[str, Any]] = []
        dep_chain: Dict[str, List[str]] = defaultdict(list)

        while queue:
            comp = queue.popleft()
            if comp in visited:
                continue
            visited.add(comp)
            # 收集该组件的漏洞
            for vuln in self._vulns.get(comp, []):
                transitive_vulns.append({
                    'component': comp,
                    'cve': vuln['cve'],
                    'severity': vuln['severity'],
                })
            # 传递依赖
            for dep in self._deps.get(comp, set()):
                if dep not in visited:
                    dep_chain[dep] = dep_chain.get(comp, []) + [comp]
                    queue.append(dep)

        # 去重 CVE
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
            # 该节点风险 = 其漏洞严重度之和
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
