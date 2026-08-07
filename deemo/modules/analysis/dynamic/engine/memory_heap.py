# Memory 堆分析工具集
# 栈追踪监控、分配器元数据内省、堆布局工程
#
# Round 6: 堆操作竞态条件检测 — TOCTOU 模式
# 双重检查锁定、多分配器代码中的锁顺序违反
# 并发 free/use 检测（时间戳相关性）

from typing import Dict, Any, List, Optional
import logging, re, os, json, subprocess, hashlib, time, threading, sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class HeapBlock:
    address: int; size: int; flags: int; metadata_addr: int


class HeapAllocatorStateAnalyzer:
    def __init__(self):
        self.allocator_type: Optional[str] = None
        self.heap_blocks: Dict[int, HeapBlock] = {}
    def detect_allocator_type(self, binary_path: str) -> str: return "unknown"
    def parse_heap_metadata(self, heap_addr: int) -> List[HeapBlock]: return []
    def get_block_size(self, block_addr: int) -> Optional[int]: return None
    def get_block_flags(self, block_addr: int) -> Optional[int]: return None
    def find_free_chunks(self, heap_addr: int) -> List[int]: return []
    def plan_heap_exploitation(self, target_state: str) -> List[str]: return []


@dataclass
class HeapOperation:
    op_type: str; size: int; address: int


class HeapFuzzGenerator:
    def __init__(self):
        self.operations: List[HeapOperation] = []; self.heap_state_history: List[Dict[str, Any]] = []
    def generate_random_sequence(self, length: int) -> List[HeapOperation]: return []
    def mutate_sequence(self, sequence: List[HeapOperation]) -> List[HeapOperation]:
        return sequence.copy()
    def find_shortest_trigger_sequence(self, target_state: str) -> List[HeapOperation]: return []
    def replay_sequence(self, sequence: List[HeapOperation]) -> Dict[str, Any]: return {}


@dataclass
class HeapOperationRecord:
    operation_type: str; address: Optional[int]; size: Optional[int]; timestamp: float


class HeapFengShuiRecorder:
    def __init__(self):
        self.operation_log: List[HeapOperationRecord] = []; self.heap_state_at_record: Dict[str, Any] = {}
    def start_recording(self) -> None: self.operation_log = []
    def record_operation(self, op_type: str, address: Optional[int] = None,
                         size: Optional[int] = None) -> None:
        self.operation_log.append(HeapOperationRecord(
            operation_type=op_type, address=address, size=size, timestamp=time.time()))
    def stop_recording(self) -> None: pass
    def generate_replay_script(self) -> str: return ""
    def replay_operations(self, script: str) -> bool: return True


class KernelSymbolAssociator:
    def __init__(self): self.symbol_mapping: Dict[str, int] = {}
    def extract_symbols(self, ko_path: str) -> List[str]: return []
    def find_vmlinux_match(self, symbols: List[str], kernel_version: str) -> Optional[str]: return None
    def resolve_symbol_address(self, symbol_name: str) -> Optional[int]: return None


class MemoryCorruptionPreciseLocator:
    def __init__(self):
        self.corruption_patterns: Dict[str, Dict[str, Any]] = {}
        self.located_vulnerabilities: Dict[int, Dict[str, Any]] = {}
        self._register_corruption_patterns()

    def _register_corruption_patterns(self):
        self.corruption_patterns['buffer_overflow'] = {
            'signature': [r'mov\s+\[.*\],\s*\w+', r'strcpy', r'sprintf', r'memcpy'],
            'constraint': 'write_size > buffer_size', 'severity': 'critical'}
        self.corruption_patterns['use_after_free'] = {
            'signature': [r'mov\s+\[.*\],\s*\w+', r'free', r'malloc'],
            'constraint': 'access_after_free', 'severity': 'critical'}
        self.corruption_patterns['null_pointer_deref'] = {
            'signature': [r'mov\s+\[.*\],\s*\w+', r'cmp\s+\w+,\s*0', r'test\s+\w+,\s*\w+'],
            'constraint': 'ptr == NULL && access', 'severity': 'high'}
        self.corruption_patterns['double_free'] = {
            'signature': [r'free\s*\(', r'free\s*\('],
            'constraint': 'free_count > 1', 'severity': 'critical'}
        # Round 6: TOCTOU 竞态模式 (Time-of-Check Time-of-Use)
        self.corruption_patterns['toctou_race'] = {
            'signature': [r'access\s*\(', r'open\s*\(', r'stat\s*\(',
                         r'chmod\s*\(', r'chown\s*\(', r'rename\s*\('],
            'constraint': 'check_then_use_gap > 0', 'severity': 'high'}
        self.corruption_patterns['double_checked_locking'] = {
            'signature': [r'if\s*\(\s*!\w+\s*\).*mutex_lock',
                         r'if\s*\(\s*!\w+\s*\).*pthread_mutex_lock'],
            'constraint': 'first_check_no_barrier', 'severity': 'medium'}

    def locate_trigger_instruction(self, vulnerability: Dict[str, Any],
                                    code_context: str) -> Dict[str, Any]:
        location = {'vuln_type': vulnerability.get('type', 'unknown'),
                     'trigger_addr': None, 'trigger_instruction': None,
                     'memory_operation': None, 'constraint': None, 'confidence': 0.0}
        vuln_type = vulnerability.get('type', '')
        pattern_info = self.corruption_patterns.get(vuln_type, {})
        if pattern_info:
            for sig in pattern_info.get('signature', []):
                match = re.search(sig, code_context)
                if match:
                    location['trigger_instruction'] = match.group(0)
                    location['trigger_addr'] = match.start()
                    location['constraint'] = pattern_info.get('constraint')
                    location['confidence'] = 0.8
                    break
        return location

    def trace_memory_operation(self, trigger_addr: int, code_context: str) -> Dict[str, Any]:
        trace = {'operation_type': 'unknown', 'source_address': None,
                 'target_address': None, 'size': None, 'preceding_operations': []}
        lines_before = code_context[:trigger_addr].split('\n')[-10:]
        lines_after = code_context[trigger_addr:].split('\n')[:10]
        mem_op_pattern = r'(mov|lea|add|sub)\s+(\w+),\s*\[([^\]]+)\]'
        for line in lines_before + lines_after:
            match = re.search(mem_op_pattern, line)
            if match:
                trace['preceding_operations'].append({
                    'instruction': match.group(1),
                    'destination': match.group(2),
                    'address_expression': match.group(3)})
        return trace

    def solve_trigger_constraint(self, constraint: str,
                                  symbolic_state: Dict[str, Any]) -> Dict[str, Any]:
        solution = {'satisfiable': False, 'trigger_values': {}, 'path_conditions': []}
        if 'write_size > buffer_size' in constraint:
            solution['trigger_values'] = {
                'write_size': symbolic_state.get('max_write', 1024),
                'buffer_size': symbolic_state.get('buffer_size', 64)}
            solution['satisfiable'] = solution['trigger_values']['write_size'] > solution['trigger_values']['buffer_size']
        elif 'ptr == NULL' in constraint:
            solution['trigger_values'] = {'ptr_value': 0}
            solution['satisfiable'] = True
        return solution

    def generate_instruction_level_report(self, vulnerability: Dict[str, Any],
                                           location: Dict[str, Any],
                                           trace: Dict[str, Any]) -> str:
        report = f'''
# 内存破坏精确定位报告

# 漏洞类型
{vulnerability.get('type', 'unknown')}

# 触发指令
Address: {hex(location.get('trigger_addr', 0))}
Instruction: {location.get('trigger_instruction', 'unknown')}
Operation Type: {trace.get('operation_type', 'unknown')}
'''
        if trace.get('preceding_operations'):
            report += '\n### 前置操作:\n'
            for op in trace['preceding_operations']:
                report += f"- {op['instruction']} {op['destination']}, [{op['address_expression']}]\n"
        return report

# Round 6: 竞态条件检测

@dataclass
class RaceCondition:
    """检测到的竞态条件记录，包含 TOCTOU 文件操作和双重检查锁定。"""
    race_id: str; race_type: str    # toctou | lock_order | double_checked_lock
    location: str                    # 函数名:行号
    first_call: str                  # check 操作 (e.g. access/stat)
    second_call: str                 # use 操作 (e.g. open/chmod)
    window_size_estimate: int = 0    # check-use 窗口中的指令数估计
    severity: str = "high"
    annotation: str = ""

class RaceDetector:
    """竞态条件检测器 — 基于调用序列分析和时间戳相关性。

    TOCTOU：查找 access()+open() 或 stat()+chmod() 等先检查后使用模式。
    若两调用间存在时间窗口且无互斥锁保护，构成潜在竞态。

    双重检查锁定：(!ptr){lock; (!ptr){...}} 模式中，
    外层检查缺少内存屏障时，编译器/CPU 可能重排导致部分初始化泄漏。
    """

    TOCTOU_PAIRS = [
        (r'access\s*\(', r'open\s*\('),
        (r'stat\s*\(', r'chmod\s*\('),
        (r'stat\s*\(', r'chown\s*\('),
        (r'lstat\s*\(', r'unlink\s*\('),
        (r'GetFileAttributes', r'CreateFile'),
        (r'PathFileExists', r'DeleteFile'),
    ]

    def __init__(self):
        self._findings: List[RaceCondition] = []
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"RACE-{self._counter:04d}"

    def detect_toctou(self, code_context: str, function_name: str = "") -> List[RaceCondition]:
        """在反编译代码中检测 TOCTOU 竞态条件模式。
        扫描同一函数内的 access+open / stat+chmod 配对，
        配对间的指令数作为竞态窗口大小的估计。"""
        findings = []
        lines = code_context.split('\n')
        for check_pat, use_pat in self.TOCTOU_PAIRS:
            check_positions = []
            use_positions = []
            for i, line in enumerate(lines):
                if re.search(check_pat, line, re.IGNORECASE):
                    check_positions.append(i)
            for i, line in enumerate(lines):
                if re.search(use_pat, line, re.IGNORECASE):
                    use_positions.append(i)

            # 对每个 check，找最近的 use
            for cp in check_positions:
                for up in use_positions:
                    if up > cp and up - cp <= 20:
                        findings.append(RaceCondition(
                            race_id=self._next_id(),
                            race_type="toctou",
                            location=f"{function_name}:{cp}",
                            first_call=check_pat,
                            second_call=use_pat,
                            window_size_estimate=up - cp,
                            severity="high",
                            annotation=f"TOCTOU window of ~{up-cp} instructions between check and use"))
                        break  # 每个 check 只匹配最近的 use
        self._findings.extend(findings)
        return findings

    def detect_lock_ordering(self, lock_sequences: List[List[str]]) -> List[RaceCondition]:
        """检测锁顺序不一致导致的潜在死锁。
        线程 A 按 (L1,L2) 获取锁，线程 B 按 (L2,L1) 获取 → 死锁风险。"""
        findings = []
        seq_pairs = []
        for i, seq_a in enumerate(lock_sequences):
            for j, seq_b in enumerate(lock_sequences):
                if i >= j: continue
                # 检查锁顺序反转
                for idx_a, lock_a in enumerate(seq_a):
                    for idx_b, lock_b in enumerate(seq_b):
                        if lock_a == lock_b and idx_a != idx_b:
                            findings.append(RaceCondition(
                                race_id=self._next_id(),
                                race_type="lock_order",
                                location=f"sequence_{i}_vs_{j}",
                                first_call=lock_a,
                                second_call=lock_b,
                                severity="medium",
                                annotation=f"Lock '{lock_a}' acquired at different positions in sequences {i} and {j}"))
        self._findings.extend(findings)
        return findings


class HeapAllocatorExploiter:
    def __init__(self):
        self.allocator_type: Optional[str] = None
        self.libc_version: Optional[str] = None
        self.exploit_sequences: List[Dict[str, Any]] = []
        self._race_detector = RaceDetector()

    def detect_allocator(self, binary_path: str) -> Dict[str, Any]:
        result = {'allocator_type': 'unknown', 'libc_version': 'unknown', 'features': []}
        try:
            result['allocator_type'] = self._detect_allocator_type(binary_path)
            result['libc_version'] = self._detect_libc_version(binary_path)
            result['features'] = self._detect_allocator_features(result['allocator_type'])
        except Exception as e: result['error'] = str(e)
        self.allocator_type = result['allocator_type']
        self.libc_version = result['libc_version']
        return result

    def _detect_allocator_type(self, binary_path: str) -> str: return 'ptmalloc2'
    def _detect_libc_version(self, binary_path: str) -> str: return '2.31'
    def _detect_allocator_features(self, allocator_type: str) -> List[str]:
        if allocator_type == 'ptmalloc2': return ['fastbins', 'tcache', 'unsortedbin', 'largebin']
        elif allocator_type == 'jemalloc': return ['size_class', 'arena', 'run']
        return []

    def generate_heap_feng_shui_sequence(self, target_state: str) -> List[str]:
        if self.allocator_type == 'ptmalloc2':
            return self._generate_ptmalloc_sequence(target_state)
        return self._generate_jemalloc_sequence(target_state)

    def _generate_ptmalloc_sequence(self, target_state: str) -> List[str]:
        if target_state == 'house_of_spirit':
            return ['malloc(0x100)', 'free(ptr)', 'malloc(0x100)']
        elif target_state == 'unsortedbin_attack':
            return ['malloc(0x500)', 'free(ptr)', 'malloc(0x100)']
        elif target_state == 'tcache_poisoning':
            return ['malloc(0x100)', 'free(ptr)', 'edit_chunk(next_ptr)']
        return []

    def _generate_jemalloc_sequence(self, target_state: str) -> List[str]: return []

    def generate_exploit_code(self, technique: str) -> str:
        return f'''# Heap Exploit Code — {technique} — {self.allocator_type}
def trigger_exploit(): pass
'''

    def detect_security_mitigations(self) -> Dict[str, bool]:
        m = {'safe_linking': False, 'tcache_key': False, 'alignment_check': False}
        try:
            parts = self.libc_version.split('.')[:2] if self.libc_version else ('2', '0')
            major, minor = parts
            ver = (int(major), int(minor))
            if ver >= (2, 34):
                m['tcache_key'] = m['safe_linking'] = True
            elif ver >= (2, 32):
                m['safe_linking'] = True
            if ver >= (2, 35):
                m['alignment_check'] = True
        except (ValueError, AttributeError):
            pass
        return m

    # Round 6: 竞态感知堆操作调度 — 多线程序列中检测竞态窗口
    def detect_heap_races(self, code_snippets: List[str]) -> List[RaceCondition]:
        """在多线程堆操作代码段中检测 TOCTOU 和锁顺序违反，
        返回列表供利用策略选择参考。"""
        findings = []
        for i, snippet in enumerate(code_snippets):
            toctou = self._race_detector.detect_toctou(snippet, f"heap_func_{i}")
            findings.extend(toctou)
        return findings


class HeapLayoutPredictionVisualizer:
    _ALLOC_COLOR = '#FF6B6B'; _FREE_COLOR = '#4ECDC4'

    def __init__(self):
        self.heap_chunks: List[Dict[str, Any]] = []
        self.predicted_layout: Dict[str, Any] = {}
        self.heap_state_history: List[Dict[str, Any]] = []

    def add_heap_chunk(self, address: int, size: int, allocated: bool = True) -> Dict[str, Any]:
        chunk = {'address': address, 'size': size, 'allocated': allocated,
                 'type': 'allocated' if allocated else 'free',
                 'color': self._ALLOC_COLOR if allocated else self._FREE_COLOR}
        self.heap_chunks.append(chunk)
        return chunk

    def predict_heap_layout(self, allocation_sequence: List[Dict[str, Any]]) -> Dict[str, Any]:
        layout = {'chunks': [], 'total_size': 0, 'free_chunks': 0,
                  'allocated_chunks': 0, 'visualization_data': {}}
        current_addr = 0x1000
        for alloc in allocation_sequence:
            size = alloc.get('size', 0); action = alloc.get('action', 'alloc')
            if action == 'alloc':
                chunk = {'address': current_addr, 'size': size, 'allocated': True,
                         'type': 'allocated', 'color': self._ALLOC_COLOR}
                layout['chunks'].append(chunk)
                layout['allocated_chunks'] += 1; current_addr += size
            elif action == 'free':
                for chunk in layout['chunks']:
                    if chunk['address'] == alloc.get('address'):
                        chunk['allocated'] = False; chunk['type'] = 'free'
                        chunk['color'] = self._FREE_COLOR
                        layout['free_chunks'] += 1; layout['allocated_chunks'] -= 1
                        break
        layout['total_size'] = current_addr - 0x1000
        self.predicted_layout = layout
        return layout

    def generate_visualization_json(self) -> str:
        return json.dumps({
            'heap_chunks': self.heap_chunks, 'predicted_layout': self.predicted_layout,
            'visualization_config': {'width': 800, 'height': 400, 'chunk_height': 30,
                                     'address_scale': 'linear'}}, indent=2)

    def record_heap_state(self, state: Dict[str, Any]):
        state['timestamp'] = datetime.now().isoformat(); self.heap_state_history.append(state)

    def generate_heap_feng_shui_strategy(self, target_size: int) -> Dict[str, Any]:
        strategy = {'target_size': target_size, 'allocation_sequence': [],
                    'description': '', 'probability': 0.0}
        strategy['allocation_sequence'] = [
            {'action': 'alloc', 'size': target_size - 8},
            {'action': 'free', 'address': 0x1000},
            {'action': 'alloc', 'size': target_size}]
        strategy['description'] = f'Attempt {target_size} bytes target position'
        strategy['probability'] = 0.3
        return strategy

    def frame_shift_mutate(self, sequence: List[HeapOperation],
                           preserve_sizes: bool = True) -> List[HeapOperation]:
        mutated = list(sequence)
        if len(mutated) < 2:
            return mutated
        alloc_sizes: Dict[int, int] = {}
        for op in mutated:
            if op.op_type == 'alloc': alloc_sizes[op.address] = op.size
        i = 0
        while i < len(mutated) - 1:
            a, b = mutated[i], mutated[i + 1]
            if (a.op_type == 'alloc' and b.op_type == 'free'
                    and b.address == a.address):
                if i % 3 == 0: mutated[i], mutated[i + 1] = b, a
            i += 1
        return mutated

    def diff_heap_states(self, before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
        bc = {(c['address']): c for c in before.get('chunks', [])}
        ac = {(c['address']): c for c in after.get('chunks', [])}
        added = [c for k, c in ac.items() if k not in bc]
        removed = [c for k, c in bc.items() if k not in ac]
        changed = [{'before': bc[k], 'after': ac[k]} for k in set(bc) & set(ac) if bc[k] != ac[k]]
        return {'chunks_added': len(added), 'chunks_removed': len(removed),
                'chunks_changed': len(changed),
                'details': {'added': added[:20], 'removed': removed[:20], 'changed': changed[:20]}}
