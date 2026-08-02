# 2026-08-02
# Use-After-Free 模式检测器 — 基于 typestate 分析的堆生命周期追踪
# 核心检测: 在崩溃上下文中识别 UAF (use-after-free) 和 DF (double free)
# 的典型特征模式。不做动态堆追踪（那需要 Pintool/Frida hook），
# 而是对已知崩溃信息做模式匹配 + 启发式推断。
#
# 参考:
#   Typestate-guided fuzzer for discovering UAF (Xu et al. ICSE 2020)
#   Finding the needle in the heap (USENIX 2012): 结合静态分析
#     和动态符号执行触发 UAF
#   DDRace (Yuan et al. USENIX 2024): 并发 UAF 检测
#   UAFSan (2023): 基于 ASan 增强的 UAF 专用检测
#   A Use-After-Free Vulnerability Detection Method for Multi-Threaded
#     Programs Based on an Improved Petri Net and Value Flow Graph (2023)
import re
from typing import List, Dict, Set, Tuple, Optional, Any
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum


class UAFPattern(Enum):
    EXPLICIT_UAF = "explicit_uaf"          # ASan: heap-use-after-free
    DOUBLE_FREE = "double_free"            # ASan: double-free
    STALE_PTR_DEREF = "stale_ptr_deref"    # SIGSEGV on freed memory pattern
    DANGLING_CALLBACK = "dangling_callback" # freed object still registered as callback
    REALLOC_UAF = "realloc_uaf"            # realloc 返回新地址后旧指针仍被使用
    TYPE_CONFUSION = "type_confusion"      # 释放后以不同类型重新分配并访问
    THREAD_UAF = "thread_uaf"              # 跨线程的 UAF (线程A释放, 线程B访问)


@dataclass
class HeapLifetime:
    """单个堆对象的生命周期记录。"""
    obj_id: int
    alloc_site: str = ""        # 分配调用点
    free_site: str = ""         # 释放调用点 (空=未释放)
    alloc_size: int = 0
    alloc_time: float = 0.0
    free_time: float = 0.0
    dangling_use_sites: List[str] = field(default_factory=list)  # 释放后的访问点
    tagged: bool = False         # 是否已被标记为可疑


class UAFDetector:
    """UAF 模式检测主引擎。

    输入: 崩溃信息 (signal, error msg, stack frames, sanitizer output)
    输出: UAFPattern 分类 + 置信度 + 具体证据

    检测策略分三个层次:
      Layer 1 (高置信度): ASan/UBSan 输出直接包含 "heap-use-after-free"
      Layer 2 (中置信度): SIGSEGV 发生在 free() 调用路径中
      Layer 3 (低置信度): 间接证据组合 (悬挂指针模式、时序模式)"""

    # 高置信度 ASan 模式
    _ASAN_UAF = re.compile(
        r'heap-use-after-free', re.IGNORECASE)
    _ASAN_DF = re.compile(
        r'double-free', re.IGNORECASE)
    _ASAN_STALE = re.compile(
        r'(?:freed|released)\s+(?:pointer|memory|block)', re.IGNORECASE)

    # 常见 free 路径函数
    _FREE_FUNCTIONS = {
        'free', 'operator delete', 'delete', 'realloc',
        'g_free', 'CFRelease', 'objc_release', 'fclose', 'closedir',
        'munmap', 'HeapFree', 'LocalFree', 'CoTaskMemFree',
    }

    # 常见 alloc 路径函数
    _ALLOC_FUNCTIONS = {
        'malloc', 'calloc', 'realloc', 'operator new',
        'g_malloc', 'CFAllocatorAllocate', 'objc_alloc',
        'mmap', 'HeapAlloc', 'LocalAlloc', 'CoTaskMemAlloc',
    }

    def __init__(self):
        self._heap_objects: Dict[int, HeapLifetime] = {}
        self._uaf_findings: List[Dict[str, Any]] = []
        self._obj_counter = 0

    # ---- 生命周期追踪 ----
    def record_alloc(self, alloc_site: str, size: int) -> int:
        self._obj_counter += 1
        obj = HeapLifetime(
            obj_id=self._obj_counter,
            alloc_site=alloc_site, alloc_size=size,
            alloc_time=0.0)
        self._heap_objects[self._obj_counter] = obj
        return self._obj_counter

    def record_free(self, obj_id: int, free_site: str) -> bool:
        """返回 True 表示正常释放，False 表示 double free。"""
        obj = self._heap_objects.get(obj_id)
        if obj is None:
            return True
        if obj.free_site:
            # double free
            self._uaf_findings.append({
                'pattern': UAFPattern.DOUBLE_FREE,
                'obj_id': obj_id,
                'alloc_site': obj.alloc_site,
                'first_free': obj.free_site,
                'second_free': free_site,
                'confidence': 0.90,
                'detail': f'Double free: obj#{obj_id} freed at {obj.free_site}, '
                          f'再次 free 于 {free_site}',
            })
            return False
        obj.free_site = free_site
        obj.free_time = 0.0  # 实际使用中记录时间戳
        return True

    def record_use(self, obj_id: int, use_site: str) -> bool:
        """在释放后记录使用。返回 True=正常, False=UAF 嫌疑。"""
        obj = self._heap_objects.get(obj_id)
        if obj is None:
            return True
        if obj.free_site and not obj.tagged:
            obj.dangling_use_sites.append(use_site)
            detected = len(obj.dangling_use_sites)
            self._uaf_findings.append({
                'pattern': UAFPattern.EXPLICIT_UAF,
                'obj_id': obj_id,
                'alloc_site': obj.alloc_site,
                'free_site': obj.free_site,
                'use_site': use_site,
                'confidence': 0.85 + 0.05 * min(detected, 3),
                'detail': f'UAF: obj#{obj_id} (alloc={obj.alloc_site}, '
                          f'freed={obj.free_site}) 在释放后第{detected}次被访问于 {use_site}',
            })
            obj.tagged = True
            return False
        return True

    # ---- 崩溃上下文检测 ----
    def analyze_crash(self, signal_num: int,
                      error_msg: str,
                      stack_frames: List[str] = None,
                      sanitizer_output: str = "") -> Dict[str, Any]:
        """从崩溃上下文检测 UAF 模式。返回最可能的 UAF 模式 + 置信度。"""
        frames = stack_frames or []
        msg_lower = error_msg.lower()
        sanitizer_lower = sanitizer_output.lower()

        # Layer 1: ASan 直接报告
        if self._ASAN_UAF.search(sanitizer_lower):
            return self._build_result(
                UAFPattern.EXPLICIT_UAF, 0.95,
                'ASan 直接报告 heap-use-after-free',
                {'sanitizer': sanitizer_output})

        if self._ASAN_DF.search(sanitizer_lower):
            return self._build_result(
                UAFPattern.DOUBLE_FREE, 0.95,
                'ASan 直接报告 double-free',
                {'sanitizer': sanitizer_output})

        # Layer 2: SIGSEGV + free 路径
        if signal_num == 11:
            free_in_frame = self._find_free_in_stack(frames)
            if free_in_frame is not None:
                return self._build_result(
                    UAFPattern.STALE_PTR_DEREF, 0.65,
                    f'SIGSEGV 在 free 路径中被触发: {free_in_frame}',
                    {'crash_frame': free_in_frame, 'frames': frames[:3]})

        # Layer 3: 间接证据
        evidence = {}
        if signal_num == 11:
            # 检查错误消息中的悬挂指针关键词
            if any(kw in msg_lower for kw in
                   ('freed', 'invalid pointer', 'corrupted',
                    'already free', 'released')):
                evidence['error_msg_hint'] = error_msg[:200]
                return self._build_result(
                    UAFPattern.STALE_PTR_DEREF, 0.45,
                    f'错误消息暗示悬挂指针: {error_msg[:100]}',
                    evidence)

        return self._build_result(None, 0.1, '未检测到明确 UAF 模式', {})

    def _find_free_in_stack(self,
                            frames: List[str]) -> Optional[str]:
        """在栈帧中搜索 free 族函数调用。"""
        for frame in frames:
            for func in self._FREE_FUNCTIONS:
                if func.lower() in frame.lower():
                    return frame
        return None

    def _build_result(self, pattern, confidence: float,
                      detail: str,
                      evidence: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'pattern': pattern,
            'confidence': confidence,
            'detail': detail,
            'evidence': evidence,
            'is_uaf': pattern in (UAFPattern.EXPLICIT_UAF,
                                  UAFPattern.STALE_PTR_DEREF,
                                  UAFPattern.DANGLING_CALLBACK,
                                  UAFPattern.REALLOC_UAF,
                                  UAFPattern.THREAD_UAF),
            'is_df': pattern == UAFPattern.DOUBLE_FREE,
        }

    # ---- UAF 种子评分 ----
    def score_seed_for_uaf(self, signal_num: int,
                           error_msg: str,
                           stack_frames: List[str]) -> float:
        """根据崩溃特征评估该种子触发 UAF 的可能性 [0, 1]。
        用于驱动后续 fuzzing 集中在可能产生 UAF 的输入变体上。"""
        result = self.analyze_crash(signal_num, error_msg, stack_frames)
        return result['confidence']

    # ---- 跨线程 UAF 检测 ----
    def detect_thread_uaf(self, thread_traces: Dict[int, List[str]]
                          ) -> List[Dict[str, Any]]:
        """检测跨线程 UAF 模式：线程 A 释放，线程 B 随后访问。
        thread_traces: {thread_id: [operation_trace]}"""
        findings = []
        # 构建释放→访问的时间线
        all_events: List[Tuple[float, int, str, str]] = []
        for tid, trace in thread_traces.items():
            for event in trace:
                all_events.append((0.0, tid, event, ''))

        # 寻找跨线程的 free → use 对
        for i, (_, t_a, op_a, obj_a) in enumerate(all_events):
            if 'free' not in op_a.lower():
                continue
            for j in range(i + 1, len(all_events)):
                _, t_b, op_b, obj_b = all_events[j]
                if t_a == t_b:
                    continue
                if any(alloc_func in op_b.lower()
                       for alloc_func in self._ALLOC_FUNCTIONS):
                    continue  # 重新分配是合法的
                findings.append({
                    'pattern': UAFPattern.THREAD_UAF,
                    'thread_free': t_a,
                    'thread_use': t_b,
                    'op_free': op_a,
                    'op_use': op_b,
                    'confidence': 0.55,
                })
                break

        return findings

    # ---- 报告 ----
    def report(self) -> Dict[str, Any]:
        obj_count = len(self._heap_objects)
        freed_count = sum(
            1 for o in self._heap_objects.values() if o.free_site)
        dangling_count = sum(
            1 for o in self._heap_objects.values()
            if o.dangling_use_sites)
        return {
            'total_objects': obj_count,
            'freed_objects': freed_count,
            'dangling_objects': dangling_count,
            'uaf_findings': len(self._uaf_findings),
            'findings_by_pattern': self._classify_findings(),
            'details': self._uaf_findings[:10],
        }

    def _classify_findings(self) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for f in self._uaf_findings:
            p = f['pattern']
            key = p.value if isinstance(p, UAFPattern) else str(p)
            counts[key] += 1
        return dict(counts)

    def reset(self) -> None:
        self._heap_objects.clear()
        self._uaf_findings.clear()
        self._obj_counter = 0


# ---------------------------------------------------------------------------
# 便捷入口: 从 sanitizer 输出直接判定
# ---------------------------------------------------------------------------
def is_likely_uaf(sanitizer_output: str) -> bool:
    low = sanitizer_output.lower()
    return ('heap-use-after-free' in low
            or 'double-free' in low
            or 'use after free' in low)


def extract_uaf_objects(sanitizer_output: str) -> List[Dict[str, Any]]:
    addr_pat = re.compile(
        r'(0x[0-9a-fA-F]+)\s+is\s+(\d+)\s+bytes\s+inside\s+of\s+'
        r'(\d+)-byte\s+region\s+\[(0x[0-9a-fA-F]+),(0x[0-9a-fA-F]+)\)')
    objects = []
    for m in addr_pat.finditer(sanitizer_output):
        objects.append({
            'addr': m.group(1), 'offset': int(m.group(2)),
            'size': int(m.group(3)),
            'region_start': m.group(4), 'region_end': m.group(5),
        })
    return objects
