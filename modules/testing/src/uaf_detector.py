"""UAF 模式检测器——基于 typestate 分析的堆生命周期追踪——ASan 输出 + SIGSEGV 上下文"""
import re
from typing import List, Dict, Set, Tuple, Optional, Any
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum


class UAFPattern(Enum):
    EXPLICIT_UAF = "explicit_uaf"
    DOUBLE_FREE = "double_free"
    STALE_PTR_DEREF = "stale_ptr_deref"
    DANGLING_CALLBACK = "dangling_callback"
    REALLOC_UAF = "realloc_uaf"
    TYPE_CONFUSION = "type_confusion"
    THREAD_UAF = "thread_uaf"


@dataclass
class HeapLifetime:
    """堆对象生命周期记录——分配/释放/悬垂使用站点追踪"""
    obj_id: int
    alloc_site: str = ""
    free_site: str = ""
    alloc_size: int = 0
    alloc_time: float = 0.0
    free_time: float = 0.0
    dangling_use_sites: List[str] = field(default_factory=list)
    tagged: bool = False


class UAFDetector:
    """UAF 检测引擎——三层检测策略：ASan 直接报告 | SIGSEGV 在 free 路径 | 间接证据组合"""

    _ASAN_UAF = re.compile(
        r'heap-use-after-free', re.IGNORECASE)
    _ASAN_DF = re.compile(
        r'double-free', re.IGNORECASE)
    _ASAN_STALE = re.compile(
        r'(?:freed|released)\s+(?:pointer|memory|block)', re.IGNORECASE)

    _FREE_FUNCTIONS = {
        'free', 'operator delete', 'delete', 'realloc',
        'g_free', 'CFRelease', 'objc_release', 'fclose', 'closedir',
        'munmap', 'HeapFree', 'LocalFree', 'CoTaskMemFree',
    }

    _ALLOC_FUNCTIONS = {
        'malloc', 'calloc', 'realloc', 'operator new',
        'g_malloc', 'CFAllocatorAllocate', 'objc_alloc',
        'mmap', 'HeapAlloc', 'LocalAlloc', 'CoTaskMemAlloc',
    }

    def __init__(self):
        self._heap_objects: Dict[int, HeapLifetime] = {}
        self._uaf_findings: List[Dict[str, Any]] = []
        self._obj_counter = 0

    def record_alloc(self, alloc_site: str, size: int) -> int:
        """记录分配事件——返回对象 ID"""
        self._obj_counter += 1
        obj = HeapLifetime(
            obj_id=self._obj_counter,
            alloc_site=alloc_site, alloc_size=size,
            alloc_time=0.0)
        self._heap_objects[self._obj_counter] = obj
        return self._obj_counter

    def record_free(self, obj_id: int, free_site: str) -> bool:
        """记录释放事件——返回 False 表示 double free"""
        obj = self._heap_objects.get(obj_id)
        if obj is None:
            return True
        if obj.free_site:
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
        obj.free_time = 0.0
        return True

    def record_use(self, obj_id: int, use_site: str) -> bool:
        """释放后使用记录——返回 False 表示 UAF 嫌疑"""
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

    def analyze_crash(self, signal_num: int,
                      error_msg: str,
                      stack_frames: List[str] = None,
                      sanitizer_output: str = "") -> Dict[str, Any]:
        """崩溃上下文 UAF 模式检测——三层分层判定"""
        frames = stack_frames or []
        msg_lower = error_msg.lower()
        sanitizer_lower = sanitizer_output.lower()

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

        if signal_num == 11:
            free_in_frame = self._find_free_in_stack(frames)
            if free_in_frame is not None:
                return self._build_result(
                    UAFPattern.STALE_PTR_DEREF, 0.65,
                    f'SIGSEGV 在 free 路径中被触发: {free_in_frame}',
                    {'crash_frame': free_in_frame, 'frames': frames[:3]})

        evidence = {}
        if signal_num == 11:
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
        """栈帧中搜索 free 族函数调用"""
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

    def score_seed_for_uaf(self, signal_num: int,
                           error_msg: str,
                           stack_frames: List[str]) -> float:
        """种子 UAF 触发可能性评分 [0, 1]——驱动定向模糊测试"""
        result = self.analyze_crash(signal_num, error_msg, stack_frames)
        return result['confidence']

    def detect_thread_uaf(self, thread_traces: Dict[int, List[str]]
                          ) -> List[Dict[str, Any]]:
        """跨线程 UAF 检测——线程 A 释放，线程 B 随后访问"""
        findings = []
        all_events: List[Tuple[float, int, str, str]] = []
        for tid, trace in thread_traces.items():
            for event in trace:
                all_events.append((0.0, tid, event, ''))

        for i, (_, t_a, op_a, obj_a) in enumerate(all_events):
            if 'free' not in op_a.lower():
                continue
            for j in range(i + 1, len(all_events)):
                _, t_b, op_b, obj_b = all_events[j]
                if t_a == t_b:
                    continue
                if any(alloc_func in op_b.lower()
                       for alloc_func in self._ALLOC_FUNCTIONS):
                    continue
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

    def report(self) -> Dict[str, Any]:
        """堆生命周期追踪报告"""
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


def is_likely_uaf(sanitizer_output: str) -> bool:
    """sanitizer 输出快速 UAF 判定"""
    low = sanitizer_output.lower()
    return ('heap-use-after-free' in low
            or 'double-free' in low
            or 'use after free' in low)


def extract_uaf_objects(sanitizer_output: str) -> List[Dict[str, Any]]:
    """从 ASan 输出提取 UAF 对象地址和区域信息"""
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
