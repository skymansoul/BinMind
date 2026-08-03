"""堆利用原语检测 — 从分配模式推断可利用状态"""
# 参考: Gollum (CCS 2019) — 模块化灰盒堆溢出利用生成，将堆交互建模为搜索问题
# 参考: HeapMD (ASPLOS 2022) — 基于异常检测的堆 bug 识别:
#       performance allocator / security allocator 双轨架构
# 参考: FUZE (USENIX 2018) — 内核 UAF 利用生成: 通过系统调用模糊测试探索
#       slab 状态空间寻找可利用的 dangling pointer 上下文
# 参考: HEAPSTER (IEEE S&P 2022) — 嵌入式固件动态内存分配器安全分析
# 参考: "Automated Exploitable Heap Layout Generation for Heap Overflows
#       Through Manipulation Distance-Guided Fuzzing" (Zhang et al.) —
#       操纵距离引导的堆布局自动化生成

import re as _re, struct as _struct
from collections import defaultdict as _dd

# ===== 堆分配模式识别 =====
# 通过静态/动态 trace 中的分配序列推断程序使用的分配模式
# 识别: slab allocator (大小类)、buddy allocator、arena-based、custom pool

_ALLOC_PATTERNS = {
    'glibc_ptmalloc': {
        'funcs': ['malloc', 'calloc', 'realloc', 'free', 'memalign'],
        'tcache_bins': 64,       # glibc 2.26+ tcache per-thread cache
        'fastbin_max': 0x80,      # 默认 fastbin 上限 (128B on x64)
        'smallbin_max': 0x400,    # 1024B
    },
    'windows_lfh': {
        'funcs': ['HeapAlloc', 'HeapFree', 'HeapReAlloc', 'LocalAlloc', 'GlobalAlloc'],
        'lfh_threshold': 0x4000,  # Low Fragmentation Heap 激活阈值 (16KB)
        'lookaside_depth': 256,   # 前视列表深度
    },
    'kernel_slab': {
        'funcs': ['kmalloc', 'kfree', 'kzalloc', 'kmem_cache_alloc', 'kmem_cache_free'],
        'slab_sizes': [8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096],
    },
    'custom_pool': {
        'funcs': [],  # 自定义分配器无固定模式
    },
}


def identify_allocator(calls: list[str]) -> dict:
    # 从API序列识别分配器 — 简单投票
    scores: dict[str, int] = {}
    for alloc_name, info in _ALLOC_PATTERNS.items():
        funcs_lower = [f.lower() for f in info['funcs']]
        score = 0
        for call in calls:
            call_l = call.lower()
            if any(f in call_l for f in funcs_lower):
                score += 1
        if score > 0:
            scores[alloc_name] = score

    if not scores:
        return {'allocator': 'unknown', 'confidence': 0.0}

    best = max(scores, key=scores.get)
    return {
        'allocator': best,
        'confidence': min(scores[best] / max(len(calls), 1), 1.0),
        'matched_calls': scores[best],
        'total_calls': len(calls),
    }


# ===== 堆溢出利用可行性评估 =====
# 参考: Gollum 的堆交互模型 — 将堆操作序列编码为状态图
# 相邻对象类型决定溢出影响的语义:
#   overflow → adjacent object with function pointer → control flow hijack
#   overflow → adjacent object with length field → further OOB read/write

# 危险邻接类型: 若溢出可达这些字段，则可利用性显著提升
_DANGEROUS_ADJACENT_TYPES = frozenset({
    'vtable_ptr', 'function_ptr', 'data_ptr', 'length_field',
    'ref_count', 'alloc_size', 'next_free', 'prev_free',
})


def assess_heap_overflow_exploitability(overflow_size: int,
                                         adjacent_objects: list[dict],
                                         allocator_type: str = 'glibc_ptmalloc') -> dict:
    """评估堆溢出的可利用性。

    overflow_size: 可溢出的字节数 (0 = 不可控)
    adjacent_objects: 按地址升序排列的相邻堆对象:
        [{offset, size, type, has_vtable, has_fn_ptr}, ...]
    allocator_type: 分配器类型, 影响缓存机制和布局确定性

    评估维度:
    1. 溢出距离: 到达第一个危险字段需要的字节数
    2. 相邻对象类型: vtable > fn_ptr > data_ptr > length_field
    3. 布局确定性: slab (高) vs ptmalloc (中) vs custom (低)"""
    if overflow_size <= 0:
        return {'exploitable': False, 'reason': 'no overflow control',
                'score': 0.0}

    score = 0.0
    primitives = []
    remaining = overflow_size

    for obj in adjacent_objects:
        if remaining <= 0:
            break
        obj_offset = obj.get('offset', 0)
        obj_size = obj.get('size', 0)
        needed = obj_offset  # 到达对象起始需要的溢出量

        if overflow_size >= needed:
            # 可以到达此对象
            if obj.get('has_vtable'):
                primitives.append('vtable_hijack')
                score += 0.35
            elif obj.get('has_fn_ptr'):
                primitives.append('fn_ptr_overwrite')
                score += 0.25
            elif obj.get('type', '') in _DANGEROUS_ADJACENT_TYPES:
                primitives.append(f'{obj["type"]}_corruption')
                score += 0.15
            remaining -= (obj_offset + obj_size)

    # 分配器确定性加权
    determinism_map = {
        'kernel_slab': 1.0,       # 大小固定, LIFO 顺序确定性高
        'glibc_ptmalloc': 0.7,    # tcache/fastbin 有 LIFO 但多线程不确定
        'windows_lfh': 0.6,       # LFH 有随机化
        'custom_pool': 0.3,       # 完全不确定
    }
    score *= determinism_map.get(allocator_type, 0.5)

    return {
        'exploitable': score >= 0.3,
        'score': round(score, 2),
        'primitives': primitives,
        'overflow_bytes': overflow_size,
        'adjacent_objects_reachable': sum(1 for o in adjacent_objects
                                           if o.get('offset', 0) < overflow_size),
        'allocator_determinism': determinism_map.get(allocator_type, 0.5),
    }


# ===== 堆风水 (Heap Feng Shui) 基元检测 =====
# 参考: "Heap Feng Shui in JavaScript" (Sotirov, BlackHat 2007)
# 以及 Gollum 的堆布局搜索 — 将布局操作编码为 (alloc, free, fill) 三元组
# 检测目标: 在 trace 中识别 create_hole → fill_hole → trigger_overflow 模式

_HEAP_FENGSHUI_PATTERNS = [
    # 模式1: alloc(A) → free(A) → alloc(B) → 期望 B 占用 A 的位置
    {'name': 'hole_fill', 'sequence': ['alloc', 'free', 'alloc'],
     'suspicion': 'medium'},
    # 模式2: 连续 alloc-free-alloc-free — heap spray 配合
    {'name': 'spray_primitive', 'sequence': ['alloc', 'free'] * 5,
     'suspicion': 'high'},
    # 模式3: alloc(A) → overflow(A) → free(B) → alloc(C) [C overwrites freed B]
    {'name': 'use_after_free_setup', 'sequence': ['alloc', 'overflow', 'free', 'alloc'],
     'suspicion': 'critical'},
    # 模式4: 大量同大小 alloc → 耗尽特定 bin → 触发特定行为
    {'name': 'bin_exhaustion', 'sequence': ['alloc'] * 20,
     'suspicion': 'medium'},
]


def detect_heap_fengshui(trace_events: list[dict]) -> list[dict]:
    """检测 trace 中的堆风水操作序列。
    trace_events: [{event: 'alloc'|'free'|'realloc', size, address, ...}, ...]
    使用滑动窗口匹配已知模式。"""
    events = [e.get('event', '') for e in trace_events]
    findings = []

    for pattern in _HEAP_FENGSHUI_PATTERNS:
        seq = pattern['sequence']
        k = len(seq)

        for i in range(len(events) - k + 1):
            window = events[i:i + k]
            if window == seq:
                # 检查大小的相关性: 风水操作通常针对特定大小类
                sizes_in_window = set()
                for j in range(k):
                    sz = trace_events[i + j].get('size', 0)
                    if sz > 0:
                        sizes_in_window.add(sz)

                findings.append({
                    'pattern': pattern['name'],
                    'start_index': i,
                    'length': k,
                    'suspicion': pattern['suspicion'],
                    'size_classes_involved': sorted(sizes_in_window),
                    'locations': [trace_events[i + j].get('address', 0)
                                for j in range(k)],
                })

    return findings


# ===== 堆喷射 (Heap Spray) 检测 =====
# 参考: NOZZLE (USENIX 2012) — 堆喷射代码注入的运行时检测
# 检测指标:
#   - 大量相同大小的连续分配 (> 100 次)
#   - 分配内容高熵 (> 6.0) — 表明包含 shellcode/payload
#   - 分配大小的典型 spray 值: 1MB (IE), 0x100000, 0x10000

_SPRAY_SIZE_INDICATORS = [0x100000, 0x80000, 0x40000, 0x20000, 0x10000, 0x1000]
_SPRAY_COUNT_THRESHOLD = 50  # ≥50 次同大小分配 = 疑似 spray


def detect_heap_spray(alloc_records: list[dict]) -> dict:
    """检测堆喷射行为。
    alloc_records: [{size, address, content_entropy}, ...]

    返回喷射检测结果: 包含可疑大小类、喷射密度和置信度。"""
    if not alloc_records:
        return {'spray_detected': False, 'confidence': 0.0, 'reasons': []}

    # 按大小分组统计
    size_counts: dict[int, int] = _dd(int)
    size_entropies: dict[int, list[float]] = _dd(list)

    for rec in alloc_records:
        sz = rec.get('size', 0)
        size_counts[sz] += 1
        ent = rec.get('content_entropy', 0.0)
        if ent > 0:
            size_entropies[sz].append(ent)

    reasons = []
    max_conf = 0.0
    spray_sizes = []

    for sz, count in size_counts.items():
        conf = 0.0
        reason_parts = []

        # 数量异常
        if count >= _SPRAY_COUNT_THRESHOLD:
            conf += 0.3
            reason_parts.append(f'count={count}')

        # 大小可疑
        if sz in _SPRAY_SIZE_INDICATORS:
            conf += 0.2
            reason_parts.append(f'size=0x{sz:x}(known spray size)')

        # 内容高熵
        avg_ent = (sum(size_entropies.get(sz, [])) /
                   max(len(size_entropies.get(sz, [])), 1))
        if avg_ent >= 6.0:
            conf += 0.3
            reason_parts.append(f'entropy={avg_ent:.1f}')
        elif avg_ent >= 4.5:
            conf += 0.15

        if conf >= 0.4:
            spray_sizes.append(sz)
            max_conf = max(max_conf, conf)
            reasons.append(f'size 0x{sz:x}: {", ".join(reason_parts)} (conf={conf:.2f})')

    return {
        'spray_detected': len(spray_sizes) > 0,
        'confidence': round(max_conf, 2),
        'suspicious_size_classes': spray_sizes,
        'reasons': reasons,
    }


# ===== 堆布局可视化 (文本模式) =====
# 将堆对象映射生成为 ASCII 布局图 — 便于审计
def render_heap_layout(heap_objects: list[dict], chunk_size: int = 16) -> str:
    """生成堆对象的文本布局表示。
    heap_objects: [{offset, size, type, flags}, ...] 按 offset 排序"""
    if not heap_objects:
        return '(empty heap)'

    sorted_objs = sorted(heap_objects, key=lambda o: o.get('offset', 0))
    lines = []
    last_end = 0

    for obj in sorted_objs:
        off = obj.get('offset', 0)
        sz = obj.get('size', 0)
        otype = obj.get('type', 'chunk')
        flags = obj.get('flags', '')

        # 填充间隙
        if off > last_end:
            gap = off - last_end
            lines.append(f'  [{last_end:#010x}..{off:#010x}] {"(free/gap)":20s} {gap}B')

        marker = ''
        if 'vtable' in otype.lower():
            marker = ' [VTABLE]'
        elif 'fn_ptr' in flags:
            marker = ' [FN_PTR]'

        lines.append(f'  [{off:#010x}..{off+sz:#010x}] {otype:20s} {sz:>6}B{marker}')
        last_end = off + sz

    return '\n'.join(lines) if lines else '(no heap objects)'
