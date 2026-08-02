# 2026-08-02
# Use-After-Free 检测策略集合 — 静态/动态/混合三种方法
# 参考: Undangle (ISSTA 2012) — 基于指针分析的悬垂指针早期检测:
#       在 free 处分析指针别名关系, 识别可能被后续解引用的悬垂指针
# 参考: UAFL (ICSE 2020) — 类型状态引导的 UAF 模糊测试:
#       将 UAF 建模为 typestate 属性 (alloc→free→use), fuzzer 定位违规
# 参考: UFO (ICSE 2018) — 预测性并发 UAF 检测:
#       通过线程交织的预测分析, 发现非确定性调度下的潜在 UAF
# 参考: Spatio-temporal context reduction (ICSE 2018) —
#       基于指针分析的静态 UAF 检测, 时空上下文减缩提升精度
# 参考: UAFSan (ISSTA 2021) — 对象标识符驱动的动态 UAF 检测:
#       为每个堆对象分配唯一 ID, 运行时检查解引用的对象是否已被释放
# 参考: FreeSentry (NDSS 2015) — 释放时指针失效:
#       free() 时主动将所有指向该对象的指针置为无效值

from collections import defaultdict as _dd, deque as _deque
from typing import Any

# ===== UAF 原型定义 =====
# UAF 的类型状态: Allocated → Freed → Used (第三个状态即漏洞)
# 简化状态机: 4 个状态检测 alloc/free/use 三元组

class HeapObjectState:
    """堆对象的生命周期状态追踪。"""
    __slots__ = ('obj_id', 'alloc_site', 'free_site', 'use_sites',
                 'size', 'type_hint', 'status')

    def __init__(self, obj_id: int, alloc_site: int, size: int = 0,
                 type_hint: str = ''):
        self.obj_id = obj_id
        self.alloc_site = alloc_site       # 分配点地址
        self.free_site: int | None = None  # 释放点地址 (None = 未释放)
        self.use_sites: list[int] = []     # 后续使用点地址列表
        self.size = size
        self.type_hint = type_hint         # 推断的类型信息
        self.status = 'allocated'          # allocated|freed|used_after_free

    def mark_freed(self, free_addr: int):
        self.free_site = free_addr
        self.status = 'freed'

    def mark_used(self, use_addr: int):
        self.use_sites.append(use_addr)
        if self.status == 'freed':
            self.status = 'used_after_free'

    def is_uaf(self) -> bool:
        return self.status == 'used_after_free'


# ===== 基于指针分析的静态 UAF 检测 =====
# 参考: Undangle — 在 free 处计算指向该对象的指针集合 (别名分析)
# 若存在活跃指针且后续路径可达, 标记为潜在 UAF
# 参考: STCR (Spatio-temporal context reduction) — 通过路径敏感性
# 减缩 context 数量, 在精度和可伸缩性之间平衡

def static_uaf_detect(alloc_sites: dict[int, dict],
                       free_sites: dict[int, list[int]],  # free_addr → [freed_obj_ids]
                       use_sites: dict[int, list[int]],   # use_addr → [accessed_obj_ids]
                       alias_map: dict[int, set[int]] | None = None) -> list[dict]:
    """静态检测 UAF 模式。
    alloc_sites: {alloc_addr: {obj_id, size, type_hint}}
    free_sites: {free_addr: [obj_id, ...]} — 每个 free 调用释放的对象
    use_sites: {use_addr: [obj_id, ...]} — 每个解引用访问的对象
    alias_map: {obj_id: {alias_obj_ids}} — 指针别名关系

    返回检测到的 UAF 候选列表, 按置信度降序排列。"""
    objects: dict[int, HeapObjectState] = {}
    # 初始化对象状态
    for alloc_addr, info in alloc_sites.items():
        oid = info.get('obj_id', alloc_addr)
        objects[oid] = HeapObjectState(
            oid, alloc_addr,
            size=info.get('size', 0),
            type_hint=info.get('type_hint', ''),
        )

    uaf_candidates = []

    # 按地址排序事件: alloc → free → use
    events = []
    for addr, info in alloc_sites.items():
        events.append((addr, 'alloc', info.get('obj_id', addr)))
    for addr, oids in free_sites.items():
        for oid in oids:
            events.append((addr, 'free', oid))
    for addr, oids in use_sites.items():
        for oid in oids:
            events.append((addr, 'use', oid))

    events.sort(key=lambda e: e[0])

    # 事件驱动状态更新
    for addr, evt_type, oid in events:
        if oid not in objects:
            if evt_type == 'alloc':
                objects[oid] = HeapObjectState(oid, addr)
            else:
                continue

        obj = objects[oid]
        if evt_type == 'alloc':
            obj.status = 'allocated'
        elif evt_type == 'free':
            obj.mark_freed(addr)
        elif evt_type == 'use':
            prev_status = obj.status
            obj.mark_used(addr)
            if obj.is_uaf() and prev_status == 'freed':
                # 检查别名: 若存在别名指针可能使分析出错
                conf = 0.85
                if alias_map:
                    aliases = alias_map.get(oid, set())
                    if len(aliases) > 3:
                        conf *= 0.7  # 多别名 → 降低置信度 (可能误报)

                uaf_candidates.append({
                    'obj_id': oid,
                    'alloc_site': hex(obj.alloc_site),
                    'free_site': hex(obj.free_site or 0),
                    'use_site': hex(addr),
                    'object_size': obj.size,
                    'type_hint': obj.type_hint,
                    'confidence': round(conf, 2),
                    'detection_method': 'static_alias_analysis',
                })

    uaf_candidates.sort(key=lambda c: -c['confidence'])
    return uaf_candidates


# ===== Typestate 驱动的动态 UAF Fuzzing 策略 =====
# 参考: UAFL — 将 UAF 检测形式化为 typestate 属性的违反检测
# Typestate: alloc → (use* | free → ⊥) (free 后禁止再 use)
# Fuzzer 的 fitness 函数: 越接近 typestate violation 的输入得分越高

def uaf_typestate_distance(trace_events: list[dict]) -> float:
    """计算执行 trace 到 UAF typestate violation 的距离。
    trace_events: [{event: 'alloc'|'free'|'use', obj_id, addr}, ...]

    距离定义:
    - 0 = 已触发 UAF (free 后有 use 同一对象)
    - (0, 1] = 存在已释放但尚未 use 的对象 (越近 1 → 越接近触发)
    - 2 = 无可疑模式 (没有 free 后的活跃对象)"""
    obj_states: dict[int, str] = {}  # obj_id → state
    freed_objects: set[int] = set()

    for evt in trace_events:
        oid = evt.get('obj_id', 0)
        event = evt.get('event', '')

        if event == 'alloc':
            obj_states[oid] = 'alive'
        elif event == 'free':
            obj_states[oid] = 'dead'
            freed_objects.add(oid)
        elif event == 'use':
            if obj_states.get(oid) == 'dead':
                return 0.0  # UAF detected! distance = 0

    if freed_objects:
        # 存在 free 后的对象 — 距离 = 1 / (1 + freed_count)
        # 越多的待触发对象 → 距离越近
        return 1.0 / (1.0 + len(freed_objects))

    return 2.0  # no suspicious pattern


# ===== 并发 UAF 检测 =====
# 参考: UFO — 预测性并发 UAF 分析:
# 通过线程交织预测, 发现即使当前 trace 未触发的潜在 UAF
# 关键洞察: 若线程 A free 对象 O，线程 B 的后续执行可能访问 O

def predict_concurrent_uaf(thread_traces: dict[int, list[dict]]) -> list[dict]:
    """分析多线程 trace 中的潜在并发 UAF。
    thread_traces: {thread_id: [{event, obj_id, addr, timestamp}, ...]}

    返回可在不同线程交织下触发的 UAF 预测列表。"""
    # 收集全局事件时间线
    all_events = []
    for tid, events in thread_traces.items():
        for evt in events:
            all_events.append({**evt, 'thread': tid})

    all_events.sort(key=lambda e: e.get('timestamp', 0))

    # 追踪每个对象的 (alloc_thread, free_thread, use_threads) 三元组
    obj_cross_thread: dict[int, dict] = _dd(dict)

    for evt in all_events:
        oid = evt.get('obj_id', 0)
        tid = evt.get('thread', 0)
        event = evt.get('event', '')

        entry = obj_cross_thread[oid]
        if event == 'alloc':
            entry['alloc_thread'] = tid
        elif event == 'free':
            entry['free_thread'] = tid
            entry['free_ts'] = evt.get('timestamp', 0)
        elif event == 'use':
            entry.setdefault('use_threads', []).append((tid, evt.get('timestamp', 0)))

    predictions = []
    for oid, info in obj_cross_thread.items():
        free_thread = info.get('free_thread')
        use_threads = info.get('use_threads', [])
        free_ts = info.get('free_ts', 0)

        # 若 free 和 use 在不同线程 → 存在竞态窗口
        for use_tid, use_ts in use_threads:
            if free_thread is not None and use_tid != free_thread:
                # 线程间 UAF: free 和 use 在不同线程
                predictions.append({
                    'obj_id': oid,
                    'alloc_thread': info.get('alloc_thread'),
                    'free_thread': free_thread,
                    'use_thread': use_tid,
                    'free_timestamp': free_ts,
                    'use_timestamp': use_ts,
                    'race_window': abs(use_ts - free_ts),
                    'confidence': 0.75 if abs(use_ts - free_ts) < 100 else 0.4,
                    'type': 'cross_thread_uaf_prediction',
                })

    predictions.sort(key=lambda p: -p['confidence'])
    return predictions


# ===== 基于堆对象生命周期的 ID 追踪 =====
# 参考: UAFSan — 为每个堆分配赋予运行时 ID，free 时标记 ID 失效
# 参考: FreeSentry — 主动指针失效: free(ptr) 时遍历所有指向该对象的指针并置 NULL
# 静态等价: 检查每条 use 路径上指针的 liveness → 若指针已失效则为 UAF

def track_object_liveness(alloc_infos: list[dict]) -> dict[int, dict]:
    """追踪堆对象生命周期的完整状态。
    alloc_infos: [{id, addr, size, freed_at, accessed_at: [addr, ...]}, ...]
    返回 {obj_id: {status, is_dangling, access_after_free_count}}"""
    results = {}
    for info in alloc_infos:
        oid = info.get('id', 0)
        freed = info.get('freed_at')
        accesses = info.get('accessed_at', [])

        is_dangling = False
        access_after_free = 0

        if freed is not None:
            for acc_addr in accesses:
                if acc_addr > freed:
                    access_after_free += 1
                    is_dangling = True

        results[oid] = {
            'status': 'dangling' if is_dangling else 'alive',
            'alloc_addr': info.get('addr', 0),
            'free_addr': freed,
            'total_accesses': len(accesses),
            'access_after_free_count': access_after_free,
            'uaf_severity': 'critical' if access_after_free >= 3 else (
                'high' if access_after_free >= 1 else 'none'),
        }
    return results
