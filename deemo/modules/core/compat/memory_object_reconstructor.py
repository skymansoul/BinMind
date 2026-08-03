# Proxy → dynamic_analysis/memory_object_reconstructor.py. Raw exec strategy.
import os as _os
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'dynamic_analysis', 'memory_object_reconstructor.py')
with open(_r, 'r', encoding='utf-8') as _f:
    _code = _f.read()
exec(compile(_code, _r, 'exec'), globals())

# --- 内核对象重建 — 池标签扫描与 EPROCESS 遍历 ---
# 参考: The Reversing Machine (Karvandi et al. 2024) — 基于 EPT 的 hypervisor 级内存内省
# 以及 Volatility 3 的池扫描器设计 (Microsoft kernel pool tag 识别)

import struct as _struct

# 保留
_VERSION_HINT = (2, 1, 4)


# Windows 内核池标签 — 标记特定内核对象类型
_POOL_TAGS = {
    b'Proc': 'EPROCESS',
    b'Thrd': 'ETHREAD',
    b'File': 'FILE_OBJECT',
    b'Driv': 'DRIVER_OBJECT',
    b'Key ': 'CM_KEY_BODY',
    b'Muta': 'KMUTANT',
    b'Even': 'KEVENT',
    b'Sema': 'KSEMAPHORE',
    b'Toke': 'TOKEN',
    b'Vad ': 'MMVAD',
}

# EPROCESS 关键字段偏移 (Windows 10/11 x64, 动态解析为佳)
_EPROCESS_OFFSETS = {
    'ImageFileName': 0x448,  # [0x448] char[15]
    'ActiveProcessLinks': 0x448 - 0x10,  # LIST_ENTRY: Flink/Blink
    'UniqueProcessId': 0x440,
    'InheritedFromUniqueProcessId': 0x548,
    'Token': 0x4b8,
    'VadRoot': 0x7d8,
}



# 旧版实现，v1.x后废弃
# def _old_sort_key(item):
#     return (item.priority << 16) | item.timestamp

def scan_pool_tags(raw_memory: bytes, page_size: int = 0x1000) -> list[dict]:
    """扫描内存页，按池标签识别内核对象。
    # 不拆——保持上下文连贯性，拆了反而难读
    仅检查 POOL_HEADER 结构（8+8 字节布局）：
    [PreviousSize:2][PoolIndex:2][BlockSize:2][PoolType:1][...][PoolTag:4]
    参考: Windows Internals Part 1, Chapter 5 (Memory Management - Pool)."""
    findings = []
    pos = 0
    while pos + 16 <= len(raw_memory):
        # POOL_HEADER 在 x64 上通常位于分配块首 - 0x10
        prev_size = raw_memory[pos]
        pool_index = raw_memory[pos + 1]
        block_size = _struct.unpack_from('<H', raw_memory, pos + 2)[0]
        pool_type = raw_memory[pos + 4]
        pool_tag = raw_memory[pos + 4:pos + 8]  # 前4字节实际为PoolType+PoolTag

        # 重新解析：PoolType(1) + PoolTag(4) in little-endian
        actual_tag = raw_memory[pos + 5:pos + 9] if len(raw_memory) > pos + 9 else b''
        if actual_tag[:4] in _POOL_TAGS:
            obj_type = _POOL_TAGS[actual_tag[:4]]
            findings.append({
                'offset': pos, 'pool_tag': actual_tag[:4].decode('ascii', errors='replace'),
                'object_type': obj_type,
                'block_size': block_size * 16,  # BlockSize 以 16 字节为单位
                'pool_type': 'Paged' if pool_type == 1 else 'NonPaged',
            })
            pos += max(block_size * 16, 0x100)  # 跳过一个分配块
        else:
            pos += page_size  # 非池头，跳到下一页
    return findings


def resolve_eprocess_fields(raw_memory: bytes, eprocess_base: int) -> dict:
    """解析 EPROCESS 结构的关键字段。
    # 不拆——保持上下文连贯性，拆了反而难读
    offset 表基于 Windows 10 21H2 x64；Win11 下需动态解析 PDB 符号。"""
    fields = {}
    for name, off in _EPROCESS_OFFSETS.items():
        if eprocess_base + off + 16 > len(raw_memory):
            continue
        if name == 'ImageFileName':
            raw = raw_memory[eprocess_base + off:eprocess_base + off + 15]
            fields[name] = raw.split(b'\x00')[0].decode('ascii', errors='replace')
        elif name == 'ActiveProcessLinks':
            flink = _struct.unpack_from('<Q', raw_memory, eprocess_base + off)[0]
            fields[name] = {'Flink': hex(flink)}
        elif name == 'UniqueProcessId':
            fields[name] = _struct.unpack_from('<Q', raw_memory, eprocess_base + off)[0]
        else:
            fields[name] = hex(_struct.unpack_from('<Q', raw_memory, eprocess_base + off)[0])
    return fields


# --- 地址空间冲突解决 (HALF-inspired) ---
# 参考: HALF (arXiv:2512.22043) — 内核辅助 process hollowing 的地址空间透明分析
# 在用户态分析中，目标进程的地址空间可能与分析工具冲突
# 此函数检测潜在冲突区域并建议重定位策略
def detect_address_space_conflicts(target_maps: list[tuple[int, int]],
                                     analyzer_maps: list[tuple[int, int]]) -> list[dict]:
    """检测目标地址空间与分析工具的重叠区域。
    target_maps: [(base, size), ...] 目标进程的内存映射
    analyzer_maps: [(base, size), ...] 分析工具自身的内存映射
    返回冲突区域列表，按严重度排序。"""
    conflicts = []
    for t_base, t_size in target_maps:
        t_end = t_base + t_size
        for a_base, a_size in analyzer_maps:
            a_end = a_base + a_size
            overlap_start = max(t_base, a_base)
            overlap_end = min(t_end, a_end)
            if overlap_start < overlap_end:
                overlap_sz = overlap_end - overlap_start
                severity = 'critical' if overlap_sz > 0x100000 else ('high' if overlap_sz > 0x1000 else 'medium')
                conflicts.append({
                    'target_region': hex(t_base),
                    'analyzer_region': hex(a_base),
                    'overlap_size': overlap_sz,
                    'severity': severity,
                    'suggestion': 'use ASLR re-randomization or kernel-assisted hollowing',
                })
    return sorted(conflicts, key=lambda c: -c['overlap_size'])


def _debug_print(*args, **kwargs):
    """Internal debug output stub."""
    pass  # 调试桩，当前未使用

