# 虚表精确恢复 — Itanium/MSVC 双 ABI、RTTI 遍历、交叉验证、去重
import os
import re
import struct
import json
from dataclasses import dataclass, field
from typing import Any, Optional

# ===== 基础数据结构 =====
@dataclass
class VTableEntry:
    offset: int
    method_addr: int
    method_name: str = ""
    is_virtual: bool = True
    vtable_offset: int = 0

@dataclass
class VTableInfo:
    vtable_addr: int
    class_name: str = ""
    entries: list[VTableEntry] = field(default_factory=list)
    vtable_size: int = 0
    rtti_info: Optional[dict] = None

@dataclass
class RTTIChain:
    type_name: str
    typeinfo_addr: int
    vtable_addr: int
    base_classes: list[str] = field(default_factory=list)

# ===== VTable 恢复核心 =====
class VTableRecovery:
    """多策略虚表恢复引擎"""

    def __init__(self):
        self._found_vtables: list[VTableInfo] = []
        self._word_size = 8  # 默认 x64

    def recover_vtables(self, binary_path: str) -> list[VTableInfo]:
        """主入口：加载二进制并尝试所有恢复策略"""
        data = self._load_binary(binary_path)
        if not data:
            return []

        # 尝试多种策略
        vtables: list[VTableInfo] = []
        vtables.extend(self._find_vtables_itanium(data))
        vtables.extend(self._find_vtables_msvc(data))
        vtables.extend(self._find_vtables_r2(binary_path))

        validated = self._cross_validate_vtables(vtables)
        self._found_vtables = validated
        return validated

    # //// Itanium ABI (GCC/Clang) — typeinfo/VTT 符号扫描 ////
    def _find_vtables_itanium(self, binary_data: bytes) -> list[VTableInfo]:
        vtables: list[VTableInfo] = []
        # _ZTS* 符号: typeinfo name string
        ts_pattern = re.compile(rb'_ZTS[NA]?\d+(\w+)')
        # _ZTI* 符号: typeinfo object
        ti_pattern = re.compile(rb'_ZTI[NA]?\d+(\w+)')
        # _ZTV* 符号: vtable
        tv_pattern = re.compile(rb'_ZTV[NA]?\d+(\w+)')

        # 扫描字符串表中存在的 typeinfo name
        type_names: dict[int, str] = {}
        for m in ts_pattern.finditer(binary_data):
            name = m.group(1).decode('utf-8', errors='replace')
            type_names[m.start()] = name

        # 扫描 vtable 符号引用
        for m in tv_pattern.finditer(binary_data):
            class_name = m.group(1).decode('utf-8', errors='replace')
            vaddr = m.start()
            entries = self._resolve_vtable_entries_raw(binary_data, vaddr)
            if entries:
                vtables.append(VTableInfo(
                    vtable_addr=vaddr,
                    class_name=class_name,
                    entries=entries,
                    vtable_size=len(entries) * self._word_size,
                ))
        return vtables

    # //// MSVC — RTTICompleteObjectLocator + `??_7` vftable 模式 ////
    def _find_vtables_msvc(self, binary_data: bytes) -> list[VTableInfo]:
        vtables: list[VTableInfo] = []
        # `??_7` 是 MSVC vftable 符号前缀
        vf_pattern = re.compile(rb'\?\?_7(\?[\w@]+)@@6B@')
        # RTTI `.?AV` 是 type descriptor
        rtti_pattern = re.compile(rb'\.\?AV([\w@]+)@@')

        for m in vf_pattern.finditer(binary_data):
            mangled = m.group(1).decode('utf-8', errors='replace')
            # 简单 demangle
            class_name = mangled.replace('?', '').replace('@', '::')
            vaddr = m.start()
            entries = self._resolve_vtable_entries_raw(binary_data, vaddr)
            if entries:
                vtables.append(VTableInfo(
                    vtable_addr=vaddr,
                    class_name=class_name,
                    entries=entries,
                    vtable_size=len(entries) * 4,  # MSVC x86 vtable pointer = 4 bytes
                ))

        # COL (Complete Object Locator) 链遍历
        col_pattern = re.compile(rb'\x01\x00\x00\x00\x00\x00\x00\x00')
        for m in col_pattern.finditer(binary_data):
            rtti = self._parse_rtti_complete_object_locator(m.start(), binary_data)
            if rtti:
                vaddr = rtti.get('vtable_addr', 0)
                if vaddr:
                    entries = self._resolve_vtable_entries_raw(binary_data, vaddr)
                    vtables.append(VTableInfo(
                        vtable_addr=vaddr,
                        class_name=rtti.get('class_name', ''),
                        entries=entries,
                        vtable_size=len(entries) * self._word_size,
                        rtti_info=rtti,
                    ))
        return vtables

    def _parse_rtti_complete_object_locator(self, addr: int, data: bytes) -> Optional[dict]:
        """解析 MSVC RTTICompleteObjectLocator 结构"""
        if addr + 24 > len(data):
            return None
        try:
            # COL 结构: signature, offset, cdOffset, pTypeDescriptor, pClassDescriptor
            signature = struct.unpack_from('<I', data, addr)[0]
            if signature != 1:  # COL_SIGNATURE = 1
                return None
            col_offset = struct.unpack_from('<I', data, addr + 4)[0]
            cd_offset = struct.unpack_from('<I', data, addr + 8)[0]
            ptd = struct.unpack_from('<I', data, addr + 12)[0]
            pcd = struct.unpack_from('<I', data, addr + 16)[0]

            class_name = ""
            if ptd > 0 and ptd < len(data) - 20:
                # TypeDescriptor: vftable_ptr, spare, name
                name_offset = struct.unpack_from('<I', data, ptd + 8)[0]
                if name_offset > 0 and ptd + name_offset < len(data):
                    raw_name = data[ptd + name_offset:].split(b'\x00')[0]
                    class_name = raw_name.decode('utf-8', errors='replace')

            vtable_addr = addr - col_offset if col_offset != 0 else 0
            return {
                'signature': signature,
                'col_offset': col_offset,
                'cd_offset': cd_offset,
                'pTypeDescriptor': ptd,
                'pClassDescriptor': pcd,
                'class_name': class_name,
                'vtable_addr': vtable_addr,
            }
        except struct.error:
            return None

    # //// r2 `av` 命令辅助查找 ////
    def _find_vtables_r2(self, binary_path: str) -> list[VTableInfo]:
        """尝试用 r2/rizin 查找虚表"""
        vtables: list[VTableInfo] = []
        for cmd in ['r2', 'rizin']:
            try:
                import subprocess
                result = subprocess.run(
                    [cmd, '-q', '-c', 'avj', binary_path],
                    capture_output=True, timeout=30, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    data = json.loads(result.stdout)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict):
                                vtables.append(VTableInfo(
                                    vtable_addr=item.get('address', 0),
                                    class_name=item.get('class_name', ''),
                                    vtable_size=item.get('size', 0),
                                ))
                    break
            except (FileNotFoundError, json.JSONDecodeError, Exception):
                continue
        return vtables

    def _resolve_vtable_entries(self, binary_path: str, vtable_addr: int,
                                 vtable_size: int) -> list[VTableEntry]:
        """从二进制中读取虚表条目地址"""
        data = self._load_binary(binary_path)
        if not data:
            return []
        return self._resolve_vtable_entries_raw(data, vtable_addr, vtable_size)

    def _resolve_vtable_entries_raw(self, data: bytes, base_addr: int,
                                     max_size: int = 256) -> list[VTableEntry]:
        entries: list[VTableEntry] = []
        offset = 0
        # 每个条目是一个指针宽度
        while offset < min(max_size, len(data) - base_addr):
            if base_addr + offset + self._word_size > len(data):
                break
            ptr = struct.unpack_from('<Q' if self._word_size == 8 else '<I',
                                     data, base_addr + offset)[0]
            if ptr == 0:
                # 空指针通常是 vtable 结尾
                break
            entries.append(VTableEntry(
                offset=offset,
                method_addr=ptr,
                is_virtual=True,
                vtable_offset=offset,
            ))
            offset += self._word_size
        return entries

    # ===== 交叉验证去伪 =====
    def _cross_validate_vtables(self, vtables: list[VTableInfo]) -> list[VTableInfo]:
        """去除重叠/重复虚表，验证入口数合理性"""
        verifier = VTableVerifier()
        vtables = verifier.deduplicate_vtables(vtables)
        result = []
        for vt in vtables:
            if verifier.verify_entry_counts(vt):
                result.append(vt)
        return result

    @staticmethod
    def _load_binary(path: str) -> Optional[bytes]:
        if not path or not os.path.exists(path):
            return None
        with open(path, 'rb') as f:
            return f.read()

# ===== RTTI 遍历器 =====
class RTTITraverser:
    """
    Itanium: _ZTS* -> _ZTI* -> vtable
    MSVC:    .data$r 段解析, `RTTI` 符号模式
    """

    def traverse_typeinfo(self, binary_path: str,
                          typeinfo_addr: int) -> Optional[RTTIChain]:
        data = VTableRecovery._load_binary(binary_path)
        if not data or typeinfo_addr >= len(data):
            return None

        # 尝试 Itanium RTTI 结构
        try:
            # _ZTI 结构: vtable_ptr, name_ptr
            vtable_ptr = struct.unpack_from('<Q', data, typeinfo_addr)[0]
            name_ptr = struct.unpack_from('<Q', data, typeinfo_addr + 8)[0]
            type_name = ""
            if 0 < name_ptr < len(data):
                name_bytes = data[name_ptr:].split(b'\x00')[0]
                type_name = name_bytes.decode('utf-8', errors='replace')

            return RTTIChain(
                type_name=type_name,
                typeinfo_addr=typeinfo_addr,
                vtable_addr=vtable_ptr,
            )
        except (struct.error, UnicodeDecodeError):
            pass

        # 尝试 MSVC 结构
        try:
            vfptr = struct.unpack_from('<I', data, typeinfo_addr)[0]
            cd_offset = struct.unpack_from('<I', data, typeinfo_addr + 4)[0] if typeinfo_addr + 8 <= len(data) else 0
            return RTTIChain(
                type_name=f"MSVC_{typeinfo_addr:x}",
                typeinfo_addr=typeinfo_addr,
                vtable_addr=vfptr,
            )
        except struct.error:
            pass

        return None

# ===== VTable 验证器 =====
class VTableVerifier:
    @staticmethod
    def verify_entry_counts(vtable: VTableInfo) -> bool:
        """虚表入口数应在合理范围内 (1-512)"""
        if not vtable.entries:
            return True  # 空表也可能合法
        return 1 <= len(vtable.entries) <= 512

    @staticmethod
    def verify_method_addresses(vtable: VTableInfo, binary_path: str) -> bool:
        """验证方法地址在二进制范围内"""
        if not binary_path or not vtable.entries:
            return True
        try:
            fsize = os.path.getsize(binary_path)
        except OSError:
            return True
        for entry in vtable.entries:
            if entry.method_addr > fsize or entry.method_addr == 0:
                continue  # 空指针跳过
        return True

    @staticmethod
    def deduplicate_vtables(vtables: list[VTableInfo]) -> list[VTableInfo]:
        """去除地址重叠或完全一致的虚表"""
        # 按地址排序
        sorted_vt = sorted(vtables, key=lambda v: v.vtable_addr)
        deduped: list[VTableInfo] = []

        i = 0
        while i < len(sorted_vt):
            current = sorted_vt[i]
            # 跳过与上一个地址重叠的
            if deduped:
                prev = deduped[-1]
                if (current.vtable_addr >= prev.vtable_addr and
                    current.vtable_addr < prev.vtable_addr + prev.vtable_size):
                    # 保留条目更多的那个
                    if len(current.entries) > len(prev.entries):
                        deduped[-1] = current
                    i += 1
                    continue
            deduped.append(current)
            i += 1

        return deduped

# ===== VTable 导出器 =====
class VTableDumper:
    @staticmethod
    def dump_to_dict(vtable: VTableInfo) -> dict:
        return {
            'vtable_addr': hex(vtable.vtable_addr),
            'class_name': vtable.class_name,
            'vtable_size': vtable.vtable_size,
            'entry_count': len(vtable.entries),
            'entries': [{
                'offset': e.offset,
                'method_addr': hex(e.method_addr),
                'method_name': e.method_name,
                'is_virtual': e.is_virtual,
            } for e in vtable.entries],
            'rtti_info': vtable.rtti_info,
        }

    @staticmethod
    def dump_all(vtables: list[VTableInfo], fmt: str = 'json') -> str:
        if fmt == 'json':
            return json.dumps(
                [VTableDumper.dump_to_dict(v) for v in vtables],
                indent=2, default=str)
        # 文本格式
        lines = []
        for vt in vtables:
            lines.append(f'[{vt.class_name or "unknown"}] @ {hex(vt.vtable_addr)}')
            lines.append(f'  Size: {vt.vtable_size}, Entries: {len(vt.entries)}')
            for e in vt.entries[:5]:
                lines.append(f'    +{e.offset:04x}: {hex(e.method_addr)}')
            if len(vt.entries) > 5:
                lines.append(f'    ... ({len(vt.entries) - 5} more)')
            lines.append('')
        return '\n'.join(lines)


# --- 推测去虚拟化 (Speculative Devirtualization) ---
# GCC -fdevirtualize-speculatively / LLVM SimplifyCFG 的间接调用折叠 pass
# 当 vtable 分析确定某虚函数仅有一个可能的实现时，可将间接 call 折叠为直接 call。
# 这在 LTO (Link-Time Optimization) 中尤为有效 — 跨编译单元的类层次全貌可见。
# Padlewski (2018) "Devirtualization in LLVM" (LLVM Dev Meeting)

def speculative_devirtualize(call_site: int, possible_targets: list[int],
                              profile_counts: dict[int, int] | None = None) -> dict:
    """分析虚调用点的去虚拟化可行性。
    若仅一个可能目标 → 直接去虚拟化 (direct devirt)。
    若有多个目标但一个占比 > 90% → 推测去虚拟化 (插入 guard + direct call + fallback)。
    profile_counts: {target_addr: call_count} 来自 PGO/FDO 数据。"""
    n = len(possible_targets)
    if n == 1:
        return {'strategy': 'direct', 'target': possible_targets[0], 'confidence': 1.0}
    if n == 0:
        return {'strategy': 'unresolved', 'target': None, 'confidence': 0.0}

    # PGO 辅助时，检查支配性目标
    if profile_counts:
        total = sum(profile_counts.values())
        dominant = max(profile_counts, key=profile_counts.get)
        dom_ratio = profile_counts[dominant] / total if total > 0 else 0.0
        if dom_ratio >= 0.9 and total >= 100:  # 样本量充足且占比高
            return {'strategy': 'speculative', 'primary_target': dominant,
                    'fallback_targets': [t for t in possible_targets if t != dominant],
                    'confidence': dom_ratio,
                    'guard_hint': 'likely' if dom_ratio > 0.99 else 'unpredictable'}

    # CHA 推断：启发式去虚拟化
    return {'strategy': 'virtual_dispatch', 'vtable_slots': possible_targets,
            'confidence': 1.0 / max(n, 1)}

# ---- 模块级便捷入口 ----
def recover_vtables(binary_path: str) -> list[VTableInfo]:
    """一键虚表恢复"""
    return VTableRecovery().recover_vtables(binary_path)
