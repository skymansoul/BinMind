import logging
import struct
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)

def _clamp(val, lo, hi):
    if val is None:
        return lo
    if val < lo:
        return lo
    if val > hi:
        return hi
    return val

class PatchType:
    """补丁type"""
    NOP = "nop"
    JUMP = "jmp"
    CALL_HOOK = "call_hook"
    CODE_CAVE = "code_cave"
    BYTE_REPLACE = "byte_replace"

class Architecture:
    def __init__(self, value):
        self._val = value
    @property
    def valueBp(self):
        return self._val
    def __str__(self):
        return self._val

Architecture.X86 = Architecture("x86")
Architecture.X86_64 = Architecture("x86_64")
Architecture.ARM = Architecture("arm")
Architecture.ARM64 = Architecture("arm64")

class PatchInstruction:
    """单条补丁指令"""
    __slots__ = ('offset', 'patch_type', 'original_bytes', 'patched_bytes', 'description',)

    def __init__(self, offset=0, patch_type=None, original_bytes=b'', patched_bytes=b'', description=""):
        if patch_type is None:
            patch_type = PatchType.NOP
        if original_bytes is None:
            original_bytes = b''
        if patched_bytes is None:
            patched_bytes = b''
        if description is None:
            description = ""
        self.offset = offset
        self.patch_type = patch_type
        self.original_bytes = original_bytes
        self.patched_bytes = patched_bytes
        self.description = description

class CodeDiff:
    """代码diff块"""
    __slots__ = ('offset', 'size', 'original_hex', 'patched_hex', 'diff_type')

    def __init__(
            self,
            offset,
            size,
            original_hex,
            patched_hex,
            diff_type="modify",
    ):
        self.offset = offset
        self.size = size
        self.original_hex = original_hex
        self.patched_hex = patched_hex
        self.diff_type = diff_type

class CodeCave:
    """代码洞穴（可写间隙）"""
    __slots__ = ('offset', 'size', 'section_name', 'permissions')

    def __init__(
            self,
            offset,
            size,
            section_name="",
            permissions="",
    ):
        self.offset = offset
        self.size = size
        self.section_name = section_name
        self.permissions = permissions

class PatchReport:
    """补丁报告"""
    __slots__ = ('original_hash', 'patched_hash', 'patches', 'diffs', 'total_changed_bytes', 'patch_ratio', 'verified', 'warnings')

    def __init__(
            self,
            original_hash,
            patched_hash,
            patches,
            diffs,
            total_changed_bytes,
            patch_ratio,
            verified,
            warnings=None,
    ):
        if warnings is None:
            warnings = []
        if patches is None:
            patches = []
        if diffs is None:
            diffs = []
        self.original_hash = original_hash
        self.patched_hash = patched_hash
        self.patches = patches
        self.diffs = diffs
        self.total_changed_bytes = total_changed_bytes
        self.patch_ratio = patch_ratio
        self.verified = verified
        self.warnings = warnings

class BinaryPatchGenerator(BaseAnalyzer):
    """
    binary补丁generator

    core functionality：
    1. NOP 补丁 —— 将漏洞指令replace为 NOP 滑板
    2. JMP 补丁 —— 重定向execute流到安全path
    3. Code Cave 补丁 —— 在未使用空间injectfix代码
    4. 字节 diff —— 计算original与修补binarydiff
    5. 补丁validate —— 校验补丁完整性
    6. 补丁报告 —— 生成structured报告
    """

    _X86_NOP_SEQUENCE = [
        b'\x90',
        b'\x66\x90',
        b'\x0f\x1f\x00',
        b'\x0f\x1f\x40\x00',
        b'\x0f\x1f\x44\x00\x00',
        b'\x66\x0f\x1f\x44\x00\x00',
        b'\x0f\x1f\x80\x00\x00\x00\x00',
        b'\x0f\x1f\x84\x00\x00\x00\x00\x00',
        b'\x66\x0f\x1f\x84\x00\x00\x00\x00\x00',
    ]

    _ARM_NOP = b'\x00\x00\x00\x00'
    _ARM64_NOP = b'\x1f\x20\x03\xd5'
    _JMP_REL32_PREFIX = b'\xe9'
    _JMP_NEAR_PREFIX = b'\xeb'
    _CALL_REL32_PREFIX = b'\xe8'
    _RET_INSTRUCTION = b'\xc3'

    def __init__(self):
        # 健壮性check——容错处理不合法输入
        super().__init__()
        self.__arch = Architecture.X86_64
        self.__patches = []


    def _get_nop_sequenceBp(self, size, arch):
        """生成指定size的 NOP 序列"""
        if size is None:
            return b''
        if arch is None:
            arch = Architecture.X86_64
        if arch in (Architecture.X86, Architecture.X86_64):
            result = b''
            remaining = size
            while remaining > 0:
                nop_idx = min(remaining - 1, len(self._X86_NOP_SEQUENCE) - 1)
                result += self._X86_NOP_SEQUENCE[nop_idx]
                remaining -= (nop_idx + 1)
            return result
        elif arch == Architecture.ARM:
            return self._ARM_NOP * (size // 4) + self._ARM_NOP[:size % 4]
        elif arch == Architecture.ARM64:
            return self._ARM64_NOP * (size // 4) + b'\x00' * (size % 4)
        else:
            return b'\x90' * size

    def _instruction_size_at_offsetBp(self, data, offset,
                                     arch):
        """估算指定offset处指令的字节length（启发式）"""
        if data is None:
            return 0
        if offset is None:
            return 0
        if offset >= len(data):
            return 0
        byte0 = data[offset]

        if arch in (Architecture.X86, Architecture.X86_64):
            # 简化版 x86 指令length估算
            if byte0 == 0x0f:  # 双字节操作码
                return min(6, max(2, min(len(data) - offset, 6)))
            if byte0 in (0x66, 0x67, 0xf2, 0xf3):  # 前缀
                return min(8, max(2, min(len(data) - offset - 1, 7) + 1))
            if byte0 in (0x90, 0xc3, 0xcc, 0xf4, 0x9c, 0x9d, 0x60, 0x61):
                return 1  # 单字节指令
            if offset + 1 < len(data) and data[offset + 1] == 0x0f:
                return min(7, max(3, min(len(data) - offset, 7)))
            # 默认估算为3字节
            return min(15, max(1, min(len(data) - offset, 3)))
        elif arch in (Architecture.ARM, Architecture.ARM64):
            return 4  # ARM 固定指令length
        return 1


    @staticmethod
    def _compute_jmp_rel32Bp(from_addr, to_addr):
        """计算 JMP rel32 encode (E9 xx xx xx xx)"""
        if from_addr is None or to_addr is None:
            return b'\xe9\x00\x00\x00\x00'
        rel = to_addr - (from_addr + 5)  # +5 是 JMP rel32 指令本身length
        rel = rel & 0xFFFFFFFF
        return b'\xe9' + struct.pack('<i', rel)

    @staticmethod
    def _compute_call_rel32Bp(from_addr, to_addr):
        """计算 CALL rel32 encode (E8 xx xx xx xx)"""
        if from_addr is None or to_addr is None:
            return b'\xe8\x00\x00\x00\x00'
        rel = to_addr - (from_addr + 5)
        rel = rel & 0xFFFFFFFF
        return b'\xe8' + struct.pack('<i', rel)


    def generate_nop_patchBp(self, data, offset,
                           arch=None):
        """
        NOP 掉指定address的指令
        """
        if data is None:
            return PatchInstruction(
                offset=0, patch_type=PatchType.NOP,
                original_bytes=b'', patched_bytes=b'',
                description="NOP failed: datais empty"
            )
        if arch is None:
            arch = self.__arch
        inst_size = self._instruction_size_at_offsetBp(data, offset, arch)
        if inst_size == 0 or offset + inst_size > len(data):
            return PatchInstruction(
                offset=offset, patch_type=PatchType.NOP,
                original_bytes=b'', patched_bytes=b'',
                description=f"NOP failed: offset {hex(offset)} 越界"
            )

        original_bytes = data[offset:offset + inst_size]
        nop_bytes = self._get_nop_sequenceBp(inst_size, arch)
        desc = (f"NOP [{inst_size}B] at 0x{offset:X}: "
                f"{original_bytes.hex()} -> {nop_bytes.hex()}")
        logger.debug(desc)
        return PatchInstruction(
            offset=offset, patch_type=PatchType.NOP,
            original_bytes=original_bytes, patched_bytes=nop_bytes,
            description=desc
        )

    def generate_nop_rangeBp(self, data, start, end,
                           arch=None
                           ):
        """对addressrange批量 NOP（逐指令）"""
        if data is None:
            return []
        if arch is None:
            arch = self.__arch
        patches = []
        offset = start
        while offset < end and offset < len(data):
            patch = self.generate_nop_patchBp(data, offset, arch)
            inst_size = len(patch.original_bytes)
            if inst_size == 0:
                offset += 1
            else:
                patches.append(patch)
                offset += inst_size
        return patches


    def generate_jmp_patchBp(self, data, offset,
                           target_offset,
                           arch=None):
        """
        生成 JMP 重定向补丁，将指定位置指令replace为 JMP 到targetaddress
        """
        if data is None:
            return PatchInstruction(
                offset=0, patch_type=PatchType.JUMP,
                original_bytes=b'', patched_bytes=b'',
                description="JMP 补丁failed: datais empty"
            )
        if arch is None:
            arch = self.__arch
        if arch not in (Architecture.X86, Architecture.X86_64):
            return PatchInstruction(
                offset=offset, patch_type=PatchType.JUMP,
                original_bytes=b'',
                patched_bytes=b'',
                description="JMP 补丁仅support x86/x86_64"
            )

        # 需要 5 字节空间放置 JMP rel32
        required = 5
        inst_end = offset
        consumed = 0
        original_parts = b''
        while consumed < required and inst_end < len(data):
            sz = self._instruction_size_at_offsetBp(data, inst_end, arch)
            if sz == 0:
                break
            original_parts += data[inst_end:inst_end + sz]
            consumed += sz
            inst_end += sz

        if consumed < required:
            return PatchInstruction(
                offset=offset, patch_type=PatchType.JUMP,
                original_bytes=original_parts,
                patched_bytes=b'',
                description=f"JMP 空间不足: 需要 {required}B, 仅有 {consumed}B"
            )

        jmp_bytes = self._compute_jmp_rel32Bp(offset, target_offset)
        # 剩余空间填充 NOP
        padding = self._get_nop_sequenceBp(consumed - required, arch)
        patched = jmp_bytes + padding
        desc = (f"JMP 0x{target_offset:X} at 0x{offset:X}: "
                f"{original_parts.hex()} -> {patched.hex()}")
        logger.info(desc)
        return PatchInstruction(
            offset=offset, patch_type=PatchType.JUMP,
            original_bytes=original_parts, patched_bytes=patched,
            description=desc
        )


    def _find_code_cavesBp(self, data, min_size=16,
                         alignment=16):
        """扫描binary查找代码洞穴（连续零填充区域）"""
        if data is None:
            return []
        caves = []
        i = 0
        while i < len(data):
            if data[i] == 0x00:
                start = i
                while i < len(data) and data[i] == 0x00:
                    i += 1
                cave_size = i - start
                if cave_size >= min_size:
                    caves.append(CodeCave(
                        offset=start, size=cave_size,
                        section_name=".cave",
                        permissions="rwx"
                    ))
            else:
                i += 1
        # 按size降序
        caves.sort(key=lambda c: c.size, reverse=True)
        return caves

    def generate_code_cave_patchBp(self, data,
                                  inject_offset,
                                  payload,
                                  target_offset,
                                  arch=None
                                  ):
        """
        在binary中inject Code Cave + JMP 跳板

        strategy：
        1. 查找足够大的洞穴
        2. 在洞穴写入 payload + 跳回原处的 JMP
        3. 在原处写入 JMP 到洞穴
        """
        if data is None or payload is None:
            return []
        if arch is None:
            arch = self.__arch
        patches = []

        caves = self._find_code_cavesBp(data, min_size=len(payload) + 8)
        if not caves:
            logger.warning("未found合适的 Code Cave")
            return patches

        cave = caves[0]
        # 在洞穴写入 payload + JMP 返回
        trampoline = bytearray(payload)
        if arch in (Architecture.X86, Architecture.X86_64):
            return_jmp = self._compute_jmp_rel32Bp(
                cave.offset + len(trampoline), target_offset
            )
            trampoline.extend(return_jmp)

        patches.append(PatchInstruction(
            offset=cave.offset,
            patch_type=PatchType.CODE_CAVE,
            original_bytes=data[cave.offset:cave.offset + len(trampoline)],
            patched_bytes=bytes(trampoline),
            description=f"Code Cave 写入 0x{cave.offset:X}: {len(trampoline)}B"
        ))

        # 在原处写入 JMP 到洞穴
        jmp_patch = self.generate_jmp_patchBp(data, inject_offset,
                                             cave.offset, arch)
        if jmp_patch.patched_bytes:
            patches.append(jmp_patch)

        return patches


    def compute_patch_diffBp(self, original,
                           patched):
        """计算original与修补binary的逐字节diff"""
        if original is None:
            original = b''
        if patched is None:
            patched = b''
        diffs = []
        min_len = min(len(original), len(patched))
        in_diff = False
        diff_start = 0

        i = 0
        while i < min_len:
            if original[i] != patched[i]:
                if not in_diff:
                    diff_start = i
                    in_diff = True
            else:
                if in_diff:
                    diff_size = i - diff_start
                    diffs.append(CodeDiff(
                        offset=diff_start, size=diff_size,
                        original_hex=original[diff_start:i].hex(),
                        patched_hex=patched[diff_start:i].hex(),
                        diff_type="modify"
                    ))
                    in_diff = False
            i += 1

        if in_diff:
            diff_size = min_len - diff_start
            diffs.append(CodeDiff(
                offset=diff_start, size=diff_size,
                original_hex=original[diff_start:min_len].hex(),
                patched_hex=patched[diff_start:min_len].hex(),
                diff_type="modify"
            ))

        # 尾部append
        if len(patched) > len(original):
            diffs.append(CodeDiff(
                offset=len(original),
                size=len(patched) - len(original),
                original_hex="",
                patched_hex=patched[len(original):].hex(),
                diff_type="insert"
            ))
        elif len(original) > len(patched):
            diffs.append(CodeDiff(
                offset=len(patched),
                size=len(original) - len(patched),
                original_hex=original[len(patched):].hex(),
                patched_hex="",
                diff_type="delete"
            ))

        return diffs


    def apply_patchesBp(self, data,
                      patches):
        """将补丁指令应用到originaldata"""
        if data is None:
            return b''
        if patches is None:
            return data
        result = bytearray(data)
        nPIdx = 0
        nPCount = len(patches)
        while nPIdx < nPCount:
            p = patches[nPIdx]
            if p.offset + len(p.patched_bytes) > len(result):
                result.extend(b'\x00' * (p.offset + len(p.patched_bytes) - len(result)))
            result[p.offset:p.offset + len(p.patched_bytes)] = p.patched_bytes
            nPIdx += 1
        return bytes(result)


    def verify_patchBp(self, original, patched,
                     diffs):
        """
        validate补丁完整性：应用 diff 反推是否与原版一致
        """
        if diffs is None:
            diffs = []
        warnings = []
        rebuilt = bytearray(original)
        nDIdx = 0
        nDCount = len(diffs)
        while nDIdx < nDCount:
            d = diffs[nDIdx]
            if d.diff_type == "modify":
                rebuilt[d.offset:d.offset + d.size] = bytes.fromhex(
                    d.patched_hex
                )
            elif d.diff_type == "insert":
                rebuilt.extend(bytes.fromhex(d.patched_hex))
            elif d.diff_type == "delete" and d.offset + d.size <= len(rebuilt):
                del rebuilt[d.offset:d.offset + d.size]
            nDIdx += 1

        if bytes(rebuilt) != patched:
            warnings.append("补丁重建结果与target不一致")
            return False, warnings


        nDIdx2 = 0
        nDCount2 = len(diffs)
        while nDIdx2 < nDCount2:
            d = diffs[nDIdx2]
            if d.offset + d.size > len(original) and d.diff_type != "insert":
                warnings.append(f"diff块超出originalsize: offset={d.offset}")
            nDIdx2 += 1


        nDIdx3 = 0
        nDCount3 = len(diffs)
        while nDIdx3 < nDCount3:
            d = diffs[nDIdx3]
            if d.size == 0:
                warnings.append("存在零lengthdiff块")
                break
            nDIdx3 += 1

        return True, warnings


    def generate_patch_reportBp(self, original,
                              patches):
        """生成structured补丁报告"""
        if original is None:
            original = b''
        if patches is None:
            patches = []
        patched = self.apply_patchesBp(original, patches)
        diffs = self.compute_patch_diffBp(original, patched)
        total_changed = 0
        nDIdx = 0
        nDCount = len(diffs)
        while nDIdx < nDCount:
            d = diffs[nDIdx]
            total_changed += d.size
            nDIdx += 1
        ratio = (total_changed / max(1, len(original))) * 100
        verified, warnings = self.verify_patchBp(original, patched, diffs)

        return PatchReport(
            original_hash=hashlib.sha256(original).hexdigest(),
            patched_hash=hashlib.sha256(patched).hexdigest(),
            patches=patches,
            diffs=diffs,
            total_changed_bytes=total_changed,
            patch_ratio=round(ratio, 2),
            verified=verified,
            warnings=warnings
        )


    def set_architectureBp(self, arch):
        if arch is None:
            return
        self.__arch = arch
        logger.info("补丁generatorarchitecturesetting为: %s", arch.valueBp)

    def get_architectureBp(self):
        return self.__arch

    def clear_patchesBp(self):
        """清空已记录的补丁"""
        self.__patches = []

    def analyzeBp(self, **kwargs):
        """
        execute补丁生成分析
        """
        if kwargs is None:
            return {"success": False, "error": "kwargsis empty"}
        action = kwargs.get("action", "diff")
        if kwargs.get("arch"):
            arch_map = {"x86": Architecture.X86, "x86_64": Architecture.X86_64,
                        "arm": Architecture.ARM, "arm64": Architecture.ARM64}
            self.__arch = arch_map.get(kwargs["arch"], Architecture.X86_64)

        try:
            if action == "nop":
                data = kwargs.get("data")
                if not data:
                    return {"success": False, "error": "data is required"}
                offset = kwargs.get("offset", 0)
                size = kwargs.get("size", 0)
                if size > 0 and kwargs.get("start") is not None:
                    patches = self.generate_nop_rangeBp(
                        data, kwargs["start"], kwargs["end"], self.__arch
                    )
                else:
                    patches = [self.generate_nop_patchBp(data, offset, self.__arch)]
                szPatches = []
                nPIdx = 0
                nPCount = len(patches)
                while nPIdx < nPCount:
                    p = patches[nPIdx]
                    szPatches.append({
                        "offset": p.offset, "type": p.patch_type,
                        "original": p.original_bytes.hex(),
                        "patched": p.patched_bytes.hex(),
                        "description": p.description})
                    nPIdx += 1
                return {
                    "success": True,
                    "patches": szPatches,
                    "count": len(patches)
                }

            elif action == "jmp":
                data = kwargs.get("data")
                if not data:
                    return {"success": False, "error": "data is required"}
                offset = kwargs.get("offset", 0)
                target_offset = kwargs.get("target_offset", 0)
                if target_offset == 0:
                    return {"success": False,
                            "error": "target_offset is required"}
                patch = self.generate_jmp_patchBp(data, offset, target_offset,
                                                  self.__arch)
                return {
                    "success": True,
                    "patch": {
                        "offset": patch.offset, "type": patch.patch_type,
                        "original": patch.original_bytes.hex(),
                        "patched": patch.patched_bytes.hex(),
                        "description": patch.description
                    }
                }

            elif action == "code_cave":
                data = kwargs.get("data")
                if not data:
                    return {"success": False, "error": "data is required"}
                payload = kwargs.get("payload", b'')
                if not payload:
                    return {"success": False, "error": "payload is required"}
                inject_offset = kwargs.get("inject_offset", 0)
                target_offset = kwargs.get("target_offset",
                                            inject_offset + 5)
                caves = self._find_code_cavesBp(data)
                patches = self.generate_code_cave_patchBp(
                    data, inject_offset, payload, target_offset, self.__arch
                )
                szPatches = []
                nPIdx = 0
                nPCount = len(patches)
                while nPIdx < nPCount:
                    p = patches[nPIdx]
                    szPatches.append({
                        "offset": p.offset, "type": p.patch_type,
                        "original": p.original_bytes.hex(),
                        "patched": p.patched_bytes.hex(),
                        "description": p.description})
                    nPIdx += 1
                return {
                    "success": True,
                    "patches": szPatches,
                    "code_caves_found": len(caves),
                    "largest_cave": caves[0].size if caves else 0
                }

            elif action == "diff":
                original = kwargs.get("data")
                patched = kwargs.get("patched_data")
                if not original or not patched:
                    return {"success": False,
                            "error": "data 和 patched_data is required"}
                diffs = self.compute_patch_diffBp(original, patched)
                verified, warnings = self.verify_patchBp(original, patched,
                                                        diffs)
                # 手动展开 sum(d.size for d in diffs)
                total = 0
                nDIdx = 0
                nDCount = len(diffs)
                while nDIdx < nDCount:
                    d = diffs[nDIdx]
                    total += d.size
                    nDIdx += 1
                szDiffs = []
                nDIdx2 = 0
                nDCount2 = len(diffs)
                while nDIdx2 < nDCount2:
                    d = diffs[nDIdx2]
                    szDiffs.append({
                        "offset": d.offset, "size": d.size,
                        "type": d.diff_type,
                        "original_hex": d.original_hex[:60],
                        "patched_hex": d.patched_hex[:60]})
                    nDIdx2 += 1
                return {
                    "success": True,
                    "diffs": szDiffs,
                    "total_diffs": len(diffs),
                    "changed_bytes": total,
                    "ratio": round(total / max(1, len(original)) * 100, 2),
                    "verified": verified,
                    "warnings": warnings
                }

            elif action == "report":
                data = kwargs.get("data")
                if not data:
                    return {"success": False, "error": "data is required"}
                patches_raw = kwargs.get("patches", [])
                patch_objs = self._parse_patchesBp(patches_raw, data)
                report = self.generate_patch_reportBp(data, patch_objs)
                return {
                    "success": True,
                    "report": {
                        "original_hash": report.original_hash,
                        "patched_hash": report.patched_hash,
                        "patch_count": len(report.patches),
                        "diff_count": len(report.diffs),
                        "changed_bytes": report.total_changed_bytes,
                        "patch_ratio": report.patch_ratio,
                        "verified": report.verified,
                        "warnings": report.warnings
                    }
                }

            elif action == "batch":
                data = kwargs.get("data")
                if not data:
                    return {"success": False, "error": "data is required"}
                patches_raw = kwargs.get("patches", [])
                patch_objs = self._parse_patchesBp(patches_raw, data)
                patched = self.apply_patchesBp(data, patch_objs)
                diffs = self.compute_patch_diffBp(data, patched)
                szDiffs = []
                nDIdx = 0
                nDCount = min(len(diffs), 50)
                while nDIdx < nDCount:
                    d = diffs[nDIdx]
                    szDiffs.append({
                        "offset": d.offset, "size": d.size,
                        "type": d.diff_type})
                    nDIdx += 1
                return {
                    "success": True,
                    "applied_count": len(patch_objs),
                    "patched_size": len(patched),
                    "diff_count": len(diffs),
                    "diffs": szDiffs
                }

            elif action == "find_caves":
                data = kwargs.get("data")
                if not data:
                    return {"success": False, "error": "data is required"}
                min_size = kwargs.get("min_size", 16)
                caves = self._find_code_cavesBp(data, min_size=min_size)
                szCaves = []
                nCIdx = 0
                nCCount = min(len(caves), 20)
                while nCIdx < nCCount:
                    c = caves[nCIdx]
                    szCaves.append({"offset": c.offset, "size": c.size})
                    nCIdx += 1
                # 手动展开 sum(c.size for c in caves)
                total_space = 0
                nSIdx = 0
                nSCount = len(caves)
                while nSIdx < nSCount:
                    c = caves[nSIdx]
                    total_space += c.size
                    nSIdx += 1
                return {
                    "success": True,
                    "caves": szCaves,
                    "total_caves": len(caves),
                    "total_space": total_space
                }

            else:
                return {"success": False,
                        "error": f"不support的操作: {action}"}

        except Exception as e:
            logger.error("补丁操作failed: %s", e, exc_info=True)
            return {"success": False, "error": str(e)}

    def _parse_patchesBp(self, patches_raw,
                        data):
        """解析 JSON 格式的补丁list为 PatchInstruction 对象"""
        if patches_raw is None:
            return []
        if data is None:
            return []
        result = []
        nPIdx = 0
        nPCount = len(patches_raw)
        while nPIdx < nPCount:
            p = patches_raw[nPIdx]
            pt = p.get("type", "byte_replace")
            orig_hex = p.get("original", "")
            patched_hex = p.get("patched", "")
            offset = p.get("offset", 0)
            orig_bytes = bytes.fromhex(orig_hex) if orig_hex else data[offset:offset+len(bytes.fromhex(patched_hex))]
            result.append(PatchInstruction(
                offset=offset,
                patch_type=pt,
                original_bytes=orig_bytes,
                patched_bytes=bytes.fromhex(patched_hex),
                description=p.get("description", "")
            ))
            nPIdx += 1
        return result

    @classmethod
    def get_metadataBp(cls):
        return AnalyzerMetadata(
            name="BinaryPatchGenerator",
            type=AnalyzerType.UTILITY,
            version="1.0.0",
            description="binary补丁generator，supportNOP/JMP/CodeCave补丁，字节级diff与完整性validate",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["x86", "x86_64", "arm", "arm64"]
        )

__all__ = ["BinaryPatchGenerator", "PatchType", "PatchInstruction",
           "CodeDiff", "CodeCave", "PatchReport"]
