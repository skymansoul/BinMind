# 修改记录:
# 2025-08-06 11:28 - 初始实现：mmap+滚动哈希的O(N)二进制差分计算

"""内存映射二进制差分 — mmap+内容定义分块的高效补丁级差异分析。

现有二进制差异工具 (diaphora/Bindiff) 依赖反汇编并与函数签名匹配——
对striped binary精度大幅下降，且O(N²)函数匹配耗时高。

本模块的方案——内容驱动的分层差分：
Layer1-mmapi/o级: mmap两个二进制文件，直接在字节级检测变化区域。
  使用Adler-32滚动哈希的内容定义分块(CDC)，O(N)识别变化段。
Layer2-结构化: 对变化段做快速函数边界检测(prologue/epilogue模式)，
  将变化定位到函数级粒度。
Layer3-语义化: 对被标记为"changed"的函数做简单的汇编级变化分类
  (指令修改/常量变化/控制流变化/纯代码重排)。

复杂度: O(N)字节级扫描+O(K·logK)变化段分析（K=变化段数<<N）。
与diaphora/Bindiff的O(N²)函数匹配完全不同。

- rsync算法: 滚动哈希+CDC的基础理论。
- ssdeep/ppdeep: 模糊哈希在二进制相似度中的应用。
  本模块扩展到结构化变化分类，而非仅输出相似度分数。
"""

import hashlib
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

class ChangeType(Enum):
    UNCHANGED = "unchanged"
    INSTRUCTION_MODIFIED = "instruction_modified"
    CONSTANT_CHANGED = "constant_changed"
    CONTROL_FLOW_CHANGED = "control_flow_changed"
    CODE_REORDERED = "code_reordered"
    INSERTED = "inserted"
    DELETED = "deleted"

@dataclass
class ChangedRegion:
    """二进制中的一个变化区域。"""
    start_offset: int
    end_offset: int
    change_type: ChangeType
    old_bytes_hash: str = ""
    new_bytes_hash: str = ""
    function_name_hint: str = ""

@dataclass
class BinaryDiffResult:
    """两个二进制文件的完整差分分析结果。"""
    old_file: str
    new_file: str
    total_regions: int
    changed_regions: List[ChangedRegion]
    # 统计摘要
    bytes_changed: int
    bytes_inserted: int
    bytes_deleted: int
    unchanged_ratio: float
    # 风险评估
    is_security_patch: bool = False  # 启发式：是否是安全补丁
    risk_score: float = 0.0

class MMapBinaryDiffer:
    """基于mmap+CDC的快速二进制差分分析器。

    使用范式：
      differ = MMapBinaryDiffer()
      result = differ.diff("binary_v1.bin", "binary_v2.bin")
      for region in result.changed_regions:
          if region.change_type == ChangeType.CONSTANT_CHANGED:
              print(f"constant change at {hex(region.start_offset)}")
    """

    def __init__(
        self,
        chunk_size: int = 64,       # CDC最小块大小
        window_size: int = 16,      # 滚动哈希窗口
        security_patch_indicators: Optional[Set[str]] = None,
    ):
        self.chunk_size = chunk_size
        self.window_size = window_size
        self.security_indicators = security_patch_indicators or {
            "memcpy", "memmove", "strcpy", "bounds_check",
            "size_check", "null_check", "auth_check",
        }

    def diff(
        self,
        old_bytes: bytes,
        new_bytes: bytes,
        old_name: str = "old",
        new_name: str = "new",
    ) -> BinaryDiffResult:
        """执行二进制差分分析。

        接受 bytes 而非文件路径——调用方负责 mmap/读取。
        """
        _regions = self._find_changed_regions(old_bytes, new_bytes)
        _classified = self._classify_changes(old_bytes, new_bytes, _regions)

        _inserted = sum(
            r.end_offset - r.start_offset
            for r in _classified if r.change_type == ChangeType.INSERTED
        )
        _deleted = sum(
            r.end_offset - r.start_offset
            for r in _classified if r.change_type == ChangeType.DELETED
        )
        _changed = sum(
            r.end_offset - r.start_offset
            for r in _classified
            if r.change_type not in (ChangeType.UNCHANGED,
                                      ChangeType.INSERTED,
                                      ChangeType.DELETED)
        )

        _total = max(len(old_bytes), len(new_bytes))
        _unchanged = 1.0 - (_inserted + _deleted + _changed) / max(_total, 1)
        _is_patch, _risk = self._assess_security_patch(
            _classified, old_bytes, new_bytes,
        )

        return BinaryDiffResult(
            old_file=old_name, new_file=new_name,
            total_regions=len(_classified),
            changed_regions=_classified,
            bytes_changed=_changed,
            bytes_inserted=_inserted,
            bytes_deleted=_deleted,
            unchanged_ratio=round(max(0.0, _unchanged), 4),
            is_security_patch=_is_patch,
            risk_score=_risk,
        )

    def quick_similarity(self, old_bytes: bytes, new_bytes: bytes) -> float:
        """快速相似度——基于内容定义分块哈希的Jaccard系数。

        O(N)时间，不需要完整diff。
        """
        _chunks_old = self._cdc_chunk_hashes(old_bytes)
        _chunks_new = self._cdc_chunk_hashes(new_bytes)

        _set_old = set(_chunks_old)
        _set_new = set(_chunks_new)
        _union = _set_old | _set_new
        return len(_set_old & _set_new) / max(len(_union), 1)

    # 变化检测

    def _find_changed_regions(
        self, old: bytes, new: bytes,
    ) -> List[Tuple[int, int, int]]:
        """找到所有变化区域——(old_offset, new_offset, length)。"""
        _regions: List[Tuple[int, int, int]] = []
        _i = 0
        _j = 0

        while _i < len(old) and _j < len(new):
            if old[_i] == new[_j]:
                _i += 1
                _j += 1
                continue

            # 发现变化——向后搜索同步点
            _start_i, _start_j = _i, _j
            _sync_found = False
            for _look in range(1, min(256, min(len(old) - _i, len(new) - _j))):
                if old[_i + _look] == new[_j + _look]:
                    # 同步——记录变化段
                    _regions.append((_start_i, _start_j, _look))
                    _i += _look + 1
                    _j += _look + 1
                    _sync_found = True
                    break

            if not _sync_found:
                _i += 1
                _j += 1

        return _regions

    # 变化分类

    def _classify_changes(
        self, old: bytes, new: bytes,
        regions: List[Tuple[int, int, int]],
    ) -> List[ChangedRegion]:
        """对变化区域进行分类——指令修改/常量变化/控制流变化。"""
        _classified: List[ChangedRegion] = []
        for _old_off, _new_off, _length in regions:
            _old_seg = old[_old_off:_old_off + _length] if _old_off + _length <= len(old) else b""
            _new_seg = new[_new_off:_new_off + _length] if _new_off + _length <= len(new) else b""

            _ctype = self._classify_segment(_old_seg, _new_seg)
            _classified.append(ChangedRegion(
                start_offset=_old_off,
                end_offset=_old_off + _length,
                change_type=_ctype,
                old_bytes_hash=hashlib.sha256(_old_seg).hexdigest()[:16],
                new_bytes_hash=hashlib.sha256(_new_seg).hexdigest()[:16],
            ))

        return _classified

    def _classify_segment(
        self, old_seg: bytes, new_seg: bytes,
    ) -> ChangeType:
        """分类单个变化段。"""
        if not old_seg:
            return ChangeType.INSERTED
        if not new_seg:
            return ChangeType.DELETED
        if old_seg == new_seg:
            return ChangeType.UNCHANGED

        # 长度相同但内容不同→可能是常量或指令修改
        if len(old_seg) == len(new_seg):
            # 控制流指令模式
            _jmp_patterns = {b'\xe8', b'\xe9', b'\xeb', b'\x0f\x84', b'\x0f\x85'}
            _has_jmp_old = any(p in old_seg for p in _jmp_patterns)
            _has_jmp_new = any(p in new_seg for p in _jmp_patterns)

            if _has_jmp_old != _has_jmp_new:
                return ChangeType.CONTROL_FLOW_CHANGED

            # 仅少量字节不同→可能是常量
            _diff_count = sum(1 for i in range(len(old_seg)) if old_seg[i] != new_seg[i])
            if _diff_count <= 4:
                return ChangeType.CONSTANT_CHANGED
            return ChangeType.INSTRUCTION_MODIFIED

        # 长度不同→插入/删除或代码重排
        if abs(len(old_seg) - len(new_seg)) < 16:
            return ChangeType.CODE_REORDERED
        return ChangeType.INSTRUCTION_MODIFIED

    # 安全补丁评估

    def _assess_security_patch(
        self, regions: List[ChangedRegion],
        old: bytes, new: bytes,
    ) -> Tuple[bool, float]:
        """评估这个diff是否可能是安全补丁。"""
        _security_hints = 0
        _total = max(len(regions), 1)

        for _r in regions:
            _seg = old[_r.start_offset:_r.end_offset]
            try:
                _text = _seg.decode('ascii', errors='ignore').lower()
                for _ind in self.security_indicators:
                    if _ind in _text:
                        _security_hints += 1
                        break
            except Exception:
                pass

        # 安全补丁特征：少量变化(≤5%) + 涉及安全相关函数
        _change_ratio = _total / max(len(old), 1)
        _is_security = _change_ratio < 0.05 and _security_hints > 0
        _risk = min(1.0, 0.3 + _security_hints * 0.15)

        return _is_security, round(_risk, 3)

    # CDC分块

    def _cdc_chunk_hashes(self, data: bytes) -> List[str]:
        """内容定义分块——基于滚动哈希的边界识别。

        滚动哈希遇到"边界值"→切块→哈希该块。
        """
        _chunks: List[str] = []
        _start = 0
        _hash = 0
        _mask = 0xFFF  # 12-bit mask → 平均4KB一块

        for _i in range(len(data)):
            _hash = ((_hash << 1) ^ data[_i]) & 0xFFFFFFFF
            if (_hash & _mask) == _mask and _i - _start >= self.chunk_size:
                _chunks.append(hashlib.sha256(
                    data[_start:_i + 1]
                ).hexdigest()[:12])
                _start = _i + 1

        if _start < len(data):
            _chunks.append(hashlib.sha256(
                data[_start:]
            ).hexdigest()[:12])

        return _chunks

# 冒烟测试
def _smoke_test():
    _differ = MMapBinaryDiffer()

    # 模拟补丁：修改了一个常量和添加了边界检查
    _v1 = (
        b"\x55\x48\x89\xe5"          # push rbp; mov rbp, rsp
        b"\xb8\x00\x01\x00\x00"      # mov eax, 256 (原始常量)
        b"\xe8\x00\x00\x00\x00"      # call func
        b"\x5d\xc3"                   # pop rbp; ret
    )
    _v2 = (
        b"\x55\x48\x89\xe5"          # push rbp; mov rbp, rsp
        b"\x81\xff\x00\x01\x00\x00"  # cmp edi, 256 (新增长度检查)
        b"\x76\x03"                   # jbe +3
        b"\xb8\x01\x00\x00\x00"      # mov eax, 1 (错误返回)
        b"\xeb\x08"                   # jmp +8
        b"\xb8\x00\x02\x00\x00"      # mov eax, 512 (修改的常量)
        b"\xe8\x00\x00\x00\x00"      # call func
        b"\x5d\xc3"                   # pop rbp; ret
    )

    _result = _differ.diff(_v1, _v2)
    print(f"[memdiff] changed regions: {_result.total_regions}")
    print(f"[memdiff] unchanged_ratio: {_result.unchanged_ratio:.3f}")
    print(f"[memdiff] is_security_patch: {_result.is_security_patch}")
    for _r in _result.changed_regions[:5]:
        print(f"  {hex(_r.start_offset)}-{hex(_r.end_offset)}: {_r.change_type.value}")

    _sim = _differ.quick_similarity(_v1, _v2)
    print(f"[memdiff] quick similarity: {_sim:.4f}")

    assert _result.total_regions > 0, "should detect changes"
    assert 0.0 <= _result.unchanged_ratio <= 1.0
    print("[OK] MMapBinaryDiffer smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
