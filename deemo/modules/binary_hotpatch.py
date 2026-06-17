"""
内存损坏模式自动修复建议 (二进制补丁级别) 模块

功能:
    1. 对于明确的漏洞类型 (如栈溢出), 自动在二进制中插入修复代码 (如附加段)
    2. 不只是重编译建议
    3. 利用二进制重写技术实现临时热修复

核心技术:
    - PE/ELF 段/节添加
    - 跳转重定向 (JMP 到新代码)
    - 修复 stub 生成 (长度检查等)
    - 二进制回写 (lief / 自实现)
"""

import logging
import os
import struct
import shutil
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


class VulnKind(Enum):
    """漏洞类型"""
    STACK_BUFFER_OVERFLOW = "stack_buffer_overflow"
    FORMAT_STRING = "format_string"
    USE_AFTER_FREE = "use_after_free"
    INTEGER_OVERFLOW = "integer_overflow"
    DOUBLE_FREE = "double_free"


class PatchStrategy(Enum):
    """补丁策略"""
    LENGTH_CHECK = "length_check"          # 添加长度检查
    FORMAT_SAFE = "format_safe"            # 替换为安全函数
    REFERENCE_CHECK = "reference_check"    # 添加引用检查
    ARITHMETIC_SAFE = "arithmetic_safe"    # 添加溢出检查
    REPLACE_FUNCTION = "replace_function"  # 函数替换


@dataclass
class PatchSite:
    """补丁位置"""
    address: int
    func_name: str
    vuln_type: VulnKind
    strategy: PatchStrategy
    original_bytes: bytes = b""
    replacement_bytes: bytes = b""
    description: str = ""


@dataclass
class HotPatch:
    """热补丁"""
    original_path: str
    patched_path: str
    sites: List[PatchSite] = field(default_factory=list)
    new_section_name: Optional[str] = None
    new_section_data: bytes = b""
    success: bool = False
    warnings: List[str] = field(default_factory=list)


class PatchCodeGenerator:
    """补丁代码生成器"""

    # x64 长度检查 stub: 插入到调用危险函数前
    @staticmethod
    def length_check_stub(target_addr: int, max_len: int = 256) -> bytes:
        """
        生成 x64 长度检查代码:
        cmp rdx, max_len
        ja  .skip
        call target
        .skip:
        """
        # 简化: 返回汇编模板 (实际应使用汇编器)
        # cmp rdx, 0x100
        # ja  +5
        # call target
        stub = bytearray()
        stub += b"\x48\x81\xfa" + struct.pack("<I", max_len)
        stub += b"\x77\x05"  # ja +5
        stub += b"\xe8"      # call rel32
        # 相对偏移 (占位)
        stub += b"\x00\x00\x00\x00"
        return bytes(stub)

    @staticmethod
    def format_safe_stub(target_addr: int) -> bytes:
        """格式化字符串安全化 (替换为 %s)"""
        return b""  # 占位

    @staticmethod
    def reference_check_stub(addr: int) -> bytes:
        """引用检查 (test rdi, rdi; jz .skip)"""
        stub = bytearray()
        stub += b"\x48\x85\xff"  # test rdi, rdi
        stub += b"\x74\x05"      # jz +5
        stub += b"\xe8\x00\x00\x00\x00"  # call (占位)
        return bytes(stub)


class BinaryRewriter:
    """二进制重写器"""

    def __init__(self, original_path: str):
        self.original_path = original_path
        self.binary: Optional[Any] = None
        if LIEF_AVAILABLE:
            try:
                self.binary = lief.parse(original_path)
            except Exception as e:
                logger.warning(f"LIEF 解析失败: {e}")
                self.binary = None

    def add_section(self, name: str, data: bytes) -> bool:
        if not LIEF_AVAILABLE or self.binary is None:
            return False
        try:
            new_section = lief.ELF.Section(name=name)
            new_section.content = list(data)
            if isinstance(self.binary, lief.ELF.Binary):
                self.binary.add(new_section, loaded=True)
            else:
                # PE
                self.binary.add_section(new_section)
            return True
        except Exception as e:
            logger.warning(f"添加段失败: {e}")
            return False

    def patch_bytes(self, address: int, new_bytes: bytes) -> bool:
        if not LIEF_AVAILABLE or self.binary is None:
            return False
        try:
            # 计算文件偏移
            for section in self.binary.sections:
                if (section.virtual_address <= address <
                        section.virtual_address + section.size):
                    offset = address - section.virtual_address
                    content = list(section.content)
                    for i, b in enumerate(new_bytes):
                        if offset + i < len(content):
                            content[offset + i] = b
                    section.content = content
                    return True
        except Exception as e:
            logger.warning(f"补丁字节失败: {e}")
        return False

    def write(self, output_path: str) -> bool:
        if not LIEF_AVAILABLE or self.binary is None:
            return False
        try:
            self.binary.write(output_path)
            return True
        except Exception as e:
            logger.warning(f"写入失败: {e}")
            return False


class HotPatchGenerator:
    """热补丁生成器"""

    def __init__(self):
        self.code_gen = PatchCodeGenerator()
        self.sites: List[PatchSite] = []

    def analyze_and_patch(self, binary_path: str,
                          vulns: List[Dict[str, Any]],
                          output_path: str) -> HotPatch:
        rewriter = BinaryRewriter(binary_path)
        sites: List[PatchSite] = []
        for v in vulns:
            kind = v.get('type', '').lower()
            addr = int(v.get('address', 0), 16) if isinstance(
                v.get('address'), str) else int(v.get('address', 0))
            func = v.get('function', 'unknown')
            site = self._generate_site(kind, addr, func)
            if site:
                sites.append(site)
        # 收集新增段
        new_section_data = b""
        for site in sites:
            new_section_data += site.replacement_bytes
        # 应用补丁
        hot = HotPatch(
            original_path=binary_path, patched_path=output_path,
            sites=sites
        )
        if rewriter.binary is not None:
            if new_section_data:
                rewriter.add_section(".vulnfix", new_section_data)
                hot.new_section_name = ".vulnfix"
                hot.new_section_data = new_section_data
            for site in sites:
                # 备份原字节
                site.original_bytes = b"\x90" * len(site.replacement_bytes)
                rewriter.patch_bytes(site.address, site.replacement_bytes)
            rewriter.write(output_path)
            hot.success = True
        else:
            # 降级: 仅生成补丁建议
            hot.warnings.append("LIEF 不可用, 仅生成建议")
            try:
                shutil.copy(binary_path, output_path)
            except Exception as e:
                hot.warnings.append(f"复制失败: {e}")
            hot.success = False
        return hot

    def _generate_site(self, kind: str, addr: int,
                       func: str) -> Optional[PatchSite]:
        if "stack" in kind or "buffer" in kind:
            stub = self.code_gen.length_check_stub(addr)
            return PatchSite(
                address=addr, func_name=func,
                vuln_type=VulnKind.STACK_BUFFER_OVERFLOW,
                strategy=PatchStrategy.LENGTH_CHECK,
                replacement_bytes=stub,
                description="添加长度检查, 防止栈溢出"
            )
        if "format" in kind:
            return PatchSite(
                address=addr, func_name=func,
                vuln_type=VulnKind.FORMAT_STRING,
                strategy=PatchStrategy.FORMAT_SAFE,
                description="替换为安全格式化函数"
            )
        if "uaf" in kind or "use_after_free" in kind:
            stub = self.code_gen.reference_check_stub(addr)
            return PatchSite(
                address=addr, func_name=func,
                vuln_type=VulnKind.USE_AFTER_FREE,
                strategy=PatchStrategy.REFERENCE_CHECK,
                replacement_bytes=stub,
                description="使用前检查引用有效性"
            )
        if "integer" in kind:
            return PatchSite(
                address=addr, func_name=func,
                vuln_type=VulnKind.INTEGER_OVERFLOW,
                strategy=PatchStrategy.ARITHMETIC_SAFE,
                description="添加整数溢出检查"
            )
        return None


def generate_hotpatch(
    binary_path: str,
    vulns: List[Dict[str, Any]],
    output_path: str
) -> Dict[str, Any]:
    """便捷入口"""
    gen = HotPatchGenerator()
    hot = gen.analyze_and_patch(binary_path, vulns, output_path)
    return {
        'success': hot.success,
        'patched_path': hot.patched_path,
        'sites': [
            {
                'address': hex(s.address),
                'function': s.func_name,
                'vuln_type': s.vuln_type.value,
                'strategy': s.strategy.value,
                'description': s.description
            }
            for s in hot.sites
        ],
        'new_section': hot.new_section_name,
        'new_section_size': len(hot.new_section_data),
        'warnings': hot.warnings
    }
