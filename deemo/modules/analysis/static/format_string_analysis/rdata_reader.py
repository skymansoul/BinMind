"""二进制 .rdata/.rodata 读取器 — PE/ELF 只读数据段字符串提取.

零依赖 stdlib. PE (DOS→NT→section→.rdata) / ELF (header→sections→.rodata).
用于 objdump 级格式字符串分析: lea rcx,[rip+off] → .rdata 数据 → 说明符分类.
"""

import struct
import os
from typing import Optional, List, Tuple, Dict


class RdataReader:
    """PE/ELF 只读数据段读取器 — 从二进制文件提取 .rdata/.rodata 字符串.

    使用方式:
      reader = RdataReader("sample.exe")
      offset_in_rdata = 0x9830  # 来自 lea rcx, [rip+0x9830]
      fmt_str = reader.read_string_at_rva(offset_in_rdata)
      specifiers = RdataReader.classify_specifiers(fmt_str)
    """

    def __init__(self, binary_path: str):
        self._path = binary_path
        self._data: bytes = b""
        self._base_va: int = 0      # section 在内存中的基址 (VA)
        self._file_offset: int = 0  # section 在文件中的偏移
        self._size: int = 0
        self._fmt: str = ""         # "pe" | "elf"
        self._image_base: int = 0   # PE ImageBase (用于 VA→RVA 转换)
        with open(binary_path, "rb") as f:
            header = f.read(128)
            if header[:2] == b'MZ':
                self._fmt = "pe"
                self._parse_pe(f, header)
            elif header[:4] == b'\x7fELF':
                self._fmt = "elf"
                self._parse_elf(f, header)

    def _parse_pe(self, f, header: bytes):
        """解析 PE 格式, 定位 .rdata 段."""
        # DOS header → e_lfanew (at offset 60)
        e_lfanew = struct.unpack_from("<I", header, 60)[0]
        f.seek(e_lfanew)
        pe_sig = f.read(4)
        if pe_sig[:2] != b'PE':
            return
        # COFF header (20 bytes)
        coff = f.read(20)
        num_sections = struct.unpack_from("<H", coff, 2)[0]
        opt_header_size = struct.unpack_from("<H", coff, 16)[0]
        # Read optional header magic to determine PE32/PE32+
        opt_start = e_lfanew + 4 + 20
        f.seek(opt_start)
        magic = struct.unpack("<H", f.read(2))[0]
        # PE32+: ImageBase at offset 24 in optional header
        # PE32:  ImageBase at offset 28 in optional header
        if magic == 0x20b:  # PE32+
            f.seek(opt_start + 24)
            self._image_base = struct.unpack("<Q", f.read(8))[0]
        elif magic == 0x10b:  # PE32
            f.seek(opt_start + 28)
            self._image_base = struct.unpack("<I", f.read(4))[0]
        # Skip to section headers
        f.seek(e_lfanew + 4 + 20 + opt_header_size)
        for _ in range(num_sections):
            sh = f.read(40)
            name = sh[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
            if name == '.rdata':
                vsize = struct.unpack_from("<I", sh, 8)[0]
                self._base_va = struct.unpack_from("<I", sh, 12)[0]
                raw_size = struct.unpack_from("<I", sh, 16)[0]
                raw_ptr = struct.unpack_from("<I", sh, 20)[0]
                self._file_offset = raw_ptr
                self._size = min(vsize, raw_size) if raw_size else vsize
                f.seek(raw_ptr)
                self._data = f.read(self._size)
                return

    def _parse_elf(self, f, header: bytes):
        """解析 ELF64 格式, 定位 .rodata 段."""
        ei_class = header[4]  # 1=32bit, 2=64bit
        if ei_class == 2:  # 64-bit
            e_shoff = struct.unpack_from("<Q", header, 40)[0]
            e_shentsize = struct.unpack_from("<H", header, 58)[0]
            e_shnum = struct.unpack_from("<H", header, 60)[0]
            e_shstrndx = struct.unpack_from("<H", header, 62)[0]
        else:  # 32-bit
            e_shoff = struct.unpack_from("<I", header, 32)[0]
            e_shentsize = struct.unpack_from("<H", header, 46)[0]
            e_shnum = struct.unpack_from("<H", header, 48)[0]
            e_shstrndx = struct.unpack_from("<H", header, 50)[0]

        # Read all section headers
        f.seek(e_shoff)
        all_sh = f.read(e_shnum * e_shentsize)
        # Read section name string table
        strtab_sh_offset = e_shoff + e_shstrndx * e_shentsize
        if ei_class == 2:
            strtab_off = struct.unpack_from("<Q", all_sh, e_shstrndx * e_shentsize + 24)[0]
            strtab_size = struct.unpack_from("<Q", all_sh, e_shstrndx * e_shentsize + 32)[0]
        else:
            strtab_off = struct.unpack_from("<I", all_sh, e_shstrndx * e_shentsize + 16)[0]
            strtab_size = struct.unpack_from("<I", all_sh, e_shstrndx * e_shentsize + 20)[0]
        f.seek(strtab_off)
        strtab = f.read(strtab_size)

        # Iterate sections, find .rodata
        for i in range(e_shnum):
            if ei_class == 2:
                sh_offset_in_table = i * e_shentsize
                sh_name_idx = struct.unpack_from("<I", all_sh, sh_offset_in_table)[0]
                sh_type = struct.unpack_from("<I", all_sh, sh_offset_in_table + 4)[0]
                sh_addr = struct.unpack_from("<Q", all_sh, sh_offset_in_table + 16)[0]
                sh_file_off = struct.unpack_from("<Q", all_sh, sh_offset_in_table + 24)[0]
                sh_size = struct.unpack_from("<Q", all_sh, sh_offset_in_table + 32)[0]
            else:
                sh_offset_in_table = i * e_shentsize
                sh_name_idx = struct.unpack_from("<I", all_sh, sh_offset_in_table)[0]
                sh_type = struct.unpack_from("<I", all_sh, sh_offset_in_table + 4)[0]
                sh_addr = struct.unpack_from("<I", all_sh, sh_offset_in_table + 12)[0]
                sh_file_off = struct.unpack_from("<I", all_sh, sh_offset_in_table + 16)[0]
                sh_size = struct.unpack_from("<I", all_sh, sh_offset_in_table + 20)[0]
            # Get name from strtab
            name_end = strtab.find(b'\x00', sh_name_idx)
            name = strtab[sh_name_idx:name_end].decode('ascii', errors='ignore')
            if name == '.rodata' and sh_type != 0:
                self._base_va = sh_addr
                self._file_offset = sh_file_off
                self._size = sh_size
                f.seek(sh_file_off)
                self._data = f.read(sh_size)
                return

    @property
    def is_loaded(self) -> bool: return len(self._data) > 0

    @property
    def format(self) -> str: return self._fmt

# VA → 字符串读取

    def read_string_at_va(self, va: int, max_len: int = 256) -> Optional[str]:
        """在给定的绝对 VA (虚拟地址) 处读取字符串.
        自动转换为 RVA → section 内偏移 → 文件偏移."""
        if not self._data:
            return None
        if self._image_base and va >= self._image_base:
            rva = va - self._image_base
        else:
            rva = va
        rva_in_section = rva - self._base_va
        if rva_in_section < 0 or rva_in_section >= self._size:
            return None
        end = min(rva_in_section + max_len, self._size)
        raw = self._data[rva_in_section:end]
        null_pos = raw.find(b'\x00')
        if null_pos >= 0:
            raw = raw[:null_pos]
        try:
            return raw.decode('utf-8', errors='replace')
        except Exception:
            return raw.decode('ascii', errors='replace')

    def read_string_at_rva(self, rva: int, max_len: int = 256) -> Optional[str]:
        """在给定的 RVA (相对虚拟地址) 处读取字符串.
        若 ImageBase 已知, RVA = VA - ImageBase; 否则 RVA = section 内偏移."""
        if not self._data:
            return None
        if self._image_base and rva < self._image_base:
            # rva 是真正的 RVA, 不是绝对地址
            rva_in_section = rva - self._base_va
        elif self._image_base:
            # rva 是绝对 VA
            rva_in_section = (rva - self._image_base) - self._base_va
        else:
            rva_in_section = rva - self._base_va
        if rva_in_section < 0 or rva_in_section >= self._size:
            return None
        end = min(rva_in_section + max_len, self._size)
        raw = self._data[rva_in_section:end]
        null_pos = raw.find(b'\x00')
        if null_pos >= 0:
            raw = raw[:null_pos]
        try:
            return raw.decode('utf-8', errors='replace')
        except Exception:
            return raw.decode('ascii', errors='replace')

    def read_string_at_rip_offset(self, rip_offset: int,
                                  image_base: int = 0x140000000,
                                  code_section_base: int = 0x1000,
                                  max_len: int = 256) -> Optional[str]:
        """从 rip-relative 偏移计算实际字符串.

        lea rcx, [rip+off] → rip = 下条指令地址.
        """
        # rip_offset 是相对 rip 的偏移, 需要转换为 RVA
        # 简单模型: rip_offset 直接是 rdata 中的偏移
        # 更准确: objdump 地址 → RVA = addr - image_base
        if self._fmt == "pe":
            return self.read_string_at_rva(rip_offset, max_len)
        elif self._fmt == "elf":
            # ELF .rodata 在 objdump 中地址是绝对地址
            return self.read_string_at_rva(rip_offset, max_len)
        return None

# 格式说明符分类

    @staticmethod
    def classify_specifiers(fmt_str: str) -> Dict[str, List[str]]:
        """解析格式字符串, 按危险等级分类说明符.

        返回: {"write": [...], "leak": [...], "aslr_bypass": [...], "info": [...]}
        """
        result = {"write": [], "leak": [], "aslr_bypass": [], "info": []}
        if not fmt_str:
            return result
        i = 0
        current_spec = []
        while i < len(fmt_str):
            if fmt_str[i] == '%' and i + 1 < len(fmt_str):
                i += 1
                # 跳过 flags, width, precision, length
                spec_start = i
                while i < len(fmt_str) and fmt_str[i] in '#0- +\'IhljztLq':
                    i += 1
                # 读数字 (width/precision)
                while i < len(fmt_str) and fmt_str[i].isdigit():
                    i += 1
                if i < len(fmt_str) and fmt_str[i] == '.':
                    i += 1
                    while i < len(fmt_str) and fmt_str[i].isdigit():
                        i += 1
                # 类型字符
                if i < len(fmt_str):
                    c = fmt_str[i]
                    spec = fmt_str[spec_start - 1:i + 1]
                    if c == 'n':
                        result["write"].append(spec)
                    elif c in ('s', 'S'):
                        result["leak"].append(spec)
                    elif c in ('p', 'P'):
                        result["aslr_bypass"].append(spec)
                    elif c in ('x', 'X', 'lx', 'llx'):
                        result["info"].append(spec)
                    i += 1
                    continue
            i += 1
        return result

    @staticmethod
    def danger_score(fmt_str: str) -> float:
        """计算格式字符串的 CVSS 风格危险评分 (0.0-1.0).

        %n (write-what-where): +0.5, 每个额外 %n +0.1
        %s (info leak): +0.2 each
        %p (ASLR bypass): +0.15 each
        %x (stack leak): +0.05 each
        """
        c = RdataReader.classify_specifiers(fmt_str)
        score = 0.0
        n_count = len(c["write"])
        if n_count > 0:
            score += 0.5 + (n_count - 1) * 0.1
        score += len(c["leak"]) * 0.2
        score += len(c["aslr_bypass"]) * 0.15
        score += len(c["info"]) * 0.05
        return min(score, 1.0)


# smoke test
def _check():
    """验证 PE/ELF 解析 + 格式说明符分类."""
    import tempfile

    # 测试 1: 格式说明符分类
    r = RdataReader.classify_specifiers("hello %s: %n at %p → %x")
    assert len(r["write"]) == 1 and "%n" in r["write"][0], f"write:{r['write']}"
    assert len(r["leak"]) == 1, f"leak:{r['leak']}"
    assert len(r["aslr_bypass"]) == 1, f"aslr:{r['aslr_bypass']}"
    assert len(r["info"]) == 1, f"info:{r['info']}"

    # 测试 2: 危险评分
    s1 = RdataReader.danger_score("%s%s%n")  # 2 leaks + write
    assert s1 >= 0.85, f"high danger expected, got {s1}"
    s2 = RdataReader.danger_score("hello world")
    assert s2 == 0.0, f"zero danger expected, got {s2}"
    s3 = RdataReader.danger_score("value=%x, ptr=%p")
    assert 0.1 < s3 < 0.4, f"medium danger expected, got {s3}"

    # 测试 3: PE 解析 (创建一个最小的 PE 用于测试)
    # 注: 完整 PE/ELF 解析测试需要真实二进制文件, 此处仅验证分类逻辑
    # 真实二进制测试在 run_scanner.py 集成时进行

    print("[OK] rdata_reader")


if __name__ == "__main__":
    _check()
