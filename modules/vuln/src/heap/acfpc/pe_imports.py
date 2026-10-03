"""PE 导入表解析 — 无符号二进制下的分配器识别.

  - stripped 二进制无符号名, call 目标退化为裸地址. 通过 objdump -p
    解析 IAT 槽→名字映射, 再在反汇编流中匹配 jmp [rip+disp] thunk,
    建立 thunk 地址→名字映射. 这是"不依赖调试信息"的关键机制.
  - objdump -p 的 vma 列为 RVA, 需加 ImageBase (objdump -f 读取).
  - thunk 支持 rex.W 前缀 (48 ff 25) 与普通 ff 25 形式.
"""

import re
import subprocess
from typing import Dict


def _image_base(binary_path: str) -> int:
    """MinGW-W64 PE 默认 ImageBase 0x140000000.

    objdump -f 的 start address 是 entry point 而非 ImageBase,
    不据此推导."""
    # TODO: 从 PE 可选头 ImageBase 字段解析, 覆盖非 MinGW 链接器
    return 0x140000000


def parse_imports(binary_path: str) -> Dict[int, str]:
    """objdump -p 解析导入表 → {IAT_VA: name}."""
    result: Dict[int, str] = {}
    try:
        proc = subprocess.run(['objdump', '-p', binary_path],
                              capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            return result
    except Exception:
        return result
    base = _image_base(binary_path)
    in_imports = False
    for line in proc.stdout.splitlines():
        s = line.strip()
        if s.startswith('DLL Name:'):
            in_imports = True
            continue
        if not in_imports:
            continue
        m = re.match(r'^([0-9a-fA-F]{6,16})\s+\S+\s+\S+\s+(\S+)', s)
        if m:
            try:
                rva = int(m.group(1), 16)
                result[rva + base] = m.group(2)
            except ValueError:
                continue
    return result


def parse_thunks(asm_text: str) -> Dict[int, int]:
    """反汇编文本中的 jmp [rip+disp] thunk → {thunk_addr: iat_va}.

    IAT 地址优先取 objdump 注释中的绝对地址, 回退 rip+disp 计算."""
    thunks: Dict[int, int] = {}
    pattern = re.compile(
        r'^\s*([0-9a-fA-F]+):\s+(?:48\s+)?ff\s+25[0-9a-fA-F ]*'
        r'\s+jmp\s+QWORD PTR \[rip\+0x([0-9a-fA-F]+)\]\s*'
        r'(?:#\s+0x([0-9a-fA-F]+))?',
        re.IGNORECASE | re.M)
    for m in pattern.finditer(asm_text):
        try:
            thunk = int(m.group(1), 16)
            disp = int(m.group(2), 16)
            if m.group(3):
                iat = int(m.group(3), 16)
            else:
                iat = thunk + 6 + disp
            thunks[thunk] = iat
        except ValueError:
            continue
    return thunks


def build_import_map(binary_path: str, asm_text: str) -> Dict[int, str]:
    """thunk 地址 → 导入函数名."""
    iat_names = parse_imports(binary_path)
    thunks = parse_thunks(asm_text)
    result: Dict[int, str] = {}
    for thunk, iat in thunks.items():
        name = iat_names.get(iat)
        if name:
            result[thunk] = name
    return result
