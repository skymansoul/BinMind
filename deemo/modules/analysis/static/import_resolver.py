# PE/ELF导入函数调用增强器: 解析间接call目标为函数名

import os
import re
from typing import Dict, List, Optional, Tuple

from .disasm_util import resolve_rip_relative, extract_func_name


def _resolve_pe_imports(binary_path: str) -> Dict[int, str]:
    """解析PE导入表, 返回 {IAT虚拟地址 → 函数名}."""
    try:
        from modules.vuln.detection.plt_resolver import resolve_imports
        return resolve_imports(binary_path)
    except Exception:
        return {}


def _resolve_elf_plt(binary_path: str) -> Dict[int, str]:
    """解析ELF PLT表, 返回 {PLT入口地址 → 函数名}."""
    import subprocess
    mapping: Dict[int, str] = {}
    try:
        out = subprocess.run(
            ["objdump", "-d", "-M", "intel", binary_path],
            capture_output=True, timeout=30
        ).stdout.decode("utf-8", errors="replace")

        # 匹配 PLT stub: <funcname@plt>:
        current_addr = 0
        current_name = ""
        for line in out.split("\n"):
            line = line.strip()
            if "@plt>:" in line.lower() or "@plt>:" in line:
                m = re.search(r'<([^>]+@plt)>', line)
                if m:
                    try:
                        addr = int(line.split()[0].rstrip(":"), 16)
                        current_addr = addr
                        current_name = m.group(1).split("@")[0]
                        mapping[addr] = current_name
                    except (ValueError, IndexError):
                        pass
                    continue
            # PLT stub内 jmp [rip+...] 的目标地址
            if current_addr and "jmp" in line.lower() and "rip" in line.lower():
                # 记录PLT stub到GOT的映射
                pass
    except Exception:
        pass
    return mapping


def resolve_call_targets(binary_path: str,
                         instructions: List[dict],
                         file_format: str) -> List[dict]:
    """增强指令序列: 将间接call的目标地址替换为函数名.

    对PE: 解析IAT, 将 call <IAT_addr> 改写为 call <funcname>
    对ELF: 解析PLT, 将 call <PLT_addr> 改写为 call <funcname@plt>
    """
    import_map: Dict[int, str] = {}

    if "pei" in (file_format or "").lower():
        import_map = _resolve_pe_imports(binary_path)
    else:
        import_map = _resolve_elf_plt(binary_path)

    if not import_map:
        return instructions

    # 也解析 objdump 已标注的 <funcname> 格式
    enhanced = []
    for ins in instructions:
        mnem = ins.get("mnemonic", "").lower()
        if mnem != "call":
            enhanced.append(ins)
            continue

        ops = ins.get("operands", [])
        if not ops:
            enhanced.append(ins)
            continue

        target = ops[0]
        addr = ins.get("address", 0)

        # 1. 若objdump已标注 <funcname>, 直接用
        if "<" in target and ">" in target:
            enhanced.append(ins)
            continue

        # 2. RIP相对: call [rip+0x...] 或 call 0xADDR
        target_addr = _extract_call_target(target, addr, ins)
        if target_addr is not None and target_addr in import_map:
            func_name = import_map[target_addr]
            new_ins = dict(ins)
            new_ins["operands"] = [f"<{func_name}>"]
            enhanced.append(new_ins)
            continue

        # 3. 直接地址匹配
        try:
            direct_addr = int(target.strip(), 16)
            if direct_addr in import_map:
                func_name = import_map[direct_addr]
                new_ins = dict(ins)
                new_ins["operands"] = [f"<{func_name}>"]
                enhanced.append(new_ins)
                continue
        except (ValueError, TypeError):
            pass

        enhanced.append(ins)

    return enhanced


def _extract_call_target(operand: str, ins_addr: int,
                         ins: dict) -> Optional[int]:
    """从call操作数提取目标地址.

    格式: "rip+0x1234" → 解析RIP相对
         "0x1400032a0" → 直接地址
         "rax" → 间接寄存器, 无法确定
    """
    target = operand.strip().lower()

    # 直接地址
    try:
        return int(target, 16)
    except ValueError:
        pass

    # RIP相对: call [rip+0x...]
    if "rip" in target:
        rip_addr = resolve_rip_relative(
            {"mnemonic": "call", "operands": [target]}, target, ins_addr)
        return rip_addr

    return None


__all__ = ["resolve_call_targets"]
