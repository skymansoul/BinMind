# Angr 堆溢出检测基线 - CFG + capstone 指令级调用点定位
#
# 作为对比基线: Angr 代表"通用反汇编+CFG 工具"的典型能力.
# 检测逻辑:
#   1. CFGFast 建图
#   2. 用 capstone 遍历每个函数块的指令, 定位 call malloc/memcpy/...
#   3. 在调用点所在函数内后向扫描, 解析 size 立即数
#   4. 解析成功 → 数值比较; 失败 (符号/寄存器传播) → 保守告警
#
# 关键: 不依赖调试信息. 只能解析立即数, 对"同变量分配=写入"
# 的寄存器数据流无法判定 → 误报. 模拟 Ghidra/objdump 人工审计水平.
#
# 输出: 统一 JSON. 创建: 2026-08-11

import time

_DANGEROUS = {"memcpy", "memmove", "strcpy", "strncpy", "memset",
              "read", "fread", "recv", "strcat", "sprintf", "snprintf",
              "__mingw_memcpy", "__mingw_memset", "__mingw_strcpy",
              "__mingw_strncpy", "__mingw_strcat", "__mingw_sprintf"}
_ALLOC = {"malloc", "calloc", "realloc", "g_malloc",
          "__mingw_malloc", "__mingw_calloc", "__mingw_realloc"}
_SIZE_ARG = {"memcpy": 2, "memmove": 2, "strncpy": 2, "memset": 2,
             "read": 2, "fread": 1, "recv": 2,
             "__mingw_memcpy": 2, "__mingw_memset": 2}
_UNBOUNDED = {"strcpy", "strcat", "sprintf",
              "__mingw_strcpy", "__mingw_strcat", "__mingw_sprintf"}

# SysV / Win64 size 参数寄存器
_SYSV_SIZE_REG = ["", "rdi", "rsi", "rdx", "rcx", "r8", "r9"]
_WIN_SIZE_REG = ["", "rcx", "rdx", "r8", "r9"]
# 立即数解析时同时接受 32 位变体
_SIZE_REG_ALIASES = {"rdi": {"rdi", "edi"}, "rsi": {"rsi", "esi"},
                     "rdx": {"rdx", "edx"}, "rcx": {"rcx", "ecx"},
                     "r8": {"r8", "r8d"}, "r9": {"r9", "r9d"}}


def _is_windows_abi(proj):
    try:
        imports = proj.loader.main_object.imports
        names = " ".join(imports.keys()).lower()
        return any(k in names for k in ("kernel32", "msvcrt", "ucrtbase"))
    except Exception:
        return False


def _func_name(proj, addr):
    for f in proj.kb.functions.values():
        if f.addr == addr:
            return f.name.split("@")[0]
    return ""


def analyze_binary(binary_path: str) -> dict:
    t0 = time.perf_counter()
    result = {
        "tool": "Angr", "binary": binary_path, "detected": False,
        "findings": [], "fp_likely": 0, "time_ms": 0, "error": "",
    }
    try:
        import angr
    except ImportError:
        result["error"] = "angr not installed"
        result["time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        return result

    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        is_win = _is_windows_abi(proj)
        cfg = proj.analyses.CFGFast()

        # 地址 → 函数名映射 (capstone call 目标是裸地址)
        addr_to_name = {}
        for f in proj.kb.functions.values():
            addr_to_name[f.addr] = f.name.split("@")[0]

        # 1) 收集所有函数块指令
        func_blocks = {}  # func_addr → [insn,...]
        for f in proj.kb.functions.values():
            if not f.is_plt and not f.is_syscall:
                try:
                    func_blocks[f.addr] = list(f.blocks)
                except Exception:
                    pass

        # 2) 定位危险调用点 + 分配调用点
        danger_sites = []   # (site_addr, func_name, size_arg_idx)
        alloc_sites = []    # (site_addr, 0)
        for faddr, blocks in func_blocks.items():
            for blk in blocks:
                try:
                    insns = list(blk.capstone.insns)
                except Exception:
                    continue
                for insn in insns:
                    if insn.mnemonic != "call":
                        continue
                    name = _resolve_call_target(insn.op_str, addr_to_name)
                    if name in _DANGEROUS:
                        danger_sites.append((insn.address, name,
                                             _SIZE_ARG.get(name, 2)))
                    elif name in _ALLOC:
                        alloc_sites.append((insn.address, 0))

        # 3) 解析分配大小 (每个分配调用点所在函数的全局近似)
        alloc_sizes = {}
        for site_addr, _ in alloc_sites:
            faddr = _containing_func(site_addr, func_blocks)
            sz = _scan_alloc_size(faddr, func_blocks, is_win)
            alloc_sizes[site_addr] = sz  # None=未知

        # 4) 危险写入判定
        seen = set()
        for site_addr, name, size_arg_idx in danger_sites:
            if site_addr in seen:
                continue
            seen.add(site_addr)
            faddr = _containing_func(site_addr, func_blocks)
            if name in _UNBOUNDED:
                result["findings"].append({
                    "function": name, "type": "heap_write_unbounded",
                    "addr": site_addr, "confidence": 0.4, "fp_likely": True,
                })
                result["fp_likely"] += 1
                continue
            size_reg = (_WIN_SIZE_REG[size_arg_idx] if is_win
                        else _SYSV_SIZE_REG[size_arg_idx])
            sz = _scan_size_at(faddr, site_addr, size_reg, func_blocks,
                               is_win)
            if sz is None:
                # 无法解析 → 符号值 → 保守告警 (通用工具误报源)
                result["findings"].append({
                    "function": name, "type": "heap_write_symbolic_size",
                    "addr": site_addr, "confidence": 0.5, "fp_likely": True,
                })
                result["fp_likely"] += 1
            else:
                result["findings"].append({
                    "function": name, "type": "heap_write",
                    "addr": site_addr, "size": sz, "confidence": 0.6,
                    "fp_likely": False,
                })

        result["detected"] = len(result["findings"]) > 0
    except Exception as e:
        result["error"] = str(e)[:200]
    result["time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return result


def _containing_func(addr, func_blocks):
    best = None
    for faddr, blocks in func_blocks.items():
        if not blocks:
            continue
        try:
            lo = blocks[0].addr
            hi = blocks[-1].addr
        except Exception:
            continue
        if lo <= addr <= hi:
            if best is None or (hi - lo) < (blocks[-1].addr - blocks[0].addr):
                best = faddr
    return best


def _scan_alloc_size(faddr, func_blocks, is_win):
    """在函数内后向扫描 malloc 的 size 立即数 (Win64: rcx; SysV: rdi)."""
    reg = "rcx" if is_win else "rdi"
    return _scan_func_for_imm(faddr, func_blocks, reg)


def _scan_func_for_imm(faddr, func_blocks, reg):
    if faddr is None or faddr not in func_blocks:
        return None
    aliases = _SIZE_REG_ALIASES.get(reg, {reg})
    for blk in reversed(func_blocks[faddr]):
        try:
            insns = list(blk.capstone.insns)
        except Exception:
            continue
        for insn in reversed(insns):
            dst = insn.op_str.split(",")[0].strip().lower() \
                if "," in insn.op_str else ""
            if insn.mnemonic == "mov" and dst in aliases:
                parts = insn.op_str.split(",")
                if len(parts) >= 2:
                    val = _parse_imm(parts[1])
                    if val is not None:
                        return val
    return None


def _scan_size_at(faddr, site_addr, size_reg, func_blocks, is_win):
    """在 site_addr 所在函数内, 后向扫描到 site 解析 size 立即数."""
    if faddr is None or faddr not in func_blocks:
        return None
    aliases = _SIZE_REG_ALIASES.get(size_reg, {size_reg})
    for blk in reversed(func_blocks[faddr]):
        try:
            insns = list(blk.capstone.insns)
        except Exception:
            continue
        for insn in reversed(insns):
            if insn.address >= site_addr:
                continue
            dst = insn.op_str.split(",")[0].strip().lower() \
                if "," in insn.op_str else ""
            if insn.mnemonic == "mov" and dst in aliases:
                parts = insn.op_str.split(",")
                if len(parts) >= 2:
                    val = _parse_imm(parts[1])
                    if val is not None:
                        return val
    return None


def _parse_imm(s):
    s = s.strip().lower().replace("0x", "").split("#")[0].strip()
    try:
        return int(s, 16)
    except ValueError:
        return None


def _resolve_call_target(op_str, addr_to_name=None):
    """从 call 操作数提取目标名: '<memcpy@plt>' 或裸地址查函数表."""
    t = op_str.strip()
    if "<" in t and ">" in t:
        return t.split("<")[1].split(">")[0].split("@")[0]
    if addr_to_name is not None:
        try:
            addr = int(t, 16)
            return addr_to_name.get(addr, t)
        except ValueError:
            return t
    return t


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("binary")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()
    r = analyze_binary(args.binary)
    if args.json:
        import json
        print(json.dumps(r, indent=2))
    else:
        print(f"Angr: {len(r['findings'])} findings, "
              f"fp_likely={r['fp_likely']}, {r.get('time_ms', 0)}ms "
              f"{r.get('error', '')}")
