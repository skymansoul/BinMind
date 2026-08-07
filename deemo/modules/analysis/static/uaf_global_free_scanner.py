# UAF 全局变量延迟 Free 检测器.
#
# 核心问题: 全局变量 g = malloc(); func_A(); free(g); func_B(); g[0];
# 当 free(g) 在独立函数中, 指令流顺序可能导致 free 先于 malloc 出现,
# 或 free 时 _addr_to_obj 尚未建立映射 → 漏检.
#
# 本模块在 finalize 阶段做后处理扫描:
#   1. 收集所有 free(g) 调用 (通过 RIP 相对寻址识别全局变量)
#   2. 检查 free 是否标记了对应对象 — 未标记则补标记
#   3. 检查 free 后是否存在全局变量解引用 → UAF
#
# 创建: 2026-05-28

from typing import Dict, List, Optional, Set, Tuple

from .disasm_util import resolve_rip_relative, extract_func_name, norm_reg
from .uaf_global_deref import GlobalDerefChecker


class GlobalFreeScanner:
    """全局变量 free 后处理扫描器.

    在 finalize 阶段补充检测:
      - 全局变量对象的延迟 free 标记
      - 全局变量在 free 后的解引用 (跨函数 UAF)
    """

    _FREE_FUNCS = {"free", "_ZdlPv", "_ZdaPv", "operator_delete",
                   "g_free", "ExFreePool", "__builtin_free"}
    _DANGEROUS_DEREF_MNEMS = {"movzx", "movsx", "movsxd", "mov", "lea",
                              "cmp", "test", "add", "sub"}

    def __init__(self, detector):
        self._det = detector
        self._deref_checker = GlobalDerefChecker(detector)

    def scan(self, instructions: List[dict]) -> List[dict]:
        """扫描全局变量的 free→use 模式, 返回新发现 findings.

        步骤:
          1. 构建全局变量地址→obj_id 映射 (从 malloc 后的 store 指令)
          2. 标记所有 free(g) 调用的对象为 freed
          3. 检查 free 后的全局变量解引用
        """
        new_findings: List[dict] = []
        addr_to_ins: Dict[int, dict] = {}
        addr_to_idx: Dict[int, int] = {}

        for idx, ins in enumerate(instructions):
            a = ins.get("address", 0)
            addr_to_ins[a] = ins
            addr_to_idx[a] = idx

        # 阶段1: 构建全局变量地址→对象ID映射
        # 已在 detector._addr_to_obj 中, 但可能不完整
        # 补充: 扫描 mov [rip+global], rax (malloc 返回值存储)
        global_to_obj: Dict[int, int] = dict(self._det._addr_to_obj)

        for ins in instructions:
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            addr = ins.get("address", 0)
            if mnem == "mov" and len(ops) >= 2:
                dst_op = ops[0].strip()
                if "[" in dst_op.lower() and "rip" in dst_op.lower():
                    abs_addr = resolve_rip_relative(ins, dst_op, addr)
                    if abs_addr is not None:
                        src_reg = norm_reg(ops[1].strip())
                        oid = self._det._reg_to_obj.get(src_reg) if src_reg else None
                        # _reg_to_obj 可能已被清空, 查 _objects 中 alloc_addr 最近的
                        if oid is None:
                            # 通过 _addr_to_obj 已有映射补充
                            oid = global_to_obj.get(abs_addr)
                        if oid is not None and abs_addr not in global_to_obj:
                            global_to_obj[abs_addr] = oid

        # 阶段2: 标记所有 free(g) 调用
        # 同时记录 free 时全局变量指向的 obj_id (通过回溯指令流构建)
        free_sites: List[Tuple[int, int, int]] = []  # (free_addr, global_addr, obj_id)

        for idx, ins in enumerate(instructions):
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            addr = ins.get("address", 0)
            if mnem not in ("call", "jmp") or not ops:
                continue
            callee = extract_func_name(ops[0])
            if callee not in self._FREE_FUNCS:
                continue
            if not self._det._is_user_code(addr):
                continue

            global_addr = self._trace_free_to_global(instructions, idx, addr)
            if global_addr is not None:
                # 构建free时的全局变量→obj_id映射: 扫描free之前的store指令
                oid = self._find_obj_at_free(instructions, idx, global_addr)
                if oid is not None and oid in self._det._objects:
                    obj = self._det._objects[oid]
                    if addr not in obj.freed_at:
                        obj.freed_at.append(addr)
                    free_sites.append((addr, global_addr, oid))

        # 阶段3: 检查 free 后的全局变量解引用
        for free_addr, global_addr, oid in free_sites:
            obj = self._det._objects.get(oid)
            if not obj:
                continue

            # 从free后第一条用户指令开始一次性扫描50条
            start_idx = None
            for idx, ins in enumerate(instructions):
                addr = ins.get("address", 0)
                if addr > free_addr and self._det._is_user_code(addr):
                    start_idx = idx
                    break
            if start_idx is None:
                continue

            deref_addr = self._deref_checker.check(
                instructions, start_idx, global_addr, free_addr, oid)
            if deref_addr is not None:
                gap = deref_addr - free_addr
                if self._det._path_analyzer.are_mutually_exclusive(free_addr, deref_addr):
                    continue
                finding = {
                    "type": "use_after_free",
                    "address": deref_addr,
                    "obj_id": oid,
                    "freed_at": free_addr,
                    "instr_gap": gap,
                    "deref_reg": "global",
                    "severity": "critical" if gap > 100 else "high",
                }
                new_findings.append(finding)

        return new_findings

    def _trace_free_to_global(self, instructions: List[dict],
                              call_idx: int, call_addr: int) -> Optional[int]:
        """回溯 free() 的参数到全局变量地址.

        模式: mov rax,[rip+global]; mov rcx,rax; call free
        """
        for j in range(call_idx - 1, max(-1, call_idx - 10), -1):
            ins = instructions[j]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            addr = ins.get("address", 0)
            if mnem == "call":
                break
            if mnem in ("mov", "movzx", "movsx") and len(ops) >= 2:
                dst = norm_reg(ops[0].strip())
                src_raw = ops[1].strip()
                if dst == "rcx" and "rip" in src_raw.lower():
                    return resolve_rip_relative(ins, src_raw, addr)
                # mov rax, [rip+global]; mov rcx, rax; call free
                if "rip" in src_raw.lower() and "[" in src_raw.lower():
                    return resolve_rip_relative(ins, src_raw, addr)
        return None

    def _find_obj_at_free(self, instructions: List[dict],
                          free_idx: int, global_addr: int) -> Optional[int]:
        """确定free时全局变量指向的obj_id.

        反汇编按地址排序, 函数布局可能与执行顺序不同:
          cleanup(0x760) → free(g)    但setup(0x77a) → malloc + store 在后面
        
        策略: 双向扫描找 mov [rip+global], reg,
        再追踪reg来源到call malloc, 通过alloc_addr匹配_objects.
        """
        store_idx, store_reg = self._find_store_to_global(
            instructions, free_idx, global_addr)
        if store_reg is None:
            return self._det._addr_to_obj.get(global_addr)
        oid = self._trace_reg_to_alloc(instructions, store_idx, store_reg)
        return oid if oid is not None else \
            self._det._addr_to_obj.get(global_addr)

    def _find_store_to_global(self, instructions: List[dict],
                              free_idx: int,
                              global_addr: int) -> Tuple[Optional[int], Optional[str]]:
        """双向扫描找 mov [rip+global_addr], reg — 回溯优先, 前向兜底."""
        # 向后: free之前同函数的store
        for j in range(free_idx - 1, max(-1, free_idx - 30), -1):
            ins = instructions[j]
            if ins.get("mnemonic", "").lower() == "ret":
                break
            si, sr = self._match_store(ins, global_addr)
            if si is not None:
                return j, sr
        # 前向: free之后(跨函数, setup在cleanup后)
        for j in range(free_idx + 1, min(len(instructions), free_idx + 200)):
            ins = instructions[j]
            si, sr = self._match_store(ins, global_addr)
            if si is not None:
                return j, sr
        return None, None

    def _match_store(self, ins: dict,
                     global_addr: int) -> Tuple[bool, Optional[str]]:
        """检查指令是否为 mov [rip+global], reg."""
        if ins.get("mnemonic", "").lower() not in ("mov", "movzx"):
            return False, None
        ops = ins.get("operands", [])
        if len(ops) < 2:
            return False, None
        dst_raw = ops[0].strip()
        if "[" not in dst_raw.lower() or "rip" not in dst_raw.lower():
            return False, None
        gaddr = resolve_rip_relative(ins, dst_raw, ins.get("address", 0))
        if gaddr != global_addr:
            return False, None
        return True, norm_reg(ops[1].strip())

    def _trace_reg_to_alloc(self, instructions: List[dict],
                            store_idx: int,
                            store_reg: str) -> Optional[int]:
        """从store指令追踪reg来源到call malloc."""
        search_reg = store_reg
        for k in range(store_idx - 1, max(-1, store_idx - 30), -1):
            ins2 = instructions[k]
            mnem2 = ins2.get("mnemonic", "").lower()
            ops2 = ins2.get("operands", [])
            if mnem2 == "call" and ops2:
                func2 = extract_func_name(ops2[0])
                if func2 in self._FREE_FUNCS:
                    break
                if func2 in self._det.ALLOC_FUNCS:
                    alloc_addr = ins2.get("address", 0)
                    for oid, obj in self._det._objects.items():
                        if obj.alloc_addr == alloc_addr:
                            return oid
                    break
            if mnem2 == "mov" and len(ops2) >= 2:
                d2 = norm_reg(ops2[0].strip())
                s2 = norm_reg(ops2[1].strip())
                if d2 == search_reg and s2 in ("rax", "eax"):
                    search_reg = "rax"
        return None


__all__ = ["GlobalFreeScanner"]
