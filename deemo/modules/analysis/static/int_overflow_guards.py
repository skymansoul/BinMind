# 整数溢出守卫识别 mixin — 溢出检查模式检测
#
# 职责: 识别编译器生成的溢出检查守卫, 判定溢出操作是否已检查.
#
# 守卫模式 (safe 样本的溢出检查编译形态):
#   a) shr 回除校验: sz=count*4; if(sz/4 != count) reject
#   b) mul/imul 后 jno (jump if no overflow)
#   c) add/sub 后 jae/jno/jnc (进位标志检查加法溢出)
#   d) cmp 大常量边界: len > UINT32_MAX-offset 等
#   e) shr 高位检查: count>>60 后 jne (乘法溢出预检查)
#
# 判定原则: 仅当溢出检查成立 (危险调用仅在安全路径可达) 才标记
# checked; 无法证明安全时保守保留告警, 避免误杀真实漏洞.
# 创建: 2024-04-25

import re
from typing import Optional

# jno/jnc/jae: 跳转目标是安全路径 (无溢出才跳)
# jne: 跳转目标是拒绝路径, fallthrough 是安全路径
_GUARD_JUMP_OK = ("jno", "jnc", "jae", "jbe")
_GUARD_JUMP_REJECT = ("jne",)


class IntOverflowGuardMixin:
    """溢出守卫识别, 由 IntegerOverflowDetector 继承."""

    def apply_guard(self, mnem: str, ins: dict, ops) -> bool:
        """识别单条指令是否为溢出守卫, 标记 pending 中对应溢出已检查.

        返回 True 表示该指令是守卫跳转 (已处理).
        """
        # a) shr/sar 回除: 标记最近乘法或涉及寄存器
        if mnem in ("shr", "sar") and len(ops) >= 2:
            return self._apply_shr_guard(ins, ops)

        # b/c/d) cmp 比较守卫
        if mnem == "cmp" and len(ops) >= 2:
            return self._apply_cmp_guard(ops)

        # b/c/e) 守卫跳转
        if mnem in _GUARD_JUMP_OK + _GUARD_JUMP_REJECT:
            return self._apply_guard_jump(mnem, ins)

        return False

    def _apply_shr_guard(self, ins: dict, ops) -> bool:
        """shr/sar 回除校验: 乘法结果被右移回除."""
        dst_reg = self._normalize(ops[0])
        shr_regs = {dst_reg}
        for o in ops[1:]:
            r = self._normalize(o)
            if "[" not in r and r:
                shr_regs.add(r)
        for op in self._pending_ops[-8:]:
            if op.get("checked"):
                continue
            op_regs = {op.get("result_reg"), op.get("src1"),
                       op.get("src2")}
            if op_regs & shr_regs:
                op["_shr_seen"] = True
        # 回退: shr 紧跟的乘法 (lea/mul) 即被回除校验的溢出源
        if self._pending_ops:
            last = self._pending_ops[-1]
            if last.get("overflow_type") == "multiplication" \
                    and not last.get("_shr_seen") \
                    and not last.get("checked"):
                last["_shr_seen"] = True
        return True

    def _apply_cmp_guard(self, ops) -> bool:
        """cmp 比较守卫: 大常量边界 或 回除结果比较."""
        cmp_regs = set()
        for o in ops:
            r = self._normalize(o)
            if "[" not in r and r:
                cmp_regs.add(r)
        big_const = self._cmp_nonzero_big(ops)
        for op in self._pending_ops[-8:]:
            if op.get("checked"):
                continue
            if op.get("_shr_seen"):
                op["checked"] = True
                continue
            involved = {op.get("result_reg"), op.get("src1"),
                        op.get("src2")}
            if big_const and (involved & cmp_regs):
                op["checked"] = True
        return True

    def _apply_guard_jump(self, mnem: str, ins: dict) -> bool:
        """守卫跳转: jno/jae (安全路径跳转) 或 jne (拒绝路径跳转)."""
        if not self._pending_ops:
            return True
        has_shr = any(op.get("_shr_seen") for op in self._pending_ops)
        last_is_mul = self._pending_ops[-1].get("mnemonic") in ("mul", "imul")
        has_add = any(op.get("overflow_type") == "addition"
                      for op in self._pending_ops)
        guarded = has_shr or last_is_mul or \
            (has_add and mnem in _GUARD_JUMP_OK)
        if not guarded:
            return True
        target = self._extract_jump_target(ins)
        if mnem == "jne":
            ft = self._fallthrough_addr(ins)
            if ft is not None:
                self._jno_targets.append(ft)
        elif target is not None:
            self._jno_targets.append(target)
        for op in self._pending_ops:
            if op.get("overflow_type") in ("multiplication", "addition") \
                    and not op.get("checked"):
                op["checked"] = True
        return True

    @staticmethod
    def _cmp_nonzero_big(ops) -> bool:
        """cmp 是否含大常量 (>=2^16) 作为溢出边界.

        逻辑守卫 (如 sz<4096) 的阈值小, 不是溢出检查;
        误标会使真实 vuln (guard 后仍流向 malloc) 漏检.
        """
        for o in ops:
            s2 = o.strip().lower().replace("$", "")
            try:
                if s2.startswith("0x"):
                    v = int(s2, 16)
                elif s2.isdigit():
                    v = int(s2)
                else:
                    continue
                if v >= 0x10000:
                    return True
            except ValueError:
                continue
        return False

    def _fallthrough_addr(self, ins: dict) -> Optional[int]:
        """条件跳转的 fallthrough 地址 (下一指令)."""
        if not self._instructions:
            return None
        idx = self._ins_idx
        if idx + 1 < len(self._instructions):
            return self._instructions[idx + 1].get("address", 0)
        return None

    @staticmethod
    def _extract_jump_target(ins: dict) -> Optional[int]:
        """从条件跳转指令提取目标地址.

        objdump 格式: '140001796 <func+0x36>' -> 剥离注释后解析.
        """
        ops = ins.get("operands", [])
        if not ops:
            return None
        target = ops[0].strip()
        if "<" in target:
            target = target.split("<")[0].strip()
        target = target.lower().lstrip("%").replace("$", "")
        try:
            if target.startswith("0x"):
                return int(target, 16)
            return int(target, 16)
        except ValueError:
            return None


__all__ = ["IntOverflowGuardMixin"]
