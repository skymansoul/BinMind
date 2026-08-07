# analysis/stack_frame_model — 栈帧布局建模与 canary 交互分析
# 不依赖反汇编; 从源码模式推断栈帧结构, 建模 saved-RIP 距离和 canary 有效性。
from __future__ import annotations
from typing import Dict, List, Tuple, Optional
import re

# x86_64 典型栈帧布局 offset (从低地址到高地址):
# [local_bufs] [canary(8B)] [saved_RBP(8B)] [saved_RIP(8B)] [args...]
# i386: [local_bufs] [canary(4B)] [saved_EBP(4B)] [saved_EIP(4B)] [args...]

def estimate_frame_layout(code: str, arch: str = "x86_64") -> Dict:
    """从源码推断栈帧布局。返回 buffer 名→(size, offset_from_buf_to_rip) 的映射。"""
    ptr_sz = 8 if "64" in arch else 4
    canary_sz = ptr_sz
    saved_bp_sz = ptr_sz
    saved_ip_sz = ptr_sz

    bufs = _extract_stack_buffers(code)
    frame: Dict[str, Dict] = {}

    # 按声明顺序计算 offset (简化: 按源码出现顺序排列)
    sorted_bufs = sorted(bufs.items(), key=lambda x: x[1]["pos"])
    running_offset = 0  # 从低地址开始

    for name, info in sorted_bufs:
        sz = info["size"]
        is_vla = info["is_vla"]
        # buf 到 saved_RIP 的距离 = (后续所有buf的总大小) + canary + saved_bp + saved_ip
        # 简化: 假设所有 buf 都在 canary 之前, 按声明顺序排列
        frame[name] = {
            "size": sz,
            "is_vla": is_vla,
            "decl_order": info.get("order", 0),
        }

    # 计算每个 buf 之后还有多少字节到 saved_RIP
    # 累积: 从最后一个 buf 开始往回算
    distances = {}  # buf_name → bytes_after_this_buf_to_saved_RIP
    remaining = canary_sz + saved_bp_sz
    for name, info in reversed(sorted_bufs):
        distances[name] = remaining
        remaining += info["size"]

    for name in frame:
        frame[name]["bytes_to_saved_rip"] = distances.get(name, canary_sz + saved_bp_sz)
        frame[name]["canary_protected"] = _has_canary_in_scope(code, name)

    frame["_meta"] = {
        "arch": arch, "ptr_size": ptr_sz, "canary_size": canary_sz,
        "total_buffer_space": sum(b["size"] for b in frame.values() if "size" in b),
        "canary_present": _detect_canary_usage(code),
    }
    return frame

def _extract_stack_buffers(code: str) -> Dict:
    """提取栈上局部缓冲区: char buf[N], VLA, 以及 struct on stack。"""
    bufs = {}
    idx = 0
    # char name[SIZE];
    for m in re.finditer(r'char\s+(\w+)\s*\[\s*(\d+)\s*\]', code):
        bufs[m.group(1)] = {"size": int(m.group(2)), "is_vla": False,
                            "pos": m.start(), "order": idx}; idx += 1
    # char name[VAR]; (VLA 或宏)
    for m in re.finditer(r'char\s+(\w+)\s*\[\s*(\w+)\s*\]', code):
        nm, sz_var = m.group(1), m.group(2)
        if nm not in bufs:
            try:
                bufs[nm] = {"size": int(sz_var), "is_vla": False,
                            "pos": m.start(), "order": idx}
            except ValueError:
                bufs[nm] = {"size": -1, "is_vla": True, "pos": m.start(), "order": idx}
            idx += 1
    # struct on stack (大型结构体)
    for m in re.finditer(r'(?:struct\s+\w+|(\w+_t))\s+(\w+)\s*;', code):
        if m.group(2) not in bufs:
            bufs[m.group(2)] = {"size": -1, "is_vla": False,
                                "pos": m.start(), "order": idx}; idx += 1
    return bufs

def _has_canary_in_scope(code: str, buf_name: str) -> bool:
    """判断特定 buffer 所在函数是否受 canary 保护。"""
    return bool(re.search(r'__stack_chk|__builtin_stack|canary|stack_chk_fail', code))

def _detect_canary_usage(code: str) -> bool:
    """检测代码中是否有 canary 相关引用。"""
    patterns = [r'__stack_chk_fail', r'__builtin___stack_chk', r'-fstack-protector',
                r'__security_cookie', r'___chkstk_ms', r'__stack_chk_guard']
    return any(re.search(p, code) for p in patterns)

def canary_bypass_risk(code: str) -> Dict:
    """评估 canary 被绕过的风险。

    返回 {bypassable, methods, confidence}
    bypass 方法:
    - INFO_LEAK: 存在信息泄露可能泄露 canary 值
    - SKIP_OVER: 溢出可直接跳过 canary (修改 saved_RBP/saved_RIP 而不碰 canary)
    - BRUTEFORCE: fork 型服务可暴力破解 canary (i386: 2^24, x64: 2^56)
    - OVERWRITE_EXCEPTION: 覆盖 exception handler 绕过 canary
    """
    risks = []
    conf = 0.0

    # 信息泄露: printf(%s, buf) / send(buf) 等可能泄露 canary
    if re.search(r'printf\s*\(\s*"[^"]*%\s*s[^"]*"\s*,\s*\w+', code):
        risks.append("INFO_LEAK"); conf += 0.30
    if re.search(r'(?:send|write|fwrite)\s*\([^,]+,\s*(\w+)\s*,', code):
        risks.append("INFO_LEAK"); conf += 0.20

    # struct 中有函数指针 → 可跳过 canary 直接覆盖函数指针
    if re.search(r'struct\s+\w+\s*\{[^}]*\(\s*\*\s*\w+\s*\)\s*\(', code, re.DOTALL):
        risks.append("SKIP_OVER_FP"); conf += 0.25

    # fork 型服务器: canary 值不变 → 可暴力破解
    if re.search(r'\bfork\s*\(\)', code):
        risks.append("BRUTEFORCE"); conf += 0.15

    # setjmp/longjmp → 可覆盖 jmp_buf
    if re.search(r'\b(?:setjmp|longjmp)\s*\(', code):
        risks.append("JMPBUF_OVERWRITE"); conf += 0.20

    return {"bypassable": len(risks) > 0, "methods": risks,
            "confidence": min(conf, 0.95), "has_canary": _detect_canary_usage(code)}

def compute_frame_overflow_risk(buf_size: int, write_range_lo: float,
                                 write_range_hi: float, bytes_to_saved_rip: int,
                                 canary_protected: bool, canary_bypass_conf: float) -> Dict:
    """综合判定: 给定 buffer 和写入范围, 评估栈溢出风险。

    buf_size: buffer 的字节数
    write_range_lo/hi: 写入量的 [lo, hi] 区间
    bytes_to_saved_rip: 该 buffer 末尾到 saved_RIP 的字节数
    canary_protected: 是否受 canary 保护
    canary_bypass_conf: canary 绕过风险置信度
    """
    overflow_to_rip = write_range_lo > (buf_size + bytes_to_saved_rip)
    overflow_to_canary = write_range_lo > buf_size
    overflow_possible = write_range_hi > buf_size

    if not overflow_possible:
        return {"overflow": False, "hits_rip": False, "confidence": 0.02,
                "reason": f"write({write_range_lo:.0f}-{write_range_hi:.0f}) <= buf({buf_size})"}

    if overflow_to_rip:
        conf = 0.95
        reason = f"WRITE_DIST > BUF({buf_size})+{bytes_to_saved_rip}bytes → saved_RIP可覆盖"
        if canary_protected and canary_bypass_conf < 0.30:
            conf = max(0.40, conf - 0.35)
            reason += " [CANARY低绕过风险→压制]"
        elif canary_protected:
            conf = max(0.55, conf - 0.15)
            reason += f" [CANARY存在但可绕过(c={canary_bypass_conf:.2f})]"
    elif overflow_to_canary:
        conf = 0.70
        reason = f"WRITE越过BUF({buf_size})边界→可覆盖canary"
        if canary_protected:
            conf = max(0.25, conf - 0.40)
            reason += f" [CANARY保护→需先泄露canary,绕过c={canary_bypass_conf:.2f}]"
    else:
        conf = 0.30
        reason = f"WRITE可能越过BUF({buf_size})边界但无法确定"

    return {"overflow": True, "hits_rip": overflow_to_rip,
            "hits_canary": overflow_to_canary, "confidence": round(conf, 2),
            "reason": reason}
