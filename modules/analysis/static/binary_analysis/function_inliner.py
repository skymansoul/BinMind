from __future__ import annotations


def analyze_inlining(func_code: bytes) -> dict:
    """检测函数代码是否为内联候选: 通过序言/结尾缺失与 call 嵌入特征判定"""
    if not func_code or len(func_code) < 3:
        return {"is_inlined": False, "confidence": 0.0}
    # 内联函数通常无独立序言/结尾; 检查是否以 ret (0xc3) 结尾
    has_ret = func_code[-1] == 0xC3
    # 检查是否有 push rbp/ebp 序言
    has_prologue = (
        func_code[:3] in (b"\x55\x89\xe5", b"\x55\x48\x89\xe5[:3]")
        or func_code[:1] == b"\x55"
    )
    # 短函数 (< 32 字节) 且有 ret 但无独立序言 → 内联候选
    is_short = len(func_code) < 32
    if is_short and has_ret and not has_prologue:
        confidence = min(1.0, 1.0 - len(func_code) / 32.0)
        return {"is_inlined": True, "confidence": round(confidence, 3)}
    if has_prologue and has_ret:
        return {"is_inlined": False, "confidence": 0.1}
    return {"is_inlined": False, "confidence": 0.0}
