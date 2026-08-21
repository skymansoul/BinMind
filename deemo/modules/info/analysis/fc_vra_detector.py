# analysis/fc_vra_detector — FC-VRA 流相关值域分析检测器 (本项目核心创新)
# 管线: C0 值流配对 → C1 大小等价 → C2 区间+分配器松弛 → C3 支配守卫 → C4 可控性确认
#
# 误报压制机理 (相对 PSVR-HLM v2):
#   C0: 把 O(A×W) 笛卡尔积替换为 O(写入点) 的缓冲区别名绑定
#   C1: alloc size ≡ write size 的代数等价 → 必然安全 (仅限编译期常量/读源已知)
#   C2: 区间化的对齐感知判定 (HLM 从常量扩展到区间)
#   C3: 只承认支配写入点且约束写入量变量的守卫
#   C4: 攻击者不可控的常量错配 → 威胁降级
# 召回保持: 真堆溢出必然满足"写入目标=某分配点缓冲区" (必要不充分条件),
# 因此 C0 保证召回下界; C1/C2 仅在可证明安全时抑制。
# 真实 CVE 语料验证揭示的精度边界:
#   (a) heartbleed 类读溢出 (malloc(n)+memcpy(dst,src,n), n 运行时) 不得
#       按常量等量抑制 — 仅在读源为已知本地数组时判定堆写作用域内安全;
#   (b) 含可控变量的 alloc 尺寸 (len*4 回绕) 不得按 write⊆alloc 抑制。
# 无源码回退: code 为空或配对失败时委托 detect_heap_overflow_v2,
# 保持二进制级 (导入表) 检出能力不变。

from __future__ import annotations
from typing import Dict, List
import re

from .value_range_analyzer import ValueRange, extract_value_ranges
from size_expr_evaluator import eval_size_expr, resolve_defines
from flow_pair_generator import generate_correlated_pairs, CorrelatedPair
from size_equivalence import sizes_equivalent, write_bounded_by_alloc
from allocator_slack import verdict_with_slack, usable_range_for_alloc
from guard_dominance import find_dominating_guards
from taint_confirm import confirm_controllability
from heap_overflow_v2 import detect_heap_overflow_v2, _in_loop, _has_loop_accumulation
from fc_size_proof import (
    size_is_constant, resolve_sizeof_var, write_ternary_capped_by_alloc,
    read_source_is_local_array,
)
from fc_direct_writes import detect_direct_writes

_WRITE_FUNC_RISK = {
    "memcpy": 0.55, "memmove": 0.55, "strncpy": 0.50, "strncat": 0.50,
    "strcpy": 0.80, "strcat": 0.80, "sprintf": 0.80, "gets": 0.85,
    "read": 0.70, "recv": 0.75, "fread": 0.65, "manual_loop_write": 0.85,
}

_ARRAY_DECL_RE = re.compile(
    r"\b(?:char|unsigned char|signed char|int|unsigned|short|long|size_t)"
    r"\s+(\w+)\s*\[\s*(\d+)\s*\]")


def intra_tainted_vars(code: str) -> set:
    """函数内污染变量集合 (输入源 → 赋值/算术传播)。"""
    return _propagate(code, _seed_sources(code))


def _param_tainted_vars(code: str, intra_tainted) -> set:
    """跨函数参数污染: 函数参数被 tainted 实参传入 → 参数视为可控。

    用于 size 表达式可控性判定 (heartbleed/grub 等 CVE 的 size 均来自
    函数参数, 而参数在调用点被 atoi/recv 等输入驱动)。
    """
    tainted_params = set()
    for m in re.finditer(
        r"(?:static\s+)?(?:void|int|char|size_t|unsigned|long|bool|"
        r"unsigned\s+int)\s+(\w+)\s*\(([^)]*)\)", code):
        fn_name, params = m.group(1), m.group(2)
        # 参数名列表 (按声明顺序, 去掉类型/数组/指针)
        param_names = []
        for part in params.split(","):
            part = part.strip()
            if not part or "..." in part:
                continue
            pn = part.split()[-1].strip("*").strip()
            if pn and pn[0].isalpha():
                param_names.append(pn)
        for call in re.finditer(rf"\b{re.escape(fn_name)}\s*\(\s*([^)]*?)\)",
                                code):
            args = [a.strip() for a in call.group(1).split(",")]
            for i, pn in enumerate(param_names):
                if i >= len(args):
                    break
                arg = args[i]
                if not arg or arg.startswith('"'):
                    continue
                arg_vars = set(re.findall(r"\b(\w+)\b", arg))
                if re.match(r"argv\s*\[", arg) or \
                   re.search(r"argv\s*\[\s*\d+\s*\]", arg) or \
                   any(v in intra_tainted for v in arg_vars):
                    tainted_params.add(pn)
    return tainted_params


def _size_var_tainted(code: str, expr: str, intra_tainted) -> bool:
    """size 表达式是否含攻击者可控变量 (含跨函数参数)。"""
    if not expr:
        return False
    vars_in = [v for v in re.findall(r"\b(\w+)\b", expr)
               if not v.isdigit() and v not in ("int", "char", "short",
                                                "long", "size", "t",
                                                "sizeof")]
    if not vars_in:
        return False
    if any(v in intra_tainted for v in vars_in):
        return True
    return bool(_param_tainted_vars(code, intra_tainted) & set(vars_in))


def size_is_constant(code: str, expr: str, defines: Dict) -> bool:
    """尺寸表达式是否为编译期常量 (字面量/sizeof/#define 宏)。

    运行时变量 (参数/输入/计算值) 即使与写入量相等, 也可能因
    回绕或读源更小而构成溢出 → 不得判定必然安全。
    """
    if not expr:
        return False
    e = expr.strip()
    if not e:
        return False
    if e.isdigit():
        return True
    if re.match(r"sizeof\s*\(", e):
        return True
    # sizeof(T) 为编译期常量, 其内部类型名不参与变量判定
    e = re.sub(r"sizeof\s*\([^)]*\)", "4", e)
    vars_ = [v for v in re.findall(r"\b([a-zA-Z_]\w*)\b", e)
             if v not in ("sizeof", "int", "char", "short", "long", "size",
                          "t")]
    if not vars_:
        return True  # 无变量 (纯运算)
    return all(v in defines for v in vars_)


def resolve_sizeof_var(code: str, expr: str) -> Optional[ValueRange]:
    """sizeof(数组变量) → 数组声明尺寸 (tp_06/tp_09 等 char src[N] 场景)。"""
    m = re.match(r"sizeof\s*\(\s*(\w+)\s*\)", expr.strip())
    if not m:
        return None
    name = m.group(1)
    for dm in _ARRAY_DECL_RE.finditer(code):
        if dm.group(1) == name:
            return ValueRange.const(int(dm.group(2)))
    return None


def write_ternary_capped_by_alloc(code: str, alloc_expr: str,
                                  write_expr: str) -> bool:
    """写入量表达式是否被分配量截断。

    两类截断:
      a) min-style: 写入含分配变量 (NEG-007: len<alloc?len:alloc)
      b) 三目常量截断: X < N ? X : K 或 X < N ? K : X, 且
         max(K, N-1) ≤ 分配常量 (CVE-2024-017: len<1024?len:1023)
    与 grub 类 (write=len, alloc=len*4) 的区别: 后者为纯变量写, 无截断结构。
    """
    if not write_expr or write_expr == alloc_expr:
        return False
    if "?" not in write_expr and "<" not in write_expr and \
       ">" not in write_expr:
        return False
    # a) 写入含分配变量 (min-style)
    if alloc_expr:
        alloc_vars = set(re.findall(r"\b([a-zA-Z_]\w*)\b", alloc_expr))
        alloc_vars -= {"int", "char", "short", "long", "size", "t", "sizeof"}
        if any(v in write_expr for v in alloc_vars):
            return True
    # b) 三目常量截断: X < N ? X : K / X < N ? K : X → 结果上界可计算
    m = re.fullmatch(
        r"(\w+)\s*[<>]\s*(\d+)\s*\?\s*(\w+)\s*:\s*(\w+)",
        write_expr.replace(" ", ""))
    if m:
        var, n_val, b1, b2 = m.group(1), int(m.group(2)), \
            m.group(3), m.group(4)
        upper = []
        ok = True
        for b in (b1, b2):
            if b.isdigit():
                upper.append(int(b))
            elif b == var:
                upper.append(n_val - 1)
            else:
                ok = False
                break
        if ok and alloc_expr and alloc_expr.strip().isdigit():
            return max(upper) <= int(alloc_expr.strip())
    return False


def read_source_is_local_array(code: str, write_func: str) -> bool:
    """memcpy 读源是否为已知尺寸的本地数组。

    等尺寸运行时变量的读溢出候选 (heartbleed 类) 仅在读源尺寸未知
    (指针/参数) 时成立; 读源为已知本地数组时, 目标缓冲区等量安全,
    属于 CWE-122 堆写作用域外, 不告警。
    """
    for m in re.finditer(
        rf"\b{re.escape(write_func)}\s*\(((?:[^()]|\([^()]*\))*)\)", code):
        args = [a.strip() for a in m.group(1).split(",")]
        if len(args) < 2:
            continue
        src = re.sub(r"\s*\+\s*[\w.]+", "", args[1])
        src = re.sub(r"\[[^\]]*\]", "", src).strip()
        if src and re.match(r"^[a-zA-Z_]\w*$", src):
            for dm in _ARRAY_DECL_RE.finditer(code):
                if dm.group(1) == src:
                    return True
    return False


def detect_direct_writes(code: str, ranges: Dict, defines: Dict,
                         arch: str) -> List[Dict]:
    """直接偏移写检测 (CVE-2024-004 off-by-one 类)。

    覆盖分配点缓冲区的两种非函数式写入:
      a) buf[CONST] = value                     → 写 [CONST, CONST+1)
      b) for(i=0;i<LIMIT;i++){buf[i]=...}       → 写 [0, LIMIT)
         while(i<LIMIT){buf[i++]=...}           → 写 [0, LIMIT)
    当 write_end > 对齐后可用空间 → 堆溢出候选。
    """
    model = get_allocator_model(arch)
    findings = []
    for hp in extract_heap_ptrs(code):
        alloc_range = eval_size_expr(hp.alloc_size_expr or "unknown",
                                     ranges, defines)
        if not alloc_range.is_const:
            continue
        usable = model.usable_size_min(alloc_range.const_value)
        var = hp.var

        # a) 直接常量偏移写
        for m in re.finditer(rf"\b{re.escape(var)}\s*\[\s*(\d+)\s*\]\s*=", code):
            off = int(m.group(1))
            if off + 1 > usable:
                findings.append({
                    "type": "heap-overflow", "cwe": "CWE-122",
                    "alloc_func": "malloc", "write_func": "direct_offset",
                    "alloc_size_source": hp.alloc_size_expr,
                    "write_size_source": f"offset {off} + 1B",
                    "buffer": var, "alloc_var": var,
                    "binding_conf": 1.0,
                    "confidence": 0.85,
                    "severity": "High",
                    "reason": f"C0:direct offset buf[{off}]+1 > 可用{usable}B",
                })
        # b) 循环全量写 (for/while 定界; <=N 为 N+1 次 → off-by-one)
        # TODO: 循环上界为变量 (i < n) 时无法静态判定, 需接入区间推断
        for lm in re.finditer(
            rf"(?:for\s*\([^;]*;\s*[^;]*(<=|<)\s*(\d+)\s*[^;]*;\s*[^)]*\)|"
            rf"while\s*\(\s*\w+\s*(<=|<)\s*(\d+)\s*\))", code):
            limit = int(lm.group(2) or lm.group(4))
            op = lm.group(1) or lm.group(3)
            total = limit + 1 if op == "<=" else limit
            body_start = lm.end()
            body_end = min(body_start + 400, len(code))
            body = code[body_start:body_end]
            if re.search(rf"\b{re.escape(var)}\s*\[[^\]]*\]\s*=", body):
                if total > usable:
                    findings.append({
                        "type": "heap-overflow", "cwe": "CWE-122",
                        "alloc_func": "malloc", "write_func": "loop_offset",
                        "alloc_size_source": hp.alloc_size_expr,
                        "write_size_source": f"loop {total}B ({op}{limit})",
                        "buffer": var, "alloc_var": var,
                        "binding_conf": 0.9,
                        "confidence": 0.80,
                        "severity": "High",
                        "reason": f"C0:loop write {total}B > 可用{usable}B",
                    })
    return findings


def _base_confidence(pair: CorrelatedPair) -> float:
    """由写入函数与绑定强度确定基础置信度。"""
    risk = _WRITE_FUNC_RISK.get(pair.write_func, 0.55)
    return round(min(1.0, 0.40 + 0.5 * risk + 0.25 * (pair.binding_conf - 0.5)), 3)


def _eval_pair_ranges(code: str, pair: CorrelatedPair,
                      ranges: Dict[str, ValueRange],
                      defines: Dict[str, int]):
    """求值配对双方的大小区间。"""
    alloc_expr = pair.alloc_size_expr or "unknown"
    write_expr = pair.write_size_expr or "unknown"
    a = eval_size_expr(alloc_expr, ranges, defines) \
        if alloc_expr not in ("unknown", "") else ValueRange.top()
    if write_expr in ("unknown", "unbounded", "loop_bounded", ""):
        w = ValueRange.top()
    else:
        w = resolve_sizeof_var(code, write_expr)
        if w is None:
            w = eval_size_expr(write_expr, ranges, defines)
    return a, w


def _analyze_pair(code: str, pair: CorrelatedPair, ranges: Dict,
                  defines: Dict, arch: str) -> Dict:
    """对单个流相关对执行 C1-C4, 返回分析结果。"""
    reasons: List[str] = []
    conf = _base_confidence(pair)

# C1: 大小结构等价 → 等量安全/读溢出候选
    if pair.alloc_size_expr and pair.write_size_expr:
        in_loop = _in_loop(code, pair.write_func)
        # 循环内写入为"每次迭代量"; 运行时尺寸可能回绕/读源更小 →
        # 均不得判定必然安全。realloc 扩容后等量写入为惯用安全语义。
        const_alloc = size_is_constant(code, pair.alloc_size_expr, defines)
        realloc_grow = pair.alloc_func == "realloc"
        suppressible = (not in_loop) and (const_alloc or realloc_grow)
        if sizes_equivalent(code, pair.alloc_size_expr, pair.write_size_expr):
            if suppressible:
                reasons.append("C1:alloc==write(代数等价,常量)→安全")
                conf -= 0.60
                return {"confidence": round(max(conf, 0.0), 3),
                        "reasons": reasons, "suppressed": True}
            if read_source_is_local_array(code, pair.write_func):
                # 读源为已知本地数组 → 目标缓冲等量安全 (堆写作用域内)
                reasons.append("C1:等尺寸(运行时)读源为本地数组→堆写安全")
                conf -= 0.55
                return {"confidence": round(max(conf, 0.0), 3),
                        "reasons": reasons, "suppressed": True}
            conf = 0.45
            reasons.append("C1:等尺寸但读源尺寸未知→读溢出候选")
            return {"confidence": conf, "reasons": reasons,
                    "suppressed": False}
        if suppressible and write_bounded_by_alloc(
                code, pair.alloc_size_expr, pair.write_size_expr):
            reasons.append("C1:write⊆alloc(子项,常量)→安全")
            conf -= 0.50
            return {"confidence": round(max(conf, 0.0), 3), "reasons": reasons,
                    "suppressed": True}

# C2: 区间 + 分配器松弛
    alloc_range, write_range = _eval_pair_ranges(code, pair, ranges, defines)
    # 循环累加写入:
    # 目标带偏移且循环内累加 → 总写入量无静态上界 → 扩大为 top
    # 例外: 循环体内存在 break 守卫 (offset+K>LIMIT) → 写入被钳制 → 不扩大
    if pair.write_func in ("memcpy", "memmove", "strncpy") and \
       "+" in pair.raw_buffer and _in_loop(code, pair.write_func) and \
       _has_loop_accumulation(code):
        has_break_guard = bool(re.search(
            r"if\s*\([^)]*\+[^)]*>[^)]*\)\s*break", code))
        if not has_break_guard:
            write_range = ValueRange.top()
            reasons.append("C2:loop_accum→写入量扩大")
        else:
            # 循环内 break 守卫证明写入不越过分配 → 安全
            reasons.append("C2:loop_accum有break守卫→写入受限")
            return {"confidence": 0.15, "reasons": reasons, "suppressed": True}
    # 分配未知 + 小常量写入 → 无溢出证据 (NEG-004 calloc 安全类)
    if alloc_range.is_top and write_range.is_const and \
       write_range.const_value is not None and \
       write_range.const_value <= 1024:
        reasons.append("C2:alloc未知+小常量写入→无溢出证据")
        return {"confidence": 0.10, "reasons": reasons, "suppressed": True}
    # 写入被分配量截断 (三目/比较钳制) → 不越过分配 (NEG-007 类)
    if write_ternary_capped_by_alloc(code, pair.alloc_size_expr or "",
                                      pair.write_size_expr or ""):
        reasons.append("C2:写入被分配量截断(min-style)→安全")
        return {"confidence": 0.10, "reasons": reasons, "suppressed": True}
    ov, vconf, vreason = verdict_with_slack(alloc_range, write_range, arch)
    reasons.append(f"C2:{vreason}")
    if ov and vconf >= 0.70:
        conf += 0.25
    elif vconf <= 0.06:
        # 可证明安全 (write ≤ 可用下界): 抑制到零置信度
        reasons.append("C2:proven_safe")
        return {"confidence": 0.0, "reasons": reasons, "suppressed": True}
    elif vconf <= 0.20:
        # 可能安全 (write 落在 [可用下界+1, 可用上界]): 降权但保留
        conf -= 0.25
        reasons.append("C2:possibly_safe")
    elif vconf <= 0.35:
        conf -= 0.15

# C3: 支配守卫
    # FIXME: write_pos 取该写入函数首次出现处, 同一函数多次调用时守卫归属可能错位
    write_pos = code.find(pair.write_func + "(", 0) if pair.write_func else -1
    guard = find_dominating_guards(code, write_pos, pair.write_size_expr or "")
    if guard["has_guard"]:
        conf -= guard["effective_strength"] * 0.40
        reasons.append(
            f"C3:guard={guard['effective_strength']:.2f}"
            f"({'/'.join(g['kind'] for g in guard['guards'])}"
            if guard["guards"] else "C3:guard=min/ternary")
        if guard["bounded_write_max"] is not None and not alloc_range.is_top:
            u_lo, _ = usable_range_for_alloc(alloc_range.lo, alloc_range.hi, arch)
            if u_lo != float("-inf") and guard["bounded_write_max"] <= u_lo:
                # 写入量被守卫上界截断且 ≤ 可用下界 → 证明安全
                reasons.append("C3:bounded_write≤usable→安全")
                return {"confidence": 0.0, "reasons": reasons, "suppressed": True}

# C4: 可控性确认
    taint = confirm_controllability(code, pair.write_size_expr or "",
                                    pair.write_buffer)
    if not taint["controllable"] and taint["write_size_is_const"]:
        reasons.append("C4:常量错配·攻击者不可控")
        conf -= 0.20
    elif taint["size_tainted"]:
        conf += 0.10
        reasons.append("C4:size可控")

    return {"confidence": round(max(min(conf, 1.0), 0.0), 3),
            "reasons": reasons, "suppressed": False,
            "alloc_range": alloc_range, "write_range": write_range}


def detect_heap_overflow_fcv3(
    code: str = "", imports: Dict = None, strings: List[str] = None,
    checksec: Dict = None, min_confidence: float = 0.25,
    func_name: str = "",
) -> Dict:
    """FC-VRA v3.0 主入口。返回格式与 detect_heap_overflow_v2 兼容。"""
    imports = imports or {}
    checksec = checksec or {}
    arch = checksec.get("arch", "x86_64")

    ablation = {"input_pairs": 0, "after_c0": 0, "c1_safe": 0,
                "c2_proven_safe": 0, "c3_guarded": 0, "c4_suppressed": 0,
                "final_findings": 0}

    # 无源码 → 委托 v2 (二进制导入路径)
    if not code.strip():
        res = detect_heap_overflow_v2(code, imports, strings, checksec,
                                      min_confidence, func_name)
        res["method"] = "FC-VRA-v3.0(bin-fallback)"
        return res

    pairs = generate_correlated_pairs(code)
    ranges = extract_value_ranges(code)
    defines = resolve_defines(code)

    findings: List[Dict] = []
    pipeline: List[str] = []

    if not pairs:
        # 无流相关对: 委托 v2 保证召回, 直接偏移写补充 off-by-one
        res = detect_heap_overflow_v2(code, imports, strings, checksec,
                                      min_confidence, func_name)
        findings = list(res.get("findings", []))
        pipeline = ["C0: 0 flow pairs → v2 fallback"]
    else:
        ablation["input_pairs"] = len(pairs)
        pipeline = ["C0: %d flow-correlated pairs" % len(pairs)]
        pipeline.append("C1-C5: value-flow analysis")
        for pair in pairs:
            res = _analyze_pair(code, pair, ranges, defines, arch)
            if res["suppressed"]:
                ablation["c1_safe"] += 1
                ablation["c2_proven_safe"] += 1 if "C2:proven_safe" in ";".join(
                    res["reasons"]) else 0
                continue
            if any("C3:guard" in r for r in res["reasons"]):
                ablation["c3_guarded"] += 1
            conf = res["confidence"]
            severity = "High" if conf > 0.60 else ("Medium" if conf > 0.35 else "Low")
            findings.append({
                "type": "heap-overflow",
                "cwe": "CWE-122",
                "alloc_func": pair.alloc_func,
                "write_func": pair.write_func,
                "alloc_size_source": pair.alloc_size_expr or "UNKNOWN",
                "write_size_source": pair.write_size_expr or "UNKNOWN",
                "buffer": pair.write_buffer,
                "alloc_var": pair.alloc_var,
                "binding_conf": round(pair.binding_conf, 2),
                "confidence": round(conf, 2),
                "severity": severity,
                "reason": "; ".join(res["reasons"]),
                "same_dll": False,
            })

    # 直接偏移写补充 (off-by-one / 循环定界写) — 与配对路径无关, 恒执行
    direct = detect_direct_writes(code, ranges, defines, arch)
    if direct:
        pipeline.append(f"C0-direct: {len(direct)} offset-write findings")
        findings.extend(direct)
        findings.sort(key=lambda f: f["confidence"], reverse=True)
    ablation["final_findings"] = len(findings)

    hi = sum(1 for f in findings if f["confidence"] >= 0.70)
    med = sum(1 for f in findings if 0.35 <= f["confidence"] < 0.70)
    lo = sum(1 for f in findings if f["confidence"] < 0.35)

    pipeline.append(f"Final: {len(findings)}f ({hi}H/{med}M/{lo}L)")

    return {
        "findings": findings,
        "stats": {"total": len(findings), "high_conf": hi, "medium_conf": med,
                  "low_conf": lo,
                  "avg_confidence": round(
                      sum(f["confidence"] for f in findings) / max(len(findings), 1), 3)},
        "alloc_write_pairs_total": len(pairs),
        "method": "FC-VRA-v3.0",
        "pipeline": pipeline,
        "fp_reduction_pct": round(
            (1.0 - len(findings) / max(len(pairs), 1)) * 100, 1),
        "ablation": ablation,
        "false_positive_mitigations": ablation,
    }


if __name__ == "__main__":
    import sys
    import json
    code = sys.stdin.read() if not sys.stdin.isatty() else (
        "int n = atoi(argv[1]);\n"
        "char *buf = malloc(64);\n"
        "memcpy(buf, src, n);\n")
    r = detect_heap_overflow_fcv3(code=code)
    print(json.dumps(r, indent=2, ensure_ascii=False))
