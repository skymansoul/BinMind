# analysis/uaf_field_access_tracker.py — UAF结构体字段穿越追踪
# 现有UAF检测只追踪 free(var)→use(var), 漏掉 free(cur)→cur->next 的链式访问。
# 本模块检测: 链表遍历UAF / 树遍历UAF / 通用field-after-free。
# 在free点后搜索 obj->field / obj.field / obj[idx], 追踪别名传播链。

from __future__ import annotations
import re
from typing import Dict, List, Set, Tuple, Optional

def _extract_struct_fields(code: str) -> Dict[str, Set[str]]:
    """从struct定义中提取字段名集合 → {struct_name: {field1, ...}}。"""
    fields: Dict[str, Set[str]] = {}
    for sm in re.finditer(
        r'struct\s+(\w+)\s*\{([^}]+)\}',
        code, re.DOTALL
    ):
        struct_name = sm.group(1)
        body = sm.group(2)
        field_set: Set[str] = set()
        for fm in re.finditer(r'(\w+)\s*;', body):
            field_set.add(fm.group(1))
        # 去掉类型关键字
        field_set.discard('int'); field_set.discard('char'); field_set.discard('void')
        field_set.discard('size_t'); field_set.discard('unsigned'); field_set.discard('long')
        field_set.discard('float'); field_set.discard('double'); field_set.discard('short')
        fields[struct_name] = field_set
    return fields

def _find_field_accesses_after(code: str, var: str, start_pos: int) -> List[Dict]:
    """在 start_pos 后搜索 var->field / var.field / var[idx] 访问。"""
    after = code[start_pos:]
    accesses: List[Dict] = []

    # var->field 解引用
    for m in re.finditer(rf'\b{re.escape(var)}\s*->\s*(\w+)', after):
        accesses.append({
            "field": m.group(1),
            "pos": m.start(),
            "ctx": after[max(0, m.start()-20):m.end()+10],
            "access_type": "deref",
        })

    # var.field 点访问
    for m in re.finditer(rf'\b{re.escape(var)}\s*\.\s*(\w+)', after):
        accesses.append({
            "field": m.group(1),
            "pos": m.start(),
            "ctx": after[max(0, m.start()-20):m.end()+10],
            "access_type": "dot",
        })

    # var[idx] 数组索引
    for m in re.finditer(rf'\b{re.escape(var)}\s*\[', after):
        accesses.append({
            "field": None,
            "pos": m.start(),
            "ctx": after[max(0, m.start()-10):m.end()+15],
            "access_type": "array",
        })

    return accesses

def _resolve_alias_chain(code: str, var: str, max_depth: int = 3) -> Dict[str, str]:
    """BFS遍历赋值语句, 构建别名反向映射: {tmp: head, cur: head}。"""
    aliases: Dict[str, str] = {var: var}

    for _ in range(max_depth):
        changed = False
        # ptr = expr 赋值
        for m in re.finditer(r'(\w+)\s*=\s*(\w+(?:\s*->\s*\w+)?)\s*;', code):
            lhs, rhs = m.group(1), m.group(2)
            rhs_base = rhs.split('->')[0]
            if rhs_base in aliases and lhs not in aliases:
                aliases[lhs] = aliases[rhs_base]
                changed = True
        if not changed:
            break

    return aliases

def detect_field_uaf(code: str, func_name: str = "") -> List[Dict]:
    """检测通过结构体字段穿越的UAF: free(ptr)后访问ptr->field。

    逻辑: 定位free()→搜索field访问→解析别名→排除NULL守卫→判定链表遍历。
    """
    findings: List[Dict] = []
    struct_fields = _extract_struct_fields(code)

    free_sites = []
    for m in re.finditer(r'free\s*\(\s*(\w+(?:\s*->\s*\w+)?)\s*\)', code):
        var_raw = m.group(1)
        base_var = var_raw.split('->')[0].split('.')[0]
        free_sites.append({
            "var": base_var,
            "full_expr": var_raw,
            "pos_start": m.start(),
            "pos_end": m.end(),
            "line": code[:m.start()].count('\n') + 1,
        })

    if not free_sites:
        return findings

    for fs in free_sites:
        base = fs["var"]
        after_free = code[fs["pos_end"]:]

        # 检查free之后是否有 NULL 赋值 (安全模式)
        null_guard = re.search(
            rf'{re.escape(base)}\s*=\s*(?:NULL|0|nullptr)\s*;',
            after_free
        )
        null_guard_pos = null_guard.start() if null_guard else float('inf')

        field_accesses = _find_field_accesses_after(code, base, fs["pos_end"])

        aliases = _resolve_alias_chain(code, base)
        alias_accesses: List[Dict] = []
        for alias_var, root in aliases.items():
            if alias_var == base or root != base:
                continue
            acc = _find_field_accesses_after(code, alias_var, fs["pos_end"])
            for a in acc:
                a["via_alias"] = alias_var
            alias_accesses.extend(acc)

        all_accesses = field_accesses + alias_accesses

        real_uaf_accesses = [
            a for a in all_accesses
            if a["pos"] < null_guard_pos
        ]

        if not real_uaf_accesses:
            continue

        real_uaf_accesses = [
            a for a in real_uaf_accesses
            if f'free({base}' not in a["ctx"] and f'free ({base}' not in a["ctx"]
        ]

        if not real_uaf_accesses:
            continue

        is_list_traversal = False
        traversal_field = None
        for acc in real_uaf_accesses:
            ctx_after = after_free[acc["pos"]:acc["pos"]+100]
            # 检测: var = var->field 模式 (即 free(cur) 后 cur = cur->next)
            if re.search(rf'{re.escape(base)}\s*=\s*{re.escape(base)}\s*->\s*\w+', ctx_after):
                is_list_traversal = True
                tm = re.search(rf'{re.escape(base)}\s*=\s*{re.escape(base)}\s*->\s*(\w+)', ctx_after)
                if tm:
                    traversal_field = tm.group(1)
                break

        # 置信度计算
        conf = 0.70  # 基础: field-after-free
        reasons = [f"字段穿越访问: {base}->{real_uaf_accesses[0].get('field', '?')}"]

        if is_list_traversal:
            conf = min(0.95, conf + 0.20)
            reasons.append(f"链表遍历模式: free后通过->{traversal_field}前移"
                           f"→ 经典UAF遗漏点")
        else:
            # 检查是否在自己的free调用内
            for acc in real_uaf_accesses:
                if acc["pos"] < 3:  # 紧跟在free后
                    conf = min(0.92, conf + 0.12)
                    reasons.append("free后立即字段访问→高时序关联")
                    break

        # 排除模式: 如果free的是 obj->field 而不是 obj 本身,
        # 则 obj->other_field 访问不构成UAF
        if "->" in fs["full_expr"]:
            free_field = fs["full_expr"].split("->")[-1]
            same_field = all(
                a.get("field") == free_field
                for a in real_uaf_accesses
            )
            if not same_field:
                # free(obj->a) 后访问 obj->b — 可能安全
                conf = max(0.30, conf - 0.30)
                reasons.append("释放子字段后访问其他字段→可能安全")

        findings.append({
            "type": "use-after-free",
            "subtype": "field_access_after_free",
            "function": func_name,
            "variable": base,
            "free_line": fs["line"],
            "field_accesses": [
                {"field": a.get("field"), "access_type": a["access_type"],
                 "ctx": a["ctx"].strip(), "via_alias": a.get("via_alias")}
                for a in real_uaf_accesses[:5]
            ],
            "is_list_traversal": is_list_traversal,
            "traversal_field": traversal_field,
            "severity": "Critical",
            "cwe": "CWE-416",
            "confidence": round(conf, 2),
            "description": (
                f"UAF-FIELD: {base} freed at line {fs['line']}, "
                f"subsequently accessed via ->{real_uaf_accesses[0].get('field', '?')} "
                f"({'链表遍历' if is_list_traversal else '字段穿越'}), "
                f"conf={conf:.2f}"
            ),
        })

    # 按置信度降序
    findings.sort(key=lambda f: f["confidence"], reverse=True)
    return findings

def detect_list_traversal_uaf(code: str, func_name: str = "") -> List[Dict]:
    """专门检测链表/树遍历中的UAF模式:
    while (cur) { free(cur); cur = cur->next; }
    这种模式中, free(cur) 之后立即访问 cur->next,
    当前所有检测器都无法捕获因为访问的是cur->next而非cur本身。
    """
    findings: List[Dict] = []

    # 匹配 while/for 循环体中的 free + field访问
    loop_pattern = re.compile(
        r'(?:while|for)\s*\([^)]*\)\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}',
        re.DOTALL
    )

    for lm in loop_pattern.finditer(code):
        loop_body = lm.group(1)

        # 在循环体中找 free(var)
        free_in_loop = list(re.finditer(
            r'free\s*\(\s*(\w+)\s*\)', loop_body
        ))
        if not free_in_loop:
            continue

        for fm in free_in_loop:
            freed_var = fm.group(1)
            after_free_in_loop = loop_body[fm.end():]

            # 在free之后搜索: var = var->field 或 var->field (读取)
            traversal_match = re.search(
                rf'{re.escape(freed_var)}\s*=\s*{re.escape(freed_var)}\s*->\s*(\w+)',
                after_free_in_loop
            )
            deref_match = re.search(
                rf'{re.escape(freed_var)}\s*->\s*(\w+)',
                after_free_in_loop
            )

            if traversal_match:
                field = traversal_match.group(1)
                findings.append({
                    "type": "use-after-free",
                    "subtype": "list_traversal_uaf",
                    "function": func_name,
                    "variable": freed_var,
                    "traversal_field": field,
                    "pattern": f"free({freed_var}); ... {freed_var} = {freed_var}->{field}",
                    "severity": "Critical",
                    "cwe": "CWE-416",
                    "confidence": 0.93,
                    "description": (
                        f"UAF-LIST: 循环遍历中 free({freed_var}) 后通过 "
                        f"->{field} 访问已释放内存 → 链表/树遍历UAF"
                    ),
                })
            elif deref_match:
                field = deref_match.group(1)
                findings.append({
                    "type": "use-after-free",
                    "subtype": "list_field_deref_after_free",
                    "function": func_name,
                    "variable": freed_var,
                    "field": field,
                    "pattern": f"free({freed_var}); ... {freed_var}->{field}",
                    "severity": "Critical",
                    "cwe": "CWE-416",
                    "confidence": 0.88,
                    "description": (
                        f"UAF-LIST: 循环中 free({freed_var}) 后解引用 "
                        f"->{field} → 字段穿越悬垂指针"
                    ),
                })

    return findings
