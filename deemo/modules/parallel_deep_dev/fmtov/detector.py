"""格式化字符串检测 — 格式源验证 (FSV) 编排。

遍历语句: 维护污点/字面量来源; 命中 printf 族调用时评估格式参数。
判定: 字面量→SAFE; 字面量来源变量→SAFE; 污点变量→确认漏洞;
其余变量→UNCERTAIN(抑制)。
"""

# TODO: %n 位写需格式内容追踪, 当前仅判定污点来源

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from heapov.cparser import parse_source_full
from heapov.expr_ast import Expr, Var, Call, Const, Field, Index, Binary
from heapov.stmts import If, For, While, Block, CallStmt
from heapov.dataflow import _stmt_list

from fmtov import verdict as V
from fmtov.taint import TaintEnv, FMT_FUNCS


@dataclass
class Finding:
    func: str
    fmt_expr: str
    call: str
    verdict: str
    confidence: float
    reasons: List[str] = field(default_factory=list)
    description: str = ''
    pos: int = 0


class FmtWalker:
    def __init__(self, func, lits: dict):
        self.func = func
        self.lits = lits
        self.env = TaintEnv(func.params)
        self.findings: List[Finding] = []
        self.seq = 0

    def run(self) -> None:
        self._walk(_stmt_list(self.func.body))

    def _walk(self, stmts) -> None:
        for s in stmts:
            self.seq += 1
            items = s if isinstance(s, list) else [s]
            for it in items:
                if isinstance(it, Block):
                    self._walk(it.stmts)
                elif isinstance(it, If):
                    self._walk(_stmt_list(it.then_b))
                    if it.else_b is not None:
                        self._walk(_stmt_list(it.else_b))
                elif isinstance(it, (For, While)):
                    self._walk(_stmt_list(it.body))
                elif isinstance(it, CallStmt) and it.call.name in FMT_FUNCS:
                    self._eval_site(it.call, self.seq)
                    self.env.apply_stmt(it, self.lits)
                else:
                    self.env.apply_stmt(it, self.lits)

    def _eval_site(self, call: Call, pos: int) -> None:
        idx = FMT_FUNCS[call.name]
        if len(call.args) <= idx:
            return
        fmt = call.args[idx]
        name = call.name

        if self.env.expr_literal(fmt):
            return  # SAFE: 字面量或字面量来源
        if isinstance(fmt, Const):
            return
        if self._fmt_tainted(fmt):
            self.findings.append(Finding(
                func=self.func.name, fmt_expr=_sexpr(fmt), call=name,
                verdict=V.FORMAT_STRING, confidence=V.CONF_FORMAT,
                reasons=['tainted-format'],
                description=f'{name} 使用污点格式串', pos=pos))
            return
        # 不可证来源: UNCERTAIN, 抑制
        return

    def _fmt_tainted(self, e: Expr) -> bool:
        """格式表达式是否携带污点。

        字段读取 p->fmt 的字段值不可证, 不计入污点(UNCERTAIN 抑制);
        数组元素/指针算术/变量/调用实参按基变量污点判定。
        """
        if isinstance(e, Var):
            return e.name in self.env.tainted
        if isinstance(e, Field):
            return False
        if isinstance(e, Index):
            return self._fmt_tainted(e.base) or self.env.expr_tainted(e.index)
        if isinstance(e, Binary):
            return self._fmt_tainted(e.left) or self._fmt_tainted(e.right)
        if isinstance(e, Call):
            return any(self._fmt_tainted(a) for a in e.args)
        return self.env.expr_tainted(e)


def _sexpr(e: Expr) -> str:
    from heapov.expr_ast import expr_str
    return expr_str(e)


def analyze_source(src: str, threshold: float = V.REPORT_MIN):
    """分析 C 源码, 返回 (report, stats)。"""
    funcs, lits = parse_source_full(src)
    findings: List[Finding] = []
    for func in funcs:
        w = FmtWalker(func, lits)
        w.run()
        findings.extend(w.findings)
    reportable = [f for f in findings
                  if f.verdict in V.REPORT_SET and f.confidence >= threshold]
    report = [{'func': f.func, 'fmt': f.fmt_expr, 'call': f.call,
               'verdict': f.verdict, 'confidence': round(f.confidence, 3),
               'reasons': f.reasons, 'description': f.description,
               'pos': f.pos} for f in reportable]
    stats = {'functions': len(funcs), 'raw': len(findings),
             'reported': len(reportable)}
    return report, stats
