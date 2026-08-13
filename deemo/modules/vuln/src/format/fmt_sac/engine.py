"""FMT-SAC 判定引擎 — 来源分类 + 一致性 → 最终判定.

创建: 2023-10-11
设计决策:
  - SAFE_FILTERED 仅当 CONST_RDATA 且说明符数 ≤ 实参数:
    常量格式串的参数不匹配是参数错误而非格式化漏洞, 但因无攻击面,
    一致时过滤, 不一致时降级 POSSIBLE 保留.
  - CONFIRMED: 非常量来源 (栈/堆/用户输入) 且说明符数 > 0.
  - %n + 可写输出 (sprintf 类) 增强置信度.
"""
from typing import List

from .types import (SacVerdict, SacRule, Evidence, FmtCall, CallVerdict,
                    FmtSource)
from .arg_consistency import _norm_name


class SacEngine:
    """单函数 FMT-SAC 判定引擎."""

    def __init__(self, consistency):
        self._consistency = consistency
        self._stats = {'total': 0, 'safe': 0, 'confirmed': 0,
                       'likely': 0, 'possible': 0}

    def evaluate(self, call: FmtCall, sample_id: str = '') -> CallVerdict:
        self._stats['total'] += 1
        cv = CallVerdict(sample_id=sample_id, call=call)

        n_args = self._consistency.count_args(call)
        call.n_args = n_args

        if call.source == FmtSource.CONST_RDATA:
            # 常量格式串无攻击面: 参数不匹配属参数错误(崩溃风险),
            # 不构成格式化字符串漏洞 — 一律过滤
            cv.verdict = SacVerdict.SAFE_FILTERED
            if call.n_specifiers <= n_args:
                cv.evidences.append(Evidence(
                    rule=SacRule.CONST_MATCH,
                    detail='const fmt %d specifiers <= %d args'
                           % (call.n_specifiers, n_args),
                    confidence=0.95,
                    extra={'spec': call.n_specifiers,
                           'args': n_args}))
                cv.fp_probability = 0.95
            else:
                cv.evidences.append(Evidence(
                    rule=SacRule.CONST_MISMATCH,
                    detail='const fmt %d specifiers > %d args (arg error, '
                           'not fmt vuln)' % (call.n_specifiers, n_args),
                    confidence=0.75,
                    extra={'spec': call.n_specifiers,
                           'args': n_args}))
                cv.fp_probability = 0.9
            self._stats['safe'] += 1
            return cv

        # 非常量来源
        if call.source in (FmtSource.STACK_BUFFER, FmtSource.HEAP_BUFFER,
                           FmtSource.USER_INPUT):
            ev = Evidence(
                rule=SacRule.NON_CONST_SOURCE,
                detail='fmt from %s (%s)' % (call.source.name,
                                             call.source_detail),
                confidence=0.85)
            cv.evidences.append(ev)
            writable = call.writable_out and call.has_pct_n
            if writable:
                cv.evidences.append(Evidence(
                    rule=SacRule.PCT_N_WRITABLE,
                    detail='%%n with writable output target',
                    confidence=0.9))
            cv.verdict = SacVerdict.CONFIRMED if writable or \
                call.source == FmtSource.USER_INPUT else SacVerdict.LIKELY
            cv.fp_probability = 0.05 if cv.verdict == SacVerdict.CONFIRMED \
                else 0.3
            self._stats['confirmed' if cv.verdict == SacVerdict.CONFIRMED
                        else 'likely'] += 1
            return cv

        cv.verdict = SacVerdict.POSSIBLE
        cv.evidences.append(Evidence(
            rule=SacRule.UNRESOLVED,
            detail='fmt source unresolved (%s)' % call.source_detail,
            confidence=0.3))
        cv.fp_probability = 0.4
        self._stats['possible'] += 1
        return cv

    def stats(self) -> dict:
        return dict(self._stats)
