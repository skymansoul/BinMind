"""Fmt-OG 冒烟测试 — 常量串/参数契约/输入源/透传四证据链."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))))  # deemo

from modules.vuln.src.format.fmtog.fmt_compressor import FmtCompressor
from modules.vuln.src.format.fmtog.verdict import FmtVerdictKind

FAIL = []


def check(name, cond, extra=''):
    print(f'  [{"PASS" if cond else "FAIL"}] {name} {extra}')
    if not cond:
        FAIL.append(name)


def run(ins, labels=None, rdata=None):
    addrs = [0x140001000 + i * 4 for i in range(len(ins))]
    return FmtCompressor().compress(ins, addrs, labels, rdata)


def _run_smoke() -> int:
    print('== 常量串无 %n → SUPPRESS ==')
    INS_CONST = [
        'lea rcx, [rip+0x100]        # 0x14000b000',
        'mov edx, 0x2a',
        'call printf',
    ]
    r = run(INS_CONST, rdata={0x14000b000: 'value=%d\\n'})
    check('const suppressed', r.stats.suppressed == 1,
          f'sup={r.stats.suppressed} kept={len(r.kept)}')

    print('== 参数不足 → CONFIRM ==')
    INS_SHORT = [
        'lea rcx, [rip+0x100]        # 0x14000b000',
        'call printf',
    ]
    r = run(INS_SHORT, rdata={0x14000b000: '%d %d %d\\n'})
    check('short args confirmed', r.stats.confirmed == 1,
          f'cfm={r.stats.confirmed}')

    print('== 参数充足 → SUPPRESS ==')
    INS_OK = [
        'lea rcx, [rip+0x100]        # 0x14000b000',
        'mov edx, 0x2a',
        'mov r8d, 0x2b',
        'mov r9d, 0x2c',
        'call printf',
    ]
    r = run(INS_OK, rdata={0x14000b000: '%d %d %d\\n'})
    check('args sufficient suppressed', r.stats.suppressed == 1,
          f'sup={r.stats.suppressed}')

    print('== 输入源 → CONFIRM ==')
    INS_INPUT = [
        'mov rcx, [rbp-0x8]',
        'call gets',
        'mov [rbp-0x8], rax',
        'mov rcx, [rbp-0x8]',
        'call printf',
    ]
    r = run(INS_INPUT)
    check('input confirmed', r.stats.confirmed == 1,
          f'cfm={r.stats.confirmed}')

    print('== 常量透传 vprintf → SUPPRESS ==')
    INS_WRAP = [
        'push rbp',
        'mov rbp, rsp',
        'mov [rbp+0x10], rcx',
        'mov rcx, [rbp+0x10]',
        'call vprintf',
        'pop rbp',
        'ret',
        'lea rcx, [rip+0x100]        # 0x14000b000',
        'call my_log',
    ]
    labels = [('my_log', 0)]
    r = run(INS_WRAP, labels=labels,
            rdata={0x14000b000: 'hello %s\\n'})
    check('wrapper const suppressed', r.stats.suppressed == 1,
          f'sup={r.stats.suppressed} kept={len(r.kept)}')

    print(f'\nRESULT: {"ALL PASS" if not FAIL else "FAILED: " + ",".join(FAIL)}')
    return 1 if FAIL else 0


def test_fmtog_smoke():
    """Fmt-OG 冒烟路径的 pytest 入口。"""
    assert _run_smoke() == 0


if __name__ == '__main__':
    sys.exit(_run_smoke())
