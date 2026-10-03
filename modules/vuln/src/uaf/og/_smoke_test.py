"""UAF-OG 冒烟测试 — 代际推进/重赋值/同代际确认."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # src

from og.gen_flow import GenState, GEN_UNKNOWN, GEN_NULL, GenFlowTracker
from og.og_filter import GenVerifier, GenVerdict
from og.og_filter import OgFilter

FAIL = []


def check(name, cond, extra=''):
    print(f'  [{"PASS" if cond else "FAIL"}] {name} {extra}')
    if not cond:
        FAIL.append(name)


PREAMBLE = [
    'mov ecx, 0x10',
    'call malloc',            # rax = gen1
    'mov [rbp-0x8], rax',     # p 槽 = gen1
    'mov ecx, 0x20',
    'call malloc',            # rax = gen2
    'mov [rbp-0x10], rax',    # q 槽 = gen2
]

def _run_smoke() -> int:
    print('== 同代际确认 (TP: free; use 同对象) ==')
    INS_UAF = PREAMBLE + [
        'mov rcx, [rbp-0x8]',
        'call free',              # free(p): rcx=gen1 → freed
        'mov rax, [rbp-0x8]',     # rax = gen1 (槽未变)
        'mov eax, DWORD PTR [rax]',
    ]
    t = GenFlowTracker()
    t.run(INS_UAF)
    finds = [{'free_line': 7, 'use_line': 9, 'use_reg': 'rax',
              'use_slot': None, 'confidence': 0.5}]
    r = OgFilter().compress(INS_UAF, finds)
    check('same-gen kept', len(r.kept) == 1 and r.stats.same_gen == 1,
          f'kept={len(r.kept)} same={r.stats.same_gen}')

    print('== 重赋值推进代际 (TN: free; p=q; use) ==')
    INS_REASSIGN = PREAMBLE + [
        'mov rcx, [rbp-0x8]',
        'call free',              # free(p)
        'mov rax, [rbp-0x10]',    # rax = gen2 (q)
        'mov [rbp-0x8], rax',     # p 槽 = gen2 → 代际推进
        'mov rax, [rbp-0x8]',
        'mov eax, DWORD PTR [rax]',
    ]
    t2 = GenFlowTracker()
    t2.run(INS_REASSIGN)
    finds2 = [{'free_line': 7, 'use_line': 11, 'use_reg': 'rax',
               'use_slot': None, 'confidence': 0.6}]
    r2 = OgFilter().compress(INS_REASSIGN, finds2)
    check('reassign suppressed', len(r2.kept) == 0 and r2.stats.diff_gen == 1,
          f'kept={len(r2.kept)} diff={r2.stats.diff_gen}')
    if r2.suppressed:
        print('   reason:', r2.suppressed[0].get('og_reason', ''))

    print('== NULL 赋值 (TN: free; p=NULL; 条件 use) ==')
    INS_NULL = PREAMBLE + [
        'mov rcx, [rbp-0x8]',
        'call free',
        'mov QWORD PTR [rbp-0x8], 0x0',
        'mov rax, [rbp-0x8]',
        'test rax, rax',
        'je 0x140001000',
    ]
    t3 = GenFlowTracker()
    t3.run(INS_NULL)
    finds3 = [{'free_line': 7, 'use_line': 10, 'use_reg': 'rax',
               'use_slot': None, 'confidence': 0.5}]
    r3 = OgFilter().compress(INS_NULL, finds3)
    check('null suppressed', len(r3.kept) == 0 and r3.stats.diff_gen == 1,
          f'kept={len(r3.kept)} diff={r3.stats.diff_gen}')

    print('== 真实编译模式: QWORD PTR 前缀 ==')
    INS_REAL = PREAMBLE + [
        'mov rcx, QWORD PTR [rbp-0x8]',
        'call free',
        'mov rax, QWORD PTR [rbp-0x10]',
        'mov QWORD PTR [rbp-0x8], rax',
        'mov rax, QWORD PTR [rbp-0x8]',
        'mov eax, DWORD PTR [rax]',
    ]
    t4 = GenFlowTracker()
    t4.run(INS_REAL)
    finds4 = [{'free_line': 7, 'use_line': 11, 'use_reg': 'rax',
               'use_slot': None, 'confidence': 0.6}]
    r4 = OgFilter().compress(INS_REAL, finds4)
    check('real reassign suppressed', len(r4.kept) == 0 and r4.stats.diff_gen == 1,
          f'kept={len(r4.kept)} diff={r4.stats.diff_gen}')

    print(f'\nRESULT: {"ALL PASS" if not FAIL else "FAILED: " + ",".join(FAIL)}')
    return 1 if FAIL else 0


def test_og_smoke():
    """UAF-OG 冒烟路径的 pytest 入口。"""
    assert _run_smoke() == 0


if __name__ == '__main__':
    sys.exit(_run_smoke())
