"""分配契约流保持引擎冒烟测试 — 覆盖三证据链与压制/确认路径."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acfpc.def_chain import DefChainTracker
from acfpc.alloc_contract import AllocContractExtractor
from acfpc.write_coupling import WriteCouplingAnalyzer, Coupling
from acfpc.guard_dominance import GuardDominanceChecker
from acfpc.allocator_geometry import usable_size, write_fits, overflow_bytes
from acfpc.fp_compressor import FpCompressor

FAIL = []


def check(name, cond, extra=''):
    print(f'  [{"PASS" if cond else "FAIL"}] {name} {extra}')
    if not cond:
        FAIL.append(name)

print('== allocator geometry ==')
check('usable(40)=40', usable_size(40) == 40, f'got {usable_size(40)}')
check('usable(24)=24', usable_size(24) == 24, f'got {usable_size(24)}')
check('usable(0)=0 strict', usable_size(0) == 0, f'got {usable_size(0)}')
check('glibc usable(40)=40', usable_size(40, 'glibc') == 40,
      f'got {usable_size(40, "glibc")}')
check('glibc usable(41)=56', usable_size(41, 'glibc') == 56,
      f'got {usable_size(41, "glibc")}')
check('fits(40,0,40)', write_fits(40, 0, 40))
check('not fits(40,0,48)', not write_fits(40, 0, 48))
check('overflow(40,0,48)=8', overflow_bytes(40, 0, 48) == 8)

def _run_smoke() -> int:
    print('== allocator geometry ==')
    check('usable(40)=40', usable_size(40) == 40, f'got {usable_size(40)}')
    check('usable(24)=24', usable_size(24) == 24, f'got {usable_size(24)}')
    check('usable(0)=0 strict', usable_size(0) == 0, f'got {usable_size(0)}')
    check('glibc usable(40)=40', usable_size(40, 'glibc') == 40,
          f'got {usable_size(40, "glibc")}')
    check('glibc usable(41)=56', usable_size(41, 'glibc') == 56,
          f'got {usable_size(41, "glibc")}')
    check('fits(40,0,40)', write_fits(40, 0, 40))
    check('not fits(40,0,48)', not write_fits(40, 0, 48))
    check('overflow(40,0,48)=8', overflow_bytes(40, 0, 48) == 8)

    INS_SAME = [
        'mov [rbp-0x8], rdx',
        'mov rcx, [rbp-0x8]',
        'call malloc',
        'mov [rbp-0x10], rax',
        'mov r8, [rbp-0x8]',
        'mov rdx, r8',
        'mov rcx, [rbp-0x10]',
        'call memcpy',
    ]
    INS_GUARD = [
        'mov ecx, 0x100',
        'call malloc',
        'mov edx, [rbp-0x10]',
        'cmp edx, 0x100',
        'jbe 0x401000',
        'mov r8, rdx',
        'call memcpy',
    ]
    INS_CONST_OVF = [
        'mov ecx, 0x40',
        'call malloc',
        'mov r8, 0x100',
        'call memcpy',
    ]

    def run(ins):
        t = DefChainTracker()
        t.scan(ins)
        ex = AllocContractExtractor(t)
        cs = ex.extract()
        return t, cs

    print('== coupling ==')
    t, cs = run(INS_SAME)
    check('contract found', len(cs) == 1, f'n={len(cs)}')
    if cs:
        c = cs[0]
        check('size slot', c.size_kind == 'SLOT', c.describe())
        wa = WriteCouplingAnalyzer(t)
        snaps = [s for s in t.calls() if s.callee == 'memcpy']
        check('memcpy found', len(snaps) == 1)
        if snaps:
            v = wa.judge(c, snaps[0])
            check('COUPLED', v.verdict == Coupling.COUPLED, v.reason)

    print('== guard dominance ==')
    t, cs = run(INS_GUARD)
    check('contract imm 0x100', cs and cs[0].size_kind == 'IMM' and cs[0].size_imm == 0x100)
    if cs:
        gd = GuardDominanceChecker(t)
        snaps = [s for s in t.calls() if s.callee == 'memcpy']
        gs = gd.collect(INS_GUARD, snaps[0].insn_idx) if snaps else []
        check('guard collected', len(gs) >= 1, f'n={len(gs)}')
        if snaps:
            wa = WriteCouplingAnalyzer(t)
            wnode = wa.write_size_node(snaps[0])
            bound = gd.size_guard_bound(gs, wnode)
            check('guard bound 0x100', bound == 0x100, f'got {bound}')
            bounded, reason = gd.prove_write_within(gs, wnode, usable_size(0x100))
            check('prove within', bounded, reason)

    print('== const overflow confirm ==')
    t, cs = run(INS_CONST_OVF)
    check('contract 0x40', cs and cs[0].size_imm == 0x40)
    if cs:
        wa = WriteCouplingAnalyzer(t)
        snaps = [s for s in t.calls() if s.callee == 'memcpy']
        wimm = wa.write_size_imm(snaps[0]) if snaps else None
        check('write imm 0x100', wimm == 0x100, f'got {wimm}')
        check('overflow == 0x100-usable(0x40)',
              overflow_bytes(cs[0].size_imm, 0, wimm or 0)
              == 0x100 - usable_size(0x40),
              f'{overflow_bytes(cs[0].size_imm, 0, wimm or 0)}')

    print('== compressor integration ==')
    findings = [{'insn_addr': 0x401003, 'semantic_score': 0.6, 'confidence': 0.6,
                 'description': 'memcpy overflow'}]
    addrs = [0x401000, 0x401001, 0x401002, 0x401003]
    r = FpCompressor().compress(INS_CONST_OVF, findings, addrs)
    check('confirm mapped', len(r.kept) == 1 and r.stats.confirmed >= 1,
          f'kept={len(r.kept)} confirmed={r.stats.confirmed}')

    f2 = [{'insn_addr': 0x401007, 'semantic_score': 0.55, 'confidence': 0.55}]
    a2 = [0x401000, 0x401001, 0x401002, 0x401003,
          0x401004, 0x401005, 0x401006, 0x401007]
    r2 = FpCompressor().compress(INS_SAME, f2, a2)
    check('coupling suppressed', len(r2.kept) == 0 and r2.stats.suppressed >= 1,
          f'kept={len(r2.kept)} suppressed={r2.stats.suppressed}')

    print(f'\nRESULT: {"ALL PASS" if not FAIL else "FAILED: " + ",".join(FAIL)}')
    return 1 if FAIL else 0


def test_acfpc_smoke():
    """分配契约流保持引擎冒烟路径的 pytest 入口。"""
    assert _run_smoke() == 0


if __name__ == '__main__':
    sys.exit(_run_smoke())
