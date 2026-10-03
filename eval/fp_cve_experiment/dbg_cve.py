"""调试 — safe_13 / safe_15 / cve_2023_0464 判定链路."""
import sys

sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\src\heap')

from pcfv.pipeline import _disassemble, _parse_functions
from pcfv.access_extractor import AccessExtractor
from pcfv.loop_bound import LoopBoundExtractor
from pcfv.engine import PCFVEngine

CORPUS = r'C:\Users\Administrator\Desktop\BinMind\deemo\eval\fp_cve_experiment\corpus'

for sid in ('safe_13_guard_index', 'safe_15_loop_in_bounds',
            'cve_2023_0464_openssl', 'cve_2022_23222_bpf'):
    exe = CORPUS + '\\' + sid + '\\vuln.exe'
    asm = _disassemble(exe, 60)
    print('====', sid)
    for name, insns in _parse_functions(asm):
        ex = AccessExtractor(name, insns)
        if not ex.accesses:
            continue
        lbx = LoopBoundExtractor(insns, ex.tracer)
        for acc in ex.accesses:
            loop = lbx.is_in_loop(acc['addr'])
            if loop:
                acc['kind'] = 'loop_store'
                acc['loop_iters'] = loop['iters']
                acc['loop_stride'] = loop['stride']
            eng = PCFVEngine()
            fv = eng.evaluate_access(acc, ex.mallocs, insns)
            print('  fn=%s kind=%s base=%s off=%s verdict=%s alloc=%s' % (
                name, acc['kind'], acc.get('base_ptr') or acc.get('dst_info'),
                acc.get('offset_info') and acc['offset_info'].summary,
                fv.verdict.name, fv.alloc_size))
            for e in fv.evidences:
                print('     ev:', e.rule.name, '|', e.detail[:110])
