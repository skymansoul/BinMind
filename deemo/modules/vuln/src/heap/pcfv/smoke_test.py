"""PCFV 冒烟测试 — 在 fp_reduction 样本集上验证判定正确性."""
import glob
import os
import sys

sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\src\heap')

from pcfv import analyze_heap_pcfv

EXPECT_SAFE = {
    'fp_01_alignment_safe', 'fp_02_path_constrained', 'fp_03_struct_field',
    'fp_04_realloc_shrink', 'fp_05_min_constrained', 'fp_06_sample',
    'fp_07_sample', 'fp_10_sample', 'fp_13_sample', 'fp_14_sample',
}

def main():
    total = ok = 0
    for exe in sorted(glob.glob(
            r'C:\Users\Administrator\Desktop\BinMind\deemo\eval\fp_cve_experiment\corpus\bin\*.exe')):
        name = os.path.basename(exe)[:-4]
        r = analyze_heap_pcfv(exe)
        kept = r.confirmed + r.likely + r.uncertain
        expected_safe = name in EXPECT_SAFE
        pass_ = (kept == 0) == expected_safe
        total += 1
        ok += 1 if pass_ else 0
        print('%s raw=%2d conf=%d likely=%d uncert=%d filt=%2d -> %s %s err=%s' % (
            name.ljust(28), r.raw_findings, r.confirmed, r.likely,
            r.uncertain, r.filtered_fp,
            'FILTER' if kept == 0 else 'KEEP',
            'OK' if pass_ else 'MISMATCH', r.error))
        if not pass_:
            for fv in r.verdicts:
                if expected_safe and fv.is_kept:
                    print('   kept:', fv.access_kind, hex(fv.insn_addr),
                          'alloc=', fv.alloc_size, 'off=',
                          fv.offset_info.summary if fv.offset_info else None,
                          [e.rule.name for e in fv.evidences])
    print('=' * 60)
    print('PASS %d/%d' % (ok, total))
    return 0 if ok == total else 1


if __name__ == '__main__':
    sys.exit(main())
