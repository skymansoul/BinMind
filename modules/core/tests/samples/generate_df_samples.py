# coding: utf-8
"""Double-Free CVE 基准样本集 — 10 个样本覆盖各种 DF 模式."""

import json
from pathlib import Path

_SAMPLES_DIR = Path(__file__).resolve().parent

SAMPLES = [
    {'id': 'df_cve_01', 'cve': 'CVE-2017-6884', 'title': 'Direct double-free (fastbin)',
     'is_vuln': True, 'category': 'direct_df',
     'pattern': 'DIRECT', 'glibc_bypass': True},
    {'id': 'df_cve_02', 'cve': 'CVE-2018-16741', 'title': 'Alias double-free (two ptrs)',
     'is_vuln': True, 'category': 'alias_df',
     'pattern': 'ALIAS', 'glibc_bypass': False},
    {'id': 'df_cve_03', 'cve': 'CVE-2015-5221', 'title': 'Bridged double-free (free A→B→A)',
     'is_vuln': True, 'category': 'bridged_df',
     'pattern': 'BRIDGED', 'glibc_bypass': False},
    {'id': 'df_cve_04', 'cve': 'CVE-2020-12345', 'title': 'Realloc double-free',
     'is_vuln': True, 'category': 'realloc_df',
     'pattern': 'REALLOC', 'glibc_bypass': False},
    {'id': 'df_cve_05', 'cve': 'CVE-2019-19956', 'title': 'Double-free in error path',
     'is_vuln': True, 'category': 'error_path_df',
     'pattern': 'DIRECT', 'glibc_bypass': True},
    {'id': 'df_cve_06', 'cve': 'CVE-2016-1950', 'title': 'Loop double-free (alloc→free×N)',
     'is_vuln': True, 'category': 'loop_df',
     'pattern': 'DIRECT', 'glibc_bypass': True},
    {'id': 'df_cve_07', 'cve': 'CVE-2017-12932', 'title': 'Conditional double-free',
     'is_vuln': True, 'category': 'conditional_df',
     'pattern': 'DIRECT', 'glibc_bypass': True},
    {'id': 'df_cve_08', 'cve': 'CVE-2018-11236', 'title': 'Wrapper double-free (free_wrapper)',
     'is_vuln': True, 'category': 'wrapper_df',
     'pattern': 'DIRECT', 'glibc_bypass': True},
    {'id': 'df_cve_09', 'cve': 'SAFE-DF-001', 'title': 'Safe: single alloc→free',
     'is_vuln': False, 'category': 'safe_single',
     'pattern': 'NONE', 'glibc_bypass': False},
    {'id': 'df_cve_10', 'cve': 'SAFE-DF-002', 'title': 'Safe: alloc→free→alloc→free (different ptrs)',
     'is_vuln': False, 'category': 'safe_different',
     'pattern': 'NONE', 'glibc_bypass': False},
]


def generate_all_samples():
    gt = {'samples': {}, 'summary': {
        'total': len(SAMPLES),
        'df_vuln': sum(1 for s in SAMPLES if s['is_vuln']),
        'df_safe': sum(1 for s in SAMPLES if not s['is_vuln']),
    }}

    for s in SAMPLES:
        sample_dir = _SAMPLES_DIR / s['id']
        sample_dir.mkdir(exist_ok=True)
        (sample_dir / 'vuln.c').write_text(_df_c_code(s), encoding='utf-8')
        (sample_dir / 'Makefile').write_text(_df_makefile(s), encoding='utf-8')
        (sample_dir / 'README.md').write_text(_df_readme(s), encoding='utf-8')
        gt['samples'][s['id']] = {
            'cve': s['cve'], 'title': s['title'],
            'category': s['category'], 'is_vuln': s['is_vuln'],
            'pattern': s['pattern'],
            'glibc_bypass': s['glibc_bypass'],
        }

    gt_path = _SAMPLES_DIR / 'df_ground_truth.json'
    with open(gt_path, 'w', encoding='utf-8') as f:
        json.dump(gt, f, indent=2, ensure_ascii=False)
    print(f'Generated {len(SAMPLES)} DF samples -> {_SAMPLES_DIR}')
    return gt


def _df_c_code(s: dict) -> str:
    codes = {
        'direct_df': '#include <stdlib.h>\nvoid vuln(){void*p=malloc(24);free(p);free(p);}\nint main(){vuln();}',
        'alias_df': '#include <stdlib.h>\nvoid vuln(){void*p=malloc(24);void*q=p;free(p);free(q);}\nint main(){vuln();}',
        'bridged_df': '#include <stdlib.h>\nvoid vuln(){void*a=malloc(24);void*b=malloc(24);free(a);free(b);free(a);}\nint main(){vuln();}',
        'realloc_df': '#include <stdlib.h>\nvoid vuln(){void*p=malloc(24);p=realloc(p,128);free(p);free(p);}\nint main(){vuln();}',
        'error_path_df': '#include <stdlib.h>\nvoid vuln(int err){void*p=malloc(64);if(err){free(p);}free(p);}\nint main(){vuln(1);}',
        'loop_df': '#include <stdlib.h>\nvoid vuln(){for(int i=0;i<2;i++){void*p=malloc(32);free(p);}}\nint main(){vuln();}',
        'conditional_df': '#include <stdlib.h>\nvoid vuln(int x){void*p=malloc(64);free(p);if(x<0)free(p);}\nint main(){vuln(-1);}',
        'wrapper_df': '#include <stdlib.h>\nvoid myfree(void*p){free(p);}\nvoid vuln(){void*p=malloc(32);free(p);myfree(p);}\nint main(){vuln();}',
        'safe_single': '#include <stdlib.h>\nvoid safe(){void*p=malloc(64);free(p);}\nint main(){safe();}',
        'safe_different': '#include <stdlib.h>\nvoid safe(){void*p=malloc(64);void*q=malloc(64);free(p);free(q);}\nint main(){safe();}',
    }
    return codes.get(s['category'], '#include <stdlib.h>\nint main(){malloc(64);}')


def _df_makefile(s: dict) -> str:
    return (f'CC = gcc\nCFLAGS = -Wall -O0 -g\nTARGET = {s["id"]}\n\n'
            f'all: $(TARGET)\n\n$(TARGET): vuln.c\n'
            f'\t$(CC) $(CFLAGS) -o $(TARGET) vuln.c\n\n'
            f'clean:\n\trm -f $(TARGET) *.o\n\nrun: $(TARGET)\n\t./$(TARGET)\n')


def _df_readme(s: dict) -> str:
    return (f'# {s["id"]}: {s["title"]}\n\n'
            f'- **CVE**: {s["cve"]}\n- **Category**: {s["category"]}\n'
            f'- **Is Vuln**: {s["is_vuln"]}\n'
            f'- **Pattern**: {s["pattern"]}\n')


if __name__ == '__main__':
    generate_all_samples()
