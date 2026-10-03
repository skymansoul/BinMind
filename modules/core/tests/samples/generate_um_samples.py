# coding: utf-8
"""Uninitialized Memory CVE 基准样本集 — 10 个样本覆盖各种 UM 模式."""

import json
from pathlib import Path

_SAMPLES_DIR = Path(__file__).resolve().parent

SAMPLES = [
    {'id': 'um_cve_01', 'cve': 'CVE-2017-1000251', 'title': 'Uninitialized stack variable',
     'alloc_sz': 64, 'write_start': 0, 'write_end': 0, 'read_start': 0, 'read_end': 8,
     'is_vuln': True, 'category': 'fully_uninit'},
    {'id': 'um_cve_02', 'cve': 'CVE-2018-1000021', 'title': 'Partial init → partial read beyond',
     'alloc_sz': 64, 'write_start': 0, 'write_end': 32, 'read_start': 16, 'read_end': 48,
     'is_vuln': True, 'category': 'partial_uninit'},
    {'id': 'um_cve_03', 'cve': 'CVE-2019-10126', 'title': 'Heap alloc → uninit field read',
     'alloc_sz': 128, 'write_start': 0, 'write_end': 64, 'read_start': 80, 'read_end': 96,
     'is_vuln': True, 'category': 'heap_uninit_field'},
    {'id': 'um_cve_04', 'cve': 'CVE-2020-10732', 'title': 'Realloc without init',
     'alloc_sz': 64, 'write_start': 0, 'write_end': 0, 'read_start': 0, 'read_end': 64,
     'is_vuln': True, 'category': 'realloc_no_init'},
    {'id': 'um_cve_05', 'cve': 'CVE-2019-7222', 'title': 'Kernel info leak via uninit memory',
     'alloc_sz': 256, 'write_start': 0, 'write_end': 128, 'read_start': 128, 'read_end': 256,
     'is_vuln': True, 'category': 'info_leak_um'},
    {'id': 'um_cve_06', 'cve': 'CVE-2018-1000200', 'title': 'Conditional init → uninit on path',
     'alloc_sz': 64, 'write_start': 0, 'write_end': 0, 'read_start': 0, 'read_end': 32,
     'is_vuln': True, 'category': 'conditional_uninit'},
    {'id': 'um_cve_07', 'cve': 'CVE-2021-3347', 'title': 'Struct padding uninit leak',
     'alloc_sz': 32, 'write_start': 0, 'write_end': 24, 'read_start': 24, 'read_end': 32,
     'is_vuln': True, 'category': 'padding_uninit'},
    {'id': 'um_cve_08', 'cve': 'CVE-2022-0171', 'title': 'Memset partial then full read',
     'alloc_sz': 96, 'write_start': 0, 'write_end': 48, 'read_start': 48, 'read_end': 96,
     'is_vuln': True, 'category': 'memset_partial'},
    {'id': 'um_cve_09', 'cve': 'SAFE-UM-001', 'title': 'Safe: fully written before read',
     'alloc_sz': 64, 'write_start': 0, 'write_end': 64, 'read_start': 0, 'read_end': 8,
     'is_vuln': False, 'category': 'safe_full_write'},
    {'id': 'um_cve_10', 'cve': 'SAFE-UM-002', 'title': 'Safe: memset zero + write → read',
     'alloc_sz': 128, 'write_start': 0, 'write_end': 128, 'read_start': 32, 'read_end': 64,
     'is_vuln': False, 'category': 'safe_initialized'},
]


def generate_all_samples():
    gt = {'samples': {}, 'summary': {
        'total': len(SAMPLES),
        'um_vuln': sum(1 for s in SAMPLES if s['is_vuln']),
        'um_safe': sum(1 for s in SAMPLES if not s['is_vuln']),
    }}

    for s in SAMPLES:
        sample_dir = _SAMPLES_DIR / s['id']
        sample_dir.mkdir(exist_ok=True)
        (sample_dir / 'vuln.c').write_text(_um_c_code(s), encoding='utf-8')
        (sample_dir / 'Makefile').write_text(_um_makefile(s), encoding='utf-8')
        (sample_dir / 'README.md').write_text(_um_readme(s), encoding='utf-8')
        gt['samples'][s['id']] = {
            'cve': s['cve'], 'title': s['title'],
            'category': s['category'], 'is_vuln': s['is_vuln'],
            'alloc_sz': s['alloc_sz'],
            'write_start': s['write_start'], 'write_end': s['write_end'],
            'read_start': s['read_start'], 'read_end': s['read_end'],
        }

    gt_path = _SAMPLES_DIR / 'um_ground_truth.json'
    with open(gt_path, 'w', encoding='utf-8') as f:
        json.dump(gt, f, indent=2, ensure_ascii=False)
    print(f'Generated {len(SAMPLES)} UM samples -> {_SAMPLES_DIR}')
    return gt


def _um_c_code(s: dict) -> str:
    codes = {
        'fully_uninit': '#include <stdlib.h>\n#include <string.h>\nvoid vuln(){char*b=malloc(64);printf("%02x",b[0]);}\nint main(){vuln();}',
        'partial_uninit': '#include <stdlib.h>\n#include <string.h>\nvoid vuln(){char*b=malloc(64);memset(b,0,32);printf("%02x",b[40]);}\nint main(){vuln();}',
        'heap_uninit_field': '#include <stdlib.h>\n#include <string.h>\nstruct S{char pad[80];int x;};void vuln(){struct S*s=malloc(128);memset(s,0,64);printf("%d",s->x);}\nint main(){vuln();}',
        'realloc_no_init': '#include <stdlib.h>\nvoid vuln(){char*b=malloc(32);b=realloc(b,64);printf("%02x",b[32]);}\nint main(){vuln();}',
        'info_leak_um': '#include <stdlib.h>\n#include <string.h>\nvoid vuln(){char*b=malloc(256);memset(b,0,128);write(1,b,256);}\nint main(){vuln();}',
        'conditional_uninit': '#include <stdlib.h>\nvoid vuln(int x){char*b=malloc(64);if(x>0)memset(b,0,64);printf("%02x",b[0]);}\nint main(){vuln(0);}',
        'padding_uninit': '#include <stdlib.h>\n#include <string.h>\nstruct P{short a;int b;long c;char d;};void vuln(){struct P*p=malloc(32);memset(p,0,24);write(1,p,32);}\nint main(){vuln();}',
        'memset_partial': '#include <stdlib.h>\n#include <string.h>\nvoid vuln(){char*b=malloc(96);memset(b,0,48);printf("%s",b+48);}\nint main(){vuln();}',
        'safe_full_write': '#include <stdlib.h>\n#include <string.h>\nvoid safe(){char*b=malloc(64);memset(b,0xAB,64);printf("%02x",b[0]);}\nint main(){safe();}',
        'safe_initialized': '#include <stdlib.h>\n#include <string.h>\nvoid safe(){char*b=malloc(128);memset(b,0,128);printf("%02x",b[32]);}\nint main(){safe();}',
    }
    return codes.get(s['category'], '#include <stdlib.h>\nint main(){malloc(64);}')


def _um_makefile(s: dict) -> str:
    return (f'CC = gcc\nCFLAGS = -Wall -O0 -g\nTARGET = {s["id"]}\n\n'
            f'all: $(TARGET)\n\n$(TARGET): vuln.c\n'
            f'\t$(CC) $(CFLAGS) -o $(TARGET) vuln.c\n\n'
            f'clean:\n\trm -f $(TARGET) *.o\n\nrun: $(TARGET)\n\t./$(TARGET)\n')


def _um_readme(s: dict) -> str:
    return (f'# {s["id"]}: {s["title"]}\n\n'
            f'- **CVE**: {s["cve"]}\n- **Category**: {s["category"]}\n'
            f'- **Is Vuln**: {s["is_vuln"]}\n'
            f'- **alloc={s["alloc_sz"]}, write=[{s["write_start"]},{s["write_end"]}), '
            f'read=[{s["read_start"]},{s["read_end"]})\n')


if __name__ == '__main__':
    generate_all_samples()
