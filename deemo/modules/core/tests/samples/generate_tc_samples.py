# coding: utf-8
"""Type Confusion CVE 基准样本集 — 10 个样本覆盖各种 TC 模式."""

import json
from pathlib import Path

_SAMPLES_DIR = Path(__file__).resolve().parent

SAMPLES = [
    {'id': 'tc_cve_01', 'cve': 'CVE-2015-6097', 'title': 'Vtable hijack via type confusion',
     'alloc_sz': 16, 'vtable': 0x4000, 'access_offset': 24, 'cast_size': 32,
     'is_vuln': True, 'category': 'vtable_hijack'},
    {'id': 'tc_cve_02', 'cve': 'CVE-2016-0189', 'title': 'Downcast confusion (Base→Derived mismatch)',
     'alloc_sz': 16, 'vtable': 0x5000, 'access_offset': 16, 'cast_size': 32,
     'is_vuln': True, 'category': 'downcast_mismatch'},
    {'id': 'tc_cve_03', 'cve': 'CVE-2017-8543', 'title': 'Reinterpret_cast size conflict',
     'alloc_sz': 8, 'vtable': 0x6000, 'access_offset': 12, 'cast_size': 24,
     'is_vuln': True, 'category': 'reinterpret_conflict'},
    {'id': 'tc_cve_04', 'cve': 'CVE-2018-8174', 'title': 'Vtable pointer overwrite via UAF',
     'alloc_sz': 24, 'vtable': 0x7000, 'access_offset': 0, 'cast_size': 0,
     'is_vuln': True, 'category': 'vtable_overwrite'},
    {'id': 'tc_cve_05', 'cve': 'CVE-2019-0943', 'title': 'Multiple cast size conflict',
     'alloc_sz': 16, 'vtable': 0x8000, 'access_offset': 8, 'cast_size': 48,
     'is_vuln': True, 'category': 'multi_cast'},
    {'id': 'tc_cve_06', 'cve': 'CVE-2020-0674', 'title': 'Field access OOB via wrong type',
     'alloc_sz': 24, 'vtable': 0x9000, 'access_offset': 32, 'cast_size': 0,
     'is_vuln': True, 'category': 'field_oob'},
    {'id': 'tc_cve_07', 'cve': 'CVE-2021-26411', 'title': 'Dynamic_cast fail → use as wrong type',
     'alloc_sz': 32, 'vtable': 0xA000, 'access_offset': 40, 'cast_size': 64,
     'is_vuln': True, 'category': 'dynamic_cast_fail'},
    {'id': 'tc_cve_08', 'cve': 'CVE-2022-21846', 'title': 'Static_cast incorrect downcast',
     'alloc_sz': 16, 'vtable': 0xB000, 'access_offset': 20, 'cast_size': 40,
     'is_vuln': True, 'category': 'static_downcast'},
    {'id': 'tc_cve_09', 'cve': 'SAFE-TC-001', 'title': 'Safe: correct cast within bounds',
     'alloc_sz': 32, 'vtable': 0xC000, 'access_offset': 8, 'cast_size': 0,
     'is_vuln': False, 'category': 'safe_bounds'},
    {'id': 'tc_cve_10', 'cve': 'SAFE-TC-002', 'title': 'Safe: single type, no cast confusion',
     'alloc_sz': 64, 'vtable': 0xD000, 'access_offset': 16, 'cast_size': 0,
     'is_vuln': False, 'category': 'safe_single_type'},
]


def generate_all_samples():
    gt = {'samples': {}, 'summary': {
        'total': len(SAMPLES),
        'tc_vuln': sum(1 for s in SAMPLES if s['is_vuln']),
        'tc_safe': sum(1 for s in SAMPLES if not s['is_vuln']),
    }}

    for s in SAMPLES:
        sample_dir = _SAMPLES_DIR / s['id']
        sample_dir.mkdir(exist_ok=True)
        (sample_dir / 'vuln.c').write_text(_tc_c_code(s), encoding='utf-8')
        (sample_dir / 'Makefile').write_text(_tc_makefile(s), encoding='utf-8')
        (sample_dir / 'README.md').write_text(_tc_readme(s), encoding='utf-8')
        gt['samples'][s['id']] = {
            'cve': s['cve'], 'title': s['title'],
            'category': s['category'], 'is_vuln': s['is_vuln'],
            'alloc_sz': s['alloc_sz'], 'access_offset': s['access_offset'],
            'cast_size': s['cast_size'],
        }

    gt_path = _SAMPLES_DIR / 'tc_ground_truth.json'
    with open(gt_path, 'w', encoding='utf-8') as f:
        json.dump(gt, f, indent=2, ensure_ascii=False)
    print(f'Generated {len(SAMPLES)} TC samples -> {_SAMPLES_DIR}')
    return gt


def _tc_c_code(s: dict) -> str:
    codes = {
        'vtable_hijack': '#include <stdlib.h>\nstruct A{void*v;int x;};void vuln(){struct A*a=malloc(16);a->v=(void*)0x4000;a->x=42;}\nint main(){vuln();}',
        'downcast_mismatch': '#include <stdlib.h>\nstruct B{void*v;int x;};struct D{void*v;int x;long y;};void vuln(){struct B*b=malloc(16);((struct D*)b)->y=0;}\nint main(){vuln();}',
        'reinterpret_conflict': '#include <stdlib.h>\nstruct X{void*v;};struct Y{void*v;int a;long b;};void vuln(){struct X*x=malloc(8);((struct Y*)x)->b=0;}\nint main(){vuln();}',
        'vtable_overwrite': '#include <stdlib.h>\n#include <string.h>\nstruct V{void*v;};void vuln(){struct V*p=malloc(24);p->v=(void*)0x7000;}\nint main(){vuln();}',
        'multi_cast': '#include <stdlib.h>\nstruct S{void*v;int x;};struct L{void*v;int x;long y;long z;};void vuln(){struct S*s=malloc(16);((struct L*)s)->z=1;}\nint main(){vuln();}',
        'field_oob': '#include <stdlib.h>\nstruct C{void*v;int a;int b;};struct E{void*v;long x;long y;long z;};void vuln(){struct C*c=malloc(24);((struct E*)c)->z=0;}\nint main(){vuln();}',
        'dynamic_cast_fail': '#include <stdlib.h>\nstruct P{void*v;int x;int y;int z;};struct Q{void*v;int a;int b;int c;int d;int e;};void vuln(){struct P*p=malloc(32);((struct Q*)p)->e=0;}\nint main(){vuln();}',
        'static_downcast': '#include <stdlib.h>\nstruct R{void*v;int x;};struct T{void*v;int x;long y;long z;};void vuln(){struct R*r=malloc(16);((struct T*)r)->z=0;}\nint main(){vuln();}',
        'safe_bounds': '#include <stdlib.h>\nstruct U{void*v;int x;int y;int z;};void safe(){struct U*u=malloc(32);u->x=42;}\nint main(){safe();}',
        'safe_single_type': '#include <stdlib.h>\nstruct W{void*v;int a;int b;int c;int d;};void safe(){struct W*w=malloc(64);w->a=1;}\nint main(){safe();}',
    }
    return codes.get(s['category'], '#include <stdlib.h>\nint main(){malloc(64);}')


def _tc_makefile(s: dict) -> str:
    return (f'CC = gcc\nCFLAGS = -Wall -O0 -g\nTARGET = {s["id"]}\n\n'
            f'all: $(TARGET)\n\n$(TARGET): vuln.c\n'
            f'\t$(CC) $(CFLAGS) -o $(TARGET) vuln.c\n\n'
            f'clean:\n\trm -f $(TARGET) *.o\n\nrun: $(TARGET)\n\t./$(TARGET)\n')


def _tc_readme(s: dict) -> str:
    return (f'# {s["id"]}: {s["title"]}\n\n'
            f'- **CVE**: {s["cve"]}\n- **Category**: {s["category"]}\n'
            f'- **Is Vuln**: {s["is_vuln"]}\n'
            f'- **alloc={s["alloc_sz"]}, access_offset={s["access_offset"]}, '
            f'cast_size={s["cast_size"]}\n')


if __name__ == '__main__':
    generate_all_samples()
