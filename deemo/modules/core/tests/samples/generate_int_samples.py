# -*- coding: utf-8 -*-
"""整数溢出 CVE 基准样本集 — 10 个样本覆盖各种溢出模式."""

import json
from pathlib import Path

_SAMPLES_DIR = Path(__file__).resolve().parent

SAMPLES = [
    {'id': 'int_cve_01', 'cve': 'CVE-2021-31566', 'title': 'Mul overflow → heap undersize',
     'op': 'mul', 'left': 'nitems', 'right': 'size', 'width': 32, 'signed': False,
     'is_vuln': True, 'category': 'mul_heap_alloc',
     'left_range': (0, 65536), 'right_range': (0, 65536)},
    {'id': 'int_cve_02', 'cve': 'CVE-2019-13135', 'title': 'Add overflow → buffer overrun',
     'op': 'add', 'left': 'offset', 'right': 'len', 'width': 32, 'signed': False,
     'is_vuln': True, 'category': 'add_buffer',
     'left_range': (0x7FFFFFF0, 0xFFFFFFFF), 'right_range': (0, 256)},
    {'id': 'int_cve_03', 'cve': 'CVE-2020-10713', 'title': 'Truncation → size bypass',
     'op': 'trunc', 'left': 'size64', 'right': '', 'width': 32, 'signed': False,
     'is_vuln': True, 'category': 'truncation',
     'left_range': (0x100000000, 0x100000100), 'right_range': (0, 0)},
    {'id': 'int_cve_04', 'cve': 'CVE-2018-1000001', 'title': 'Signed→unsigned conversion',
     'op': 'sub', 'left': 'len', 'right': '1', 'width': 32, 'signed': True,
     'is_vuln': True, 'category': 'signed_unsigned',
     'left_range': (0, 0), 'right_range': (0, 1)},
    {'id': 'int_cve_05', 'cve': 'CVE-2017-1000112', 'title': 'Left shift overflow',
     'op': 'shl', 'left': 'val', 'right': 'shift', 'width': 32, 'signed': False,
     'is_vuln': True, 'category': 'shift_overflow',
     'left_range': (1, 0x10000000), 'right_range': (4, 8)},
    {'id': 'int_cve_06', 'cve': 'CVE-2016-2177', 'title': 'Mul overflow in length calc',
     'op': 'mul', 'left': 'count', 'right': 'sizeof_elem', 'width': 32, 'signed': False,
     'is_vuln': True, 'category': 'mul_length',
     'left_range': (0, 0x10000000), 'right_range': (16, 16)},
    {'id': 'int_cve_07', 'cve': 'CVE-2022-22817', 'title': 'Narrowing cast overflow',
     'op': 'trunc', 'left': 'large', 'right': '', 'width': 16, 'signed': False,
     'is_vuln': True, 'category': 'narrowing',
     'left_range': (65536, 131072), 'right_range': (0, 0)},
    {'id': 'int_cve_08', 'cve': 'CVE-2020-35516', 'title': 'Sub overflow → negative alloc',
     'op': 'sub', 'left': 'allocated', 'right': 'used', 'width': 32, 'signed': True,
     'is_vuln': True, 'category': 'sub_underflow',
     'left_range': (0, 100), 'right_range': (200, 300)},
    {'id': 'int_cve_09', 'cve': 'SAFE-INT-001', 'title': 'Safe: bounds check before mul',
     'op': 'mul', 'left': 'x', 'right': 'y', 'width': 32, 'signed': False,
     'is_vuln': False, 'category': 'safe_bounds',
     'left_range': (0, 100), 'right_range': (0, 100)},
    {'id': 'int_cve_10', 'cve': 'SAFE-INT-002', 'title': 'Safe: small operands, no overflow',
     'op': 'add', 'left': 'a', 'right': 'b', 'width': 64, 'signed': False,
     'is_vuln': False, 'category': 'safe_small',
     'left_range': (0, 1000), 'right_range': (0, 1000)},
]


def generate_all_samples():
    gt = {'samples': {}, 'summary': {
        'total': len(SAMPLES),
        'int_vuln': sum(1 for s in SAMPLES if s['is_vuln']),
        'int_safe': sum(1 for s in SAMPLES if not s['is_vuln']),
    }}

    for s in SAMPLES:
        sample_dir = _SAMPLES_DIR / s['id']
        sample_dir.mkdir(exist_ok=True)
        c_code = _int_c_code(s)
        (sample_dir / 'vuln.c').write_text(c_code, encoding='utf-8')
        makefile = _int_makefile(s)
        (sample_dir / 'Makefile').write_text(makefile, encoding='utf-8')
        readme = _int_readme(s)
        (sample_dir / 'README.md').write_text(readme, encoding='utf-8')
        gt['samples'][s['id']] = {
            'cve': s['cve'], 'title': s['title'],
            'category': s['category'], 'is_vuln': s['is_vuln'],
            'op': s['op'], 'width': s['width'],
            'left_range': s['left_range'], 'right_range': s['right_range'],
            'signed': s['signed'],
        }

    gt_path = _SAMPLES_DIR / 'int_ground_truth.json'
    with open(gt_path, 'w', encoding='utf-8') as f:
        json.dump(gt, f, indent=2, ensure_ascii=False)
    print(f'Generated {len(SAMPLES)} INT samples -> {_SAMPLES_DIR}')
    return gt


def _int_c_code(s: dict) -> str:
    codes = {
        'mul_heap_alloc': '#include <stdlib.h>\nvoid vuln(unsigned n, unsigned sz) { malloc(n*sz); }\nint main(){vuln(65536,65536);}',
        'add_buffer': '#include <stdlib.h>\nvoid vuln(unsigned o, unsigned l) { char b[256]; if(o+l<256) b[o]=0; }\nint main(){vuln(0xFFFFFFF0,256);}',
        'truncation': '#include <stdlib.h>\nvoid vuln(unsigned long long sz) { unsigned s=(unsigned)sz; malloc(s); }\nint main(){vuln(0x100000010);}',
        'signed_unsigned': '#include <stdlib.h>\nvoid vuln(int len) { unsigned n=len-1; malloc(n); }\nint main(){vuln(0);}',
        'shift_overflow': '#include <stdlib.h>\nvoid vuln(unsigned v, int s) { malloc(v<<s); }\nint main(){vuln(0x10000000,8);}',
        'mul_length': '#include <stdlib.h>\nvoid vuln(int c) { malloc(c*16); }\nint main(){vuln(0x10000000);}',
        'narrowing': '#include <stdlib.h>\nvoid vuln(unsigned long l) { unsigned short s=(unsigned short)l; malloc(s); }\nint main(){vuln(65537);}',
        'sub_underflow': '#include <stdlib.h>\nvoid vuln(int alloc, int used) { malloc(alloc-used); }\nint main(){vuln(50,300);}',
        'safe_bounds': '#include <stdlib.h>\nvoid safe(unsigned x,unsigned y){if(x>100||y>100)return;malloc(x*y);}\nint main(){safe(50,50);}',
        'safe_small': '#include <stdlib.h>\nvoid safe(unsigned long a,unsigned long b){malloc(a+b);}\nint main(){safe(500,500);}',
    }
    return codes.get(s['category'], '#include <stdlib.h>\nint main(){malloc(64);}')


def _int_makefile(s: dict) -> str:
    return f'CC = gcc\nCFLAGS = -Wall -O0 -g\nTARGET = {s["id"]}\n\nall: $(TARGET)\n\n$(TARGET): vuln.c\n\t$(CC) $(CFLAGS) -o $(TARGET) vuln.c\n\nclean:\n\trm -f $(TARGET) *.o\n\nrun: $(TARGET)\n\t./$(TARGET)\n'


def _int_readme(s: dict) -> str:
    return f'# {s["id"]}: {s["title"]}\n\n- **CVE**: {s["cve"]}\n- **Category**: {s["category"]}\n- **Is Vuln**: {s["is_vuln"]}\n- **Op**: {s["op"]}, width={s["width"]}, signed={s["signed"]}\n- **Ranges**: left={s["left_range"]}, right={s["right_range"]}\n'


if __name__ == '__main__':
    generate_all_samples()
