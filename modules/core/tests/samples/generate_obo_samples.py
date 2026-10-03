# coding: utf-8
"""Off-by-One CVE 基准样本集 — 10 个样本覆盖各种 OBO 模式."""

import json
from pathlib import Path

_SAMPLES_DIR = Path(__file__).resolve().parent

SAMPLES = [
    {'id': 'obo_cve_01', 'cve': 'CVE-2014-3470', 'title': 'Null-byte poisoning classic',
     'alloc': 24, 'write': 25, 'adj_alloc': 248, 'is_vuln': True, 'category': 'null_byte_poison',
     'overwrite_byte': 0},
    {'id': 'obo_cve_02', 'cve': 'CVE-2016-6306', 'title': 'Size LSB overwrite',
     'alloc': 120, 'write': 121, 'adj_alloc': 256, 'is_vuln': True, 'category': 'size_lsb',
     'overwrite_byte': 0x00},
    {'id': 'obo_cve_03', 'cve': 'CVE-2015-1788', 'title': 'Prev-size field overwrite',
     'alloc': 24, 'write': 25, 'adj_alloc': 128, 'is_vuln': True, 'category': 'prev_size',
     'overwrite_byte': 0x41},
    {'id': 'obo_cve_04', 'cve': 'CVE-2019-1547', 'title': 'Size MSB overwrite → chunk extension',
     'alloc': 56, 'write': 57, 'adj_alloc': 64, 'is_vuln': True, 'category': 'size_msb',
     'overwrite_byte': 0x80},
    {'id': 'obo_cve_05', 'cve': 'CVE-2020-1971', 'title': 'ASN.1 parser off-by-one',
     'alloc': 248, 'write': 249, 'adj_alloc': 0, 'is_vuln': True, 'category': 'user_data',
     'overwrite_byte': 0x00},
    {'id': 'obo_cve_06', 'cve': 'CVE-2018-0739', 'title': 'ASN1_get_object off-by-one',
     'alloc': 120, 'write': 144, 'adj_alloc': 0, 'is_vuln': True, 'category': 'regular_overflow',
     'overwrite_byte': 0x00},
    {'id': 'obo_cve_07', 'cve': 'CVE-2017-3735', 'title': 'Multi-byte OBO near boundary',
     'alloc': 504, 'write': 505, 'adj_alloc': 32, 'is_vuln': True, 'category': 'boundary_obo',
     'overwrite_byte': 0x00},
    {'id': 'obo_cve_08', 'cve': 'CVE-2021-3449', 'title': 'Zero-alloc off-by-one (min chunk)',
     'alloc': 0, 'write': 25, 'adj_alloc': 32, 'is_vuln': True, 'category': 'zero_alloc_obo',
     'overwrite_byte': 0x00},
    {'id': 'obo_cve_09', 'cve': 'SAFE-OBO-001', 'title': 'Safe: write == usable (no overflow)',
     'alloc': 64, 'write': 64, 'adj_alloc': 128, 'is_vuln': False, 'category': 'safe_exact',
     'overwrite_byte': 0},
    {'id': 'obo_cve_10', 'cve': 'SAFE-OBO-002', 'title': 'Safe: write < usable (underfit)',
     'alloc': 256, 'write': 128, 'adj_alloc': 64, 'is_vuln': False, 'category': 'safe_under',
     'overwrite_byte': 0},
]


def generate_all_samples():
    gt = {'samples': {}, 'summary': {
        'total': len(SAMPLES),
        'obo_vuln': sum(1 for s in SAMPLES if s['is_vuln']),
        'obo_safe': sum(1 for s in SAMPLES if not s['is_vuln']),
    }}

    for s in SAMPLES:
        sample_dir = _SAMPLES_DIR / s['id']
        sample_dir.mkdir(exist_ok=True)
        (sample_dir / 'vuln.c').write_text(_obo_c_code(s), encoding='utf-8')
        (sample_dir / 'Makefile').write_text(_obo_makefile(s), encoding='utf-8')
        (sample_dir / 'README.md').write_text(_obo_readme(s), encoding='utf-8')
        gt['samples'][s['id']] = {
            'cve': s['cve'], 'title': s['title'],
            'category': s['category'], 'is_vuln': s['is_vuln'],
            'alloc': s['alloc'], 'write': s['write'],
            'adj_alloc': s['adj_alloc'],
            'overwrite_byte': s['overwrite_byte'],
        }

    gt_path = _SAMPLES_DIR / 'obo_ground_truth.json'
    with open(gt_path, 'w', encoding='utf-8') as f:
        json.dump(gt, f, indent=2, ensure_ascii=False)
    print(f'Generated {len(SAMPLES)} OBO samples -> {_SAMPLES_DIR}')
    return gt


def _obo_c_code(s: dict) -> str:
    codes = {
        'null_byte_poison': '#include <stdlib.h>\n#include <string.h>\nvoid vuln(){char*a=malloc(24);char*b=malloc(248);char*c=malloc(24);memset(a,65,25);free(b);}\nint main(){vuln();}',
        'size_lsb': '#include <stdlib.h>\n#include <string.h>\nvoid vuln(){char*a=malloc(120);char*b=malloc(256);memset(a,65,121);free(b);}\nint main(){vuln();}',
        'prev_size': '#include <stdlib.h>\n#include <string.h>\nvoid vuln(){char*a=malloc(24);char*b=malloc(128);memset(a,65,25);free(b);}\nint main(){vuln();}',
        'size_msb': '#include <stdlib.h>\n#include <string.h>\nvoid vuln(){char*a=malloc(56);char*b=malloc(64);memset(a,0x80,57);free(b);}\nint main(){vuln();}',
        'user_data': '#include <stdlib.h>\n#include <string.h>\nvoid vuln(){char*buf=malloc(248);memset(buf,65,249);}\nint main(){vuln();}',
        'regular_overflow': '#include <stdlib.h>\n#include <string.h>\nvoid vuln(){char*buf=malloc(120);memset(buf,65,144);}\nint main(){vuln();}',
        'boundary_obo': '#include <stdlib.h>\n#include <string.h>\nvoid vuln(){char*a=malloc(504);char*b=malloc(32);memset(a,65,505);free(b);}\nint main(){vuln();}',
        'zero_alloc_obo': '#include <stdlib.h>\n#include <string.h>\nvoid vuln(){char*a=malloc(0);char*b=malloc(32);memset(a,65,25);free(b);}\nint main(){vuln();}',
        'safe_exact': '#include <stdlib.h>\n#include <string.h>\nvoid safe(){char*buf=malloc(64);memset(buf,65,64);}\nint main(){safe();}',
        'safe_under': '#include <stdlib.h>\n#include <string.h>\nvoid safe(){char*buf=malloc(256);memset(buf,65,128);}\nint main(){safe();}',
    }
    return codes.get(s['category'], '#include <stdlib.h>\nint main(){malloc(64);}')


def _obo_makefile(s: dict) -> str:
    return (f'CC = gcc\nCFLAGS = -Wall -O0 -g\nTARGET = {s["id"]}\n\n'
            f'all: $(TARGET)\n\n$(TARGET): vuln.c\n'
            f'\t$(CC) $(CFLAGS) -o $(TARGET) vuln.c\n\n'
            f'clean:\n\trm -f $(TARGET) *.o\n\nrun: $(TARGET)\n\t./$(TARGET)\n')


def _obo_readme(s: dict) -> str:
    return (f'# {s["id"]}: {s["title"]}\n\n'
            f'- **CVE**: {s["cve"]}\n- **Category**: {s["category"]}\n'
            f'- **Is Vuln**: {s["is_vuln"]}\n'
            f'- **alloc={s["alloc"]}, write={s["write"]}, '
            f'adj_alloc={s["adj_alloc"]}\n')


if __name__ == '__main__':
    generate_all_samples()
