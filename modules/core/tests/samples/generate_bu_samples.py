# coding: utf-8
"""Buffer Underflow CVE 基准样本集 — 10 个样本覆盖各种 BU 模式."""

import json
from pathlib import Path

_SAMPLES_DIR = Path(__file__).resolve().parent

SAMPLES = [
    {'id': 'bu_cve_01', 'cve': 'CVE-2014-0160', 'title': 'Heartbleed: negative offset read',
     'buf_addr': 0x1000, 'buf_sz': 64, 'offset': -16, 'access_sz': 8,
     'prev_chunk_sz': 64, 'is_vuln': True, 'category': 'negative_offset'},
    {'id': 'bu_cve_02', 'cve': 'CVE-2015-0204', 'title': 'FREAK: RSA key underflow read',
     'buf_addr': 0x1000, 'buf_sz': 128, 'offset': -32, 'access_sz': 16,
     'prev_chunk_sz': 256, 'is_vuln': True, 'category': 'crypto_underflow'},
    {'id': 'bu_cve_03', 'cve': 'CVE-2016-6304', 'title': 'TLS: oversized OCSP underflow',
     'buf_addr': 0x1000, 'buf_sz': 256, 'offset': -8, 'access_sz': 32,
     'prev_chunk_sz': 64, 'is_vuln': True, 'category': 'metadata_overlap'},
    {'id': 'bu_cve_04', 'cve': 'CVE-2017-3732', 'title': 'BN_mod_exp underflow in OpenSSL',
     'buf_addr': 0x1000, 'buf_sz': 96, 'offset': -64, 'access_sz': 16,
     'prev_chunk_sz': 128, 'is_vuln': True, 'category': 'bignum_underflow'},
    {'id': 'bu_cve_05', 'cve': 'CVE-2018-0732', 'title': 'DH keygen underflow index',
     'buf_addr': 0x1000, 'buf_sz': 48, 'offset': -4, 'access_sz': 4,
     'prev_chunk_sz': 32, 'is_vuln': True, 'category': 'index_underflow'},
    {'id': 'bu_cve_06', 'cve': 'CVE-2019-1551', 'title': 'RSA padding underflow',
     'buf_addr': 0x1000, 'buf_sz': 72, 'offset': -24, 'access_sz': 12,
     'prev_chunk_sz': 96, 'is_vuln': True, 'category': 'padding_underflow'},
    {'id': 'bu_cve_07', 'cve': 'CVE-2020-1968', 'title': 'Raccoon: DH secret underflow',
     'buf_addr': 0x1000, 'buf_sz': 80, 'offset': -48, 'access_sz': 8,
     'prev_chunk_sz': 256, 'is_vuln': True, 'category': 'dh_underflow'},
    {'id': 'bu_cve_08', 'cve': 'CVE-2021-23840', 'title': 'EVP_PKEY underflow read',
     'buf_addr': 0x1000, 'buf_sz': 56, 'offset': -12, 'access_sz': 24,
     'prev_chunk_sz': 48, 'is_vuln': True, 'category': 'evp_underflow'},
    {'id': 'bu_cve_09', 'cve': 'SAFE-BU-001', 'title': 'Safe: valid offset within bounds',
     'buf_addr': 0x1000, 'buf_sz': 64, 'offset': 0, 'access_sz': 16,
     'prev_chunk_sz': 0, 'is_vuln': False, 'category': 'safe_in_bounds'},
    {'id': 'bu_cve_10', 'cve': 'SAFE-BU-002', 'title': 'Safe: positive offset, normal access',
     'buf_addr': 0x1000, 'buf_sz': 128, 'offset': 16, 'access_sz': 8,
     'prev_chunk_sz': 0, 'is_vuln': False, 'category': 'safe_positive'},
]


def generate_all_samples():
    gt = {'samples': {}, 'summary': {
        'total': len(SAMPLES),
        'bu_vuln': sum(1 for s in SAMPLES if s['is_vuln']),
        'bu_safe': sum(1 for s in SAMPLES if not s['is_vuln']),
    }}

    for s in SAMPLES:
        sample_dir = _SAMPLES_DIR / s['id']
        sample_dir.mkdir(exist_ok=True)
        (sample_dir / 'vuln.c').write_text(_bu_c_code(s), encoding='utf-8')
        (sample_dir / 'Makefile').write_text(_bu_makefile(s), encoding='utf-8')
        (sample_dir / 'README.md').write_text(_bu_readme(s), encoding='utf-8')
        gt['samples'][s['id']] = {
            'cve': s['cve'], 'title': s['title'],
            'category': s['category'], 'is_vuln': s['is_vuln'],
            'buf_sz': s['buf_sz'], 'offset': s['offset'],
            'access_sz': s['access_sz'],
            'prev_chunk_sz': s['prev_chunk_sz'],
        }

    gt_path = _SAMPLES_DIR / 'bu_ground_truth.json'
    with open(gt_path, 'w', encoding='utf-8') as f:
        json.dump(gt, f, indent=2, ensure_ascii=False)
    print(f'Generated {len(SAMPLES)} BU samples -> {_SAMPLES_DIR}')
    return gt


def _bu_c_code(s: dict) -> str:
    codes = {
        'negative_offset': '#include <stdlib.h>\nvoid vuln(){char*b=malloc(64);char c=*(b-16);}\nint main(){vuln();}',
        'crypto_underflow': '#include <stdlib.h>\nvoid vuln(){char*b=malloc(128);char c=*(b-32);}\nint main(){vuln();}',
        'metadata_overlap': '#include <stdlib.h>\nvoid vuln(){char*b=malloc(256);int*v=(int*)(b-8);*v=0;}\nint main(){vuln();}',
        'bignum_underflow': '#include <stdlib.h>\nvoid vuln(){char*b=malloc(96);char c=*(b-64);}\nint main(){vuln();}',
        'index_underflow': '#include <stdlib.h>\nvoid vuln(){char*b=malloc(48);char c=b[-4];}\nint main(){vuln();}',
        'padding_underflow': '#include <stdlib.h>\nvoid vuln(){char*b=malloc(72);char c=*(b-24);}\nint main(){vuln();}',
        'dh_underflow': '#include <stdlib.h>\nvoid vuln(){char*b=malloc(80);char c=*(b-48);}\nint main(){vuln();}',
        'evp_underflow': '#include <stdlib.h>\nvoid vuln(){char*b=malloc(56);char c=*(b-12);}\nint main(){vuln();}',
        'safe_in_bounds': '#include <stdlib.h>\nvoid safe(){char*b=malloc(64);char c=*(b+0);}\nint main(){safe();}',
        'safe_positive': '#include <stdlib.h>\nvoid safe(){char*b=malloc(128);char c=*(b+16);}\nint main(){safe();}',
    }
    return codes.get(s['category'], '#include <stdlib.h>\nint main(){malloc(64);}')


def _bu_makefile(s: dict) -> str:
    return (f'CC = gcc\nCFLAGS = -Wall -O0 -g\nTARGET = {s["id"]}\n\n'
            f'all: $(TARGET)\n\n$(TARGET): vuln.c\n'
            f'\t$(CC) $(CFLAGS) -o $(TARGET) vuln.c\n\n'
            f'clean:\n\trm -f $(TARGET) *.o\n\nrun: $(TARGET)\n\t./$(TARGET)\n')


def _bu_readme(s: dict) -> str:
    return (f'# {s["id"]}: {s["title"]}\n\n'
            f'- **CVE**: {s["cve"]}\n- **Category**: {s["category"]}\n'
            f'- **Is Vuln**: {s["is_vuln"]}\n'
            f'- **buf={s["buf_sz"]}, offset={s["offset"]}, '
            f'access={s["access_sz"]}, prev_chunk={s["prev_chunk_sz"]}\n')


if __name__ == '__main__':
    generate_all_samples()
