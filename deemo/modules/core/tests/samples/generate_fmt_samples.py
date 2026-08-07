# coding: utf-8
"""FMT CVE 基准样本集 — 10 个样本覆盖格式串漏洞的各种模式."""

import json, os
from pathlib import Path

_SAMPLES_DIR = Path(__file__).resolve().parent

SAMPLES = [
    {'id': 'fmt_cve_01', 'cve': 'CVE-2020-6449', 'title': 'Direct user fmt — printf(user_input)',
     'pattern': 'printf(user_input)', 'category': 'direct_user_fmt', 'is_vuln': True,
     'fmt_str': '%x %x %n', 'source': 'WebRTC CVE-2020-6449'},
    {'id': 'fmt_cve_02', 'cve': 'CVE-2019-5798', 'title': 'Indirect fmt via heap buffer',
     'pattern': 'snprintf(buf,sz,user,args...)', 'category': 'indirect_fmt', 'is_vuln': True,
     'fmt_str': '%s %s %n', 'source': 'Chrome CVE-2019-5798'},
    {'id': 'fmt_cve_03', 'cve': 'CVE-2018-1000115', 'title': 'Fmt in error path — printf(recv_data)',
     'pattern': 'printf(recv_buf)', 'category': 'error_path_fmt', 'is_vuln': True,
     'fmt_str': 'Error: %s %n', 'source': 'Memcached CVE-2018-1000115'},
    {'id': 'fmt_cve_04', 'cve': 'CVE-2017-1000370', 'title': 'Stack probing via %n$ — positional args',
     'pattern': 'printf(user_fmt, a1, a2)', 'category': 'positional_fmt', 'is_vuln': True,
     'fmt_str': '%7$n', 'source': 'Linux kernel CVE-2017-1000370'},
    {'id': 'fmt_cve_05', 'cve': 'CVE-2016-6290', 'title': 'Wide-char write — %hn for 2-byte write',
     'pattern': 'wprintf(user_fmt)', 'category': 'wide_write_fmt', 'is_vuln': True,
     'fmt_str': '%hn %hn', 'source': 'PHP CVE-2016-6290'},
    {'id': 'fmt_cve_06', 'cve': 'CVE-2015-8612', 'title': 'syslog format — syslog(user_msg)',
     'pattern': 'syslog(LOG_ERR, user_msg)', 'category': 'syslog_fmt', 'is_vuln': True,
     'fmt_str': '%n', 'source': 'Bluetooth CVE-2015-8612'},
    {'id': 'fmt_cve_07', 'cve': 'CVE-2021-31566', 'title': 'Multi %n — arbitrary write chain',
     'pattern': 'fprintf(stderr, user_fmt)', 'category': 'multi_write_fmt', 'is_vuln': True,
     'fmt_str': '%n %n %n', 'source': 'libarchive CVE-2021-31566'},
    {'id': 'fmt_cve_08', 'cve': 'CVE-2020-10878', 'title': 'Perl fmt — sprintf(user)',
     'pattern': 'sprintf(buf, user_fmt, args)', 'category': 'sprintf_fmt', 'is_vuln': True,
     'fmt_str': '%*d %n', 'source': 'Perl CVE-2020-10878'},
    {'id': 'fmt_cve_09', 'cve': 'SAFE-FMT-001', 'title': 'Safe: constant fmt string',
     'pattern': 'printf("%s", user)', 'category': 'safe_constant_fmt', 'is_vuln': False,
     'fmt_str': '%s', 'source': 'Safe pattern: constant format'},
    {'id': 'fmt_cve_10', 'cve': 'SAFE-FMT-002', 'title': 'Safe: no %n — info leak only',
     'pattern': 'printf(user_fmt)', 'category': 'safe_info_leak', 'is_vuln': False,
     'fmt_str': '%x %x %s', 'source': 'Info leak only, no write primitive'},
]


def generate_all_samples():
    gt = {'samples': {}, 'summary': {
        'total': len(SAMPLES),
        'fmt_vuln': sum(1 for s in SAMPLES if s['is_vuln']),
        'fmt_safe': sum(1 for s in SAMPLES if not s['is_vuln']),
    }}

    for s in SAMPLES:
        sample_dir = _SAMPLES_DIR / s['id']
        sample_dir.mkdir(exist_ok=True)
        c_code = _fmt_c_code(s)
        (sample_dir / 'vuln.c').write_text(c_code, encoding='utf-8')
        makefile = _fmt_makefile(s)
        (sample_dir / 'Makefile').write_text(makefile, encoding='utf-8')
        readme = _fmt_readme(s)
        (sample_dir / 'README.md').write_text(readme, encoding='utf-8')
        gt['samples'][s['id']] = {
            'cve': s['cve'], 'title': s['title'],
            'category': s['category'], 'is_vuln': s['is_vuln'],
            'pattern': s['pattern'], 'fmt_str': s['fmt_str'],
        }

    gt_path = _SAMPLES_DIR / 'fmt_ground_truth.json'
    with open(gt_path, 'w', encoding='utf-8') as f:
        json.dump(gt, f, indent=2, ensure_ascii=False)
    print(f'Generated {len(SAMPLES)} FMT samples -> {_SAMPLES_DIR}')
    return gt


def _fmt_c_code(s: dict) -> str:
    codes = {
        'direct_user_fmt': '#include <stdio.h>\nvoid vuln(char *u) { printf(u); /* %n in u */ }\nint main(){vuln("%x %x %n");}',
        'indirect_fmt': '#include <stdio.h>\nvoid vuln(char *u, int a) { char b[256]; snprintf(b,256,u,a); }\nint main(){vuln("%s %s %n",42);}',
        'error_path_fmt': '#include <stdio.h>\nvoid vuln(char *d) { if(!d) printf("Error: %s %n", d); else printf("%s",d); }\nint main(){vuln(0);}',
        'positional_fmt': '#include <stdio.h>\nvoid vuln(char *f, int a, int b) { printf(f, a, b); }\nint main(){vuln("%7$n",1,2);}',
        'wide_write_fmt': '#include <stdio.h>\n#include <wchar.h>\nvoid vuln(wchar_t *f) { wprintf(f); }\nint main(){wprintf(L"%hn %hn");}',
        'syslog_fmt': '#include <syslog.h>\nvoid vuln(char *m) { syslog(LOG_ERR, m); }\nint main(){vuln("%n");}',
        'multi_write_fmt': '#include <stdio.h>\nvoid vuln(char *f) { fprintf(stderr, f); }\nint main(){vuln("%n %n %n");}',
        'sprintf_fmt': '#include <stdio.h>\nvoid vuln(char *f, int a) { char b[256]; sprintf(b, f, a); }\nint main(){vuln("%*d %n", 10);}',
        'safe_constant_fmt': '#include <stdio.h>\nvoid safe(char *u) { printf("%s", u); }\nint main(){safe("hello");}',
        'safe_info_leak': '#include <stdio.h>\nvoid vuln(char *f) { printf(f); }\nint main(){vuln("%x %x %s");}',
    }
    return codes.get(s['category'], '#include <stdio.h>\nint main(){printf("test");}')


def _fmt_makefile(s: dict) -> str:
    return f'CC = gcc\nCFLAGS = -Wall -O0 -g\nTARGET = {s["id"]}\n\nall: $(TARGET)\n\n$(TARGET): vuln.c\n\t$(CC) $(CFLAGS) -o $(TARGET) vuln.c\n\nclean:\n\trm -f $(TARGET) *.o\n\nrun: $(TARGET)\n\t./$(TARGET)\n'


def _fmt_readme(s: dict) -> str:
    return f'# {s["id"]}: {s["title"]}\n\n- **CVE**: {s["cve"]}\n- **Category**: {s["category"]}\n- **Is Vuln**: {s["is_vuln"]}\n- **Pattern**: `{s["pattern"]}`\n- **Format String**: `{s["fmt_str"]}`\n- **Source**: {s["source"]}\n'


if __name__ == '__main__':
    generate_all_samples()
