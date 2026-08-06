"""生成 9 个独立的 CVE 漏洞样本 (heap_overflow x3, uaf x3, format_string x3)"""
import os; SAMPLES = 'samples'

CVE_SAMPLES = {
    'cve_2014_0160_heartbleed': ('CVE-2014-0160', 'heap_overflow',
        'OpenSSL Heartbleed heap over-read', '''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void process_heartbeat(const char *payload, unsigned int plen, unsigned int clen) {
    char *buf = malloc(65536); if(!buf) return;
    memcpy(buf, payload, plen);
    char *resp = malloc(clen);
    memcpy(resp, buf, clen); /* BUG: clen > plen causes heap over-read */
    printf("%.*s", clen, resp); free(buf); free(resp);
}
int main(int a, char **v) { if(a<3) return 1;
    char d[256]; memset(d, 'A', 256);
    process_heartbeat(d, atoi(v[1]), atoi(v[2])); return 0; }'''),

    'cve_2015_3864_stagefright': ('CVE-2015-3864', 'heap_overflow',
        'Android Stagefright MP4 heap overflow via integer underflow', '''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void parse_mp4(const char *data, unsigned int size) {
    if(size < 16) return;
    char *buf = malloc(size - 16); /* underflow if size<16 */
    if(!buf) return;
    memcpy(buf, data+16, size); /* heap overflow */
    printf("%s", buf); free(buf);
}
int main(int a, char **v) { if(a<2) return 1;
    char d[4096]; memset(d, 'B', 4096);
    parse_mp4(d, atoi(v[1])); return 0; }'''),

    'cve_2022_0185_fs_heap': ('CVE-2022-0185', 'heap_overflow',
        'Linux kernel heap overflow in filesystem option parsing', '''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void parse_opt(const char *input) {
    char buf[64];
    size_t len = strlen(input);
    memcpy(buf, input, len); /* BUG: no bounds check */
    buf[63]=0; printf("opt: %s", buf);
}
int main(int a, char **v) { if(a<2) return 1;
    parse_opt(v[1]); return 0; }'''),

    'cve_2019_2215_binder_uaf': ('CVE-2019-2215', 'uaf',
        'Android Binder UAF via freed wait queue', '''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char *g_ptr;
void init() { g_ptr = malloc(256); memcpy(g_ptr, "data", 4); }
void cleanup() { free(g_ptr); g_ptr = NULL; /* FIX: NULL assignment removed for demo */ }
void use() { if(g_ptr) printf("data: %s", g_ptr); } /* UAF */
int main() { init(); cleanup();
    /* re-establish dangling pointer: */ g_ptr = (char*)0x41414141;
    use(); return 0; }'''),

    'cve_2020_0022_bt_uaf': ('CVE-2020-0022', 'uaf',
        'Android Bluetooth UAF in packet reassembly', '''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct { char *data; int len; } Pkt;
Pkt *pkt;
void alloc() { pkt = malloc(sizeof(Pkt)); pkt->data = malloc(512); pkt->len = 0; }
void free_p() { free(pkt->data); free(pkt); } /* BUG: pkt not nulled */
void use_p() { if(pkt && pkt->data) memset(pkt->data, 0xFF, 512); } /* UAF */
int main() { alloc(); free_p(); use_p(); return 0; }'''),

    'cve_2021_34866_ebpf_uaf': ('CVE-2021-34866', 'uaf',
        'Linux eBPF UAF via verifier bypass', '''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void proc(char *input) {
    char *a1 = malloc(128); char *a2 = a1;
    memcpy(a1, input, 128);
    free(a2); /* BUG: a1 still references freed memory */
    printf("out: %s", a1); /* UAF */
}
int main(int a, char **v) { char d[128]; memset(d, 'C', 128); proc(d); return 0; }'''),

    'cve_2015_5677_bsd_fmtstr': ('CVE-2015-5677', 'format_string',
        'FreeBSD bsnmpd format string via SNMP', '''#include <stdio.h>
void log_event(const char *input) {
    char buf[256];
    snprintf(buf, sizeof(buf), input); /* BUG: input used as format string */
    printf("LOG: %s", buf);
}
int main(int a, char **v) { if(a<2) return 1;
    log_event(v[1]); return 0; }'''),

    'cve_2012_0809_sudo_fmtstr': ('CVE-2012-0809', 'format_string',
        'Sudo format string via argv[0] in debug logging', '''#include <stdio.h>
void debug(const char *prog, const char *msg) {
    fprintf(stderr, prog); /* BUG: prog from argv[0], used as format */
    fprintf(stderr, ": %s\\n", msg);
}
int main(int a, char **v) { debug(v[0], "test"); return 0; }'''),

    'cve_2018_12020_gnupg_fmtstr': ('CVE-2018-12020', 'format_string',
        'GnuPG format string via crafted filename', '''#include <stdio.h>
#include <string.h>
void print_status(const char *fn, int st) {
    char line[512];
    snprintf(line, sizeof(line), fn, st); /* BUG: filename as format */
    printf("%s", line);
}
int main(int a, char **v) { if(a<2) return 1;
    print_status(v[1], 0); return 0; }'''),
}

for d, (cve, vtype, desc, code) in CVE_SAMPLES.items():
    p = os.path.join(SAMPLES, d); os.makedirs(p, exist_ok=True)
    with open(os.path.join(p, 'vuln.c'), 'w') as f: f.write(code)
    with open(os.path.join(p, 'README.txt'), 'w') as f:
        f.write(f'CVE: {cve}\nType: {vtype}\nDesc: {desc}\nCompile: gcc -o vuln vuln.c -no-pie -fno-stack-protector\n')
    with open(os.path.join(p, 'compile.sh'), 'w') as f:
        f.write('#!/bin/bash\ngcc -o vuln vuln.c -no-pie -fno-stack-protector -w 2>/dev/null && echo OK || echo FAIL\n')
    os.chmod(os.path.join(p, 'compile.sh'), 0o755)

print(f'Created {len(CVE_SAMPLES)} samples')
