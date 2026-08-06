# tests/generate_cve_samples.py
# 生成10个CVE漏洞样本的C源码+编译脚本+元数据
# 每个样本放在独立目录, 包含vuln.c, build.sh, README.md
import os

BASE = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(BASE, 'cve_samples')

SAMPLES = {
    'CVE-2016-6301_heap_overflow': (
        'heap_overflow',
        'ntpd CRYPTO_ASSOC heap overflow via oversized extension field',
        'CVE-2016-6301'),
    'CVE-2014-0160_heartbleed': (
        'heap_overflow',
        'OpenSSL Heartbleed: missing bounds check on heartbeat payload length',
        'CVE-2014-0160'),
    'CVE-2019-0708_uaf': (
        'uaf',
        'RDP Use-After-Free in termdd.sys channel management',
        'CVE-2019-0708'),
    'CVE-2020-7460_uaf': (
        'uaf',
        'FreeBSD if_smsc UAF via detach race condition',
        'CVE-2020-7460'),
    'CVE-2001-0017_format_string': (
        'format_string',
        'Windows UPnP format string in NOTIFY message handling',
        'CVE-2001-0017'),
    'CVE-2012-0809_format_string': (
        'format_string',
        'sudo format string via sudo_debug() function',
        'CVE-2012-0809'),
    'CVE-2023-0179_stack_overflow': (
        'stack_overflow',
        'Linux kernel netfilter nft_payload stack buffer overflow',
        'CVE-2023-0179'),
    'CVE-2022-2588_double_free': (
        'double_free',
        'Linux kernel cls_route double free via route4_change error path',
        'CVE-2022-2588'),
    'CVE-2024-21762_off_by_one': (
        'heap_overflow',
        'FortiOS sslvpnd off-by-one write in HTTP header parsing',
        'CVE-2024-21762'),
    'CVE-2023-44487_use_after_scope': (
        'uaf',
        'HTTP/2 Rapid Reset - UAF pattern via connection lifecycle',
        'CVE-2023-44487'),
}

VULN_TEMPLATES = {
    'heap_overflow': r'''#include <stdlib.h>
#include <string.h>
#include <stdio.h>
// {description}
// {cve_id}
void process_input(char *input, unsigned int len) {{
    char *buf = malloc(64);
    // VULN: len not validated against allocation size
    memcpy(buf, input, len);
    printf("processed: %s\n", buf);
    free(buf);
}}
int main(int argc, char **argv) {{
    char data[256];
    memset(data, 'A', sizeof(data));
    unsigned int n = argc > 1 ? (unsigned int)atoi(argv[1]) : 200;
    process_input(data, n);
    return 0;
}}
''',
    'uaf': r'''#include <stdlib.h>
#include <string.h>
#include <stdio.h>
// {description}
// {cve_id}
struct object {{
    int id;
    char data[64];
    void (*callback)(struct object *);
}};
static struct object *g_obj = NULL;
void create_object(int id) {{
    g_obj = malloc(sizeof(struct object));
    g_obj->id = id;
    g_obj->callback = NULL;
}}
void destroy_object() {{
    // VULN: freed but pointer not nulled
    free(g_obj);
}}
void use_object() {{
    // UAF: g_obj may have been freed by destroy_object
    if (g_obj && g_obj->callback) {{
        g_obj->callback(g_obj);
    }}
}}
int main() {{
    create_object(1);
    destroy_object();
    create_object(2);  // may reuse freed memory
    use_object();
    return 0;
}}
''',
    'format_string': r'''#include <stdio.h>
#include <string.h>
// {description}
// {cve_id}
void log_message(const char *user_input) {{
    // VULN: user_input passed directly as format string to printf
    printf(user_input);
    printf("\n");
}}
int main(int argc, char **argv) {{
    if (argc < 2) {{
        log_message("normal log message");
    }} else {{
        // attacker: argv[1] = "AAAA%x%x%x%x%n"
        log_message(argv[1]);
    }}
    return 0;
}}
''',
    'stack_overflow': r'''#include <string.h>
#include <stdio.h>
#include <stdlib.h>
// {description}
// {cve_id}
void process_packet(const char *data, unsigned int len) {{
    char buf[64];
    // VULN: len may exceed sizeof(buf), causing stack buffer overflow
    if (len > 0) memcpy(buf, data, len);
    printf("packet: %s\n", buf);
}}
int main(int argc, char **argv) {{
    char input[256];
    memset(input, 'B', sizeof(input));
    unsigned int n = argc > 1 ? (unsigned int)atoi(argv[1]) : 200;
    process_packet(input, n);
    return 0;
}}
''',
    'double_free': r'''#include <stdlib.h>
#include <stdio.h>
// {description}
// {cve_id}
struct filter {{
    int id;
    char name[32];
}};
static struct filter *g_f = NULL;
int create_filter() {{
    g_f = malloc(sizeof(struct filter));
    if (!g_f) return -1;
    g_f->id = 1;
    return 0;
}}
void destroy_filter() {{
    // VULN: freed but pointer not nulled
    if (g_f) {{ free(g_f); }}
}}
int main() {{
    create_filter();
    destroy_filter();  // free #1
    destroy_filter();  // free #2 - double free
    return 0;
}}
''',
}


def generate():
    for dirname, (vtype, desc, cve) in SAMPLES.items():
        d = os.path.join(SAMPLES_DIR, dirname)
        os.makedirs(d, exist_ok=True)
        # source
        tmpl = VULN_TEMPLATES.get(vtype, VULN_TEMPLATES['heap_overflow'])
        src = tmpl.format(description=desc, cve_id=cve)
        with open(os.path.join(d, 'vuln.c'), 'w') as f:
            f.write(src)
        # build script
        build = (f'#!/bin/bash\n'
                f'# {dirname}\n'
                f'gcc -g -o vuln_O0 vuln.c\n'
                f'gcc -O2 -o vuln_O2 vuln.c\n'
                f'echo "Built {dirname}"\n')
        with open(os.path.join(d, 'build.sh'), 'w') as f:
            f.write(build)
        # metadata
        meta = (f'# {dirname}\n'
                f'CVE: {cve}\n'
                f'Type: {vtype}\n'
                f'Description: {desc}\n')
        with open(os.path.join(d, 'README.md'), 'w') as f:
            f.write(meta)
        print(f'  Created: {dirname} ({vtype})')
    print(f'Done: {len(SAMPLES)} samples generated')


if __name__ == '__main__':
    generate()
