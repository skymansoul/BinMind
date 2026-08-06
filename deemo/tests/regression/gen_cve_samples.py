# 一键生成15个CVE堆溢出样本的 vuln.c + Makefile
import os

BASE = os.path.dirname(os.path.abspath(__file__))

S = {
'CVE-2015-0235_ghost': ('''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void process_hostname(const char *hostname) {
    size_t len = strlen(hostname);
    char *buf = malloc(len);
    memcpy(buf, hostname, len + 1);
    printf("resolved\\n");
    free(buf);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    process_hostname(argv[1]);
    return 0;
}
''', 'heap_overflow'),

'CVE-2016-10190_ffmpeg': ('''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void parse_header(const char *data, int data_len) {
    char *buf = malloc(128);
    if (!buf) return;
    memcpy(buf, data, data_len);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    parse_header(argv[1], strlen(argv[1]));
    return 0;
}
''', 'heap_overflow'),

'CVE-2017-1000253_pie': ('''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void copy_with_limit(const char *src, int limit) {
    char *buf = malloc(limit);
    strcpy(buf, src);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    copy_with_limit(argv[1], 16);
    return 0;
}
''', 'heap_overflow'),

'CVE-2018-1000001_glibc': ('''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void resolve_path(const char *path) {
    int size = strlen(path) + 1;
    if (size < 256) size = 256;
    char *buf = malloc(size);
    strcpy(buf, path);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    resolve_path(argv[1]);
    return 0;
}
''', 'heap_overflow'),

'CVE-2019-11477_tcp_sack': ('''#include <stdio.h>
#include <stdlib.h>
void allocate_packets(int count, int pkt_size) {
    int total = count * pkt_size;
    char *buf = malloc(total);
    if (!buf) return;
    for (int i = 0; i < count; i++) buf[i * pkt_size] = 0;
    free(buf);
}
int main() { allocate_packets(65536, 65536); return 0; }
''', 'integer_overflow'),

'CVE-2020-10713_grub2': ('''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void parse_descriptor(const unsigned char *data, int len) {
    char *buf = malloc(64);
    memcpy(buf, data, len);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    parse_descriptor((unsigned char*)argv[1], strlen(argv[1]));
    return 0;
}
''', 'heap_overflow'),

'CVE-2021-3156_sudo': ('''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void sudo_edit(const char *input) {
    int len = strlen(input);
    char *buf = malloc(len + 64);
    int pos = 0;
    for (int i = 0; i < len; i++) {
        if (input[i] == '\\\\') { buf[pos++] = '\\\\'; buf[pos++] = '\\\\'; }
        else buf[pos++] = input[i];
    }
    buf[pos] = 0;
    free(buf);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    sudo_edit(argv[1]);
    return 0;
}
''', 'heap_overflow'),

'CVE-2021-4034_polkit': ('''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void handle_args(char **args, int argc) {
    char *buf = malloc(256);
    int pos = 0;
    for (int i = 0; i < argc; i++) {
        int alen = strlen(args[i]);
        memcpy(buf + pos, args[i], alen);
        pos += alen;
    }
    buf[pos] = 0;
    free(buf);
}
int main(int argc, char **argv) { handle_args(argv, argc); return 0; }
''', 'heap_overflow'),

'CVE-2022-0185_linux_fs': ('''#include <stdio.h>
#include <stdlib.h>
struct fs_context { int id; char *data; };
void cleanup(struct fs_context *ctx) { free(ctx->data); }
void use_ctx(struct fs_context *ctx) { ctx->data[0] = 'X'; }
int main() {
    struct fs_context *ctx = malloc(sizeof(*ctx));
    ctx->data = malloc(128);
    cleanup(ctx); use_ctx(ctx); free(ctx);
    return 0;
}
''', 'uaf'),

'CVE-2022-23222_kernel_bpf': ('''#include <stdio.h>
#include <stdlib.h>
void verify_bounds(int *lo, int *hi, int n) {
    int r = *hi - *lo;
    if (r < n) return;
    char *buf = malloc(r);
    for (int i = 0; i < n; i++) buf[i] = 0;
    free(buf);
}
int main() { int a=0,b=32; verify_bounds(&a,&b,256); return 0; }
''', 'heap_overflow'),

'CVE-2022-25636_netfilter': ('''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void reassemble(char **frags, int *sizes, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) total += sizes[i];
    char *buf = malloc(total);
    int pos = 0;
    for (int i = 0; i < count; i++) { memcpy(buf+pos, frags[i], sizes[i]); pos += sizes[i]; }
    free(buf);
}
int main() {
    char *f[2] = {"AAAA","BBBB"}; int s[2] = {4, 100};
    reassemble(f, s, 2); return 0;
}
''', 'heap_overflow'),

'CVE-2023-0179_kernel_bpf2': ('''#include <stdio.h>
#include <stdlib.h>
void check_and_alloc(int user_val) {
    int size = user_val & 0xFFFF;
    if (size > 4096) size = 4096;
    char *buf = malloc(size);
    for (int i = 0; i < user_val; i++) if (i < size) buf[i] = 0;
    free(buf);
}
int main(int argc, char **argv) {
    check_and_alloc(argc>1?atoi(argv[1]):65536); return 0;
}
''', 'heap_overflow'),

'CVE-2023-0464_openssl': ('''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void parse_cert_chain(const char *data, int len) {
    int n = data[0] & 0xFF;
    int sz = n * 4096;
    char *buf = malloc(sz);
    if (!buf) return;
    memcpy(buf, data+1, len-1);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    parse_cert_chain(argv[1], strlen(argv[1]));
    return 0;
}
''', 'heap_overflow'),

'CVE-2024-21626_runc': ('''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void process_fd(int fd, const char *data, int len) {
    char *buf = malloc(256);
    int alloc = len + fd;
    if (alloc > 256) alloc = 256;
    memcpy(buf, data, alloc);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    process_fd(999, argv[1], strlen(argv[1]));
    return 0;
}
''', 'heap_overflow'),

'CVE-2024-6387_openssh': ('''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
volatile int sig_flag = 0;
void sighandler(int s) { sig_flag = 1; }
void ssh_login(const char *user) {
    char *buf = malloc(strlen(user) + 32);
    strcpy(buf, user);
    if (sig_flag) { free(buf); return; }
    free(buf);
}
int main(int argc, char **argv) {
    signal(SIGALRM, sighandler); alarm(1);
    if (argc >= 2) ssh_login(argv[1]);
    return 0;
}
''', 'heap_corruption'),
}

for name, (code, vtype) in S.items():
    d = os.path.join(BASE, 'samples_heap', name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'vuln.c'), 'w') as f:
        f.write(code)
    with open(os.path.join(d, 'Makefile'), 'w') as f:
        f.write(f'CC=gcc\nCFLAGS=-g -O0 -no-pie -fno-stack-protector\n')
        f.write(f'all: vuln\n\nvuln: vuln.c\n')
        f.write(f'\t$(CC) $(CFLAGS) -o vuln vuln.c\n\n')
        f.write(f'clean:\n\trm -f vuln\n')
    print(f'  {name}: vuln.c({len(code)}B) + Makefile')

print(f'\n{len(S)} samples written to samples_heap/')
