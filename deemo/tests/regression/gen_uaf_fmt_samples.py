# 生成UAF(10个)和格式字符串(10个)测试样本
import os
BASE = os.path.dirname(os.path.abspath(__file__))

UAF = {
'uaf_simple_deref': ('#include <stdio.h>\n#include <stdlib.h>\n'
'struct obj { int id; char data[32]; };\n'
'void vuln() { struct obj *p = malloc(sizeof(struct obj)); p->id = 42;\n'
'free(p); printf("%d\\n", p->id); }\n'
'int main() { vuln(); return 0; }\n', 'uaf'),
'uaf_double_free': ('#include <stdio.h>\n#include <stdlib.h>\n'
'void cleanup(char *p) { if (p) free(p); }\n'
'int main() { char *buf = malloc(128); cleanup(buf); free(buf); return 0; }\n', 'uaf'),
'uaf_stale_callback': ('#include <stdio.h>\n#include <stdlib.h>\n'
'typedef void (*cb_t)(void);\nstruct widget { cb_t on_destroy; int data; };\n'
'void handler() { printf("freed!\\n"); }\n'
'int main() { struct widget *w = malloc(sizeof(*w)); w->on_destroy = handler;\n'
'free(w); w->on_destroy(); return 0; }\n', 'uaf'),
'uaf_realloc_race': ('#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n'
'int main() { char *p = malloc(64); strcpy(p, "original");\n'
'char *q = realloc(p, 128); strcpy(p, "stale"); free(q); return 0; }\n', 'uaf'),
'uaf_list_remove': ('#include <stdio.h>\n#include <stdlib.h>\n'
'struct node { int val; struct node *next; };\n'
'void remove_node(struct node **head, int val) {\n'
'struct node *cur = *head, *prev = NULL;\n'
'while (cur) { if (cur->val == val) {\n'
'if (prev) prev->next = cur->next; else *head = cur->next; free(cur); }\n'
'prev = cur; cur = cur->next; } }\n'
'int main() { struct node *n = malloc(sizeof(*n)); n->val=1; n->next=NULL;\n'
'remove_node(&n,1); return 0; }\n', 'uaf'),
'uaf_conditional_free': ('#include <stdio.h>\n#include <stdlib.h>\n'
'void process(int flag) { char *buf = malloc(100);\n'
'if (flag) free(buf); printf("%s\\n", buf); }\n'
'int main(int argc, char **argv) { process(argc>1?1:0); return 0; }\n', 'uaf'),
'uaf_vector_grow': ('#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n'
'int main() { char **items = malloc(4*sizeof(char*));\n'
'items[0]=strdup("a");items[1]=strdup("b");\n'
'char **n = realloc(items,8*sizeof(char*));\n'
'items[2]=strdup("c"); free(n); return 0; }\n', 'uaf'),
'uaf_io_uring': ('#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n'
'struct io_buf { char *data; int len; int refs; };\n'
'void submit(struct io_buf *b) { b->refs++; }\n'
'void complete(struct io_buf *b) { b->refs--; if(b->refs<=0){free(b->data);free(b);} }\n'
'int main() { struct io_buf *b=malloc(sizeof(*b));\n'
'b->data=strdup("x");b->refs=1;complete(b);submit(b);return 0;}\n', 'uaf'),
'uaf_func_ptr': ('#include <stdio.h>\n#include <stdlib.h>\n'
'typedef void (*fn_t)(void);\nvoid good() { printf("ok\\n"); }\n'
'int main() { fn_t *slot = malloc(sizeof(fn_t));\n'
'*slot = good; free(slot); (*slot)(); return 0; }\n', 'uaf'),
'uaf_dangling_global': ('#include <stdio.h>\n#include <stdlib.h>\n'
'char *g_buf = NULL;\nvoid init() { g_buf = malloc(256); }\n'
'void cleanup() { free(g_buf); }\n'
'int main() { init(); cleanup(); puts(g_buf); return 0; }\n', 'uaf'),
}

FMT = {
'fmt_direct': ('#include <stdio.h>\n'
'int main(int argc, char **argv) { if(argc<2)return 1;\n'
'printf(argv[1]); return 0; }\n', 'format_string'),
'fmt_syslog_indirect': ('#include <stdio.h>\n#include <string.h>\n'
'void log_msg(const char *u) { char buf[256];\n'
'snprintf(buf,sizeof(buf),"user: "); strncat(buf,u,200);\n'
'printf(buf); }\n'
'int main(int argc, char **argv) { if(argc<2)return 1;\n'
'log_msg(argv[1]); return 0; }\n', 'format_string'),
'fmt_sprintf_chain': ('#include <stdio.h>\n#include <string.h>\n'
'int main(int argc, char **argv) { if(argc<2)return 1;\n'
'char tmp[512]; sprintf(tmp,argv[1]);\n'
'fprintf(stderr,"%s\\n",tmp); return 0; }\n', 'format_string'),
'fmt_fprintf': ('#include <stdio.h>\n'
'int main(int argc, char **argv) { if(argc<2)return 1;\n'
'fprintf(stderr,argv[1]); return 0; }\n', 'format_string'),
'fmt_snprintf_leak': ('#include <stdio.h>\n#include <string.h>\n#include <unistd.h>\n'
'int main(int argc, char **argv) { if(argc<2)return 1;\n'
'char buf[64]; snprintf(buf,64,argv[1]);\n'
'write(1,buf,strlen(buf)); return 0; }\n', 'format_string'),
'fmt_wrapper': ('#include <stdio.h>\n'
'void debug(const char *f) { printf(f); }\n'
'int main(int argc, char **argv) { if(argc<2)return 1;\n'
'debug(argv[1]); return 0; }\n', 'format_string'),
'fmt_vprintf': ('#include <stdio.h>\n#include <stdarg.h>\n'
'void vlog(const char *f, ...) { va_list a; va_start(a,f);\n'
'vprintf(f,a); va_end(a); }\n'
'int main(int argc, char **argv) { if(argc<2)return 1;\n'
'vlog(argv[1]); return 0; }\n', 'format_string'),
'fmt_dprintf': ('#include <stdio.h>\n'
'int main(int argc, char **argv) { if(argc<2)return 1;\n'
'dprintf(2,argv[1]); return 0; }\n', 'format_string'),
'fmt_syslog': ('#include <stdio.h>\n#include <syslog.h>\n'
'int main(int argc, char **argv) { if(argc<2)return 1;\n'
'openlog("v",LOG_PID,LOG_USER); syslog(LOG_ERR,argv[1]);\n'
'closelog(); return 0; }\n', 'format_string'),
'fmt_indirect_title': ('#include <stdio.h>\n#include <string.h>\n'
'int main(int argc, char **argv) { if(argc<2)return 1;\n'
'char t[256]; snprintf(t,sizeof(t),"proc: %s",argv[1]);\n'
'printf(t); return 0; }\n', 'format_string'),
}

def write_all(samples, subdir):
    for name, (code, vtype) in samples.items():
        d = os.path.join(BASE, subdir, name)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, 'vuln.c'), 'w') as f: f.write(code)
        with open(os.path.join(d, 'Makefile'), 'w') as f:
            f.write('CC=gcc\nCFLAGS=-g -O0 -no-pie -fno-stack-protector\nall: vuln\nvuln: vuln.c\n\t$(CC) $(CFLAGS) -o vuln vuln.c\nclean:\n\trm -f vuln\n')
        with open(os.path.join(d, 'README.md'), 'w') as f:
            f.write(f'# {name}\n\n**Type:** {vtype}\n')
        print(f'  {name}')

write_all(UAF, 'samples_uaf')
print(f'UAF: {len(UAF)} samples')
write_all(FMT, 'samples_fmt')
print(f'FMT: {len(FMT)} samples')
