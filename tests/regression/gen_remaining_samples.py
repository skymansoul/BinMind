# 生成整数溢出(15) + UAF补充(5) + 格式字符串补充(5)测试样本
import os
BASE = os.path.dirname(os.path.abspath(__file__))

INT = {
'int_overflow_mul': ('#include <stdio.h>\n#include <stdlib.h>\n'
'void alloc(int n) { int sz=n*1024; char *p=malloc(sz); free(p); }\n'
'int main(int c,char **v){if(c>1)alloc(atoi(v[1]));return 0;}\n','integer_overflow'),
'int_overflow_add': ('#include <stdio.h>\n#include <stdlib.h>\n'
'void copy(char *s,int x){int sz=strlen(s)+x;char *p=malloc(sz);memcpy(p,s,sz);free(p);}\n'
'int main(int c,char **v){if(c>1)copy(v[1],atoi(v[2]));return 0;}\n','integer_overflow'),
'int_overflow_cast': ('#include <stdio.h>\n#include <stdlib.h>\n'
'void process(size_t n){int sz=(int)n;char *p=malloc(sz);memset(p,0,n);free(p);}\n'
'int main(){process(0x100000000ULL);return 0;}\n','integer_overflow'),
'int_overflow_sign': ('#include <stdio.h>\n#include <stdlib.h>\n'
'void read_data(int len){if(len<0)len=-len;char *b=malloc(len);read(0,b,len);free(b);}\n'
'int main(int c,char **v){if(c>1)read_data(atoi(v[1]));return 0;}\n','integer_overflow'),
'int_overflow_shift': ('#include <stdio.h>\n#include <stdlib.h>\n'
'void table(int n){int sz=1<<n;char *p=malloc(sz);free(p);}\n'
'int main(int c,char **v){if(c>1)table(atoi(v[1]));return 0;}\n','integer_overflow'),
'int_overflow_array': ('#include <stdio.h>\n#include <stdlib.h>\n'
'void matrix(int r,int c){int *m=malloc(r*c*sizeof(int));free(m);}\n'
'int main(){matrix(65536,65536);return 0;}\n','integer_overflow'),
'int_overflow_loop': ('#include <stdio.h>\n#include <stdlib.h>\n'
'void fill(int n){char *b=malloc(n);for(int i=0;i<=n;i++)b[i]=0;free(b);}\n'
'int main(int c,char **v){if(c>1)fill(atoi(v[1]));return 0;}\n','integer_overflow'),
'int_overflow_widen': ('#include <stdio.h>\n#include <stdlib.h>\n'
'void ext(unsigned short n){int sz=n*100;char *p=malloc(sz);free(p);}\n'
'int main(){ext(65535);return 0;}\n','integer_overflow'),
'int_overflow_trunc': ('#include <stdio.h>\n#include <stdlib.h>\n'
'void truncate(unsigned long long n){unsigned sz=(unsigned)n;char *p=malloc(sz);free(p);}\n'
'int main(){truncate(0x100000001ULL);return 0;}\n','integer_overflow'),
'int_overflow_neg': ('#include <stdio.h>\n#include <stdlib.h>\n'
'void do_alloc(int n){if(n<0)n=0;char *p=malloc(n);free(p);}\n'
'int main(int c,char **v){if(c>1)do_alloc(atoi(v[1]));return 0;}\n','integer_overflow'),
'int_overflow_offby': ('#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n'
'void buf_copy(char *s){int l=strlen(s);char *b=malloc(l);strcpy(b,s);free(b);}\n'
'int main(int c,char **v){if(c>1)buf_copy(v[1]);return 0;}\n','integer_overflow'),
'int_overflow_div': ('#include <stdio.h>\n#include <stdlib.h>\n'
'void part(int total,int parts){int each=total/parts;char *b=malloc(each);free(b);}\n'
'int main(){part(100,0);return 0;}\n','integer_overflow'),
'int_overflow_sub': ('#include <stdio.h>\n#include <stdlib.h>\n'
'void reserve(int avail,int used){int left=avail-used;char *b=malloc(left);free(b);}\n'
'int main(){reserve(10,100);return 0;}\n','integer_overflow'),
'int_overflow_wrap': ('#include <stdio.h>\n#include <stdlib.h>\n'
'void pad(int len){int sz=len+16;if(sz<len)sz=65536;char *b=malloc(sz);free(b);}\n'
'int main(int c,char **v){if(c>1)pad(atoi(v[1]));return 0;}\n','integer_overflow'),
'int_overflow_mixed': ('#include <stdio.h>\n#include <stdlib.h>\n'
'void combo(int a,short b,char c){int sz=a*b+c;char *p=malloc(sz);free(p);}\n'
'int main(){combo(32768,2,1);return 0;}\n','integer_overflow'),
}

UAF5 = {
'uaf_realloc_null': ('#include <stdio.h>\n#include <stdlib.h>\n'
'int main(){char *p=malloc(64);char *q=realloc(p,0);puts(q);return 0;}\n','uaf'),
'uaf_vtable_override': ('#include <stdio.h>\n#include <stdlib.h>\n'
'typedef void(*fn)(void);struct vt{fn f;};void cb(){}\n'
'int main(){struct vt *v=malloc(sizeof(*v));v->f=cb;free(v);v->f();return 0;}\n','uaf'),
'uaf_multi_path': ('#include <stdio.h>\n#include <stdlib.h>\n'
'void logic(int flag){char *b=malloc(100);if(flag)free(b);strcpy(b,"x");}\n'
'int main(int c,char **v){logic(c>1?1:0);return 0;}\n','uaf'),
'uaf_signal_handler': ('#include <stdio.h>\n#include <stdlib.h>\n#include <signal.h>\n'
'char *g;void h(int s){free(g);}\n'
'int main(){g=malloc(256);signal(SIGINT,h);raise(SIGINT);puts(g);return 0;}\n','uaf'),
'uaf_thread_pool': ('#include <stdio.h>\n#include <stdlib.h>\n'
'struct task{void *data;int done;};void run(struct task *t){t->done=1;}\n'
'int main(){struct task *t=malloc(sizeof(*t));run(t);free(t);run(t);return 0;}\n','uaf'),
}

FMT5 = {
'fmt_snprintf_ret': ('#include <stdio.h>\n#include <string.h>\n'
'int main(int c,char **v){if(c<2)return 1;char b[64];int n=snprintf(b,64,v[1]);\n'
'printf(b);return 0;}\n','format_string'),
'fmt_vsnprintf': ('#include <stdio.h>\n#include <stdarg.h>\n#include <string.h>\n'
'void logf(const char*f,...){va_list a;va_start(a,f);char b[256];\n'
'vsnprintf(b,sizeof(b),f,a);va_end(a);printf(b);}\n'
'int main(int c,char **v){if(c<2)return 1;logf(v[1]);return 0;}\n','format_string'),
'fmt_fprintf_file': ('#include <stdio.h>\n'
'int main(int c,char **v){if(c<2)return 1;FILE *f=fopen(\"/dev/null\",\"w\");\n'
'if(f){fprintf(f,v[1]);fclose(f);}return 0;}\n','format_string'),
'fmt_recursive': ('#include <stdio.h>\n'
'void deep(char *s,int d){if(d<=0)printf(s);else deep(s,d-1);}\n'
'int main(int c,char **v){if(c<2)return 1;deep(v[1],2);return 0;}\n','format_string'),
'fmt_wide_char': ('#include <stdio.h>\n#include <wchar.h>\n'
'int main(int c,char **v){if(c<2)return 1;wchar_t w[256];\n'
'mbstowcs(w,v[1],256);fwprintf(stderr,L\"%ls\",w);return 0;}\n','format_string'),
}

def write_samples(samples, subdir):
    for name, (code, vtype) in samples.items():
        d = os.path.join(BASE, subdir, name)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d,'vuln.c'),'w') as f: f.write(code)
        with open(os.path.join(d,'Makefile'),'w') as f:
            f.write('CC=gcc\nCFLAGS=-g -O0 -no-pie -fno-stack-protector\nall:vuln\nvuln:vuln.c\n\t$(CC) $(CFLAGS) -o vuln vuln.c\nclean:\n\trm -f vuln\n')
        with open(os.path.join(d,'README.md'),'w') as f:
            f.write(f'# {name}\n\n**Type:** {vtype}\n')

write_samples(INT, 'samples_int')
print(f'Integer overflow: {len(INT)} samples')
write_samples(UAF5, 'samples_uaf')
print(f'UAF supplement: {len(UAF5)} samples')
write_samples(FMT5, 'samples_fmt')
print(f'Format string supplement: {len(FMT5)} samples')
print(f'Total new: {len(INT)+len(UAF5)+len(FMT5)}')
