"""Generate 15 heap overflow C samples with Makefiles and README."""
import os
base = r"C:\Users\Administrator\Desktop\BinMind\deemo\tests\heap_overflow_samples"

S = {
"ho_01": ("CVE-2021-3156", "CWE-787", "malloc未预留转义扩展空间导致溢出",
'''#include <stdlib.h>
#include <string.h>
char* escape(const char* s) {
    char* b = malloc(strlen(s)+1); char* p = b;
    for (; *s; s++) { if (*s=='\\\\') *p++='\\\\'; *p++=*s; }
    *p=0; return b;
}
int main(int c, char** v) { char* p=escape(c>1?v[1]:"\\\\t"); free(p); return 0; }'''),

"ho_02": ("CVE-2014-0160", "CWE-126", "memcpy使用攻击者声明的长度而非实际大小",
'''#include <stdlib.h>
#include <string.h>
typedef struct { int len; char* d; } P;
P* make(int L, const char* s, int sl) { P* p=malloc(sizeof(P)); p->len=L; p->d=malloc(L); memcpy(p->d,s,L); return p; }
int main() { P* p=make(256,"s",1); free(p->d); free(p); return 0; }'''),

"ho_03": ("CVE-2016-2177", "CWE-190", "count*size整数溢出导致分配过小",
'''#include <stdlib.h>
#include <string.h>
void* alloc(int c, int s) { return malloc(c*s); }
void cp(const char* s, int c) { char* b=alloc(c,4); memcpy(b,s,c*4); free(b); }
int main() { cp("x", 1073741824); return 0; }'''),

"ho_04": ("CVE-2019-11477", "CWE-190", "size_t加法溢出导致分配不足",
'''#include <stdlib.h>
#include <string.h>
void* merge(const char* a, size_t as, const char* b, size_t bs) { size_t t=as+bs; char* m=malloc(t); memcpy(m,a,as); memcpy(m+as,b,bs); return m; }
int main() { void* p=merge("a",(size_t)-10,"b",20); free(p); return 0; }'''),

"ho_05": ("CVE-2022-0185", "CWE-787", "有符号/无符号比较绕过边界检查",
'''#include <stdlib.h>
#include <string.h>
char* cp2(const char* s, int L) { char* b; if(L>4096)return 0; b=malloc((unsigned)L); if(L<0)L=4096; memcpy(b,s,(unsigned)L); return b; }
int main() { char* p=cp2("overflow",-1); free(p); return 0; }'''),

"ho_06": ("CVE-2023-3269", "CWE-787", "realloc缩小后写超出新大小",
'''#include <stdlib.h>
#include <string.h>
char* rs(char* b, size_t o, size_t n) { char* nb=realloc(b,n); if(nb&&n<o)memset(nb+n,0,o-n); return nb?nb:b; }
int main() { char* b=malloc(4096); b=rs; free(b); return 0; }'''),

"ho_07": ("GENERIC-offbyone", "CWE-193", "malloc(strlen)未预留null终止符",
'''#include <stdlib.h>
#include <string.h>
char* dup(const char* s) { size_t l=strlen(s); char* d=malloc(l); memcpy(d,s,l); d[l]=0; return d; }
int main(int c,char**v){char*p=dup(c>1?v[1]:"t");free(p);return 0;}'''),

"ho_08": ("GENERIC-fmt-expand", "CWE-787", "sprintf格式扩展超出malloc预算",
'''#include <stdlib.h>
#include <stdio.h>
char* fmt(int n) { char* b=malloc(32); sprintf(b,"count=%d items=%d",n,n*2); return b; }
int main() { char* p=fmt(999999); free(p); return 0; }'''),

"ho_09": ("GENERIC-offbyone-loop", "CWE-787", "for i<=n 导致一次越界写入",
'''#include <stdlib.h>
typedef struct { int h; char d[64]; } I;
I* alloc(int n) { I* b=malloc(n*sizeof(I)); for(int i=0;i<=n;i++)b[i].h=i; return b; }
int main() { I* p=alloc(10); free(p); return 0; }'''),

"ho_10": ("GENERIC-strcat", "CWE-787", "strcat向固定大小缓冲区追加导致溢出",
'''#include <stdlib.h>
#include <string.h>
char* msg(const char* a, const char* b) { char* m=malloc(128); strcpy(m,a); strcat(m,b); return m; }
int main(int c,char**v){char*p=msg(c>1?v[1]:"hi",c>2?v[2]:"_world");free(p);return 0;}'''),

"ho_11": ("GENERIC-scanf", "CWE-787", "scanf %s 向固定缓冲区读入无界数据",
'''#include <stdlib.h>
#include <stdio.h>
void rd() { char* b=malloc(32); scanf("%s",b); free(b); }
int main() { rd(); return 0; }'''),

"ho_12": ("GENERIC-realloc-leak", "CWE-787", "realloc失败处理不当",
'''#include <stdlib.h>
#include <string.h>
char* grw(char* b, size_t n) { char* nb=realloc(b,n); if(!nb)free(b); return nb?nb:b; }
int main() { char* b=grw(malloc(64),128); strcpy(b,"safe"); free(b); return 0; }'''),

"ho_13": ("CVE-2024-21817", "CWE-134", "格式串漏洞通过%n写入堆地址",
'''#include <stdlib.h>
#include <stdio.h>
void log_u(char* in) { char* b=malloc(256); snprintf(b,256,"%s",in); printf(b); free(b); }
int main(int c,char**v){log_u(c>1?v[1]:"guest");return 0;}'''),

"ho_14": ("GENERIC-calloc-under", "CWE-787", "calloc参数乘积溢出",
'''#include <stdlib.h>
#include <string.h>
void* mat(int r, int c) { return calloc(r,c); }
int main() { char* p=mat; if(p)strcpy(p,"t"); free(p); return 0; }'''),

"ho_15": ("SAFE-correct-check", "SAFE", "正确边界检查——负面测试，不应检出",
'''#include <stdlib.h>
#include <string.h>
char* safe_cp(const char* s, size_t mx) {
    size_t l=strlen(s); if(l>=mx)l=mx-1;
    char* b=malloc(l+1); if(!b)return 0; memcpy(b,s,l); b[l]=0; return b;
}
int main(int c, char** v) { char* p=safe_cp(c>1?v[1]:"t",128); free(p); return 0; }'''),
}

for sid, (cve, cwe, desc, code) in S.items():
    d = os.path.join(base, sid); os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "vuln.c"), "w") as f:
        f.write(f"/* {cve} {cwe}: {desc} */\n{code}\n")
    with open(os.path.join(d, "Makefile"), "w") as f:
        f.write(f"CC=gcc\nCFLAGS=-O0 -g -w\nall: vuln_elf\nvuln_elf: vuln.c\n\t$(CC) $(CFLAGS) -o vuln_elf vuln.c\nclean:\n\trm -f vuln_elf\n# {cve} {cwe}: {desc}\n")
    with open(os.path.join(d, "README.txt"), "w") as f:
        f.write(f"CVE: {cve}\nCWE: {cwe}\n{desc}\n")
print(f"Generated {len(S)} samples")
for sid in sorted(S): print(f"  {sid}: {S[sid][0]}")
