"""Generate UAF + Format String + Integer Overflow test samples."""
import os
base = r"C:\Users\Administrator\Desktop\BinMind\deemo\tests\vuln_samples"

UAF = {
"uaf_01": ("CVE-2021-3801","CWE-416","free后继续使用指针",
"#include <stdlib.h>\ntypedef struct{int id;char d[64];}I;\nvoid proc(int n){I*items=malloc(n*sizeof(I));for(int i=0;i<n;i++)items[i].id=i;free(items);for(int i=0;i<n;i++)items[i].id=-1;}\nint main(int c,char**v){proc(c>1?atoi(v[1]):10);return 0;}"),
"uaf_02": ("CVE-2022-0185","CWE-416","内核UAF: free后通过全局变量别名使用",
"#include <stdlib.h>\nchar*g;\nvoid fb(char*p){free(p);g=p;}\nvoid ub(){if(g)g[0]='X';}\nint main(){char*b=malloc(128);fb(b);ub();return 0;}"),
"uaf_03": ("GENERIC-uaf-realloc","CWE-416","realloc移动后使用旧指针",
"#include <stdlib.h>\nchar*rs(char*b,size_t n){char*o=b;char*nb=realloc(b,n);if(nb!=o)o[0]='L';return nb;}\nint main(){char*b=malloc(64);b=rs(b,256);free(b);return 0;}"),
"uaf_04": ("CVE-2016-6301","CWE-416","竞态条件: free和use在不同位置",
"#include <stdlib.h>\n#include <string.h>\nchar*s;\nvoid fi(){free(s);}\nvoid ui(){strcpy(s,\"data\");}\nint main(){s=malloc(256);fi();ui();return 0;}"),
"uaf_05": ("GENERIC-uaf-list","CWE-416","链表节点释放后遍历",
"#include <stdlib.h>\ntypedef struct N{int v;struct N*n;}N;\nN*mk(int v){N*n=malloc(sizeof(N));n->v=v;n->n=0;return n;}\nvoid fa(N*h){while(h){N*t=h->n;free(h);h=t;}}\nint main(){N*a=mk(1);N*b=mk(2);a->n=b;fa(a);return 0;}"),
"uaf_06": ("GENERIC-uaf-callback","CWE-416","回调中释放, 外层继续使用",
"#include <stdlib.h>\ntypedef void(*cb)(void*);\nvoid df(void*p){free(p);}\nvoid proc(void*o,cb f){f(o);int*x=o;*x=42;}\nint main(){int*p=malloc(4);proc(p,df);return 0;}"),
"uaf_07": ("GENERIC-uaf-array","CWE-416","数组元素释放后仍被引用",
"#include <stdlib.h>\ntypedef struct{int id;char*n;}E;\nvoid fa2(E*a,int n){for(int i=0;i<n;i++)free(a[i].n);free(a);}\nint main(){E*a=malloc(3*sizeof(E));for(int i=0;i<3;i++){a[i].n=malloc(32);}fa2(a,3);return 0;}"),
"uaf_08": ("GENERIC-uaf-tree","CWE-416","树结构部分释放后访问子节点",
"#include <stdlib.h>\ntypedef struct T{int v;struct T*l,*r;}T;\nT*mkt(int v){T*t=malloc(sizeof(T));t->v=v;t->l=t->r=0;return t;}\nvoid fs(T*t){if(t){free(t);if(t->l)fs(t->l);}}\nint main(){T*r=mkt(1);r->l=mkt(2);fs(r);return 0;}"),
"uaf_09": ("GENERIC-uaf-double-ptr","CWE-416","双重指针释放后解引用",
"#include <stdlib.h>\nvoid dp(char**pp){free(*pp);**pp='X';}\nint main(){char*b=malloc(64);*b='A';dp(&b);return 0;}"),
"uaf_10": ("GENERIC-uaf-reuse-var","CWE-416","同一变量名重新分配但不改值",
"#include <stdlib.h>\nvoid rv(){char*p=malloc(64);free(p);p=malloc(128);if(p)p[0]='Y';free(p);}\nint main(){rv();return 0;}"),
"uaf_11": ("GENERIC-uaf-safe-null","SAFE","释放后置NULL——安全模式不应检出",
"#include <stdlib.h>\nvoid sf(char**pp){free(*pp);*pp=NULL;}\nint main(){char*b=malloc(128);sf(&b);if(b)b[0]='X';return 0;}"),
"uaf_12": ("GENERIC-uaf-guard","SAFE","free前检查并置NULL——安全模式",
"#include <stdlib.h>\nvoid mf(char*p){if(p){free(p);p=NULL;}}\nint main(){char*b=malloc(64);mf(b);return 0;}"),
}

FMT = {
"fmt_01": ("CVE-2024-21817","CWE-134","printf直接使用用户输入作为格式串",
"#include <stdio.h>\nvoid lu(char*in){printf(in);}\nint main(int c,char**v){lu(c>1?v[1]:\"guest\");return 0;}"),
"fmt_02": ("GENERIC-fmt-fprintf","CWE-134","fprintf格式串来自用户输入",
"#include <stdio.h>\nvoid el(char*m){fprintf(stderr,m);}\nint main(int c,char**v){el(c>1?v[1]:\"ok\");return 0;}"),
"fmt_03": ("GENERIC-fmt-sprintf","CWE-134","sprintf格式串可控",
"#include <stdio.h>\nchar b[256];\nvoid fm(char*f,char*a){sprintf(b,f,a);puts(b);}\nint main(int c,char**v){fm(c>1?v[1]:\"%s\",c>2?v[2]:\"w\");return 0;}"),
"fmt_04": ("GENERIC-fmt-syslog","CWE-134","syslog格式串来自输入",
"#include <syslog.h>\nvoid lr(char*d){syslog(LOG_INFO,d);}\nint main(int c,char**v){lr(c>1?v[1]:\"test\");return 0;}"),
"fmt_05": ("CVE-2017-1000253","CWE-134","内核格式串漏洞 (简化复现)",
"#include <stdio.h>\n#include <stdlib.h>\nvoid kl(char*u){char*b=malloc(512);snprintf(b,512,\"%s\",u);printf(b);free(b);}\nint main(int c,char**v){kl(c>1?v[1]:\"info\");return 0;}"),
"fmt_06": ("GENERIC-fmt-indirect","CWE-134","间接传参: 变量赋值后传入printf",
"#include <stdio.h>\nvoid sh(char*in){char*f=in;printf(f);}\nint main(int c,char**v){sh(c>1?v[1]:\"hi\");return 0;}"),
"fmt_07": ("GENERIC-fmt-snprintf-indirect","CWE-134","snprintf间接格式串",
"#include <stdio.h>\nchar gb[256];\nvoid isf(char*f,char*a){snprintf(gb,sizeof(gb),f,a);puts(gb);}\nint main(int c,char**v){isf(c>1?v[1]:\"%s\",c>2?v[2]:\"guest\");return 0;}"),
"fmt_08": ("GENERIC-fmt-varargs","CWE-134","自定义varargs函数转发格式串漏洞",
"#include <stdio.h>\n#include <stdarg.h>\nvoid vpl(const char*f,...){va_list a;va_start(a,f);vprintf(f,a);va_end(a);}\nint main(int c,char**v){vpl(c>1?v[1]:\"%s\",\"test\");return 0;}"),
"fmt_09": ("GENERIC-fmt-safe-lit","SAFE","安全使用: 格式串字面量——不应检出",
"#include <stdio.h>\nvoid ss(char*n){printf(\"Hello, %s\\n\",n);}\nint main(int c,char**v){ss(c>1?v[1]:\"guest\");return 0;}"),
"fmt_10": ("GENERIC-fmt-snprintf-safe","SAFE","snprintf正确边界检查——安全模式",
"#include <stdio.h>\nchar b2[256];\nvoid sf2(char*n){snprintf(b2,sizeof(b2),\"User: %s\",n);puts(b2);}\nint main(int c,char**v){sf2(c>1?v[1]:\"anon\");return 0;}"),
}

INT = {
"int_01": ("CVE-2016-2177","CWE-190","count*size乘法溢出导致分配过小",
"#include <stdlib.h>\n#include <string.h>\nvoid*al(int c,int s){return malloc(c*s);}\nint main(){char*p=al(1<<30,4);memcpy(p,\"x\",(size_t)(1<<30)*4);free(p);return 0;}"),
"int_02": ("CVE-2019-11477","CWE-190","size_t加法溢出导致回绕",
"#include <stdlib.h>\nvoid mg(size_t a,size_t b){size_t t=a+b;char*m=malloc(t);free(m);}\nint main(){mg((size_t)-10,20);return 0;}"),
"int_03": ("GENERIC-int-mul-wrap","CWE-190","calloc参数乘积溢出",
"#include <stdlib.h>\nvoid*mt(int r,int c){return calloc(r,c);}\nint main(){char*p=mt;if(p)free(p);return 0;}"),
"int_04": ("GENERIC-int-sign-compare","CWE-190","有符号/无符号混用绕过边界检查",
"#include <stdlib.h>\nvoid cp2(const char*s,int sz){if(sz>4096)return;char*b=malloc((unsigned)sz);free(b);}\nint main(){cp2(\"test\",-1);return 0;}"),
"int_05": ("GENERIC-int-shift-wrap","CWE-190","左移溢出导致分配大小错误",
"#include <stdlib.h>\nvoid*sa(int n){return malloc(1<<n);}\nint main(){char*p=sa(31);free(p);return 0;}"),
"int_06": ("GENERIC-int-safe-size-max","SAFE","正确SIZE_MAX检查——不应检出",
"#include <stdlib.h>\n#include <stdint.h>\nvoid*sfa(size_t c,size_t s){if(s&&c>SIZE_MAX/s)return 0;return malloc(c*s);}\nint main(){void*p=sfa(100,100);free(p);return 0;}"),
"int_07": ("GENERIC-int-safe-bounds","SAFE","边界检查正确——安全模式",
"#include <stdlib.h>\nchar*scp(const char*s,size_t mx){size_t l=strlen(s);if(l>=mx)l=mx-1;char*b=malloc(l+1);if(!b)return 0;return b;}\nint main(int c,char**v){char*p=scp(c>1?v[1]:\"t\",128);free(p);return 0;}"),
}

all_samples = {}
all_samples.update({f"uaf/{k}":v for k,v in UAF.items()})
all_samples.update({f"fmt/{k}":v for k,v in FMT.items()})
all_samples.update({f"int/{k}":v for k,v in INT.items()})

for sid, (cve, cwe, desc, code) in all_samples.items():
    d = os.path.join(base, sid.replace("/", os.sep))
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "vuln.c"), "w") as f:
        f.write(f"/* {cve} {cwe}: {desc} */\n{code}\n")
    with open(os.path.join(d, "Makefile"), "w") as f:
        f.write(f"CC=gcc\nCFLAGS=-O0 -g -w\nall: vuln_elf\nvuln_elf: vuln.c\n\t$(CC) $(CFLAGS) -o vuln_elf vuln.c\nclean:\n\trm -f vuln_elf\n# {cve} {cwe}: {desc}\n")
    with open(os.path.join(d, "README.txt"), "w") as f:
        f.write(f"CVE: {cve}\nCWE: {cwe}\n{desc}\n")

print(f"Generated {len(all_samples)} samples across 3 categories:")
for cat in ["uaf","fmt","int"]:
    count = sum(1 for k in all_samples if k.startswith(cat))
    safe = sum(1 for k,v in all_samples.items() if k.startswith(cat) and "SAFE" in v[0])
    print(f"  {cat}: {count} samples ({safe} negative/safe)")
