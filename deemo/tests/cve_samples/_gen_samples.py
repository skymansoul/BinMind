"""一次性生成所有10个CVE样本的 sample.c / sample.json / Makefile"""
import json, os

S = [
("cve_01", "CVE-2001-0017", "format_string", "Format string in syslog()", 1,
 "gcc -o sample sample.c -no-pie -fno-stack-protector -z execstack",
 '#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <syslog.h>\n\nvoid vuln(const char *in) {\n  char b[256];\n  strncpy(b,in,255);b[255]=0;\n  syslog(LOG_INFO,b); /* BUG: fmt string */\n}\nint main(int c,char**v){\n  if(c<2)return 1;\n  vuln(v[1]);\n  return 0;\n}\n'),

("cve_02", "CVE-2012-0809", "format_string", "Format string in sudo debug log", 1,
 "gcc -o sample sample.c -no-pie -fno-stack-protector",
 '#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\nvoid debug_log(const char*f,const char*m){\n  fprintf(stderr,m); /* BUG: fmt string */\n}\nint main(int c,char**v){\n  if(c<2)return 1;\n  debug_log("auth",v[1]);\n  return 0;\n}\n'),

("cve_03", "CVE-2014-0160", "buffer_overflow", "Heartbleed: OOB read via malicious length", 1,
 "gcc -o sample sample.c -no-pie -fno-stack-protector",
 '#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\nstatic unsigned char hb[64]="secret_key_material";\nvoid tls_heartbeat(unsigned char*r,unsigned int rl){\n  unsigned char resp[80];\n  unsigned int pl;\n  if(rl<3)return;\n  pl=(r[1]<<8)|r[2]; /* BUG: attacker-controlled, not validated */\n  memcpy(resp,hb,pl<80?pl:80);\n  printf("heartbeat: %u bytes\\n",pl);\n}\nint main(int c,char**v){\n  unsigned char r[3]={0x01,0xFF,0xFF};\n  tls_heartbeat(r,3);\n  return 0;\n}\n'),

("cve_04", "CVE-2016-6301", "heap_overflow", "Heap overflow from unchecked alloc", 1,
 "gcc -o sample sample.c -no-pie -fno-stack-protector",
 '#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\nvoid process(const char*d,unsigned int l){\n  char*b=malloc(l); /* should be l+1 */\n  if(!b)return;\n  memcpy(b,d,l);\n  b[l-1]=0;\n  printf("%s\\n",b);\n  free(b);\n}\nint main(void){\n  process("AAAAAAAABBBBBBBBCCCCCCCC",32);\n  return 0;\n}\n'),

("cve_05", "CVE-2019-0708", "uaf", "Use-after-free in object lifecycle", 1,
 "gcc -o sample sample.c -no-pie -fno-stack-protector",
 '#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\ntypedef struct{int id;char*d;}Obj;\nObj*g=NULL;\nObj*make(int i,const char*s){Obj*o=malloc(sizeof(Obj));o->id=i;o->d=strdup(s);return o;}\nvoid kill(Obj*o){if(o){free(o->d);free(o);}}\nvoid use(Obj*o){if(o&&o->d)printf("Obj[%d]:%s\\n",o->id,o->d);}\nint main(void){\n  g=make(1,"sensitive");\n  kill(g); /* g not set to NULL */\n  use(g);  /* UAF */\n  return 0;\n}\n'),

("cve_06", "CVE-2020-7460", "uaf", "UAF via premature free with pending cb", 1,
 "gcc -o sample sample.c -no-pie -fno-stack-protector",
 '#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\ntypedef struct{int fd;char*b;void(*cb)(struct conn*);}Conn;\nConn*active=NULL;\nvoid on_data(Conn*c){if(c&&c->b)printf("data[%d]:%s\\n",c->fd,c->b);}\nvoid close_conn(Conn*c){if(c){free(c->b);free(c);}}\nint main(void){\n  active=malloc(sizeof(Conn));active->fd=3;\n  active->b=strdup("payload");active->cb=on_data;\n  close_conn(active);\n  if(active->cb)active->cb(active); /* UAF */\n  return 0;\n}\n'),

("cve_07", "CVE-2022-2588", "double_free", "Double free in route cleanup", 1,
 "gcc -o sample sample.c -no-pie -fno-stack-protector",
 '#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\ntypedef struct{char*p;char*n;}Route;\nRoute*rt=NULL;\nvoid cleanup(Route*r){if(r){free(r->p);free(r->n);free(r);}}\nvoid remove_rt(const char*k){\n  if(rt&&strcmp(rt->p,k)==0){free(rt->p);free(rt->n);free(rt);}\n  cleanup(rt); /* BUG: double free */\n}\nint main(void){\n  rt=malloc(sizeof(Route));rt->p=strdup("10.0.0.0/8");rt->n=strdup("gw");\n  remove_rt("10.0.0.0/8");\n  return 0;\n}\n'),

("cve_08", "CVE-2023-0179", "stack_overflow", "Stack overflow via unchecked memcpy", 1,
 "gcc -o sample sample.c -no-pie -fno-stack-protector -z execstack",
 '#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\nvoid parse(const unsigned char*p,unsigned int pl){\n  char hdr[64],pay[256];\n  unsigned int off;\n  if(pl<8)return;\n  off=(p[4]<<8)|p[5];\n  memcpy(hdr,p,8);hdr[8]=0;\n  unsigned int payl=pl-off; /* BUG: can underflow */\n  memcpy(pay,p+off,payl<256?payl:255); /* overflow */\n  pay[payl<256?payl:255]=0;\n  printf("pay:%s\\n",pay);\n}\nint main(int c,char**v){\n  unsigned char p[512];memset(p,0x41,512);p[4]=0;p[5]=8;\n  parse(p,512);\n  return 0;\n}\n'),

("cve_09", "CVE-2023-44487", "use_after_scope", "Dangling stack reference via deferred work", 1,
 "gcc -o sample sample.c -no-pie -fno-stack-protector",
 '#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\ntypedef void(*cleanup_fn)(void*);\nstruct dw{void*d;cleanup_fn f;struct dw*n;};\nstruct dw*q=NULL;\nvoid queue(void*d,cleanup_fn f){struct dw*w=malloc(sizeof(*w));w->d=d;w->f=f;w->n=q;q=w;}\nvoid run(void){while(q){struct dw*w=q;q=w->n;if(w->f)w->f(w->d);free(w);}}\nvoid work(int id){char b[32];snprintf(b,32,"r%d",id);queue(b,(cleanup_fn)puts);}\nint main(void){work(42);run();return 0;}\n'),

("cve_10", "CVE-2024-21762", "off_by_one", "Off-by-one write in boundary check", 1,
 "gcc -o sample sample.c -no-pie -fno-stack-protector",
 '#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n#define MAX 128\nvoid copy_line(const char*s){\n  char line[MAX];int i;\n  for(i=0;i<=MAX&&s[i]!=0&&s[i]!=10;i++)line[i]=s[i]; /* BUG: <= writes line[128] */\n  line[i]=0;\n  printf("line:%s\\n",line);\n}\nint main(int c,char**v){\n  char t[256];memset(t,0x42,256);t[255]=0;\n  copy_line(t);\n  return 0;\n}\n'),
]

base = os.path.join(os.path.dirname(os.path.abspath(__file__)))
for name, cve, vtype, desc, expected, comp, code in S:
    d = os.path.join(base, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "sample.c"), "w") as f:
        f.write(code)
    with open(os.path.join(d, "sample.json"), "w") as f:
        json.dump({"cve_id":cve,"vuln_type":vtype,"description":desc,
                    "expected_count":expected,"compile_cmd":comp}, f, indent=2)
    with open(os.path.join(d, "Makefile"), "w") as f:
        f.write(f"# {cve}: {vtype}\nall:\n\t{comp}\nclean:\n\trm -f sample\n")
    print(f"  {name}: {cve} ({vtype})")

print(f"\nDone: {len(S)} samples in {base}")
