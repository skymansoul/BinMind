# coding: utf-8
#
"""
自检脚本: 用 Win64 风格内联反汇编文本验证 GASRI 各判定规则。

覆盖:
  f1 常量溢出        malloc(64) + memset(96)        → OVERFLOW
  f2 常量安全        malloc(64) + memset(64)        → SAFE  R3
  f3 对齐 padding    malloc(17) + memset(20)        → SAFE  R3
  f4 守卫有界        cmp r8,0x40; ja skip + memset  → SAFE  R2
  f5 共享来源        同一参数槽 → alloc/write        → SAFE  R5

运行: python -m heapver.selfcheck
"""

import sys
from pathlib import Path

from .pipeline import GASRIPipeline, GASRIReport
from .verdict import SAFE, OVERFLOW, SUSPICIOUS

_HEADER = """sample.exe:     file format pei-x86-64

Disassembly of section .text:
"""

_FIXTURES = {
    "f1_const_overflow": _HEADER + """
0000000140001000 <f1>:
   140001000:	55               	push   rbp
   140001001:	48 89 e5          	mov    rbp,rsp
   140001004:	b9 40 00 00 00    	mov    ecx,0x40
   140001009:	e8 00 00 00 00    	call   140005000 <malloc>
   14000100e:	48 89 45 f8        	mov    QWORD PTR [rbp-0x8],rax
   140001012:	48 8b 45 f8        	mov    rax,QWORD PTR [rbp-0x8]
   140001016:	41 b8 60 00 00 00  	mov    r8d,0x60
   14000101c:	ba 41 00 00 00     	mov    edx,0x41
   140001021:	48 89 c1           	mov    rcx,rax
   140001024:	e8 00 00 00 00    	call   140005010 <memset>
   140001029:	5d               	pop    rbp
   14000102a:	c3               	ret
""",
    "f2_const_safe": _HEADER + """
0000000140001000 <f2>:
   140001000:	55               	push   rbp
   140001001:	48 89 e5          	mov    rbp,rsp
   140001004:	b9 40 00 00 00    	mov    ecx,0x40
   140001009:	e8 00 00 00 00    	call   140005000 <malloc>
   14000100e:	48 89 45 f8        	mov    QWORD PTR [rbp-0x8],rax
   140001012:	48 8b 45 f8        	mov    rax,QWORD PTR [rbp-0x8]
   140001016:	41 b8 40 00 00 00  	mov    r8d,0x40
   14000101c:	ba 41 00 00 00     	mov    edx,0x41
   140001021:	48 89 c1           	mov    rcx,rax
   140001024:	e8 00 00 00 00    	call   140005010 <memset>
   140001029:	5d               	pop    rbp
   14000102a:	c3               	ret
""",
    "f3_padding_safe": _HEADER + """
0000000140001000 <f3>:
   140001000:	55               	push   rbp
   140001001:	48 89 e5          	mov    rbp,rsp
   140001004:	b9 11 00 00 00    	mov    ecx,0x11
   140001009:	e8 00 00 00 00    	call   140005000 <malloc>
   14000100e:	48 89 45 f8        	mov    QWORD PTR [rbp-0x8],rax
   140001012:	48 8b 45 f8        	mov    rax,QWORD PTR [rbp-0x8]
   140001016:	41 b8 14 00 00 00  	mov    r8d,0x14
   14000101c:	ba 41 00 00 00     	mov    edx,0x41
   140001021:	48 89 c1           	mov    rcx,rax
   140001024:	e8 00 00 00 00    	call   140005010 <memset>
   140001029:	5d               	pop    rbp
   14000102a:	c3               	ret
""",
    "f4_guard_bounded": _HEADER + """
0000000140001000 <f4>:
   140001000:	55               	push   rbp
   140001001:	48 89 e5          	mov    rbp,rsp
   140001004:	b9 40 00 00 00    	mov    ecx,0x40
   140001009:	e8 00 00 00 00    	call   140005000 <malloc>
   14000100e:	48 89 45 f8        	mov    QWORD PTR [rbp-0x8],rax
   140001012:	41 b8 20 00 00 00  	mov    r8d,0x20
   140001018:	41 83 f8 40        	cmp    r8d,0x40
   14000101c:	77 0d              	ja     14000102b
   14000101e:	48 8b 45 f8        	mov    rax,QWORD PTR [rbp-0x8]
   140001022:	48 89 c1           	mov    rcx,rax
   140001025:	ba 41 00 00 00     	mov    edx,0x41
   14000102a:	41 b8 20 00 00 00  	mov    r8d,0x20
   140001030:	e8 00 00 00 00    	call   140005010 <memset>
   140001035:	5d               	pop    rbp
   140001036:	c3               	ret
""",
    "f5_shared_src": _HEADER + """
0000000140001000 <f5>:
   140001000:	55               	push   rbp
   140001001:	48 89 e5          	mov    rbp,rsp
   140001004:	89 4d 10           	mov    DWORD PTR [rbp+0x10],ecx
   140001007:	8b 4d 10           	mov    ecx,DWORD PTR [rbp+0x10]
   14000100a:	e8 00 00 00 00    	call   140005000 <malloc>
   14000100f:	48 89 45 f8        	mov    QWORD PTR [rbp-0x8],rax
   140001013:	48 8b 45 f8        	mov    rax,QWORD PTR [rbp-0x8]
   140001017:	4c 8d 05 00 00 00 00	lea    rdx,[rip+0x0]
   14000101e:	44 8b 45 10        	mov    r8d,DWORD PTR [rbp+0x10]
   140001022:	48 89 c1           	mov    rcx,rax
   140001025:	e8 00 00 00 00    	call   140005020 <memcpy>
   14000102a:	5d               	pop    rbp
   14000102b:	c3               	ret
""",
}


def _expect(rep: GASRIReport, wanted: str) -> bool:
    if not rep.pairs:
        print(f"  FAIL: no pair found")
        return False
    v = rep.pairs[0].verdict
    ok = v == wanted
    print(f"  {'OK  ' if ok else 'FAIL'} expected={wanted:9s} got={v:9s} "
          f"rule={rep.pairs[0].rule} alloc={rep.pairs[0].alloc_region} "
          f"write={rep.pairs[0].write_region} usable={rep.pairs[0].usable}")
    if not ok:
        for e in rep.pairs[0].evidence:
            print(f"        {e}")
    return ok


def main() -> int:
    pipe = GASRIPipeline("glibc")
    cases = [
        ("f1_const_overflow", OVERFLOW),
        ("f2_const_safe", SAFE),
        ("f3_padding_safe", SAFE),
        ("f4_guard_bounded", SAFE),
        ("f5_shared_src", SAFE),
    ]
    passed = 0
    for name, want in cases:
        text = _FIXTURES[name]
        rep = pipe.analyze(text, binary_path=f"<fixture:{name}>")
        print(f"[{name}]")
        if _expect(rep, want):
            passed += 1
    print(f"\n{passed}/{len(cases)} passed")
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main())
