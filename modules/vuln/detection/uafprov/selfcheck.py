# coding: utf-8
#
"""
UAF-PROV 自检:
  u1_simple_uaf     free 后同指针解引用        → UAF
  u2_realloc_safe   free 后 malloc 复用同槽     → SAFE (R2/R3)
  u3_diff_obj       free A 后解引用 B           → SAFE (R2)
  u4_no_use         free 后无解引用             → 无对, 不检出
  u5_call_via_uaf   free 后经悬垂指针间接调用    → UAF

运行: python -m uafprov.selfcheck
"""

import sys

from .pipeline import UafProvenancePipeline, UAFReport
from .lifetime import UAF, SAFE, SUSPICIOUS

_HEADER = """sample.exe:     file format pei-x86-64

Disassembly of section .text:
"""

_FIXTURES = {
    "u1_simple_uaf": _HEADER + """
0000000140001000 <main>:
   140001000:	55               	push   rbp
   140001001:	48 89 e5          	mov    rbp,rsp
   140001004:	48 83 ec 30       	sub    rsp,0x30
   140001008:	b9 40 00 00 00    	mov    ecx,0x40
   14000100d:	e8 00 00 00 00    	call   140005000 <malloc>
   140001012:	48 89 45 f8        	mov    QWORD PTR [rbp-0x8],rax
   140001016:	48 8b 4d f8        	mov    rcx,QWORD PTR [rbp-0x8]
   14000101a:	e8 00 00 00 00    	call   140005010 <free>
   14000101f:	48 8b 5d f8        	mov    rbx,QWORD PTR [rbp-0x8]
   140001023:	8b 03              	mov    eax,DWORD PTR [rbx]
   140001025:	5d               	pop    rbp
   140001026:	c3               	ret
""",
    "u2_realloc_safe": _HEADER + """
0000000140001000 <main>:
   140001000:	55               	push   rbp
   140001001:	48 89 e5          	mov    rbp,rsp
   140001004:	48 83 ec 30       	sub    rsp,0x30
   140001008:	b9 40 00 00 00    	mov    ecx,0x40
   14000100d:	e8 00 00 00 00    	call   140005000 <malloc>
   140001012:	48 89 45 f8        	mov    QWORD PTR [rbp-0x8],rax
   140001016:	48 8b 4d f8        	mov    rcx,QWORD PTR [rbp-0x8]
   14000101a:	e8 00 00 00 00    	call   140005010 <free>
   14000101f:	b9 40 00 00 00    	mov    ecx,0x40
   140001024:	e8 00 00 00 00    	call   140005000 <malloc>
   140001029:	48 89 45 f8        	mov    QWORD PTR [rbp-0x8],rax
   14000102d:	48 8b 5d f8        	mov    rbx,QWORD PTR [rbp-0x8]
   140001031:	8b 03              	mov    eax,DWORD PTR [rbx]
   140001033:	5d               	pop    rbp
   140001034:	c3               	ret
""",
    "u3_diff_obj": _HEADER + """
0000000140001000 <main>:
   140001000:	55               	push   rbp
   140001001:	48 89 e5          	mov    rbp,rsp
   140001004:	48 83 ec 30       	sub    rsp,0x30
   140001008:	b9 40 00 00 00    	mov    ecx,0x40
   14000100d:	e8 00 00 00 00    	call   140005000 <malloc>
   140001012:	48 89 45 f8        	mov    QWORD PTR [rbp-0x8],rax
   140001016:	b9 20 00 00 00    	mov    ecx,0x20
   14000101b:	e8 00 00 00 00    	call   140005000 <malloc>
   140001020:	48 89 45 f0        	mov    QWORD PTR [rbp-0x10],rax
   140001024:	48 8b 4d f8        	mov    rcx,QWORD PTR [rbp-0x8]
   140001028:	e8 00 00 00 00    	call   140005010 <free>
   14000102d:	48 8b 5d f0        	mov    rbx,QWORD PTR [rbp-0x10]
   140001031:	8b 03              	mov    eax,DWORD PTR [rbx]
   140001033:	5d               	pop    rbp
   140001034:	c3               	ret
""",
    "u4_no_use": _HEADER + """
0000000140001000 <main>:
   140001000:	55               	push   rbp
   140001001:	48 89 e5          	mov    rbp,rsp
   140001004:	b9 40 00 00 00    	mov    ecx,0x40
   140001009:	e8 00 00 00 00    	call   140005000 <malloc>
   14000100e:	48 89 45 f8        	mov    QWORD PTR [rbp-0x8],rax
   140001012:	48 8b 4d f8        	mov    rcx,QWORD PTR [rbp-0x8]
   140001016:	e8 00 00 00 00    	call   140005010 <free>
   14000101b:	5d               	pop    rbp
   14000101c:	c3               	ret
""",
    "u5_call_via_uaf": _HEADER + """
0000000140001000 <main>:
   140001000:	55               	push   rbp
   140001001:	48 89 e5          	mov    rbp,rsp
   140001004:	b9 40 00 00 00    	mov    ecx,0x40
   140001009:	e8 00 00 00 00    	call   140005000 <malloc>
   14000100e:	48 89 45 f8        	mov    QWORD PTR [rbp-0x8],rax
   140001012:	48 8b 4d f8        	mov    rcx,QWORD PTR [rbp-0x8]
   140001016:	e8 00 00 00 00    	call   140005010 <free>
   14000101b:	48 8b 5d f8        	mov    rbx,QWORD PTR [rbp-0x8]
   14000101f:	ff d3              	call   rbx
   140001021:	5d               	pop    rbp
   140001022:	c3               	ret
""",
}


def _expect(rep: UAFReport, want: str) -> bool:
    if want == "NONE":
        ok = rep.n_pairs == 0 and not rep.detected
        print(f"  {'OK  ' if ok else 'FAIL'} expected=no-pair "
              f"pairs={rep.n_pairs} detected={rep.detected}")
        return ok
    if not rep.pairs:
        print(f"  FAIL: no pair found (want {want})")
        return False
    v = rep.pairs[0].verdict
    ok = v == want
    print(f"  {'OK  ' if ok else 'FAIL'} expected={want:9s} got={v:9s} "
          f"rule={rep.pairs[0].rule} free_obj={rep.pairs[0].free_alloc} "
          f"use_obj={rep.pairs[0].use_alloc}")
    if not ok:
        for e in rep.pairs[0].evidence:
            print(f"        {e}")
    return ok


def main() -> int:
    pipe = UafProvenancePipeline()
    cases = [
        ("u1_simple_uaf", UAF),
        ("u2_realloc_safe", SAFE),
        ("u3_diff_obj", SAFE),
        ("u4_no_use", "NONE"),
        ("u5_call_via_uaf", UAF),
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
