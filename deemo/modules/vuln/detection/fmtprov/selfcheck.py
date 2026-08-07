# coding: utf-8
# 创建: 2026-06-09  |  FMTPROV 自检——内联夹具验证
#
"""
FMTPROV 自检 (Win64):
  f1_const_literal     printf("fixed %d", x)      → SAFE  C_const_fmt
  f2_tainted_argv      printf(argv[1])            → VULN  T_tainted_fmt
  f3_const_via_slot    char*f="fixed"; printf(f)  → SAFE  (槽→rodata)
  f4_tainted_gets      gets(buf); printf(buf)     → VULN  (输入写缓冲区)
  f5_unknown_local     printf(local_ptr)          → SUSPICIOUS

运行: python -m fmtprov.selfcheck
"""

import sys

from .pipeline import FmtProvenancePipeline, FmtReport
from .pipeline import SAFE, VULN, SUSPICIOUS

_HEADER = """sample.exe:     file format pei-x86-64

Disassembly of section .text:
"""

_FIXTURES = {
    "f1_const_literal": _HEADER + """
0000000140001000 <main>:
   140001000:	55               	push   rbp
   140001001:	48 89 e5          	mov    rbp,rsp
   140001004:	48 83 ec 20       	sub    rsp,0x20
   140001008:	ba 07 00 00 00    	mov    edx,0x7
   14000100d:	48 8d 0d 00 00 00 00	lea    rcx,[rip+0x0]        # 140004000 <.LC0>
   140001014:	e8 00 00 00 00    	call   140005000 <printf>
   140001019:	5d               	pop    rbp
   14000101a:	c3               	ret
""",
    "f2_tainted_argv": _HEADER + """
0000000140001000 <main>:
   140001000:	55               	push   rbp
   140001001:	48 89 e5          	mov    rbp,rsp
   140001004:	48 83 ec 20       	sub    rsp,0x20
   140001008:	48 89 4d 10       	mov    QWORD PTR [rbp+0x10],rcx
   14000100c:	48 89 55 18       	mov    QWORD PTR [rbp+0x18],rdx
   140001010:	48 8b 45 18       	mov    rax,QWORD PTR [rbp+0x18]
   140001014:	48 83 c0 08       	add    rax,0x8
   140001018:	48 8b 00          	mov    rax,QWORD PTR [rax]
   14000101b:	48 89 c1          	mov    rcx,rax
   14000101e:	e8 00 00 00 00    	call   140005000 <printf>
   140001023:	5d               	pop    rbp
   140001024:	c3               	ret
""",
    "f3_const_via_slot": _HEADER + """
0000000140001000 <main>:
   140001000:	55               	push   rbp
   140001001:	48 89 e5          	mov    rbp,rsp
   140001004:	48 83 ec 20       	sub    rsp,0x20
   140001008:	48 8d 05 00 00 00 00	lea    rax,[rip+0x0]        # 140004000 <.LC0>
   14000100f:	48 89 45 f8       	mov    QWORD PTR [rbp-0x8],rax
   140001013:	48 8b 4d f8       	mov    rcx,QWORD PTR [rbp-0x8]
   140001017:	e8 00 00 00 00    	call   140005000 <printf>
   14000101c:	5d               	pop    rbp
   14000101d:	c3               	ret
""",
    "f4_tainted_gets": _HEADER + """
0000000140001000 <main>:
   140001000:	55               	push   rbp
   140001001:	48 89 e5          	mov    rbp,rsp
   140001004:	48 83 ec 20       	sub    rsp,0x20
   140001008:	48 8d 4d f0       	lea    rcx,[rbp-0x10]
   14000100c:	e8 00 00 00 00    	call   140005010 <gets>
   140001011:	48 8b 4d f0       	mov    rcx,QWORD PTR [rbp-0x10]
   140001015:	e8 00 00 00 00    	call   140005000 <printf>
   14000101a:	5d               	pop    rbp
   14000101b:	c3               	ret
""",
    "f5_unknown_local": _HEADER + """
0000000140001000 <main>:
   140001000:	55               	push   rbp
   140001001:	48 89 e5          	mov    rbp,rsp
   140001004:	48 83 ec 20       	sub    rsp,0x20
   140001008:	48 89 4d 10       	mov    QWORD PTR [rbp+0x10],rcx
   14000100c:	48 8b 45 10       	mov    rax,QWORD PTR [rbp+0x10]
   140001010:	48 89 c1          	mov    rcx,rax
   140001013:	e8 00 00 00 00    	call   140005000 <printf>
   140001018:	5d               	pop    rbp
   140001019:	c3               	ret
""",
}


def _expect(rep: FmtReport, want: str) -> bool:
    if not rep.findings:
        print(f"  FAIL: no format call found (want {want})")
        return False
    f = rep.findings[0]
    ok = f.verdict == want
    print(f"  {'OK  ' if ok else 'FAIL'} expected={want:9s} "
          f"got={f.verdict:9s} rule={f.rule} cls={f.classification}")
    if not ok:
        for e in f.evidence:
            print(f"        {e}")
    return ok


def main() -> int:
    pipe = FmtProvenancePipeline()
    cases = [
        ("f1_const_literal", SAFE),
        ("f2_tainted_argv", VULN),
        ("f3_const_via_slot", SAFE),
        ("f4_tainted_gets", VULN),
        ("f5_unknown_local", SUSPICIOUS),
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
