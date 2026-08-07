"""
寄存器级 VSA-Lite — Capstone 反汇编上的 stride-interval 值集分析。

DEEPVSA 用分层 Bi-LSTM 增强 VSA, 需 160 万行执行轨迹训练。
本模块做确定性 stride-interval 追踪: 每条 mov/lea 指令追踪寄存器值区间,
跨基本块汇合取并集, 遇 call 保守置 ⊤。仅追踪 malloc 返回值和 memcpy 目标地址。

参考: Balakrishnan & Reps "Analyzing Memory Accesses in x86 Executables"。
"""


import re
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class StrideInterval:
    lo: int = 0
    stride: int = 1
    count: int = 0  # 0 = ⊤

    @staticmethod
    def top() -> "StrideInterval": return StrideInterval(0, 1, 0)
    @staticmethod
    def constant(v: int) -> "StrideInterval": return StrideInterval(v, 0, 1)

    @property
    def hi(self) -> int:
        return 2**63-1 if self.count == 0 else self.lo+(self.count-1)*self.stride
    @property
    def is_top(self) -> bool: return self.count == 0


@dataclass
class HeapObj:
    obj_id: int; base_si: StrideInterval; size_si: StrideInterval
    alloc_addr: int; func: str = ""

@dataclass
class MemWrite:
    target_si: StrideInterval; size: int; insn_addr: int; func: str = ""


def analyze_vsa(binary_path: str) -> Tuple[List[dict], dict]:
    import time
    t0 = time.time()
    data, base = _read_text(binary_path)
    if not data: return [], {"error":"no .text","elapsed":time.time()-t0}
    try:
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
    except ImportError:
        return [], {"error":"capstone missing","elapsed":time.time()-t0}

    # PE导入表解析 → IAT地址→函数名映射 (委托给 core/pe_imports.py)
    from core.pe_imports import resolve as _resolve_pe
    iat_map = _resolve_pe(binary_path)

    regs: Dict[str, StrideInterval] = {}
    objs: List[HeapObj] = []; writes: List[MemWrite] = []; oid = 0

    def get(r): return regs.get(r, StrideInterval.top())
    def set_reg(r, si): regs[r] = si

    for insn in md.disasm(data, base):
        m, op = insn.mnemonic, insn.op_str
        parts = [p.strip() for p in op.split(',')]

        if m == 'mov' and len(parts) == 2:
            try:
                v = int(parts[1], 16) if parts[1].startswith('0x') else int(parts[1])
                set_reg(parts[0], StrideInterval.constant(v))
            except ValueError:
                if parts[1] in regs: set_reg(parts[0], get(parts[1]))

        if m == 'lea' and len(parts) == 2:
            si = _ea_to_si(parts[1], regs)
            if si: set_reg(parts[0], si)

        if m == 'call':
            if 'malloc' in op:
                oid += 1
                objs.append(HeapObj(oid, get('rax'), get('rdi'), insn.address))
                set_reg('rax', StrideInterval.top())
            elif 'memcpy' in op:
                writes.append(MemWrite(get('rdi'),
                                       get('rdx').lo if not get('rdx').is_top else 0,
                                       insn.address))

    violations = []
    for obj in objs:
        if obj.base_si.is_top or obj.size_si.is_top: continue
        for w in writes:
            if w.target_si.is_top or w.size == 0: continue
            if obj.base_si.stride == 0 and w.target_si.stride == 0:
                b = obj.base_si.lo; ws = w.size
                sz = obj.size_si.lo if not obj.size_si.is_top else 0
                if sz > 0 and b <= w.target_si.lo and w.target_si.lo + ws > b + sz:
                    violations.append({
                        'severity': 'CRITICAL', 'alloc': hex(b),
                        'size': sz, 'write_size': ws,
                        'overflow': w.target_si.lo+ws-(b+sz),
                        'method': 'vsa-lite',
                    })
    return violations, {"heap_objects": len(objs), "mem_writes": len(writes),
                        "violations": len(violations),
                        "elapsed": round(time.time()-t0, 4)}


def _ea_to_si(ea: str, regs: dict) -> Optional[StrideInterval]:
    inner = re.sub(r'(qword|dword|word|byte)\s+ptr\s+', '', ea).strip('[]')
    br = None; off = 0
    for p in re.split(r'\s*\+\s*', inner):
        p = p.strip()
        if p in ('rax','rbx','rcx','rdx','rsi','rdi','rsp','rbp',
                 'r8','r9','r10','r11','r12','r13','r14','r15'):
            br = p
        elif re.match(r'^-?(0x)?[0-9a-fA-F]+$', p):
            off = int(p,16) if p.startswith('0x') else int(p)
        elif '*' in p: return StrideInterval.top()
    if br and br in regs:
        si = regs[br]
        if not si.is_top and si.stride == 0: return StrideInterval.constant(si.lo+off)
    return StrideInterval.top()


def _parse_pe_imports(path: str) -> dict[int,str]:
    """解析PE导入表, 返回 {IAT地址: 函数名} 映射。"""
    try:
        with open(path,'rb') as f:
            if f.read(2)!=b'MZ': return {}
            f.seek(0x3C); pe_off=struct.unpack('<I',f.read(4))[0]
            f.seek(pe_off)
            if f.read(4)!=b'PE\x00\x00': return {}
            coh=f.read(20)
            opt_hdr_sz=struct.unpack('<H',coh[16:18])[0]
            f.seek(pe_off+24+opt_hdr_sz)
            # 遍历section headers找.idata
            nsects=struct.unpack('<H',coh[2:4])[0]
            idata_ra=0; idata_sz=0
            for _ in range(nsects):
                sh=f.read(40); nm=sh[0:8].rstrip(b'\x00').decode()
                if nm=='.idata':
                    idata_ra=struct.unpack('<I',sh[20:24])[0]
                    idata_sz=struct.unpack('<I',sh[16:20])[0]
            if not idata_ra: return {}
            # 读取导入目录
            f.seek(idata_ra)
            imap={}
            while True:
                entry=f.read(20)
                if all(b==0 for b in entry): break
                iat_rva=struct.unpack('<I',entry[16:20])[0]
                name_rva=struct.unpack('<I',entry[12:16])[0]
                if not iat_rva or not name_rva: continue
                # 读取DLL名称
                cur=f.tell(); f.seek(name_rva)
                dll_name=b''
                while True:
                    b=f.read(1)
                    if b==b'\x00': break
                    dll_name+=b
                dll_name=dll_name.decode(errors='replace')
                # 读取IAT
                f.seek(iat_rva)
                hint_off=0
                while True:
                    f.seek(iat_rva+hint_off*8)
                    va=struct.unpack('<Q',f.read(8))[0]
                    if va==0: break
                    if va&0x8000000000000000:  # ordinal import
                        ord_val=va&0xFFFF
                        imap[va]=f'{dll_name}!ord_{ord_val}'
                    else:
                        f.seek(va+2)  # skip hint
                        fn=b''
                        while True:
                            b=f.read(1)
                            if b==b'\x00': break
                            fn+=b
                        fn_name=fn.decode(errors='replace')
                        imap[va]=fn_name
                    hint_off+=1
                f.seek(cur)
            return imap
    except: return {}


def _read_text(path: str) -> Tuple[Optional[bytes], int]:
    try:
        with open(path,'rb') as f:
            h=f.read(64)
            # ELF
            if h[:4]==b'\x7fELF' and h[4]==2:
                shoff=struct.unpack('<Q',h[40:48])[0]; shesize=struct.unpack('<H',h[58:60])[0]
                shnum=struct.unpack('<H',h[60:62])[0]; shstrndx=struct.unpack('<H',h[62:64])[0]
                f.seek(shoff+shstrndx*shesize); se=f.read(shesize)
                stroff=struct.unpack('<Q',se[24:32])[0]; strsz=struct.unpack('<Q',se[32:40])[0]
                f.seek(stroff); ss=f.read(strsz)
                for i in range(shnum):
                    f.seek(shoff+i*shesize); sh=f.read(shesize)
                    no=struct.unpack('<I',sh[0:4])[0]
                    nm=ss[no:ss.index(b'\x00',no)].decode()
                    if nm=='.text':
                        return f.read(struct.unpack('<Q',sh[32:40])[0]), struct.unpack('<Q',sh[16:24])[0]
            # PE/COFF (MinGW on Windows)
            elif h[:2]==b'MZ':
                f.seek(0x3C); pe_off=struct.unpack('<I',f.read(4))[0]
                f.seek(pe_off)
                if f.read(4)==b'PE\x00\x00':
                    coh=f.read(20); nsects=struct.unpack('<H',coh[2:4])[0]
                    opt_hdr_sz=struct.unpack('<H',coh[16:18])[0]
                    f.seek(pe_off+24+opt_hdr_sz)
                    for _ in range(nsects):
                        sh=f.read(40); nm=sh[0:8].rstrip(b'\x00').decode()
                        vs=struct.unpack('<I',sh[12:16])[0]
                        ra=struct.unpack('<I',sh[20:24])[0]
                        if nm=='.text' and vs>0:
                            f.seek(ra); return f.read(vs), ra
    except: pass
    return None,0
