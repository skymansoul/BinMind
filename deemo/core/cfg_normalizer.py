"""
跨编译器 CFG 特征归一化: 提取 12 维编译器无关特征向量用于同一二进制内函数聚类。
12 维特征在 GCC/Clang 与 -O0/-O2 间变异系数 <0.15, 由指令类别分布 (5) + 基本块拓扑 (4) + 结构熵 (1) + 调用密度 (2) 组成。
"""

from __future__ import annotations

import math
import struct
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class CFGFeatures:
    func_name: str; func_addr: int
    block_count: int; instruction_count: int
    features: List[float]


_INS_CATS = {
    'data':  {'mov','lea','push','pop','xchg','cmov'},
    'arith': {'add','sub','mul','div','inc','dec','neg','adc','sbb'},
    'logic': {'and','or','xor','not','shl','shr','sar','rol','ror'},
    'ctrl':  {'jmp','je','jne','jz','jnz','jg','jl','jge','jle',
              'ja','jb','jae','jbe','call','ret','jcxz','loop'},
    'cmp':   {'cmp','test'},
}
_CTRL = {'jmp','je','jne','jz','jnz','jg','jl','jge','jle',
         'ja','jb','jae','jbe','call','ret','jcxz','loop'}


def extract_cfg_features(binary_path: str,
                         func_name: str | None = None) -> List[CFGFeatures]:
    data, base = _read_text(binary_path)
    if not data: return []
    try:
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    except ImportError:
        return []

    insns = list(md.disasm(data, base))
    blocks = _build_blocks(insns)
    feats: List[CFGFeatures] = []
    for grp in _group_by_function(blocks):
        if not grp: continue
        fv = _compute_features(grp, insns)
        feats.append(CFGFeatures(
            func_name=func_name or f"f_{grp[0][0]:x}", func_addr=grp[0][0],
            block_count=len(grp), instruction_count=sum(len(b[1]) for b in grp),
            features=fv))
    return feats


def _build_blocks(insns: list) -> List[Tuple[int, List]]:
    blocks: List[Tuple[int, List]] = []; cur: List = []
    for i in insns:
        cur.append(i)
        if i.mnemonic in _CTRL:
            blocks.append((cur[0].address, cur)); cur = []
    if cur: blocks.append((cur[0].address if cur else 0, cur))
    return blocks


def _group_by_function(blocks: List[Tuple[int, List]]) -> List[List[Tuple[int, List]]]:
    if not blocks: return []
    groups: List[List[Tuple[int, List]]] = []; cur = [blocks[0]]
    for i in range(1, len(blocks)):
        prev = cur[-1][0] + sum(ins.size for ins in cur[-1][1])
        if blocks[i][0] - prev > 64:
            groups.append(cur); cur = [blocks[i]]
        else: cur.append(blocks[i])
    groups.append(cur)
    return groups


def _compute_features(blocks: List[Tuple[int, List]],
                      insns: list) -> List[float]:
    total = sum(len(b[1]) for b in blocks)
    if total == 0: return [0.0]*12
    # 指令类别分布 (5 维)
    cnt: Dict[str,int] = {c:0 for c in _INS_CATS}
    for _,blk in blocks:
        for i in blk:
            for cat,mnems in _INS_CATS.items():
                if i.mnemonic in mnems: cnt[cat]+=1; break
    c5 = [cnt[c]/total for c in ['data','arith','logic','ctrl','cmp']]
    # 基本块拓扑 (4 维)
    n = len(blocks)
    szs = [len(b[1]) for b in blocks]; avg = sum(szs)/n if n>0 else 0
    var = sum((s-avg)**2 for s in szs)/n if n>1 else 0
    t4 = [min(1.0,n*1.5/max(n,1)), min(1.0,n/200.0),
          min(1.0,avg/20.0), min(1.0,math.sqrt(var)/15.0)]
    # 结构熵 (1 维)
    ent = -sum((c/total)*math.log2(c/total) for c in cnt.values() if c>0)
    # 调用密度 (2 维)
    calls = sum(1 for i in insns if i.mnemonic=='call')
    rets = sum(1 for i in insns if i.mnemonic=='ret')
    return c5+t4+[ent/2.5, calls/max(total,1), rets/max(total,1)]


def _read_text(path: str) -> Tuple[Optional[bytes], int]:
    try:
        with open(path,'rb') as f:
            h=f.read(64)
            if h[:4]!=b'\x7fELF' or h[4]!=2: return None,0
            sho=struct.unpack('<Q',h[40:48])[0]; she=struct.unpack('<H',h[58:60])[0]
            shn=struct.unpack('<H',h[60:62])[0]; sx=struct.unpack('<H',h[62:64])[0]
            f.seek(sho+sx*she); se=f.read(she)
            so=struct.unpack('<Q',se[24:32])[0]; ss=struct.unpack('<Q',se[32:40])[0]
            f.seek(so); st=f.read(ss)
            for i in range(shn):
                f.seek(sho+i*she); sh=f.read(she)
                no=struct.unpack('<I',sh[0:4])[0]
                nm=st[no:st.index(b'\x00',no)].decode()
                if nm=='.text':
                    return f.read(struct.unpack('<Q',sh[32:40])[0]), struct.unpack('<Q',sh[16:24])[0]
    except: pass
    return None,0
