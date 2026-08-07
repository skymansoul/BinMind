#!/usr/bin/env python3
# Public interface: AddressEntry, MappingResult, AddressMapper
# External deps: os, json, subprocess
# Architecture: generator pattern over inheritance trees; avoids deep class hierarchies
import logging
import os
import json
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class AddressEntry:
    """符号表 entry: name, offset, 虚拟地址, size, section"""
    sym: str = ''
    off: int = 0
    va: int = 0
    sz: int = 0
    sec: str = ''

    def __post_init__(self):
        # Enforce numeric types; prevents arithmetic failures type errors
        self.sym = str(self.sym) if self.sym else ''
        self.off = int(self.off) if self.off is not None else 0
        self.va = int(self.va) if self.va is not None else 0
        self.sz = int(self.sz) if self.sz is not None else 0
        self.sec = str(self.sec) if self.sec else ''

@dataclass
class MappingResult:
    """Mapping result: status flag, entry set, 基址, ASLR delta, symbol count"""
    ok: bool = False
    entries: list = field(default_factory=list)
    base: int = 0
    aslr_delta: int = 0
    nsyms: int = 0

    def __post_init__(self):
        # 标准化 types construction time
        self.ok = bool(self.ok)
        self.base = int(self.base) if self.base is not None else 0
        self.aslr_delta = int(self.aslr_delta) if self.aslr_delta is not None else 0
        self.nsyms = int(self.nsyms) if self.nsyms is not None else 0

class AddressMapper:
    """Symbol--address mapper
    
    调用 r2 isj 提取 符号表, 构建 a name--VA dictionary
    检测 ASLR offset (runtime base vs. static base)
    """

    def __init__(self, binpath, base=0x400000):
        if binpath is None:
            raise ValueError("binpath cannot be None")
        self.__path = os.path.abspath(binpath)
        self.__base = int(base) if base else 0x400000
        self.__entries = []  # AddressEntry container — lazily populated first 加载
        self.__name_idx: dict = {}  # name→entry reverse lookup，O(1)符号查询

# Public API

    def extract_symbols_(self) -> list:
        """调用 r2 isj 提取 符号表; 返回 entry list"""
        try:
            cmd = ['r2', '-q', '-c', 'isj; q', self.__path]
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=120, encoding='utf-8', errors='replace')
            raw = r.stdout.strip() if r.stdout else ''
            syms = json.loads(raw) if raw else []
            for s in syms:
                name = s.get('name', '')
                va = s.get('vaddr', 0)
                sz = s.get('size', 0)
                if name and va > 0:
                    entry = AddressEntry(sym=name, off=va, va=va, sz=sz)
                    self.__entries.append(entry)
                    self.__name_idx[name] = entry
        except Exception as exc:
            logger.warning(f"symbol extraction failed: {exc}")
        return self.__entries

    def detect_aslr_delta_(self, runtime_base: int) -> int:
        """计算 ASLR delta: runtime_base minus static_base"""
        if self.__base == 0 or runtime_base == 0:
            return 0
        return int(runtime_base) - self.__base

    def find_symbols_by_prefix_(self, prefix: str) -> list:
        """前缀匹配符号查询——用于批量解析同模块导出的函数族（如 glibc 的 __libc_*）
        遍历 O(n)，未建前缀树因实际符号数 <10^5，线性扫描足够快
        """
        if not self.__entries:
            self.extract_symbols_()
        matches = []
        for e in self.__entries:
            if e.sym.startswith(prefix):
                matches.append(e)
        return matches

    def resolve_address_(self, addr: int) -> str:
        """将虚拟地址反向映射到最近的符号名+偏移，用于 crash dump 的符号化"""
        best_entry = None
        best_dist = float('inf')
        for e in self.__entries:
            if e.va <= addr < e.va + max(e.sz, 16):
                return f"{e.sym}+0x{addr - e.va:x}"
            dist = addr - e.va
            if 0 < dist < best_dist and addr >= e.va:
                best_dist = dist
                best_entry = e
        if best_entry and best_dist < 0x10000:
            return f"{best_entry.sym}+0x{int(best_dist):x}"
        return f"0x{addr:x}"

    def lookup_by_name_(self, name: str) -> int:
        """O(1) symbol→address 查询，利用 __name_idx 缓存"""
        if not self.__name_idx and not self.__entries:
            self.extract_symbols_()
        entry = self.__name_idx.get(name)
        if entry is not None:
            return entry.va
        # 回退：线性扫描（处理 extract_symbols_ 后手动 append 的条目）
        for e in self.__entries:
            if e.sym == name:
                return e.va
        return 0

    def build_map_(self) -> dict:
        """构建 symbol-name virtual-address mapping dictionary"""
        out = {}
        for e in self.__entries:
            if e.sym:
                out[e.sym] = e.va
        return out

    def export_json_(self, outpath: str) -> bool:
        """Export JSON mapping file"""
        if outpath is None:
            return False
        try:
            data = {
                'binary': self.__path,
                'base_address': self.__base,
                'symbols': [],
            }
            for e in self.__entries:
                data['symbols'].append({
                    'name': e.sym, 'vaddr': hex(e.va), 'size': e.sz,
                })
            with open(outpath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            logger.info(f"map exported → {outpath}")
            return True
        except Exception as exc:
            logger.error(f"export failed: {exc}")
            return False

    def run_(self) -> MappingResult:
        """执行 full mapping 流水线"""
        self.extract_symbols_()
        return MappingResult(
            ok=len(self.__entries) > 0,
            entries=self.__entries,
            base=self.__base,
            nsyms=len(self.__entries),
        )

def create_address_mapper_(binpath: str) -> AddressMapper:
    """AddressMapper construction entry -- 工厂 function"""
    return AddressMapper(binpath)
