#!/usr/bin/env python3
# Public interface: AddressEntry, MappingResult, AddressMapper.
# External deps: os, json, subprocess.
# Architecture: generator pattern over inheritance trees; avoids deep class hierarchies.
import logging
import os
import json
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class AddressEntry:
    """Symbol table entry: name, offset, virtual address, size, section."""
    sym: str = ''
    off: int = 0
    va: int = 0
    sz: int = 0
    sec: str = ''

    def __post_init__(self):
        # Enforce numeric types; prevents arithmetic failures from type errors.
        self.sym = str(self.sym) if self.sym else ''
        self.off = int(self.off) if self.off is not None else 0
        self.va = int(self.va) if self.va is not None else 0
        self.sz = int(self.sz) if self.sz is not None else 0
        self.sec = str(self.sec) if self.sec else ''

@dataclass
class MappingResult:
    """Mapping result: status flag, entry set, base address, ASLR delta, symbol count."""
    ok: bool = False
    entries: list = field(default_factory=list)
    base: int = 0
    aslr_delta: int = 0
    nsyms: int = 0

    def __post_init__(self):
        # Normalize types at construction time.
        self.ok = bool(self.ok)
        self.base = int(self.base) if self.base is not None else 0
        self.aslr_delta = int(self.aslr_delta) if self.aslr_delta is not None else 0
        self.nsyms = int(self.nsyms) if self.nsyms is not None else 0

class AddressMapper:
    """Symbol-to-address mapper.

    Invokes r2 isj to extract the symbol table, builds a name-to-VA dictionary.
    Also detects ASLR offset (runtime base vs. static base).
    """

    def __init__(self, binpath, base=0x400000):
        if binpath is None:
            raise ValueError("binpath cannot be None")
        self.__path = os.path.abspath(binpath)
        self.__base = int(base) if base else 0x400000
        self.__entries = []  # AddressEntry container — lazily populated on first load

    # --- Public API ---

    def extract_symbols_(self):
        """Invoke r2 isj to extract symbol table; returns entry list."""
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
                    self.__entries.append(AddressEntry(
                        sym=name, off=va, va=va, sz=sz))
        except Exception as exc:
            logger.warning(f"symbol extraction failed: {exc}")
        return self.__entries

    def detect_aslr_delta_(self, runtime_base):
        """Compute ASLR delta: runtime_base minus static_base."""
        if self.__base == 0:
            return 0
        return int(runtime_base) - self.__base

    def build_map_(self):
        """Build symbol-name to virtual-address mapping dictionary."""
        out = {}
        for e in self.__entries:
            if e.sym:
                out[e.sym] = e.va
        return out

    def export_json_(self, outpath):
        """Export JSON mapping file."""
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

    def run_(self):
        """Execute full mapping pipeline."""
        self.extract_symbols_()
        return MappingResult(
            ok=len(self.__entries) > 0,
            entries=self.__entries,
            base=self.__base,
            nsyms=len(self.__entries),
        )

def create_address_mapper_(binpath):
    """AddressMapper construction entry -- factory function."""
    return AddressMapper(binpath)
