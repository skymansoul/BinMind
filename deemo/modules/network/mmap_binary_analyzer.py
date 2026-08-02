import logging, struct, os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

class MmapProtection: NONE=0; READ=1; WRITE=2; EXEC=4; RW=3; RX=5; RWX=7

@dataclass
class MappedRegion:
    start_addr: Any=None; end_addr: Any=None; size: int=0; protection: Any=None
    offset: int=0; inode: Any=None; pathname: Any=None; is_shared: Any=None; is_wx_violation: Any=None
    @property
    def is_rwx(self) -> bool: return self.protection == MmapProtection.RWX
    def to_dict(self) -> Dict[str, Any]:
        return {'range': f'{hex(self.start_addr)}-{hex(self.end_addr)}', 'size_kb': self.size // 1024,
                'protection': self.protection, 'is_shared': self.is_shared, 'pathname': self.pathname,
                'is_rwx': self.is_rwx, 'is_wx_violation': self.is_wx_violation}

class ElfSegment:
    __slots__ = ('seg_type', 'vaddr', 'memsz', 'offset', 'filesz', 'flags', 'alignment',)
    def __init__(self, seg_type, vaddr, memsz, offset, filesz, flags, alignment=0x1000):
        self.seg_type=seg_type; self.vaddr=vaddr; self.memsz=memsz; self.offset=offset
        self.filesz=filesz; self.flags=flags; self.alignment=alignment

class MmapParser:
    @staticmethod
    def parse_maps_line(line: str) -> Optional[MappedRegion]:
        parts = line.strip().split(None, 5)
        if len(parts) < 3: return None
        addr_range = parts[0].split('-'); start = int(addr_range[0], 16); end = int(addr_range[1], 16)
        perm_str = parts[1]; offset = int(parts[2], 16) if len(parts) > 2 else 0
        pathname = parts[-1] if len(parts) >= 6 else ""
        prot_value = 0
        if 'r' in perm_str: prot_value |= MmapProtection.READ
        if 'w' in perm_str: prot_value |= MmapProtection.WRITE
        if 'x' in perm_str: prot_value |= MmapProtection.EXEC
        is_shared = 's' in perm_str; is_wx = ('w' in perm_str and 'x' in perm_str)
        return MappedRegion(start_addr=start, end_addr=end, size=end-start,
            protection=prot_value, offset=offset, pathname=pathname,
            is_shared=is_shared, is_wx_violation=is_wx)

class ElfHeaderParser:
    ELF_MAGIC = b'\x7fELF'
    @classmethod
    def parse_program_headers(cls, data: bytes) -> List[ElfSegment]:
        if len(data) < 64 or data[:4] != cls.ELF_MAGIC: return []
        return cls._parse_phdr64(data) if data[4] == 2 else cls._parse_phdr32(data)

    @classmethod
    def _parse_phdr64(cls, data: bytes) -> List[ElfSegment]:
        phoff = struct.unpack_from('<Q', data, 32)[0]; phentsize = struct.unpack_from('<H', data, 54)[0]
        phnum = struct.unpack_from('<H', data, 56)[0]; segments = []
        SEG_TYPES = {1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 6: 'PHDR',
                     0x6474E550: 'GNU_EH_FRAME', 0x6474E551: 'GNU_STACK', 0x6474E552: 'GNU_RELRO'}
        for i in range(min(phnum, 16)):
            off = phoff + i * phentsize
            if off + 56 > len(data): break
            ptype = struct.unpack_from('<I', data, off)[0]; pflags = struct.unpack_from('<I', data, off + 4)[0]
            p_vaddr = struct.unpack_from('<Q', data, off + 16)[0]; p_memsz = struct.unpack_from('<Q', data, off + 40)[0]
            p_offset = struct.unpack_from('<Q', data, off + 8)[0]; p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
            flags_str = ''.join(['R' if pflags & 4 else '-', 'W' if pflags & 2 else '-', 'E' if pflags & 1 else '-'])
            segments.append(ElfSegment(seg_type=SEG_TYPES.get(ptype, f"UNKNOWN({ptype})"),
                vaddr=p_vaddr, memsz=p_memsz, offset=p_offset, filesz=p_filesz, flags=flags_str))
        return segments

    @classmethod
    def _parse_phdr32(cls, data: bytes) -> List[ElfSegment]:
        if len(data) < 52: return []
        phoff = struct.unpack_from('<I', data, 28)[0]; phentsize = struct.unpack_from('<H', data, 42)[0]
        phnum = struct.unpack_from('<H', data, 44)[0]; segs = []
        seg_types = {1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 6: 'PHDR',
                     0x6474E550: 'GNU_EH_FRAME', 0x6474E551: 'GNU_STACK', 0x6474E552: 'GNU_RELRO'}
        for i in range(min(phnum, 16)):
            off = phoff + i * phentsize
            if off + 32 > len(data): break
            p_type = struct.unpack_from('<I', data, off + 0)[0]; p_off = struct.unpack_from('<I', data, off + 4)[0]
            p_vaddr = struct.unpack_from('<I', data, off + 8)[0]; p_fsz = struct.unpack_from('<I', data, off + 16)[0]
            p_msz = struct.unpack_from('<I', data, off + 20)[0]; p_flags = struct.unpack_from('<I', data, off + 24)[0]
            flg = ''.join(['R' if p_flags & 4 else '-', 'W' if p_flags & 2 else '-', 'E' if p_flags & 1 else '-'])
            segs.append(ElfSegment(seg_type=seg_types.get(p_type, f"UNKNOWN({p_type})"),
                vaddr=p_vaddr, memsz=p_msz, offset=p_off, filesz=p_fsz, flags=flg))
        return segs

class MmapBinaryAnalyzer:
    def __init__(self):
        self.parser = MmapParser(); self.elf_parser = ElfHeaderParser()
        self._regions: List[MappedRegion] = []

    def parse_maps(self, maps_content: str):
        for line in maps_content.strip().split('\n'):
            region = self.parser.parse_maps_line(line)
            if region: self._regions.append(region)

    def check_wx_violations(self) -> List[MappedRegion]: return [r for r in self._regions if r.is_wx_violation]
    def check_rwx_regions(self) -> List[MappedRegion]: return [r for r in self._regions if r.is_rwx]
    def find_executable_stacks(self) -> List[MappedRegion]:
        return [r for r in self._regions if r.is_wx_violation and '[stack' in r.pathname]

    def analyze(self, maps_content: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        if maps_content: self.parse_maps(maps_content)
        wx = self.check_wx_violations(); rwx = self.check_rwx_regions()
        exec_stacks = self.find_executable_stacks()
        return {'success': True, 'total_regions': len(self._regions),
            'regions': [r.to_dict() for r in self._regions[:50]],
            'security_issues': {'wx_violations': [r.to_dict() for r in wx],
                'rwx_regions': [r.to_dict() for r in rwx],
                'executable_stacks': [r.to_dict() for r in exec_stacks]},
            'risk_level': 'critical' if exec_stacks else 'high' if rwx else 'medium' if wx else 'low',
            'stats': {'total_memory_kb': sum(r.size for r in self._regions) // 1024,
                'code_regions': sum(1 for r in self._regions if (r.protection & MmapProtection.EXEC) != 0),
                'writable_code': len(wx),
                'heap_regions': sum(1 for r in self._regions if '[heap' in r.pathname),
                'stack_regions': sum(1 for r in self._regions if '[stack' in r.pathname)}}

def analyze_mmap_regions(maps_content: str, **kwargs) -> Dict[str, Any]:
    return MmapBinaryAnalyzer().analyze(maps_content=maps_content)

__all__ = ["MmapBinaryAnalyzer", "MmapParser", "ElfHeaderParser", "MappedRegion", "MmapProtection", "ElfSegment", "analyze_mmap_regions"]
