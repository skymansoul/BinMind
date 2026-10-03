import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)



class SourceMapping:
    __slots__ = ('address', 'source_file', 'line_number', 'column', 'func_name', 'inlined_from',)

    def __init__(self, address, source_file, line_number, column=0, func_name="", inlined_from=""):
        self.address = address
        self.source_file = source_file
        self.line_number = line_number
        self.column = column
        self.func_name = func_name
        self.inlined_from = inlined_from

    def to_dict(self) -> Dict[str, Any]:
        return {
            'address': hex(self.address),
            'file': self.source_file,
            'line': self.line_number,
            'func': self.func_name,
            'inlined_from': self.inlined_from
        }


class DWARFLineParser:
    @staticmethod
    def parse_line_program(data: bytes, base_addr: int = 0) -> List[SourceMapping]:
        mappings = []
        try:
            text = data.decode('ascii', errors='replace')
            for line in text.split('\n'):
                if '0x' in line and ':' in line:
                    parts = line.strip().split()
                    if parts:
                        try:
                            addr = int(parts[0], 16)
                            mappings.append(SourceMapping(
                                address=addr, source_file='unknown',
                                line_number=0))
                        except ValueError:
                            pass
        except Exception:
            logger.debug("suppressed", exc_info=True)
        return mappings


class SourceBinaryMapper:

    def __init__(self):
        self._mappings: Dict[int, SourceMapping] = {}
        self._by_file: Dict[str, List[SourceMapping]] = {}

    def add_mapping(self, addr: int, source_file: str,
                    line: int, func_name: str = "",
                    inlined_from: str = ""):
        mapping = SourceMapping(
            address=addr, source_file=source_file,
            line_number=line, func_name=func_name,
            inlined_from=inlined_from)
        self._mappings[addr] = mapping
        self._by_file.setdefault(source_file, []).append(mapping)

    def lookup_addr(self, addr: int) -> Optional[SourceMapping]:
        if addr in self._mappings:
            return self._mappings[addr]
        closest = None
        closest_dist = float('inf')
        for mapped_addr, mapping in self._mappings.items():
            if mapped_addr <= addr and addr - mapped_addr < closest_dist:
                closest = mapping
                closest_dist = addr - mapped_addr
        return closest if closest_dist < 4096 else None

    def lookup_file(self, path_pattern: str) -> List[SourceMapping]:
        results = []
        for fname, mappings in self._by_file.items():
            if path_pattern.lower() in fname.lower():
                results.extend(mappings)
        return results

    def analyze(self, mappings: Optional[List[Dict[str, Any]]] = None,
                query_addr: Optional[int] = None, **kwargs) -> Dict[str, Any]:
        if mappings:
            for m in mappings:
                self.add_mapping(
                    m.get('address', 0),
                    m.get('source_file', 'unknown'),
                    m.get('line', 0),
                    m.get('func_name', ''),
                    m.get('inlined_from', ''))

        result = {
            'success': True,
            'total_mappings': len(self._mappings),
            'files_mapped': len(self._by_file),
            'files': list(self._by_file.keys())[:20]
        }

        if query_addr:
            found = self.lookup_addr(query_addr)
            if found:
                result['query_result'] = found.to_dict()
            else:
                result['query_result'] = None

        return result


def map_source_to_binary(mappings: List[Dict[str, Any]],
                         query_addr: Optional[int] = None,
                         **kwargs) -> Dict[str, Any]:
    mapper = SourceBinaryMapper()
    return mapper.analyze(mappings=mappings, query_addr=query_addr)


__all__ = ["SourceBinaryMapper", "DWARFLineParser", "SourceMapping",
           "map_source_to_binary"]
