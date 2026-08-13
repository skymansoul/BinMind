import logging
import json
import re
import textwrap
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

# from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

log = logging.getLogger(__name__)


class MemoryProtection(Enum):
    NONE = "---"
    READ = "r--"
    READ_WRITE = "rw-"
    READ_EXECUTE = "r-x"
    READ_WRITE_EXECUTE = "rwx"
    WRITE_EXECUTE = "-wx"
    PRIVATE = "p"
    SHARED = "s"

class MemoryRegionType(Enum):
    CODE = "code"
    DATA = "data"
    HEAP = "heap"
    STACK = "stack"
    MMAP = "mmap"
    VDSO = "vdso"
    VVAR = "vvar"
    ANONYMOUS = "anonymous"
    SHARED_LIB = "shared_library"
    UNKNOWN = "unknown"

class RiskCategory(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class MemoryRegion:
    start_addr: int
    end_addr: int
    size: int
    protection: str
    offset: int = 0
    device: str = ""
    inode: int = 0
    path: str = ""
    region_type: MemoryRegionType = MemoryRegionType.UNKNOWN
    risk: RiskCategory = RiskCategory.SAFE
    is_rwx: bool = False
    has_write_exec: bool = False
    has_exec_stack: bool = False
    adjacent_gap_before: int = 0
    adjacent_gap_after: int = 0
    attributes: Dict[str, Any] = field(default_factory=dict)

    @property
    def size_human(self) -> str:
        return _format_size(self.size)

    @property
    def start_hex(self) -> str:
        return f"0x{self.start_addr:016x}"

    @property
    def end_hex(self) -> str:
        return f"0x{self.end_addr:016x}"


@dataclass
class MemoryMap:
    pid: int = 0
    regions: List[MemoryRegion] = field(default_factory=list)
    total_regions: int = 0
    total_size: int = 0
    total_size_human: str = ""
    rwx_regions: int = 0
    heap_size: int = 0
    stack_count: int = 0
    gaps: List[Tuple[int, int, int]] = field(default_factory=list)


class MemMapParser:

    MAP_LINE_PATTERN = re.compile(
        r'^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+'
        r'([r\-][w\-][x\-][ps])\s+'
        r'([0-9a-fA-F]+)\s+'
        r'([0-9a-fA-F]+:[0-9a-fA-F]+)\s+'
        r'(\d+)\s*'
        r'(.*?)$'
    )

    KNOWN_PATHS = {
        "[heap]": MemoryRegionType.HEAP,
        "[stack]": MemoryRegionType.STACK,
        "[vdso]": MemoryRegionType.VDSO,
        "[vvar]": MemoryRegionType.VVAR,
        "[vsyscall]": MemoryRegionType.VDSO,
        "[anon]": MemoryRegionType.ANONYMOUS,
    }

    def parse(self, maps_content: str, pid: int = 0) -> MemoryMap:
        regions: List[MemoryRegion] = []
        total_size = 0
        rwx_count = 0

        for line in maps_content.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            match = self.MAP_LINE_PATTERN.match(line)
            if not match:
                continue

            start = int(match.group(1), 16)
            end = int(match.group(2), 16)
            prot = match.group(3)
            offset = int(match.group(4), 16)
            device = match.group(5)
            inode = int(match.group(6))
            path = match.group(7).strip()

            size = end - start
            total_size += size

            is_rwx = ('w' in prot and 'x' in prot)
            if is_rwx:
                rwx_count += 1

            region_type = self._classify_region(path, prot)
            risk = self._assess_risk(prot, region_type, path)

            region = MemoryRegion(
                start_addr=start,
                end_addr=end,
                size=size,
                protection=prot,
                offset=offset,
                device=device,
                inode=inode,
                path=path,
                region_type=region_type,
                risk=risk,
                is_rwx=is_rwx,
                has_write_exec=is_rwx,
                has_exec_stack=(path == "[stack]" and 'x' in prot),
            )
            regions.append(region)

        regions.sort(key=lambda r: r.start_addr)
        gaps = self._detect_gaps(regions)
        for i, region in enumerate(regions):
            if i > 0:
                region.adjacent_gap_before = region.start_addr - regions[i - 1].end_addr
            if i < len(regions) - 1:
                region.adjacent_gap_after = regions[i + 1].start_addr - region.end_addr

        heap_size = sum(r.size for r in regions if r.region_type == MemoryRegionType.HEAP)
        stack_count = sum(1 for r in regions if r.region_type == MemoryRegionType.STACK)

        return MemoryMap(
            pid=pid,
            regions=regions,
            total_regions=len(regions),
            total_size=total_size,
            total_size_human=_format_size(total_size),
            rwx_regions=rwx_count,
            heap_size=heap_size,
            stack_count=stack_count,
            gaps=gaps,
        )

    @staticmethod
    def _classify_region(path: str, prot: str) -> MemoryRegionType:
        if path in MemMapParser.KNOWN_PATHS:
            return MemMapParser.KNOWN_PATHS[path]

        if path and (path.endswith(".so") or path.endswith(".dll")):
            return MemoryRegionType.SHARED_LIB

        if path and not path.startswith("["):
            if 'x' in prot:
                return MemoryRegionType.CODE
            return MemoryRegionType.DATA

        if not path or path.startswith("["):
            return MemoryRegionType.MMAP if "mmap" in path.lower() else MemoryRegionType.ANONYMOUS

        return MemoryRegionType.UNKNOWN

    @staticmethod
    def _assess_risk(prot: str, region_type: MemoryRegionType, path: str) -> RiskCategory:
        if 'w' in prot and 'x' in prot:
            return RiskCategory.CRITICAL
        if region_type == MemoryRegionType.STACK and 'x' in prot:
            return RiskCategory.HIGH
        if ('w' in prot) and region_type == MemoryRegionType.CODE:
            return RiskCategory.HIGH
        if ('x' in prot) and region_type == MemoryRegionType.HEAP:
            return RiskCategory.HIGH
        if path == "[vsyscall]":
            return RiskCategory.MEDIUM
        return RiskCategory.SAFE

    @staticmethod
    def _detect_gaps(regions: List[MemoryRegion]) -> List[Tuple[int, int, int]]:
        gaps = []
        for i in range(len(regions) - 1):
            gap_start = regions[i].end_addr
            gap_end = regions[i + 1].start_addr
            gap_size = gap_end - gap_start
            if gap_size > 0:
                gaps.append((gap_start, gap_end, gap_size))
        return gaps


class MemoryHoleDetector:

    SIGNIFICANT_GAP_THRESHOLD = 0x10000

    @staticmethod
    def detect(regions: List[MemoryRegion]) -> Dict[str, Any]:
        holes: List[Dict[str, Any]] = []
        total_gap = 0
        significant_gaps = 0

        for i in range(len(regions) - 1):
            gap = regions[i + 1].start_addr - regions[i].end_addr
            if gap > 0:
                total_gap += gap
                hole = {
                    "address_after": hex(regions[i].end_addr),
                    "address_before": hex(regions[i + 1].start_addr),
                    "size": gap,
                    "size_human": _format_size(gap),
                    "significant": gap > MemoryHoleDetector.SIGNIFICANT_GAP_THRESHOLD,
                }
                if hole["significant"]:
                    significant_gaps += 1
                holes.append(hole)

        return {
            "total_holes": len(holes),
            "significant_holes": significant_gaps,
            "total_gap_size": total_gap,
            "total_gap_human": _format_size(total_gap),
            "holes": holes,
        }


class HeapVisualizer:

    @staticmethod
    def analyze(regions: List[MemoryRegion]) -> Dict[str, Any]:
        heap_regions = [r for r in regions if r.region_type == MemoryRegionType.HEAP]

        if not heap_regions:
            return {"heap_regions": 0, "total_heap_size": 0, "heap_size_human": "0 B"}

        total_size = sum(r.size for r in heap_regions)
        largest = max(heap_regions, key=lambda r: r.size)

        return {
            "heap_regions": len(heap_regions),
            "total_heap_size": total_size,
            "heap_size_human": _format_size(total_size),
            "largest_region": {
                "address": largest.start_hex,
                "size": largest.size,
                "size_human": largest.size_human,
                "protection": largest.protection,
            },
            "regions": [{"start": r.start_hex, "end": r.end_hex,
                          "size": r.size_human, "prot": r.protection}
                        for r in heap_regions],
        }

    @staticmethod
    def generate_heap_visualization(regions: List[MemoryRegion]) -> str:
        heap = [r for r in regions if r.region_type == MemoryRegionType.HEAP]
        if not heap:
            return "[No heap regions]"

        total = max(r.end_addr for r in heap)
        base = min(r.start_addr for r in heap)
        width = 60

        lines = [
            "Heap Layout Visualization",
            "=" * width,
            f"Base: {hex(base)}  Size: {_format_size(total - base)}",
            "=" * width,
        ]

        for r in sorted(heap, key=lambda x: x.start_addr):
            start_pct = (r.start_addr - base) / max(1, total - base)
            end_pct = (r.end_addr - base) / max(1, total - base)
            start_col = int(start_pct * width)
            end_col = max(start_col + 1, int(end_pct * width))

            marker = "H"
            line = "." * start_col + marker * (end_col - start_col)
            line = line.ljust(width, ".")
            lines.append(f"|{line}| {r.start_hex} {r.size_human}")

        lines.append("=" * width)
        return "\n".join(lines)


class StackVisualizer:

    @staticmethod
    def analyze(regions: List[MemoryRegion]) -> Dict[str, Any]:
        stack_regions = [r for r in regions if r.region_type == MemoryRegionType.STACK]

        if not stack_regions:
            return {"stack_regions": 0, "total_stack_size": 0, "executable_stacks": 0}

        total_size = sum(r.size for r in stack_regions)
        exec_stacks = sum(1 for r in stack_regions if r.has_exec_stack)

        return {
            "stack_regions": len(stack_regions),
            "total_stack_size": total_size,
            "stack_size_human": _format_size(total_size),
            "executable_stacks": exec_stacks,
            "thread_stacks": len(stack_regions) - 1 if len(stack_regions) > 1 else 0,
            "regions": [{"start": r.start_hex, "end": r.end_hex,
                          "size": r.size_human, "prot": r.protection,
                          "is_exec": r.has_exec_stack}
                        for r in stack_regions],
        }

    @staticmethod
    def generate_stack_visualization(regions: List[MemoryRegion]) -> str:
        stacks = [r for r in regions if r.region_type == MemoryRegionType.STACK]
        if not stacks:
            return "[No stack regions]"

        width = 60
        lines = ["Stack Layout", "=" * width]

        for i, s in enumerate(sorted(stacks, key=lambda x: x.start_addr, reverse=True)):
            label = "Main Stack" if i == 0 else f"Thread Stack {i}"
            risk = " [EXECUTABLE!]" if s.has_exec_stack else ""
            bar_len = min(width - 2, max(10, int(s.size / max(1, stacks[0].size) * (width - 2))))
            bar = "S" * bar_len
            lines.append(f"|{bar.ljust(width - 2)}| {label} [{s.size_human}]{risk}")
            lines.append(f"|{' ' * (width - 2)}| {s.start_hex} -> {s.end_hex}")

        lines.append("=" * width)
        return "\n".join(lines)


class ASCIICanvas:

    @staticmethod
    def render_memory_map(memory_map: MemoryMap, width: int = 70) -> str:
        regions = memory_map.regions
        if not regions:
            return "[Empty memory map]"

        base = regions[0].start_addr
        total = regions[-1].end_addr - base
        inner_width = width - 2

        lines = [
            "+" + "-" * inner_width + "+",
            "|" + f" Memory Map (PID: {memory_map.pid}) ".center(inner_width) + "|",
            "+" + "-" * inner_width + "+",
        ]

        region_chars = {
            MemoryRegionType.CODE: "C",
            MemoryRegionType.HEAP: "H",
            MemoryRegionType.STACK: "S",
            MemoryRegionType.MMAP: "M",
            MemoryRegionType.SHARED_LIB: "L",
            MemoryRegionType.VDSO: "V",
            MemoryRegionType.ANONYMOUS: "A",
            MemoryRegionType.DATA: "D",
            MemoryRegionType.UNKNOWN: "?",
        }

        for r in regions:
            start_pct = (r.start_addr - base) / max(1, total)
            end_pct = (r.end_addr - base) / max(1, total)
            start_col = max(0, int(start_pct * inner_width))
            end_col = max(start_col + 1, int(end_pct * inner_width))

            if r.is_rwx:
                marker = "X"
            elif r.region_type == MemoryRegionType.HEAP:
                marker = "H"
            elif r.region_type == MemoryRegionType.STACK:
                marker = "S"
            else:
                marker = region_chars.get(r.region_type, ".")

            segment = marker * (end_col - start_col)
            line = "." * start_col + segment + "." * (inner_width - end_col)

            risk_label = "!!!" if r.risk in (RiskCategory.CRITICAL, RiskCategory.HIGH) else ""
            name = r.path or r.region_type.value
            if len(name) > 20:
                name = name[:17] + "..."

            lines.append(f"|{line}| {name:20s} [{r.protection}] {risk_label}")

        lines.append("+" + "-" * inner_width + "+")
        lines.append(f"Total: {memory_map.total_size_human} | RWX: {memory_map.rwx_regions} | Regions: {memory_map.total_regions}")

        return "\n".join(lines)

    @staticmethod
    def render_rwx_highlight(regions: List[MemoryRegion], width: int = 70) -> str:
        rwx = [r for r in regions if r.is_rwx]
        if not rwx:
            return "No RWX regions found — memory layout appears safe."

        inner_width = width - 2
        lines = [
            "+" + "-" * inner_width + "+",
            "|" + " RWX DANGER ZONES ".center(inner_width) + "|",
            "+" + "-" * inner_width + "+",
        ]

        for r in rwx:
            lines.append(f"| {' ' * (inner_width)} |")
            lines.append(f"| {'!' * min(10, inner_width)} RWX REGION {'!' * min(10, inner_width)}".ljust(width) + "|")
            lines.append(f"|   Address: {r.start_hex} -> {r.end_hex}".ljust(width) + "|")
            lines.append(f"|   Size: {r.size_human}  Protection: {r.protection}".ljust(width) + "|")
            if r.path:
                lines.append(f"|   Path: {r.path[:inner_width - 10]}".ljust(width) + "|")

        lines.append("+" + "-" * inner_width + "+")
        return "\n".join(lines)


class SVGCanvas:

    @staticmethod
    def render_memory_map(memory_map: MemoryMap,
                          canvas_width: int = 800,
                          canvas_height: int = 600) -> str:
        regions = memory_map.regions
        if not regions:
            return '<svg xmlns="http://www.w3.org/2000/svg" width="800" height="100"><text x="10" y="30">[Empty memory map]</text></svg>'

        base = regions[0].start_addr
        total = regions[-1].end_addr - base
        margin = 60
        chart_height = canvas_height - 2 * margin
        bar_width = canvas_width - 2 * margin

        colors = {
            MemoryRegionType.CODE: "#4CAF50",
            MemoryRegionType.DATA: "#2196F3",
            MemoryRegionType.HEAP: "#FF9800",
            MemoryRegionType.STACK: "#9C27B0",
            MemoryRegionType.MMAP: "#795548",
            MemoryRegionType.SHARED_LIB: "#00BCD4",
            MemoryRegionType.VDSO: "#607D8B",
            MemoryRegionType.VVAR: "#BDBDBD",
            MemoryRegionType.ANONYMOUS: "#E0E0E0",
            MemoryRegionType.UNKNOWN: "#F5F5F5",
        }

        lines = [
            f'<?xml version="1.0" encoding="UTF-8"?>',
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{canvas_width}" height="{canvas_height}">',
            f'  <rect width="{canvas_width}" height="{canvas_height}" fill="white"/>',
            f'  <text x="{canvas_width//2}" y="20" text-anchor="middle" font-size="16" font-weight="bold">'
            f'Memory Map — PID {memory_map.pid}</text>',
        ]

        for r in regions:
            start_pct = (r.start_addr - base) / total if total > 0 else 0
            end_pct = (r.end_addr - base) / total if total > 0 else 0

            x = margin + int(start_pct * bar_width)
            w = max(2, int((end_pct - start_pct) * bar_width))
            y = margin
            h = chart_height

            color = "#FF0000" if r.is_rwx else colors.get(r.region_type, "#CCCCCC")
            stroke = "#AA0000" if r.is_rwx else "#888888"
            stroke_width = 2 if r.is_rwx else 1

            title = f"{r.start_hex}-{r.end_hex} [{r.protection}] {r.path or r.region_type.value}"
            lines.append(
                f'  <rect x="{x}" y="{y}" width="{w}" height="{h}" '
                f'fill="{color}" stroke="{stroke}" stroke-width="{stroke_width}">'
                f'<title>{title}</title></rect>'
            )

        legend_y = canvas_height - 20
        legend_x = margin
        for rtype in MemoryRegionType:
            color = colors.get(rtype, "#CCCCCC")
            lines.append(f'  <rect x="{legend_x}" y="{legend_y}" width="12" height="12" fill="{color}" stroke="#999"/>')
            lines.append(f'  <text x="{legend_x + 16}" y="{legend_y + 10}" font-size="10">{rtype.value}</text>')
            legend_x += 80

        if memory_map.rwx_regions > 0:
            lines.append(f'  <rect x="{legend_x}" y="{legend_y}" width="12" height="12" fill="#FF0000" stroke="#AA0000"/>')
            lines.append(f'  <text x="{legend_x + 16}" y="{legend_y + 10}" font-size="10" fill="red">RWX DANGER</text>')

        lines.append("</svg>")
        return "\n".join(lines)


def _format_size(size: int) -> str:
    if size >= 1024 ** 3:
        return f"{size / 1024 ** 3:.2f} GB"
    elif size >= 1024 ** 2:
        return f"{size / 1024 ** 2:.2f} MB"
    elif size >= 1024:
        return f"{size / 1024:.2f} KB"
    return f"{size} B"

class MemoryVisualizer:

    def __init__(self):
        self._parser = MemMapParser()
        self._hole_detector = MemoryHoleDetector()
        self._heap_viz = HeapVisualizer()
        self._stack_viz = StackVisualizer()
        self._ascii = ASCIICanvas()
        self._svg = SVGCanvas()
        self._memory_map: Optional[MemoryMap] = None

    def analyze(self, **kwargs) -> Dict[str, Any]:
        command = kwargs.get("command", "parse_memory_map")
        try:
            handlers = {
                "parse_memory_map": self.parse_memory_map,
                "generate_heap_visualization": self.generate_heap_visualization,
                "generate_stack_visualization": self.generate_stack_visualization,
                "detect_memory_holes": self.detect_memory_holes,
                "visualize_memory_regions": self.visualize_memory_regions,
                "export_as_svg": self.export_as_svg,
                "export_as_ascii": self.export_as_ascii,
            }
            handler = handlers.get(command)
            if handler:
                return handler(**kwargs)
            return {"success": False, "error": f"Unknown command: {command}"}
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return {"success": False, "error": str(e)}

    def parse_memory_map(self, maps_content: str = "",
                         pid: int = 0,
                         **kwargs) -> Dict[str, Any]:
        if not maps_content:
            return {"success": False, "error": "maps_content required"}

        self._memory_map = self._parser.parse(maps_content, pid)
        mm = self._memory_map

        regions_by_type: Dict[str, int] = {}
        for r in mm.regions:
            t = r.region_type.value
            regions_by_type[t] = regions_by_type.get(t, 0) + 1

        return {
            "success": True,
            "pid": mm.pid,
            "total_regions": mm.total_regions,
            "total_size": mm.total_size,
            "total_size_human": mm.total_size_human,
            "rwx_regions": mm.rwx_regions,
            "heap_regions": regions_by_type.get("heap", 0),
            "stack_regions": regions_by_type.get("stack", 0),
            "code_regions": regions_by_type.get("code", 0),
            "regions_by_type": regions_by_type,
            "regions": [
                {
                    "start": r.start_hex,
                    "end": r.end_hex,
                    "size": r.size_human,
                    "protection": r.protection,
                    "type": r.region_type.value,
                    "risk": r.risk.value,
                    "path": r.path,
                    "is_rwx": r.is_rwx,
                }
                for r in mm.regions[:100]
            ],
        }

    def generate_heap_visualization(self, maps_content: str = "",
                                     **kwargs) -> Dict[str, Any]:
        if maps_content:
            self._memory_map = self._parser.parse(maps_content)

        if not self._memory_map:
            return {"success": False, "error": "No memory map parsed"}

        analysis = self._heap_viz.analyze(self._memory_map.regions)
        ascii_viz = self._heap_viz.generate_heap_visualization(self._memory_map.regions)

        return {
            "success": True,
            "heap_analysis": analysis,
            "ascii_visualization": ascii_viz,
        }

    def generate_stack_visualization(self, maps_content: str = "",
                                      **kwargs) -> Dict[str, Any]:
        if maps_content:
            self._memory_map = self._parser.parse(maps_content)

        if not self._memory_map:
            return {"success": False, "error": "No memory map parsed"}

        analysis = self._stack_viz.analyze(self._memory_map.regions)
        ascii_viz = self._stack_viz.generate_stack_visualization(self._memory_map.regions)

        return {
            "success": True,
            "stack_analysis": analysis,
            "ascii_visualization": ascii_viz,
        }

    def detect_memory_holes(self, maps_content: str = "",
                             **kwargs) -> Dict[str, Any]:
        if maps_content:
            self._memory_map = self._parser.parse(maps_content)

        if not self._memory_map:
            return {"success": False, "error": "No memory map parsed"}

        holes = self._hole_detector.detect(self._memory_map.regions)
        return {"success": True, **holes}

    def visualize_memory_regions(self, maps_content: str = "",
                                  width: int = 70,
                                  **kwargs) -> Dict[str, Any]:
        if maps_content:
            self._memory_map = self._parser.parse(maps_content)

        if not self._memory_map:
            return {"success": False, "error": "No memory map parsed"}

        ascii_map = self._ascii.render_memory_map(self._memory_map, width)
        rwx_highlight = self._ascii.render_rwx_highlight(self._memory_map.regions)

        return {
            "success": True,
            "ascii_memory_map": ascii_map,
            "rwx_highlight": rwx_highlight,
            "total_regions": self._memory_map.total_regions,
            "rwx_count": self._memory_map.rwx_regions,
        }

    def export_as_svg(self, maps_content: str = "",
                      canvas_width: int = 800,
                      canvas_height: int = 600,
                      **kwargs) -> Dict[str, Any]:
        if maps_content:
            self._memory_map = self._parser.parse(maps_content)

        if not self._memory_map:
            return {"success": False, "error": "No memory map parsed"}

        svg_code = self._svg.render_memory_map(
            self._memory_map, canvas_width, canvas_height
        )
        return {
            "success": True,
            "format": "svg",
            "svg_code": svg_code,
            "total_regions": self._memory_map.total_regions,
        }

    def export_as_ascii(self, maps_content: str = "",
                         width: int = 70,
                         **kwargs) -> Dict[str, Any]:
        if maps_content:
            self._memory_map = self._parser.parse(maps_content)

        if not self._memory_map:
            return {"success": False, "error": "No memory map parsed"}

        ascii_art = self._ascii.render_memory_map(self._memory_map, width)
        return {
            "success": True,
            "format": "ascii",
            "ascii_art": ascii_art,
            "total_regions": self._memory_map.total_regions,
        }


__all__ = ["MemoryVisualizer"]
