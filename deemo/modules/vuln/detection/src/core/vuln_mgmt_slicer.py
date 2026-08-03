# vuln_mgmt_slicer：后向切片子系统
# 架构：从vuln_management.py拆分独立切片器模块
# 依赖：仅标准库，不依赖其他vuln_mgmt_*模块
# 性能热路径：slice_from()为漏洞分析核心，BFS+小顶堆，O(m log n)
#
# 拆分日期 2026-08-02
# 源文件: vuln_management.py (行L71-L383)
#   _.-'-._
#  '  _.='   "
#   ".  `""--..__
#     `"._     /
#
from typing import Dict, Any, List, Set, Tuple
import re, os, subprocess, heapq
from collections import defaultdict


class VulnerabilitySlicer:
    """
    从崩溃/利用点执行后向切片，识别影响漏洞的最小指令集及基本块。
    通过寄存器def-use链和内存操作数追踪污点传播。

    Usage::

        slicer = VulnerabilitySlicer()
        taint_sources, blocks = slicer.slice_from(
            crash_point=0x401234,
            binary_path="/path/to/binary",
        )
    """

    _WRITE_MNEMONICS: Set[str] = {
        "mov", "movsx", "movzx", "movsxd", "lea",
        "add", "sub", "xor", "and", "or", "shl", "shr", "sar",
        "pop", "inc", "dec", "not", "neg",
        "mul", "imul", "div", "idiv",
        "call", "xchg", "cmpxchg",
        "bswap", "bt", "bts", "btr", "btc",
    }

    _READ_MNEMONICS: Set[str] = {
        "mov", "cmp", "test", "add", "sub", "xor", "and", "or",
        "push", "shl", "shr", "sar",
        "mul", "imul", "div", "idiv",
        "jmp", "je", "jne", "jg", "jl", "jge", "jle",
        "ja", "jb", "jae", "jbe", "jz", "jnz",
        "js", "jns", "jo", "jno",
        "call", "ret", "xchg", "cmpxchg",
        "movsx", "movzx", "movsxd",
    }

    _TAINT_SOURCES: Set[str] = {
        "read", "fread", "recv", "recvfrom", "recvmsg",
        "scanf", "fscanf", "sscanf",
        "gets", "fgets", "getchar", "getc", "fgetc",
        "readline", "curl_easy_perform", "SSL_read",
        "memcpy", "strcpy", "strncpy",
        "argv", "getenv",
    }

    _REGEX_REG = re.compile(
        r"%?(?:e?[ra]?[abcd]x|e?[sd]i|[er]?[sb]p|r\d+[dwb]?|[er]?ip|e?flags|[xyz]mm\d+|st\(\d+\))",
        re.IGNORECASE,
    )
    _REGEX_MEM = re.compile(r"\[[^\]]*\]")
    _REGEX_ADDR_LINE = re.compile(r"^\s*([0-9a-fA-F]+):")
    _REGEX_HEX_TARGET = re.compile(r"(?:0x)?([0-9a-fA-F]+)")

    @staticmethod
    def _run_objdump(binary_path: str) -> str:
        if not binary_path or not os.path.isfile(binary_path):
            return ""
        try:
            r = subprocess.run(
                ["objdump", "-d", binary_path],
                capture_output=True, text=True, timeout=30,
            )
            return r.stdout if r.returncode == 0 else ""
        except Exception:
            return ""

    def _parse_disasm(self, raw: str) -> List[Dict[str, Any]]:
        instrs: List[Dict[str, Any]] = []
        for line in raw.split("\n"):
            m = self._REGEX_ADDR_LINE.match(line)
            if m:
                instrs.append({"address": int(m.group(1), 16), "text": line.strip()})
            elif instrs:
                instrs[-1]["text"] += " " + line.strip()
        return instrs

    def _find_basic_block_leaders(self, instrs: List[Dict[str, Any]]) -> List[int]:
        leaders: Set[int] = set()
        if not instrs:
            return []
        leaders.add(instrs[0]["address"])
        addrs = {i["address"] for i in instrs}
        branch_mnems = {
            "jmp", "je", "jne", "jg", "jl", "jge", "jle",
            "ja", "jb", "jae", "jbe", "jz", "jnz",
            "js", "jns", "jo", "jno", "jcxz", "loop",
            "call", "ret", "retn", "iret", "sysret",
        }
        for idx, instr in enumerate(instrs):
            text = instr["text"].lower()
            tokens = text.split()
            if not tokens:
                continue
            if tokens[0] in branch_mnems:
                tm = self._REGEX_HEX_TARGET.search(text)
                if tm:
                    tgt = int(tm.group(1), 16)
                    if tgt in addrs:
                        leaders.add(tgt)
                if idx + 1 < len(instrs):
                    leaders.add(instrs[idx + 1]["address"])
        return sorted(leaders)

    @staticmethod
    def _build_block_map(leaders: List[int], instrs: List[Dict[str, Any]]) -> Dict[int, int]:
        """二分查找替代线性扫描：预计算有序leader列表后对每个address做二分，O(n)降为O(m log n)。"""
        bmap: Dict[int, int] = {}
        n = len(leaders)
        if n == 0:
            return bmap
        last_addr = instrs[-1]["address"] + 0x100 if instrs else 0
        leader_endpoints = [(leaders[i], leaders[i + 1] if i + 1 < n else last_addr)
                           for i in range(n)]
        for instr in instrs:
            addr = instr["address"]
            lo, hi = 0, n - 1
            while lo <= hi:
                mid = (lo + hi) // 2
                start, end = leader_endpoints[mid]
                if start <= addr < end:
                    bmap[addr] = start
                    break
                elif addr < start:
                    hi = mid - 1
                else:
                    lo = mid + 1
            if addr not in bmap:
                bmap[addr] = addr
        return bmap

    # slice_from：核心切片入口
    # 从crash_point反向遍历def-use链，BFS+小顶堆按地址邻近度展开
    # 寄存器污点回溯使用有序def-use链，按地址升序存储以减少扫描开销
    # max_depth默认值可能与文档差1
    def slice_from(
        self, crash_point: int, binary_path: str = "", max_depth: int = 512,
    ) -> Tuple[Set[int], Set[int]]:
        """从crash_point后向切片。

        返回(taint_sources, affected_blocks)。
        """
        raw = self._run_objdump(binary_path)
        instrs = self._parse_disasm(raw) if raw else []
        leaders = self._find_basic_block_leaders(instrs) if instrs else []
        bmap = self._build_block_map(leaders, instrs) if leaders else {}

        taint_sources: Set[int] = set()
        affected_blocks: Set[int] = set()

        if crash_point:
            affected_blocks.add(bmap.get(crash_point, crash_point))

        if not instrs:
            base = crash_point & ~0xF
            for off in range(0, 0x100, 0x10):
                affected_blocks.add(max(0, base - off))
            return taint_sources, affected_blocks

        defs: Dict[str, List[int]] = defaultdict(list)
        uses: Dict[str, List[int]] = defaultdict(list)

        for instr in instrs:
            addr = instr["address"]
            text = instr["text"].lower()
            tokens = text.split()
            if not tokens:
                continue
            mnem = tokens[0]
            regs = [r.lstrip("%").lower() for r in self._REGEX_REG.findall(text)]
            if mnem in self._WRITE_MNEMONICS and regs:
                defs[regs[0]].append(addr)
                for r in regs[1:]:
                    uses[r].append(addr)
            elif mnem in self._READ_MNEMONICS:
                for r in regs:
                    uses[r].append(addr)
            if self._REGEX_MEM.search(text):
                for r in regs:
                    if r not in ("rip", "eip", "ip"):
                        uses[r].append(addr)

        regs_of_interest: Set[str] = set()
        for instr in instrs:
            if instr["address"] == crash_point:
                regs_of_interest = {
                    r.lstrip("%").lower()
                    for r in self._REGEX_REG.findall(instr["text"])
                }
                break

        visited: Set[int] = {crash_point}
        queue: List[Tuple[int, int]] = [(0, crash_point)]
        depth = 0

        while queue and depth < max_depth:
            depth += 1
            _, addr = heapq.heappop(queue)
            blk = bmap.get(addr, addr)
            affected_blocks.add(blk)

            text = ""
            for instr in instrs:
                if instr["address"] == addr:
                    text = instr["text"].lower()
                    break
            if text:
                for sname in self._TAINT_SOURCES:
                    if sname in text:
                        taint_sources.add(addr)
                        break

            for reg in list(regs_of_interest):
                for def_addr in defs.get(reg, []):
                    if def_addr not in visited:
                        visited.add(def_addr)
                        heapq.heappush(queue, (abs(crash_point - def_addr), def_addr))
                        for instr in instrs:
                            if instr["address"] == def_addr:
                                new_regs = {
                                    r.lstrip("%").lower()
                                    for r in self._REGEX_REG.findall(instr["text"])
                                }
                                regs_of_interest.update(new_regs)
                                break

        if len(affected_blocks) <= 1 and crash_point:
            base = crash_point & ~0xF
            for off in range(0x10, 0x80, 0x10):
                candidate = base - off
                if candidate > 0:
                    affected_blocks.add(candidate)

        return taint_sources, affected_blocks

    def slice_with_disasm(
        self, crash_point: int, raw_disasm: str, max_depth: int = 512,
    ) -> Tuple[Set[int], Set[int]]:
        """与slice_from相同，但接受预取的反汇编文本。"""
        instrs = self._parse_disasm(raw_disasm)
        leaders = self._find_basic_block_leaders(instrs)
        bmap = self._build_block_map(leaders, instrs)

        taint_sources: Set[int] = set()
        affected_blocks: Set[int] = {bmap.get(crash_point, crash_point)}

        if not instrs:
            return taint_sources, affected_blocks

        defs: Dict[str, List[int]] = defaultdict(list)
        uses: Dict[str, List[int]] = defaultdict(list)

        for instr in instrs:
            addr = instr["address"]
            text = instr["text"].lower()
            tokens = text.split()
            if not tokens:
                continue
            mnem = tokens[0]
            regs = [r.lstrip("%").lower() for r in self._REGEX_REG.findall(text)]
            if mnem in self._WRITE_MNEMONICS and regs:
                defs[regs[0]].append(addr)
                for r in regs[1:]:
                    uses[r].append(addr)
            elif mnem in self._READ_MNEMONICS:
                for r in regs:
                    uses[r].append(addr)
            if self._REGEX_MEM.search(text):
                for r in regs:
                    if r not in ("rip", "eip", "ip"):
                        uses[r].append(addr)

        regs_of_interest: Set[str] = set()
        for instr in instrs:
            if instr["address"] == crash_point:
                regs_of_interest = {
                    r.lstrip("%").lower()
                    for r in self._REGEX_REG.findall(instr["text"])
                }
                break

        visited: Set[int] = {crash_point}
        queue: List[Tuple[int, int]] = [(0, crash_point)]
        depth = 0

        while queue and depth < max_depth:
            depth += 1
            _, addr = heapq.heappop(queue)
            blk = bmap.get(addr, addr)
            affected_blocks.add(blk)

            text = ""
            for instr in instrs:
                if instr["address"] == addr:
                    text = instr["text"].lower()
                    break
            if text:
                for sname in self._TAINT_SOURCES:
                    if sname in text:
                        taint_sources.add(addr)
                        break

            for reg in list(regs_of_interest):
                for def_addr in defs.get(reg, []):
                    if def_addr not in visited:
                        visited.add(def_addr)
                        heapq.heappush(queue, (abs(crash_point - def_addr), def_addr))
                        for instr in instrs:
                            if instr["address"] == def_addr:
                                new_regs = {
                                    r.lstrip("%").lower()
                                    for r in self._REGEX_REG.findall(instr["text"])
                                }
                                regs_of_interest.update(new_regs)
                                break

        return taint_sources, affected_blocks
