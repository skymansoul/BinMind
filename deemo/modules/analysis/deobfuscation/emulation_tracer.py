
import time
import logging
import struct
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Set

logger = logging.getLogger(__name__)


@dataclass
class TraceEvent:
    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes_hex: str
    regs_read: List[str] = field(default_factory=list)
    regs_write: List[str] = field(default_factory=list)
    mem_reads: List[Tuple[int, int]] = field(default_factory=list)
    mem_writes: List[Tuple[int, int]] = field(default_factory=list)
    timestamp: int = 0

@dataclass
class EmulationTrace:
    events: List[TraceEvent] = field(default_factory=list)
    start_addr: int = 0
    end_addr: int = 0
    string_discoveries: Dict[int, str] = field(default_factory=dict)
    mem_hotspots: Dict[int, int] = field(default_factory=dict)
    smc_events: List[Tuple[int, int, int]] = field(default_factory=list)

@dataclass
class TraceResult:
    basic_blocks: List[Tuple[int, int]] = field(default_factory=list)
    call_graph: List[Tuple[int, int]] = field(default_factory=list)
    api_calls: List[Tuple[int, str]] = field(default_factory=list)
    total_instructions: int = 0
    runtime_strings: Dict[int, str] = field(default_factory=dict)
    anti_analysis_flags: List[str] = field(default_factory=list)
    smc_detected: bool = False
    smc_regions: List[Tuple[int, int]] = field(default_factory=list)


def _try_import_unicorn():
    try:
        import unicorn as uc
        return uc
    except ImportError:
        return None

def _try_import_capstone():
    try:
        import capstone as cs
        return cs
    except ImportError:
        return None

STACK_BASE = 0x7FFF0000
STACK_SIZE = 0x10000
HEAP_BASE  = 0x7F000000
HEAP_SIZE  = 0x100000


def _map_pe(data: bytes, mu, uc) -> Optional[int]:
    try:
        import pefile
        pe = pefile.PE(data=data)
        entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        image_base = pe.OPTIONAL_HEADER.ImageBase
        code_regions = []
        for section in pe.sections:
            va = image_base + section.VirtualAddress
            vs = section.Misc_VirtualSize
            raw = section.PointerToRawData
            rs = section.SizeOfRawData
            section_data = data[raw:raw + rs]
            map_addr = va & ~0xFFF
            map_size = ((va + max(vs, rs) - map_addr + 0xFFF) & ~0xFFF)
            if map_size == 0:
                continue
            mu.mem_map(map_addr, map_size)
            mu.mem_write(va, section_data.ljust(vs, b'\x00'))
            perms = 0
            characteristics = section.Characteristics
            if characteristics & 0x20000000:
                perms |= uc.UC_PROT_EXEC
                code_regions.append((va, va + vs))
            if characteristics & 0x40000000:
                perms |= uc.UC_PROT_READ
            if characteristics & 0x80000000:
                perms |= uc.UC_PROT_ALL
            if perms == 0:
                perms = uc.UC_PROT_ALL
            if perms != uc.UC_PROT_ALL:
                mu.mem_protect(map_addr, map_size, perms)
        mu._code_regions = code_regions
        return entry + image_base
    except ImportError:
        return None
    except Exception as e:
        logger.debug("PE mapping failed: %s", e)
        return None


def _map_elf(data: bytes, mu, uc) -> Optional[int]:
    try:
        from elftools.elf.elffile import ELFFile
        from io import BytesIO
        elf = ELFFile(BytesIO(data))
        entry = elf.header['e_entry']
        code_regions = []
        for segment in elf.iter_segments():
            if segment.header.p_type == 'PT_LOAD':
                va = segment.header.p_vaddr
                memsz = segment.header.p_memsz
                filesz = segment.header.p_filesz
                offset = segment.header.p_offset
                map_addr = va & ~0xFFF
                map_size = ((va + memsz - map_addr + 0xFFF) & ~0xFFF)
                mu.mem_map(map_addr, map_size)
                seg_data = data[offset:offset + filesz]
                mu.mem_write(va, seg_data.ljust(memsz, b'\x00'))
                flags = segment.header.p_flags
                perms = 0
                if flags & 1:
                    perms |= uc.UC_PROT_EXEC
                    code_regions.append((va, va + memsz))
                if flags & 2:
                    perms |= uc.UC_PROT_ALL
                if flags & 4:
                    perms |= uc.UC_PROT_READ
                if perms and perms != uc.UC_PROT_ALL:
                    mu.mem_protect(map_addr, map_size, perms)
        mu._code_regions = code_regions
        return entry
    except ImportError:
        return None
    except Exception as e:
        logger.debug("ELF mapping failed: %s", e)
        return None


def _map_flat(data: bytes, mu, uc, base: int = 0x100000) -> int:
    map_size = ((len(data) + 0xFFF) & ~0xFFF)
    mu.mem_map(base, map_size)
    mu.mem_write(base, data)
    mu._code_regions = [(base, base + len(data))]
    return base


def _make_smc_write_hook(trace: EmulationTrace, code_regions: List[Tuple[int, int]]):
    written_code_addrs: Set[int] = set()

    def _hook_mem_write(uc_ref, access, address, size, value, user_data):
        for r_start, r_end in code_regions:
            if r_start <= address < r_end:
                for off in range(size):
                    written_code_addrs.add(address + off)
                trace.smc_events.append((address, size, 0))
                break

    _hook_mem_write._written = written_code_addrs
    return _hook_mem_write


def _make_smc_code_hook(trace: EmulationTrace, code_regions: List[Tuple[int, int]],
                         write_hook_ref):
    written = getattr(write_hook_ref, '_written', set())

    def _hook_code(uc_ref, address, size, user_data):
        is_smc = any((address + off) in written for off in range(size))
        if is_smc:
            for i, (waddr, wsz, lexec) in enumerate(trace.smc_events):
                if waddr <= address < waddr + wsz and lexec == 0:
                    trace.smc_events[i] = (waddr, wsz, address)
                    break

    return _hook_code


# 标准钩子

def _make_code_hook(trace: EmulationTrace, start_time: float, capstone_md,
                    inst_counter: List[int], inst_limit: int, raw_data: bytes,
                    text_start: int, text_end: int):
    def _hook_code(uc_ref, address, size, user_data):
        inst_counter[0] += 1
        if inst_counter[0] > inst_limit:
            uc_ref.emu_stop()
            return
        ts = int((time.time() - start_time) * 1_000_000)
        try:
            raw = uc_ref.mem_read(address, min(size, 15))
        except Exception:
            raw = b'\x00' * min(size, 15)
        bytes_hex = raw.hex() if raw else ''
        mnem = '???'
        op_str = ''
        if capstone_md and raw:
            try:
                for insn in capstone_md.disasm(raw, address):
                    mnem = insn.mnemonic
                    op_str = insn.op_str
                    break
            except Exception:
                pass
        regs_read: List[str] = []
        regs_write: List[str] = []
        X86_REGS = {'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp',
                     'rsp', 'rbp', 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9'}
        for r in X86_REGS:
            if r in op_str.lower():
                if mnem.startswith('mov') or mnem.startswith('lea'):
                    if ',' in op_str and r in op_str.split(',')[0]:
                        regs_write.append(r)
                    elif ',' in op_str and r in op_str.split(',')[1]:
                        regs_read.append(r)
                elif any(mnem.startswith(p) for p in ['add', 'sub', 'xor', 'and', 'or', 'shl', 'shr', 'inc', 'dec',
                                                        'imul', 'idiv', 'not', 'neg', 'pop']):
                    regs_write.append(r)
                else:
                    regs_read.append(r)
        event = TraceEvent(
            address=address, size=size, mnemonic=mnem, op_str=op_str,
            bytes_hex=bytes_hex, regs_read=regs_read, regs_write=regs_write, timestamp=ts)
        trace.events.append(event)
    return _hook_code


def _make_mem_read_hook(trace: EmulationTrace):
    def _hook_mem_read(uc_ref, access, address, size, value, user_data):
        trace.mem_hotspots[address] = trace.mem_hotspots.get(address, 0) + 1
        if size < 4:
            return
        try:
            data = uc_ref.mem_read(address, min(size, 1024))
        except Exception:
            return
        current: List[int] = []
        for b in data:
            if 0x20 <= b < 0x7f:
                current.append(b)
            else:
                if len(current) >= 4:
                    s = bytes(current).decode('ascii', errors='replace')
                    if address + len(current) not in trace.string_discoveries:
                        trace.string_discoveries[address] = s
                current = []
        if len(current) >= 4:
            s = bytes(current).decode('ascii', errors='replace')
            if address not in trace.string_discoveries:
                trace.string_discoveries[address] = s
    return _hook_mem_read


def _make_mem_unmapped_hook(uc_ref_class):
    def _hook_mem_unmapped(uc_ref, access, address, size, value, user_data):
        page_addr = address & ~0xFFF
        try:
            uc_ref.mem_map(page_addr, 0x1000)
            return True
        except Exception:
            return False
    return _hook_mem_unmapped


class EmulationTracer:

    def __init__(self, binary_path: str, arch: str = 'x86'):
        self.binary_path = binary_path
        self.arch = arch
        self.data: bytes = b''
        self.entry: int = 0
        try:
            with open(binary_path, 'rb') as f:
                self.data = f.read()
        except Exception as e:
            logger.error("read binary failed: %s", e)

    def _init_engine(self):
        uc = _try_import_unicorn()
        if uc is None:
            return None, None, None, None
        if self.arch in ('x86', 'x86_32'):
            mu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
        elif self.arch in ('x64', 'x86_64'):
            mu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_64)
        else:
            mu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
        entry = _map_pe(self.data, mu, uc)
        if entry is None:
            entry = _map_elf(self.data, mu, uc)
        if entry is None:
            entry = _map_flat(self.data, mu, uc)
        code_regions = getattr(mu, '_code_regions', [])
        mu.mem_map(STACK_BASE, STACK_SIZE)
        mu.mem_map(HEAP_BASE, HEAP_SIZE)
        sp_val = STACK_BASE + STACK_SIZE - 0x1000
        if self.arch in ('x64', 'x86_64'):
            mu.reg_write(uc.x86_const.UC_X86_REG_RSP, sp_val)
        else:
            mu.reg_write(uc.x86_const.UC_X86_REG_ESP, sp_val)
        return mu, uc, entry, code_regions

    def trace(self, start: Optional[int] = None, end: Optional[int] = None,
              max_instructions: int = 100_000, timeout_sec: float = 30.0) -> EmulationTrace:
        trace = EmulationTrace()
        mu, uc, entry, code_regions = self._init_engine()
        if mu is None:
            logger.error("unicorn not available")
            return trace
        if start is None:
            start = entry
        trace.start_addr = start
        trace.end_addr = end or 0

        cs = _try_import_capstone()
        capstone_md = None
        if cs:
            capstone_md = cs.Cs(cs.CS_ARCH_X86,
                                cs.CS_MODE_64 if self.arch in ('x64', 'x86_64') else cs.CS_MODE_32)
            capstone_md.detail = True

        start_time_ts = time.time()
        inst_counter = [0]

        code_hook = _make_code_hook(trace, start_time_ts, capstone_md,
                                     inst_counter, max_instructions, self.data, 0, 0xFFFFFFFF)
        mem_read_hook = _make_mem_read_hook(trace)
        mem_unmapped_hook = _make_mem_unmapped_hook(uc)

        # SMC 检测钩子
        smc_write_hook = _make_smc_write_hook(trace, code_regions)
        smc_code_hook = _make_smc_code_hook(trace, code_regions, smc_write_hook)

        mu.hook_add(uc.UC_HOOK_CODE, code_hook)
        mu.hook_add(uc.UC_HOOK_MEM_READ, mem_read_hook)
        mu.hook_add(uc.UC_HOOK_MEM_WRITE, smc_write_hook)
        mu.hook_add(uc.UC_HOOK_MEM_UNMAPPED, mem_unmapped_hook)
        try:
            end_addr = end if end else start + 0x10000
            mu.emu_start(start, end_addr, timeout=int(timeout_sec * 1_000_000), count=max_instructions)
        except uc.UcError as e:
            errno = e.errno if hasattr(e, 'errno') else 0
            logger.debug("unicorn stopped: errno=%s, %s", errno, e)
        except Exception as e:
            logger.debug("emu_start error: %s", e)

        elapsed = time.time() - start_time_ts
        logger.info("traced %d instructions in %.2fs, SMC events=%d",
                    len(trace.events), elapsed,
                    sum(1 for _, _, lexec in trace.smc_events if lexec != 0))
    return trace


_ANTI_ANALYSIS_APIS = {
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
    'NtSetInformationThread', 'OutputDebugStringA', 'OutputDebugStringW',
    'GetTickCount', 'QueryPerformanceCounter', 'rdtsc',
    'FindWindowA', 'FindWindowW', 'EnumWindows',
    'Process32First', 'Process32Next', 'CreateToolhelp32Snapshot',
    'BlockInput', 'SetWindowsHookEx',
}


def _detect_anti_analysis_flags(trace: EmulationTrace) -> List[str]:
    flags = []
    api_names_in_trace: Set[str] = set()
    for addr, s in trace.string_discoveries.items():
        for api in _ANTI_ANALYSIS_APIS:
            if api.lower() in s.lower():
                api_names_in_trace.add(api)
    if api_names_in_trace:
        flags.append(f"anti_debug_apis: {sorted(api_names_in_trace)}")
    rdtsc_count = sum(1 for ev in trace.events if ev.mnemonic.lower() == 'rdtsc')
    if rdtsc_count > 3:
        flags.append(f"rdtsc_timing_check: {rdtsc_count} occurrences")
    for ev in trace.events:
        if 'fs:' in ev.op_str.lower() or 'gs:' in ev.op_str.lower():
            flags.append(f"PEB_access @ {ev.address:#x}: {ev.mnemonic} {ev.op_str}")
            break
    return flags


def analyze_trace(trace: EmulationTrace) -> TraceResult:
    result = TraceResult()
    result.total_instructions = len(trace.events)
    result.runtime_strings = dict(trace.string_discoveries)
    result.anti_analysis_flags = _detect_anti_analysis_flags(trace)

    executed_smc = [(waddr, wsz, lexec) for waddr, wsz, lexec in trace.smc_events if lexec != 0]
    if executed_smc:
        result.smc_detected = True
        result.smc_regions = [(waddr, waddr + wsz) for waddr, wsz, _ in executed_smc]

    if not trace.events:
        return result

    bb_start = trace.events[0].address
    jump_targets: Set[int] = set()
    call_pairs: List[Tuple[int, int]] = []

    for i, ev in enumerate(trace.events):
        mnem = ev.mnemonic.lower().strip()
        if mnem.startswith('j') or mnem in ('call',):
            try:
                parts = ev.op_str.split(',')
                tgt_str = parts[-1].strip()
                if tgt_str.startswith('0x'):
                    tgt = int(tgt_str, 16)
                    jump_targets.add(tgt)
                    if mnem == 'call':
                        call_pairs.append((ev.address, tgt))
                else:
                    try:
                        tgt = int(tgt_str, 16)
                        jump_targets.add(tgt)
                        if mnem == 'call':
                            call_pairs.append((ev.address, tgt))
                    except ValueError:
                        pass
            except Exception:
                pass
        is_terminator = (mnem.startswith('j') and mnem != 'jmp') or mnem in ('ret', 'retn', 'iret',
                            'call') or mnem.startswith('loop')
        if is_terminator and i + 1 < len(trace.events):
            result.basic_blocks.append((bb_start, ev.address + ev.size))
            bb_start = ev.address + ev.size
        elif i + 1 < len(trace.events):
            next_addr = trace.events[i + 1].address
            if next_addr in jump_targets or next_addr != ev.address + ev.size:
                result.basic_blocks.append((bb_start, ev.address + ev.size))
                bb_start = next_addr

    if len(trace.events) > 0:
        last = trace.events[-1]
        if not result.basic_blocks or result.basic_blocks[-1][0] != bb_start:
            result.basic_blocks.append((bb_start, last.address + last.size))

    result.call_graph = call_pairs

    _known_apis = {
        'kernel32.dll': ['IsDebuggerPresent', 'VirtualAlloc', 'VirtualProtect', 'GetProcAddress',
                          'LoadLibraryA', 'LoadLibraryW', 'CreateFileA', 'WriteFile', 'ReadFile',
                          'CloseHandle', 'Sleep', 'GetTickCount', 'OutputDebugStringA'],
        'ntdll.dll': ['NtQueryInformationProcess', 'NtSetInformationThread', 'ZwQuerySystemInformation'],
        'user32.dll': ['MessageBoxA', 'FindWindowA', 'ShowWindow'],
    }
    for addr in trace.string_discoveries:
        s = trace.string_discoveries[addr]
        for dll, apis in _known_apis.items():
            if dll.lower() in s.lower():
                for api in apis:
                    if api.lower() in s.lower():
                        result.api_calls.append((addr, api))

    return result
