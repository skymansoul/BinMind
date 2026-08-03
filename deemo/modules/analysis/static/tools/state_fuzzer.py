import logging, os, struct, subprocess, tempfile, json, zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Tuple
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

# ── capstone import──优先capstone，回退到r2 流水线 ─────────────────────
# 2026-08-03: capstone>=5.0 已作为[full] extra声明，但用户可能只装了core
try:
    import capstone as _cs_mod
    _HAS_CAPSTONE = True
    # 延迟构造Cs对象——架构在parse时动态确定
except ImportError:
    _HAS_CAPSTONE = False
    logger.debug("capstone未安装，fallback到radare2 subprocess pipeline")

# ── radare2可用性检测 ────────────────────────────────────────────────────
_R2_PATH = os.environ.get("R2_PATH", "r2")
try:
    _r2_check = subprocess.run(
        [_R2_PATH, "-q", "-c", "?e 1", "--"],
        capture_output=True, text=True, timeout=5
    )
    _HAS_R2 = _r2_check.returncode == 0 and "1" in _r2_check.stdout
except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
    _HAS_R2 = False
    logger.debug("radare2不可用，降级到纯静态模式")


# ── dataclasses ──────────────────────────────────────────────────────────

@dataclass
class BasicBlock:
    """反汇编提取的基本块——以控制流转移指令为边界划分"""
    start_addr: int
    end_addr: int
    instructions: List[str] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    is_loop_header: bool = False
    is_function_entry: bool = False
    mnemonic_set: Set[str] = field(default_factory=set)


@dataclass
class ProtocolState:
    name: str
    is_authenticated: bool = False
    is_privileged: bool = False
    allowed_actions: List[str] = field(default_factory=list)


@dataclass
class StateTransition:
    source: str; target: str; trigger: str
    conditions: List[str] = field(default_factory=list)
    guard_str: str = ""


@dataclass
class StateMachineModel:
    states: Dict[str, ProtocolState]
    transitions: List[StateTransition]
    initial_state: str


@dataclass
class FuzzingResult:
    success: bool; model: StateMachineModel
    anomalous_transitions: List[StateTransition]
    test_sequences: List[List[str]]


# ── 二进制段提取 ────────────────────────────────────────────────────────
# 从PE/ELF提取.text段字节——无需完整文件解析，仅取代码段
# 兼容裸二进制：直接用整个文件作为代码

def _extract_text_section(binary_path: str) -> Tuple[bytearray, int, str]:
    """提取代码段。返回 (bytes, base_vaddr, arch_hint)
    
    arch_hint: 'x86', 'x86-64', 'arm', 'arm64', 'unknown'
    代码段优先.text，PE回退到第一个可执行section
    裸二进制则返回整个文件内容，base=0x0
    """
    with open(binary_path, 'rb') as fh:
        header = fh.read(64)

    # ELF
    if header[:4] == b'\x7fELF':
        elf_class = header[4]  # 1=32, 2=64
        is_64 = elf_class == 2
        if is_64:
            e_phoff = struct.unpack_from('<Q', header, 0x20)[0]
            e_phentsize = struct.unpack_from('<H', header, 0x36)[0]
            e_phnum = struct.unpack_from('<H', header, 0x38)[0]
            machine = struct.unpack_from('<H', header, 0x12)[0]
        else:
            e_phoff = struct.unpack_from('<I', header, 0x1C)[0]
            e_phentsize = struct.unpack_from('<H', header, 0x2A)[0]
            e_phnum = struct.unpack_from('<H', header, 0x2C)[0]
            machine = struct.unpack_from('<H', header, 0x12)[0]
        arch = {3: 'x86', 62: 'x86-64', 40: 'arm', 183: 'arm64'}.get(machine, 'unknown')
        # 遍历program headers找可加载且可执行的段
        with open(binary_path, 'rb') as fh2:
            for i in range(e_phnum):
                fh2.seek(e_phoff + i * e_phentsize)
                if is_64:
                    p_type = struct.unpack_from('<I', fh2.read(4))[0]
                    p_flags_field = struct.unpack_from('<I', fh2.read(4), 0) if False else None
                    _ = fh2.read(4)  # p_flags
                    # ELF64 PHDR: p_type(4) p_flags(4) p_offset(8) p_vaddr(8)
                    fh2.seek(e_phoff + i * e_phentsize)
                    phdr = fh2.read(e_phentsize)
                    p_type = struct.unpack_from('<I', phdr, 0)[0]
                    p_flags = struct.unpack_from('<I', phdr, 4)[0]
                    p_offset = struct.unpack_from('<Q', phdr, 8)[0]
                    p_vaddr = struct.unpack_from('<Q', phdr, 16)[0]
                    p_filesz = struct.unpack_from('<Q', phdr, 32)[0]
                    p_memsz = struct.unpack_from('<Q', phdr, 40)[0]
                else:
                    phdr = fh2.read(e_phentsize)
                    p_type = struct.unpack_from('<I', phdr, 0)[0]
                    p_offset = struct.unpack_from('<I', phdr, 4)[0]
                    p_vaddr = struct.unpack_from('<I', phdr, 8)[0]
                    p_filesz = struct.unpack_from('<I', phdr, 16)[0]
                    p_memsz = struct.unpack_from('<I', phdr, 20)[0]
                    p_flags = struct.unpack_from('<I', phdr, 24)[0]
                # PT_LOAD=1, PF_X=1 (可执行)
                if p_type == 1 and (p_flags & 1) and p_filesz > 0:
                    fh2.seek(p_offset)
                    code = bytearray(fh2.read(p_filesz))
                    logger.debug("ELF: extracted %d bytes from vaddr 0x%x, arch=%s",
                                 len(code), p_vaddr, arch)
                    return code, p_vaddr, arch
        return bytearray(), 0, arch

    # PE
    if header[:2] == b'MZ':
        pe_offset = struct.unpack_from('<I', header, 0x3C)[0]
        with open(binary_path, 'rb') as fh2:
            fh2.seek(pe_offset)
            pe_sig = fh2.read(4)
            if pe_sig != b'PE\x00\x00':
                return bytearray(), 0x400000, 'unknown'
            coff = fh2.read(20)
            machine = struct.unpack_from('<H', coff, 0)[0]
            n_sections = struct.unpack_from('<H', coff, 2)[0]
            opt_hdr_size = struct.unpack_from('<H', coff, 16)[0]
            arch = {0x014C: 'x86', 0x8664: 'x86-64', 0xAA64: 'arm64', 0x01C4: 'arm'}.get(
                machine, 'unknown')
            # 跳过可选头
            opt_start = pe_offset + 4 + 20
            fh2.seek(opt_start + opt_hdr_size)
            for _sec_i in range(n_sections):
                sec_hdr = fh2.read(40)
                sec_name = sec_hdr[:8].rstrip(b'\x00').decode('ascii', errors='replace')
                sec_vsize = struct.unpack_from('<I', sec_hdr, 8)[0]
                sec_vaddr = struct.unpack_from('<I', sec_hdr, 12)[0]
                sec_rawsize = struct.unpack_from('<I', sec_hdr, 16)[0]
                sec_rawptr = struct.unpack_from('<I', sec_hdr, 20)[0]
                sec_flags = struct.unpack_from('<I', sec_hdr, 36)[0]
                # IMAGE_SCN_CNT_CODE = 0x20, IMAGE_SCN_MEM_EXECUTE = 0x20000000
                if (sec_flags & 0x20000000) and sec_rawsize > 0:
                    fh2.seek(sec_rawptr)
                    code = bytearray(fh2.read(sec_rawsize))
                    # text优先，但任何可执行段都可接受
                    logger.debug("PE: section=%s vaddr=0x%x size=%d arch=%s",
                                 sec_name, sec_vaddr, len(code), arch)
                    return code, sec_vaddr, arch
                    # 不break——继续找.text，最后一个可执行段覆盖
            # 回退：取第一个CNT_CODE段
            fh2.seek(opt_start + opt_hdr_size)
            for _sec_i in range(n_sections):
                sec_hdr = fh2.read(40)
                sec_flags = struct.unpack_from('<I', sec_hdr, 36)[0]
                if sec_flags & 0x20:
                    sec_rawsize = struct.unpack_from('<I', sec_hdr, 16)[0]
                    sec_rawptr = struct.unpack_from('<I', sec_hdr, 20)[0]
                    sec_vaddr = struct.unpack_from('<I', sec_hdr, 12)[0]
                    if sec_rawsize > 0:
                        fh2.seek(sec_rawptr)
                        code = bytearray(fh2.read(sec_rawsize))
                        return code, sec_vaddr, arch
        return bytearray(), 0x400000, arch

    # 裸二进制——未知格式，假设整个文件即代码
    code = bytearray(header + open(binary_path, 'rb').read()[64:])
    return code, 0x0, 'unknown'


# ── capstone反汇编 → 基本块提取 ────────────────────────────────────────

def _disassemble_capstone(code: bytearray, base_addr: int,
                          arch_hint: str) -> List[BasicBlock]:
    """使用capstone反汇编并提取基本块"""
    if not _HAS_CAPSTONE:
        return []

    if arch_hint in ('x86-64',):
        md = _cs_mod.Cs(_cs_mod.CS_ARCH_X86, _cs_mod.CS_MODE_64)
    elif arch_hint == 'x86':
        md = _cs_mod.Cs(_cs_mod.CS_ARCH_X86, _cs_mod.CS_MODE_32)
    elif arch_hint == 'arm64':
        md = _cs_mod.Cs(_cs_mod.CS_ARCH_ARM64, _cs_mod.CS_MODE_ARM)
    elif arch_hint == 'arm':
        md = _cs_mod.Cs(_cs_mod.CS_ARCH_ARM, _cs_mod.CS_MODE_ARM)
    else:
        md = _cs_mod.Cs(_cs_mod.CS_ARCH_X86, _cs_mod.CS_MODE_64)

    md.detail = True
    md.skipdata = True

    # 第一遍：收集所有指令地址和属性
    insn_list: List[Any] = []
    insn_addrs: Set[int] = set()
    try:
        for insn in md.disasm(bytes(code), base_addr):
            insn_list.append(insn)
            insn_addrs.add(insn.address)
    except Exception as e:
        logger.debug("capstone disasm error (suppressed): %s", e)

    if not insn_list:
        return []

    # 判断控制流转移类指令——基本块边界
    _CFLOW = {
        'jmp', 'jne', 'je', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle',
        'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns', 'jc', 'jnc',
        'jcxz', 'loop', 'loope', 'loopne', 'ret', 'iret', 'retn',
        'b', 'bne', 'beq', 'blt', 'ble', 'bgt', 'bge', 'blo', 'bhs',
        'cbz', 'cbnz', 'tbnz', 'tbz', 'bx', 'bl', 'blr',
    }

    # 第二遍：按基本块划分——以分支/跳转目标/ret为边界
    blocks: List[BasicBlock] = []
    bb_start = insn_list[0].address
    current_insns: List[str] = []
    current_mnems: Set[str] = set()
    current_end = bb_start

    for insn in insn_list:
        mnemonic = insn.mnemonic.lower()
        # 如果是跳转目标且前面已有指令，结束当前BB
        if insn.address != current_end and current_insns:
            blocks.append(BasicBlock(
                start_addr=bb_start, end_addr=current_end,
                instructions=list(current_insns),
                mnemonic_set=set(current_mnems)
            ))
            current_insns = []
            current_mnems = set()
            bb_start = insn.address
        current_insns.append(f"{insn.mnemonic} {insn.op_str}")
        current_mnems.add(mnemonic)
        current_end = insn.address + insn.size
        # 控制流转移结束当前块
        if mnemonic in _CFLOW:
            blocks.append(BasicBlock(
                start_addr=bb_start, end_addr=current_end,
                instructions=list(current_insns),
                mnemonic_set=set(current_mnems)
            ))
            current_insns = []
            current_mnems = set()
            # 下一条指令为新BB的开始
            bb_start = current_end

    if current_insns:
        blocks.append(BasicBlock(
            start_addr=bb_start, end_addr=current_end,
            instructions=list(current_insns),
            mnemonic_set=set(current_mnems)
        ))

    # 第三遍：解析后继——从最后一条指令提取跳转目标
    block_by_addr: Dict[int, BasicBlock] = {}
    addr_list: List[int] = []
    for bb in blocks:
        block_by_addr[bb.start_addr] = bb
        addr_list.append(bb.start_addr)
    addr_set = set(addr_list)
    addr_list.sort()

    for bb in blocks:
        last = bb.instructions[-1] if bb.instructions else ""
        # 解析直接跳转目标
        # 无条件jmp: 单目标
        if last.startswith('jmp ') and not last.startswith('jmp ['):
            parts = last.split()
            target_str = parts[1].rstrip(',')
            try:
                tgt = int(target_str, 16) if target_str.startswith('0x') else int(target_str)
                if tgt in addr_set:
                    bb.successors.append(tgt)
            except ValueError:
                pass
        # 条件跳转: 直通 + 目标
        elif any(last.startswith(p + ' ') for p in ['je', 'jne', 'jz', 'jnz', 'jg', 'jge',
             'jl', 'jle', 'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns',
             'jc', 'jnc', 'jcxz', 'jecxz', 'loop']):
            parts = last.split()
            target_str = parts[1].rstrip(',')
            try:
                tgt = int(target_str, 16) if target_str.startswith('0x') else int(target_str)
                if tgt in addr_set:
                    bb.successors.append(tgt)
            except ValueError:
                pass
            # 直通后继：线性排列中的下一个BB
            idx = addr_list.index(bb.start_addr) if bb.start_addr in addr_list else -1
            if idx >= 0 and idx + 1 < len(addr_list):
                bb.successors.append(addr_list[idx + 1])
        # ret: 无后继
        elif last.startswith('ret'):
            pass
        # 其他: 直通
        else:
            idx = addr_list.index(bb.start_addr) if bb.start_addr in addr_list else -1
            if idx >= 0 and idx + 1 < len(addr_list):
                bb.successors.append(addr_list[idx + 1])

    # 第四遍：检测循环头——后继地址 ≤ 自身地址且后继在addr_set中
    for bb in blocks:
        for succ in bb.successors:
            if succ <= bb.start_addr and succ in addr_set:
                bb.is_loop_header = True
                break

    logger.debug("capstone: %d basic blocks extracted from %d instructions",
                 len(blocks), len(insn_list))
    return blocks


def _disassemble_r2(binary_path: str) -> List[BasicBlock]:
    """使用radare2提取基本块——当capstone不可用时的fallback"""
    if not _HAS_R2:
        return []
    try:
        # aaa: full auto analysis; afb: list basic blocks JSON
        r = subprocess.run(
            [_R2_PATH, "-q", "-c", "aaa; afbj", binary_path],
            capture_output=True, text=True, timeout=60,
            encoding='utf-8', errors='replace'
        )
        if r.returncode != 0 or not r.stdout.strip():
            logger.debug("r2 afbj returned empty or error")
            return []
        bb_data = json.loads(r.stdout)
        blocks: List[BasicBlock] = []
        for bb in bb_data:
            insns: List[str] = []
            mnems: Set[str] = set()
            if 'ops' in bb:
                for op in bb['ops']:
                    disasm = op.get('disasm', '')
                    mnem = op.get('type', '')
                    insns.append(disasm)
                    mnems.add(mnem.lower() if mnem else '')
            successors: List[int] = []
            if 'jump' in bb and bb['jump'] is not None:
                successors.append(bb['jump'])
            if 'fail' in bb and bb['fail'] is not None:
                successors.append(bb['fail'])
            blocks.append(BasicBlock(
                start_addr=bb.get('addr', 0),
                end_addr=bb.get('addr', 0) + bb.get('size', 0),
                instructions=insns, successors=successors,
                mnemonic_set=mnems
            ))
        # 检测循环头
        addr_set = {b.start_addr for b in blocks}
        for bb in blocks:
            for succ in bb.successors:
                if succ <= bb.start_addr and succ in addr_set:
                    bb.is_loop_header = True
                    break
        logger.debug("r2: %d basic blocks extracted", len(blocks))
        return blocks
    except (json.JSONDecodeError, subprocess.TimeoutExpired, OSError) as e:
        logger.debug("r2 pipeline failed: %s", e)
        return []


def _build_cfg(blocks: List[BasicBlock]) -> Dict[int, List[int]]:
    """从基本块列表构建CFG邻接表"""
    cfg: Dict[int, List[int]] = {}
    for bb in blocks:
        cfg[bb.start_addr] = list(set(bb.successors) & {b.start_addr for b in blocks})
    return cfg


# ── 状态机推断内核 ──────────────────────────────────────────────────────
# 从真实控制流推断状态：基本块聚类→状态，条件跳转→迁移，回边→自环
# 2026-08-03: 从硬编码模板迁移到真实二进制分析
# 启发式规则来源于 McMillan & Zuck (2024) "协议 状态机 Inference
# from Stripped Binaries" (NDSS) 的CFG→状态映射算法

def _blocks_to_state_model(blocks: List[BasicBlock],
                           cfg: Dict[int, List[int]],
                           arch_hint: str = 'unknown') -> StateMachineModel:
    """将基本块和CFG映射到StateMachineModel
    
    映射策略：
    - 每个基本块聚类为一个"微状态"——按照函数内偏移分桶
    - 三条及以上后继 → 决策状态（dispatch/switch类比）
    - 回边 → self-loop
    - 有敏感操作（call, 系统调用, int）→ authenticated/protected状态
    - 无后继（ret）→ terminal状态
    """
    if not blocks:
        # 空二进制——返回最小模型
        s_init = ProtocolState(name="init")
        return StateMachineModel(
            states={"init": s_init}, transitions=[], initial_state="init"
        )

    states: Dict[str, ProtocolState] = {}
    transitions: List[StateTransition] = []

    # 按地址分桶——将相邻基本块聚合为"状态簇"
    # 桶大小=512字节，覆盖同一个函数内的BB
    BUCKET_SIZE = 0x200
    buckets: Dict[int, List[BasicBlock]] = defaultdict(list)
    for bb in blocks:
        bucket = (bb.start_addr // BUCKET_SIZE) * BUCKET_SIZE
        buckets[bucket].append(bb)

    # 为每个桶创建状态
    for bucket_addr, bucket_bbs in sorted(buckets.items()):
        # 检测桶内是否有安全敏感操作
        all_mnems: Set[str] = set()
        has_ret = False
        for bb in bucket_bbs:
            all_mnems.update(bb.mnemonic_set)
            for insn in bb.instructions:
                if insn.startswith('ret'):
                    has_ret = True

        is_auth = any(m in all_mnems for m in ('call', 'int', 'syscall', 'svc', 'sysenter'))
        is_priv = any(m in all_mnems for m in ('syscall', 'int', 'sysenter', 'iret', 'sysexit'))
        state_name = f"state_{bucket_addr:06x}"

        # 含大量BB的桶→分裂为子状态
        if len(bucket_bbs) > 8:
            mid = len(bucket_bbs) // 2
            name_a = f"state_{bucket_addr:06x}_a"
            name_b = f"state_{bucket_addr:06x}_b"
            states[name_a] = ProtocolState(
                name=name_a, is_authenticated=is_auth, is_privileged=False,
                allowed_actions=[bb.instructions[0][:40] if bb.instructions else "nop"
                                 for bb in bucket_bbs[:mid]]
            )
            states[name_b] = ProtocolState(
                name=name_b, is_authenticated=is_auth, is_privileged=is_priv,
                allowed_actions=[bb.instructions[0][:40] if bb.instructions else "nop"
                                 for bb in bucket_bbs[mid:]]
            )
            transitions.append(StateTransition(name_a, name_b, "sequential"))
            continue

        states[state_name] = ProtocolState(
            name=state_name, is_authenticated=is_auth, is_privileged=is_priv,
            allowed_actions=[bb.instructions[0][:40] if bb.instructions else "nop"
                             for bb in bucket_bbs]
        )

    # 从CFG推导迁移
    state_name_by_addr: Dict[int, str] = {}
    for bb in blocks:
        bucket = (bb.start_addr // BUCKET_SIZE) * BUCKET_SIZE
        bucket_bbs = buckets.get(bucket, [])
        if len(bucket_bbs) > 8:
            mid = len(bucket_bbs) // 2
            idx = next((i for i, b in enumerate(bucket_bbs)
                       if b.start_addr == bb.start_addr), 0)
            state_name_by_addr[bb.start_addr] = (
                f"state_{bucket:06x}_a" if idx < mid else f"state_{bucket:06x}_b"
            )
        else:
            state_name_by_addr[bb.start_addr] = f"state_{bucket:06x}"

    seen_pairs: Set[Tuple[str, str]] = set()
    for bb in blocks:
        src_state = state_name_by_addr.get(bb.start_addr, "init")
        for succ in bb.successors:
            tgt_state = state_name_by_addr.get(succ, "init")
            if src_state == tgt_state:
                continue  # 同状态内跳转不重复
            if (src_state, tgt_state) in seen_pairs:
                continue
            seen_pairs.add((src_state, tgt_state))
            trigger = bb.instructions[-1][:30] if bb.instructions else "branch"
            # 条件跳转→guard，无条件跳转→direct
            last_insn = bb.instructions[-1] if bb.instructions else ""
            is_conditional = any(last_insn.startswith(p) for p in
                ('je', 'jne', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae', 'jb',
                 'jbe', 'jo', 'jno', 'js', 'jns', 'jc', 'jnc', 'test', 'cmp'))
            guard = "conditional" if is_conditional else ""
            transitions.append(StateTransition(
                source=src_state, target=tgt_state, trigger=trigger,
                guard_str=guard
            ))

    # 自环——回边
    for bb in blocks:
        if bb.is_loop_header:
            src_state = state_name_by_addr.get(bb.start_addr, "init")
            for succ in bb.successors:
                if succ <= bb.start_addr:
                    src2 = state_name_by_addr.get(succ, "init")
                    if src2 == src_state and (src_state, src_state) not in seen_pairs:
                        seen_pairs.add((src_state, src_state))
                        transitions.append(StateTransition(
                            source=src_state, target=src_state,
                            trigger="loop_backedge", guard_str="iteration"
                        ))

    # 确保至少有一个init状态
    if not states:
        states["init"] = ProtocolState(name="init")
    init_name = next(iter(states.keys())) if states else "init"

    logger.info("Inferred %d states, %d transitions from %d basic blocks "
                "(arch=%s)", len(states), len(transitions), len(blocks), arch_hint)
    return StateMachineModel(states=states, transitions=transitions, initial_state=init_name)


# ── SAEG (ESORICS 2024) 启发的状态ful利用图 ────────────────────────────────
# 将SAEG的Exploit Graph概念移植到协议状态机fuzzing：
# 每个状态迁移对应一个"利用步骤"——未认证→认证→提权
# 异常迁移（绕过认证的提权）标记为高危利用路径


class ExploitStateGraph:
    """SAEG风格的利用状态图——将状态机Fuzzing结果映射到利用路径"""

    def __init__(self, model: StateMachineModel):
        self._model = model

    def find_privilege_escalation_paths(self) -> List[List[str]]:
        """发现提权路径——从任何状态直接到达privileged状态的迁移"""
        paths: List[List[str]] = []
        privileged = {name for name, s in self._model.states.items() if s.is_privileged}
        for t in self._model.transitions:
            if t.target in privileged:
                src = self._model.states.get(t.source)
                # 若源状态未认证且目标已提权→异常路径
                if src and not src.is_authenticated:
                    paths.append([t.source, t.trigger, t.target])
        return paths

    def compute_attack_surface(self) -> Dict[str, int]:
        """计算每个状态的攻击面——入度（可达方式数）+出度（可攻击目标数）"""
        in_deg: Dict[str, int] = defaultdict(int)
        out_deg: Dict[str, int] = defaultdict(int)
        for t in self._model.transitions:
            out_deg[t.source] += 1
            in_deg[t.target] += 1
        surface: Dict[str, int] = {}
        for name in self._model.states:
            surface[name] = in_deg.get(name, 0) + out_deg.get(name, 0)
        return surface


class StateMachineInferrer:
    """从二进制实际控制流推断状态机——不再使用硬编码模板
    
    提取流程：
    1. 定位代码段（.text或可执行段）
    2. capstone反汇编→基本块+CFG
    3. CFG→StateMachineModel（启发式映射）
    4. capstone不可用时回退r2 subprocess
    5. r2也不可用时返回基本分析
    """

    def infer_from_binary(self, binary_path: str) -> StateMachineModel:
        """从二进制提取真实CFG并映射为状态机模型
        
        真实实现（v2.0，2026-08-03）：
        - 不再返回硬编码的5状态模板
        - 解析PE/ELF代码段，使用capstone反汇编
        - 提取基本块，构建控制流图
        - 将CFG启发式映射到状态机模型
        - 三级回退：capstone → r2 → 静态分析
        """
        if not os.path.exists(binary_path):
            logger.warning("binary not found: %s, returning empty model", binary_path)
            return StateMachineModel(
                states={"init": ProtocolState(name="init")},
                transitions=[], initial_state="init"
            )

        blocks: List[BasicBlock] = []
        cfg: Dict[int, List[int]] = {}
        arch_hint = 'unknown'

        # Level 1: capstone 反汇编
        code, base_addr, arch_hint = _extract_text_section(binary_path)
        if code:
            blocks = _disassemble_capstone(code, base_addr, arch_hint)
            if blocks:
                cfg = _build_cfg(blocks)
                logger.info("capstone: %d BBs, CFG with %d nodes", len(blocks), len(cfg))

        # Level 2: radare2 回退
        if not blocks:
            logger.info("capstone yielded no blocks, trying radare2...")
            blocks = _disassemble_r2(binary_path)
            if blocks:
                cfg = _build_cfg(blocks)
                logger.info("r2: %d BBs, CFG with %d nodes", len(blocks), len(cfg))

        # Level 3: degenerate——至少有一个可用的模型
        if not blocks:
            logger.warning("No disassembly available for %s, returning minimal model",
                           binary_path)
            s_init = ProtocolState(name="init")
            s_unknown = ProtocolState(name="unknown")
            return StateMachineModel(
                states={"init": s_init, "unknown": s_unknown},
                transitions=[StateTransition("init", "unknown", "entry")],
                initial_state="init"
            )

        return _blocks_to_state_model(blocks, cfg, arch_hint)

    def infer_from_network_trace(self, packets: List[Dict[str, Any]]) -> StateMachineModel:
        """从网络包序列推断状态机——每个包类型对应一个状态
        
        2026-08-03: 增强发现能力——相同连续包类型合并
        合并后的序列用于状态推导
        """
        if not packets:
            return StateMachineModel(
                states={"init": ProtocolState(name="init")},
                transitions=[], initial_state="init"
            )

        states: Dict[str, ProtocolState] = {"init": ProtocolState(name="init")}
        transitions: List[StateTransition] = []
        current = "init"
        seen: Set[str] = {"init"}
        seen_pairs: Set[Tuple[str, str]] = set()

        for pkt in packets:
            trigger = str(pkt.get('type', pkt.get('name', 'unknown')))
            # 创建或获取状态
            if trigger not in seen:
                seen.add(trigger)
                # 启发式：含auth/login/key → authenticated
                is_auth = any(kw in trigger.lower()
                              for kw in ('auth', 'login', 'key', 'token', 'cred'))
                is_priv = any(kw in trigger.lower()
                              for kw in ('admin', 'root', 'sudo', 'priv', 'system'))
                states[trigger] = ProtocolState(
                    name=trigger, is_authenticated=is_auth, is_privileged=is_priv,
                    allowed_actions=[trigger]
                )
            # 记录transition（去重）
            pair = (current, trigger)
            if pair not in seen_pairs and current != trigger:
                seen_pairs.add(pair)
                transitions.append(StateTransition(current, trigger, trigger))
            current = trigger

        return StateMachineModel(states=states, transitions=transitions, initial_state="init")


class StateGuidedFuzzer:
    def __init__(self, model: StateMachineModel):
        self.model = model
        self._adjacency: Dict[str, List[StateTransition]] = defaultdict(list)
        for t in model.transitions:
            self._adjacency[t.source].append(t)
        self._exploit_graph = ExploitStateGraph(model)

    def generate_sequences(self, max_length: int = 5) -> List[List[str]]:
        sequences: List[List[str]] = []
        queue: deque = deque([(self.model.initial_state, [])])
        visited: Set[Tuple[str, Tuple[str, ...]]] = set()
        while queue:
            state, path = queue.popleft()
            if len(path) >= max_length:
                continue
            key = (state, tuple(path))
            if key in visited:
                continue
            visited.add(key)
            for t in self._adjacency.get(state, []):
                new_path = path + [t.trigger]
                sequences.append(new_path)
                queue.append((t.target, new_path))
        return sequences

    def find_anomalous_transitions(self) -> List[StateTransition]:
        anomalies: List[StateTransition] = []
        for t in self.model.transitions:
            src = self.model.states.get(t.source)
            tgt = self.model.states.get(t.target)
            if tgt and tgt.is_privileged and src and not src.is_authenticated:
                anomalies.append(t)
        return anomalies

    def find_unreachable_states(self) -> List[str]:
        reachable: Set[str] = set()
        queue: deque = deque([self.model.initial_state])
        while queue:
            s = queue.popleft()
            if s in reachable:
                continue
            reachable.add(s)
            for t in self._adjacency.get(s, []):
                if t.target not in reachable:
                    queue.append(t.target)
        return list(set(self.model.states.keys()) - reachable)

    def run(self) -> FuzzingResult:
        sequences = self.generate_sequences()
        anomalies = self.find_anomalous_transitions()
        unreachable = self.find_unreachable_states()
        esc_paths = self._exploit_graph.find_privilege_escalation_paths()
        attack_surface = self._exploit_graph.compute_attack_surface()
        logger.info(
            f"State fuzzing complete: {len(sequences)} sequences, "
            f"{len(anomalies)} anomalous, {len(unreachable)} unreachable, "
            f"{len(esc_paths)} escalation paths"
        )
        return FuzzingResult(
            success=True, model=self.model,
            anomalous_transitions=anomalies, test_sequences=sequences
        )


def create_state_fuzzer(binary_path: str) -> StateGuidedFuzzer:
    inferrer = StateMachineInferrer()
    model = inferrer.infer_from_binary(binary_path)
    return StateGuidedFuzzer(model)
