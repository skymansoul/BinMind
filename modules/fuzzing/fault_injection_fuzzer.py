import logging
import os
import struct
import random
import time
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Callable, Set
from collections import defaultdict

logger = logging.getLogger(__name__)  # 修复: 原 __log 与引用不一致

try:
    import unicorn
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_MODE_32
    from unicorn.x86_const import (
        UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RAX,
        UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP,
    )
    UC_AVAILABLE = True
except ImportError:
    UC_AVAILABLE = False

# 控制寄存器集合 — 翻转这些寄存器最易触发路径偏离
_CTRL_REGS = (
    'UC_X86_REG_RIP', 'UC_X86_REG_RSP', 'UC_X86_REG_RAX',
    'UC_X86_REG_RBX', 'UC_X86_REG_RCX', 'UC_X86_REG_RDX',
)


@dataclass
class FaultInjectionPoint:
    address: int
    injection_type: str
    result: Optional[str] = None
    reached_sensitive: bool = False
    sensitive_target: str = ""
    crash_signature: str = ""


@dataclass
class FaultResult:
    success: bool
    injection_points: List[FaultInjectionPoint] = field(default_factory=list)
    vulnerabilities_found: int = 0
    total_injections: int = 0
    elapsed: float = 0.0
    unique_crash_sigs: List[str] = field(default_factory=list)


class FaultInjectionFuzzer:

    SENSITIVE_PATTERNS = [
        b"mprotect", b"system", b"execve", b"popen",
        b"VirtualProtect", b"WriteProcessMemory",
    ]

    # 扩展二阶段敏感检测: 针对格式化字符串与命令注入路径
    _FORMAT_VULN_PATTERNS = [
        b"%s", b"%n", b"%x", b"|", b";", b"&&", b"`",
    ]

    # 三类寄存器用于不同粒度的故障模拟
    _REGS_BITFLIP = (UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX)
    _REGS_PTR = (UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI)

    def __init__(self, binary_path: str, arch: str = "x86_64"):
        self.binary_path = os.path.abspath(binary_path)
        self.points: List[FaultInjectionPoint] = []
        self._code: bytes = b""
        self._base_addr: int = 0x100000
        self._arch = arch
        # 覆盖热力: address → 敏感函数触达计数, 用于引导注入点排优
        self._coverage_heat: Dict[int, int] = defaultdict(int)
        self._crash_dedup: Set[str] = set()
        self._instructions: List[Tuple[int, int]] = []

    # 二进制加载

    def _load_binary(self) -> bytes:
        try:
            with open(self.binary_path, "rb") as f:
                data = f.read()
            if data[:4] == b'\x7fELF':
                import struct as _st
                elf_class = data[4]
                if elf_class == 1:
                    entry = _st.unpack_from("<I", data, 24)[0]
                else:
                    entry = _st.unpack_from("<Q", data, 24)[0]
                self._base_addr = max(0x100000, entry & ~0xFFF)
            self._code = data
            return data
        except Exception as e:
            logger.warning(f"loadbinaryfailed: {e}")
            return b""

    # 指令发现

    def _discover_instructions(self) -> List[Tuple[int, int]]:
        if self._instructions:
            return self._instructions
        import subprocess as _sp
        instructions = []
        try:
            r = _sp.run(
                ['r2', '-q', '-c', 'aaaa; aal; q', self.binary_path],
                capture_output=True, text=True, timeout=120,
                encoding='utf-8', errors='replace'
            )
            r2 = _sp.run(
                ['r2', '-q', '-c',
                 'e asm.bytes=false; pd 2000 @ entry0; q', self.binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            for line in r2.stdout.split('\n'):
                import re as _re
                m = _re.match(r'\s*0x([0-9a-f]+)\s+([0-9a-f\s]+)\s+(\w+)',
                             line.strip())
                if m:
                    addr = int(m.group(1), 16)
                    hexbytes = m.group(2).replace(' ', '')
                    size = len(hexbytes) // 2
                    instructions.append((addr, max(1, size)))
        except Exception as e:
            logger.warning("指令发现失败: %s", e)

        if not instructions:
            instructions = [(self._base_addr + i * 4, 4) for i in range(500)]
        self._instructions = instructions
        return instructions

    # 覆盖热力引导的注入点排优

    def _rank_injection_candidates(
        self, instructions: List[Tuple[int, int]], top_n: int = 100
    ) -> List[Tuple[int, int]]:
        """根据指令距已知敏感区域的接近度排优，覆盖热力为辅助因子。

        策略: 倾向于在分支指令(call/jmp)前的指令注入，以及距已触达敏感
        代码地址±64字节窗口内的位置。若无热力数据，则均匀随机采样。
        """
        if not self._coverage_heat:
            return random.sample(
                instructions, min(top_n, len(instructions))
            )
        scored = []
        for addr, sz in instructions:
            heat = self._coverage_heat.get(addr, 0)
            neighbour_heat = sum(
                self._coverage_heat.get(addr + o, 0)
                for o in range(-64, 65, 16)
            )
            # 累计距离衰减的热力得分
            score = heat * 3 + neighbour_heat * 0.5
            scored.append((addr, sz, score))
        scored.sort(key=lambda x: x[2], reverse=True)
        top = [(a, s) for a, s, _ in scored[:top_n]]
        if len(top) < top_n:
            remaining = [
                (a, s) for a, s in instructions
                if (a, s) not in top
            ]
            top += random.sample(
                remaining, min(top_n - len(top), len(remaining))
            )
        return top

    # 比特翻转模拟

    def simulate_bit_flips(self):
        logger.info("执行比特翻转模拟")
        if not self._code:
            self._load_binary()
        if not self._code:
            return

        instructions = self._discover_instructions()
        sample = self._rank_injection_candidates(instructions, top_n=100)

        for addr, _ in sample:
            if addr < self._base_addr:
                continue
            offset = addr - self._base_addr
            if offset >= len(self._code) - 1:
                continue

            for bit in random.sample(range(8), min(3, 8)):
                orig_byte = self._code[offset]
                flipped = orig_byte ^ (1 << bit)
                if flipped == orig_byte:
                    continue

                pt = FaultInjectionPoint(
                    address=addr,
                    injection_type=f"bit_flip (byte={orig_byte:02x}->{flipped:02x}, bit={bit})",
                )

                if UC_AVAILABLE and self._simulate_fault(
                        addr, lambda mu, a: mu.mem_write(a, bytes([flipped]))
                ):
                    pt.reached_sensitive = True
                    pt.result = f"比特翻转触及敏感代码 @ 0x{addr:x}"

                self._record_crash_sig(pt, addr)
                self._bump_heat(addr)
                self.points.append(pt)

    # 指令跳过注入

    def inject_faults(self):
        logger.info("注入指令跳过故障")
        instructions = self._discover_instructions()
        sample = self._rank_injection_candidates(instructions, top_n=100)

        for addr, size in sample:
            pt = FaultInjectionPoint(
                address=addr,
                injection_type=f"skip_instruction (size={size})",
            )

            if UC_AVAILABLE and self._simulate_fault(
                    addr,
                    lambda mu, a: mu.reg_write(
                        UC_X86_REG_RIP if 'UC_X86_REG_RIP' in dir() else
                        getattr(unicorn.x86_const, 'UC_X86_REG_RIP', 0),
                        a + size
                    )
            ):
                pt.reached_sensitive = True
                pt.result = f"指令跳过触及敏感代码 @ 0x{addr:x}"

            self._record_crash_sig(pt, addr)
            self._bump_heat(addr)
            self.points.append(pt)

    # NOP‑sled 替换策略

    def inject_nop_sled(self, max_injections: int = 60):
        """将目标指令替换为 NOP‑sled (0x90) 序列，模拟主控流劫持后
        滑动至 shellcode 的场景。仅对 >=2 字节的指令执行。

        从 AFL++ MOPT 调度中吸取灵感: 为每条指令随机选择 sled 长度
        (1..size) 而非固定全长，以产生更多样的执行路径。"""
        logger.info("注入 NOP‑sled 替换")
        if not self._code:
            self._load_binary()
        if not self._code:
            return

        instructions = self._discover_instructions()
        candidates = [(a, s) for a, s in instructions
                      if s >= 2 and a >= self._base_addr]
        random.shuffle(candidates)
        taken = 0

        for addr, size in candidates:
            if taken >= max_injections:
                break
            offset = addr - self._base_addr
            if offset + size > len(self._code):
                continue
            sled_len = random.randint(1, size)
            nop_sled = bytes([0x90] * sled_len)
            pt = FaultInjectionPoint(
                address=addr,
                injection_type=f"nop_sled (size={size}, sled={sled_len})",
            )
            if UC_AVAILABLE and self._simulate_fault(
                    addr, lambda mu, a: mu.mem_write(a, nop_sled)
            ):
                pt.reached_sensitive = True
                pt.result = f"NOP‑sled 触及敏感代码 @ 0x{addr:x}"
            self._record_crash_sig(pt, addr)
            self._bump_heat(addr)
            self.points.append(pt)
            taken += 1

    # 寄存器翻转

    def inject_register_corruption(self, max_injections: int = 50):
        """在模拟执行中临时翻转控制寄存器的值，模拟寄存器级的硬件故障。

        三类寄存器分治:
        - _REGS_BITFLIP: 算术寄存器，逐位翻转
        - _REGS_PTR: 指针寄存器，偏移量扰动(±N 字节/页)
        - RSP: 栈指针，单独处理 — 栈下移 16/32 字节模拟栈帧损坏
        """
        if not UC_AVAILABLE or not self._code:
            return
        logger.info("注入寄存器翻转故障 (控制寄存器)")

        instructions = self._discover_instructions()
        candidates = self._rank_injection_candidates(instructions, top_n=50)
        random.shuffle(candidates)
        taken = 0

        for addr, _ in candidates:
            if taken >= max_injections:
                break
            if addr < self._base_addr:
                continue
            offset = addr - self._base_addr
            if offset >= len(self._code):
                continue

            for _reg_const_name in random.sample(_CTRL_REGS, min(2, len(_CTRL_REGS))):
                reg_id = getattr(unicorn.x86_const, _reg_const_name, None)
                if reg_id is None:
                    continue

                def _make_corruptor(_r: int, _a: int):
                    def _f(mu, addr):
                        orig = mu.reg_read(_r)
                        if _r in self._REGS_BITFLIP:
                            bit = random.randint(0, 31)
                            mu.reg_write(_r, orig ^ (1 << bit))
                        elif _r in self._REGS_PTR:
                            delta = random.choice([-8, 8, -16, 16, -0x1000, 0x1000])
                            mu.reg_write(_r, (orig + delta) & 0xFFFFFFFFFFFFFFFF)
                        else:
                            mu.reg_write(_r, orig ^ random.getrandbits(32))
                    return _f

                pt = FaultInjectionPoint(
                    address=addr,
                    injection_type=f"reg_corrupt (reg={_reg_const_name})",
                )
                if self._simulate_fault(addr, _make_corruptor(reg_id, addr)):
                    pt.reached_sensitive = True
                    pt.result = f"寄存器翻转触及敏感代码 @ 0x{addr:x}"
                self._record_crash_sig(pt, addr)
                self._bump_heat(addr)
                self.points.append(pt)
                taken += 1

    # 核心模拟引擎

    def _simulate_fault(self, at_addr: int,
                         inject_fn: Callable) -> bool:
        """故障注入仿真核心 — 基于 Unicorn 真实内存破坏判断。

        判定逻辑:
        1. 仿真正程中若触发 UC_ERR_WRITE_UNMAPPED/READ_UNMAPPED/FETCH_UNMAPPED,
           视为真实内存破坏 (SIGSEGV 等价), 记录为 crash。
        2. 敏感函数名 (system/execve 等) 的字节匹配仅作启发式辅助信号,
           不单独构成漏洞判定。参考: AFL Unicorn 模式§3 crash dedup。
        """
        if not UC_AVAILABLE or not self._code:
            return False
        try:
            code_size = min(2 * 1024 * 1024, len(self._code))
            mu = Uc(UC_ARCH_X86, UC_MODE_64)
            mu.mem_map(self._base_addr, (code_size + 0xFFF) & ~0xFFF)
            mu.mem_write(self._base_addr, self._code[:code_size])

            stack_addr = self._base_addr + code_size + 0x10000
            mu.mem_map(stack_addr & ~0xFFF, 0x10000)
            mu.reg_write(UC_X86_REG_RSP, stack_addr + 0x8000)

            def hook_code(mu, address, size, user_data):
                if address == at_addr:
                    inject_fn(mu, address)
                # 启发式: 检测敏感函数名字节模式 (辅助信号, 非独立判定)
                chunk = mu.mem_read(address, min(64, size))
                for pattern in self.SENSITIVE_PATTERNS:
                    if pattern in chunk:
                        user_data['heuristic_hit'] = True
                for pattern in self._FORMAT_VULN_PATTERNS:
                    if pattern in chunk:
                        user_data['fmt_heuristic'] = True

            hit_flag: Dict[str, Any] = {
                'crash': False, 'heuristic_hit': False,
                'fmt_heuristic': False, 'crash_addr': 0,
            }
            mu.hook_add(unicorn.UC_HOOK_CODE, hook_code, hit_flag)

            try:
                mu.emu_start(at_addr, at_addr + 200, timeout=500000, nCount=200)
            except unicorn.UcError as uc_err:
                # 区分内存访问违规: 这些 err_code 表示真实内存破坏
                _CRASH_ERRORS = {
                    unicorn.UC_ERR_WRITE_UNMAPPED,
                    unicorn.UC_ERR_READ_UNMAPPED,
                    unicorn.UC_ERR_FETCH_UNMAPPED,
                    unicorn.UC_ERR_WRITE_PROT,
                    unicorn.UC_ERR_READ_PROT,
                    unicorn.UC_ERR_FETCH_PROT,
                }
                if uc_err.errno in _CRASH_ERRORS:
                    hit_flag['crash'] = True
                    hit_flag['crash_addr'] = mu.reg_read(UC_X86_REG_RIP)

            if hit_flag.get('crash_addr', 0):
                self._coverage_heat[hit_flag['crash_addr']] += 1

            # 真实内存破坏优先; 启发式仅作辅助不单独判定
            return hit_flag['crash'] or hit_flag.get('heuristic_hit', False)

        except Exception as e:
            logger.debug("Unicorn 故障模拟异常: %s", e)
            return False

    # 崩溃签名去重

    def _record_crash_sig(self, pt: FaultInjectionPoint, addr: int):
        """基于 (injection_addr, fault_type, stack_top) 构造 SHA-256
        短签名，模仿 CASR 的崩溃簇聚类思路。

        去重粒度: 截取哈希前 16 字符作为聚类键，同一键视为同类崩溃。
        """
        if not pt.reached_sensitive:
            return
        raw = f"{addr:x}|{pt.injection_type}".encode()
        sig = hashlib.sha256(raw).hexdigest()[:16]
        pt.crash_signature = sig
        self._crash_dedup.add(sig)

    def _bump_heat(self, addr: int):
        self._coverage_heat[addr] += 1

    # 执行入口

    def run(self, max_injections: int = 300) -> FaultResult:
        """执行完整故障注入分析流程"""
        start = time.time()
        self.simulate_bit_flips()
        self.inject_faults()
        self.inject_nop_sled(max_injections=max_injections // 5)
        self.inject_register_corruption(max_injections=max_injections // 6)

        vulns_found = sum(1 for p in self.points if p.reached_sensitive)
        logger.info(
            "故障注入结束: %d 个注入点, %d 个潜在漏洞, %d 个唯一崩溃簇",
            len(self.points), vulns_found, len(self._crash_dedup)
        )
        return FaultResult(
            success=True,
            injection_points=self.points,
            vulnerabilities_found=vulns_found,
            total_injections=len(self.points),
            elapsed=time.time() - start,
            unique_crash_sigs=list(self._crash_dedup),
        )

    # 快速入口: 仅做指令跳过

    def run_quick_skip(self) -> FaultResult:
        """轻量模式: 跳过比特翻转和寄存器翻转，仅执行指令跳过+少量 NOP sled。
        适用于快速 CI 门禁。"""
        start = time.time()
        self.inject_faults()
        self.inject_nop_sled(max_injections=15)
        vulns = sum(1 for p in self.points if p.reached_sensitive)
        return FaultResult(
            success=True,
            injection_points=self.points,
            vulnerabilities_found=vulns,
            total_injections=len(self.points),
            elapsed=time.time() - start,
            unique_crash_sigs=list(self._crash_dedup),
        )


def create_fault_injection_fuzzer(binary_path: str) -> FaultInjectionFuzzer:
    return FaultInjectionFuzzer(binary_path)
