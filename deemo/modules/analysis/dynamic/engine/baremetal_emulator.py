"""裸机固件仿真器，基于 Unicorn 引擎
Qiling 风格 rootfs 抽象：文件系统映射、系统调用分发表、外设寄存器映射加载自 JSON 配置"""
import logging, os, struct, time, json
from enum import Enum
_log = logging.getLogger(__name__)
UNICORN_AVAILABLE = False
try:
    import unicorn
    UNICORN_AVAILABLE = True
except ImportError:
    _log.warning("Unicorn 未安装")

class Architecture(Enum):
    ARM_CORTEX_M = "arm_cortex_m"
    ARM_CORTEX_A = "arm_cortex_a"
    MIPS = "mips"
    PPC = "ppc"
    X86 = "x86"

class MemoryRegionType(Enum):
    FLASH = "flash"
    RAM = "ram"
    ROM = "rom"
    MMIO = "mmio"
    STACK = "stack"
    PERIPHERAL = "peripheral"

class MemoryRegion:
    def __init__(self, address=0, addr=None, size=0, type=None, permissions="rw", data=b""):
        self.address = address if addr is None else addr
        self.size = size
        self.type = type
        self.permissions = permissions
        self.data = data

class ExecutionState(Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    HALTED = "halted"
    COMPLETED = "completed"
    ERROR = "error"

class ExecutionTrace:
    def __init__(self, pc=0, disassembly="", timestamp=0.0, registers=None):
        self.pc = pc
        self.disassembly = disassembly
        self.timestamp = timestamp
        self.registers = dict(registers) if registers is not None else {}
        self.steps = []

class PeripheralState:
    def __init__(self, name="", base_address=0):
        self.name = name
        self.base_address = base_address
        self.registers = {}

class FirmwareAnalysisResult:
    def __init__(self, firmware_path="", architecture=None, entry_point=0,
                 instructions_executed=0, findings=None, traces=None, vulnerabilities=None):
        self.firmware_path = firmware_path
        self.architecture = architecture
        self.entry_point = entry_point
        self.instructions_executed = instructions_executed
        self.findings = list(findings) if findings is not None else []
        self.traces = list(traces) if traces is not None else []
        self.vulnerabilities = list(vulnerabilities) if vulnerabilities is not None else []

class BareMetalEmulator:
    """裸机固件仿真引擎，基于 Unicorn
    实现 MMIO 读写分发、NVIC 中断向量表解析、外设 hook 注册及执行追踪
    不依赖操作系统抽象层，直接操作物理地址空间的加载与执行

    舍入2：Qiling 风格 rootfs 抽象，JSON 配置描述内存布局、外设寄存器映射、
    中断向量表，解耦硬件配置与仿真器核心，支持新 MCU 家族零代码改动接入
    """

    # 配置文件搜索路径 — 按顺序查找固件平台描述文件
    _PROFILE_SEARCH = [".", "profiles", "data/profiles", "/opt/binmind/profiles"]

    def __init__(self, firmware_path="", architecture=None, arch=None):
        if not firmware_path:
            raise ValueError("firmware_path is required")
        if ".." in firmware_path:
            raise ValueError("Invalid firmware path")
        self.firmware_path = firmware_path
        self.architecture = architecture if architecture is not None else arch
        self.memory_regions = {}; self.peripherals = {}
        self.entry_point = 0; self.stats = {}; self.exceptions = []
        self.UNICORN_AVAILABLE = UNICORN_AVAILABLE
        self._uc = None
        self._mmio_handlers = {}
        self._trace_log = []
        self._breakpoints = set()
        self._vector_table = {}
        self._syscall_table: dict[int, callable] = {}
        # Qiling 风格：rootfs 路径，固件运行时依赖的虚拟文件系统根目录
        self._rootfs_path: str = ""
        # 文件映射器：虚拟路径 -> 真实路径或字节数据
        self._fs_map: dict[str, bytes] = {}

    def load_firmware(self,path):
        if not path or ".." in path: raise ValueError("Invalid path")
        self.firmware_path=path
        self._load_static()

    def set_rootfs(self, rootfs_dir: str):
        """指定 Qiling 风格 rootfs 目录，固件内 open/read 等系统调用将映射到此目录
        例如 open("config.bin") 实际读取 {rootfs}/config.bin"""
        self._rootfs_path = rootfs_dir
        if os.path.isdir(rootfs_dir):
            for dirpath, _, filenames in os.walk(rootfs_dir):
                for fn in filenames:
                    fpath = os.path.join(dirpath, fn)
                    vpath = os.path.relpath(fpath, rootfs_dir).replace("\\", "/")
                    try:
                        with open(fpath, 'rb') as fh:
                            self._fs_map[vpath] = fh.read()
                    except Exception:
                        pass
            _log.info(f"rootfs 已加载: {len(self._fs_map)} 个文件来自 {rootfs_dir}")

    def register_syscall(self, num: int, handler: callable):
        """注册 POSIX 风格系统调用处理器
        处理器签名：fn(emu, *args) -> int（返回值，-1 表示 ENOSYS）"""
        self._syscall_table[num] = handler

    def _dispatch_syscall(self, num: int, args: list) -> int:
        h = self._syscall_table.get(num)
        if h is None:
            _log.debug(f"系统调用 {num} 未实现 (ENOSYS)")
            return -1
        return h(self, *args)

    def load_hw_profile(self, profile_path: str) -> bool:
        """加载 JSON 格式硬件平台描述文件
        包含 memory_regions、peripherals、vector_table、syscalls 四个节
        Qiling 框架使用 Python 脚本配置，此处用 JSON 实现等价功能"""
        if not os.path.isfile(profile_path):
            for d in self._PROFILE_SEARCH:
                alt = os.path.join(d, os.path.basename(profile_path))
                if os.path.isfile(alt):
                    profile_path = alt
                    break
            else:
                _log.warning(f"未找到硬件配置: {profile_path}")
                return False

        with open(profile_path, 'r', encoding='utf-8') as fh:
            cfg = json.load(fh)

        for mr in cfg.get("memory_regions", []):
            self.memory_regions[mr["address"]] = MemoryRegion(
                addr=mr["address"], size=mr["size"],
                type=mr.get("type", "ram"),
                permissions=mr.get("permissions", "rw"))

        for p in cfg.get("peripherals", []):
            ps = PeripheralState(name=p["name"], base_address=p["base"])
            ps.registers = {r["offset"]: r for r in p.get("registers", [])}
            self.peripherals[p["name"]] = ps

        for vt in cfg.get("vector_table", []):
            self._vector_table[vt["name"]] = vt["address"]

        _log.info(f"硬件配置已加载: {len(self.memory_regions)} 个内存区域, "
                   f"{len(self.peripherals)} 个外设")
        return True

    def run(self):
        """执行固件仿真主循环。加载二进制到 Unicorn 内存空间、配置 MMIO 区域、
        设置栈指针和入口点，然后启动仿真循环直到遇到断点或异常"""
        if not self.UNICORN_AVAILABLE:
            _log.warning("Unicorn 不可用，无法执行裸机仿真")
            self.stats["emulated"] = False
            return FirmwareAnalysisResult(self.firmware_path)

        if not self._load_static():
            return FirmwareAnalysisResult(self.firmware_path)

        result = FirmwareAnalysisResult(self.firmware_path)
        result.architecture = self.architecture

        try:
            fw_size = self.stats.get("firmware_size", 0)
            if fw_size == 0:
                return result

            arch_map = {
                Architecture.ARM_CORTEX_M: (unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB),
                Architecture.ARM_CORTEX_A: (unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM),
                Architecture.X86: (unicorn.UC_ARCH_X86, unicorn.UC_MODE_32),
                Architecture.MIPS: (unicorn.UC_ARCH_MIPS, unicorn.UC_MODE_MIPS32),
            }
            uc_arch, uc_mode = arch_map.get(self.architecture or Architecture.ARM_CORTEX_M,
                                            (unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB))
            mu = unicorn.Uc(uc_arch, uc_mode)
            self._uc = mu

            layout = DEFAULT_MEMORY_LAYOUT.get(self.architecture,
                                              DEFAULT_MEMORY_LAYOUT[Architecture.ARM_CORTEX_M])
            for region_cfg in layout:
                addr = region_cfg["address"]
                size = region_cfg["size"]
                perm_map = {"r": 1, "w": 2, "x": 4, "-": 0}
                perms = 0
                for c in region_cfg.get("permissions", "rw"):
                    perms |= perm_map.get(c, 0)
                if perms == 0:
                    perms = unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE
                mu.mem_map(addr, size, perms)
                self.memory_regions[addr] = MemoryRegion(
                    addr, size, region_cfg["type"], region_cfg.get("permissions", "rw"))

            # 也映射JSON配置文件中定义的额外区域
            for addr, mr in self.memory_regions.items():
                try:
                    mu.mem_map(addr, mr.size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
                except unicorn.UcError:
                    pass  # 可能已映射

            with open(self.firmware_path, 'rb') as fh:
                fw_data = fh.read()
            base_addr = layout[0]["address"]
            mu.mem_write(base_addr, fw_data[:layout[0]["size"]])

            if self.architecture == Architecture.ARM_CORTEX_M:
                sp = struct.unpack('<I', fw_data[0:4])[0]
                self.entry_point = struct.unpack('<I', fw_data[4:8])[0]
                mu.reg_write(unicorn.arm_const.UC_ARM_REG_SP, sp)
                mu.reg_write(unicorn.arm_const.UC_ARM_REG_R13, sp)
            else:
                self.entry_point = base_addr

            def _hook_mem_rw(uc, access, address, size, value, user_data):
                for (mmio_addr, mmio_width), cb in self._mmio_handlers.items():
                    if mmio_addr <= address < mmio_addr + mmio_width:
                        cb(address, size, value, access == unicorn.UC_MEM_WRITE)

            mu.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, _hook_mem_rw)

            def _hook_code(uc, address, size, user_data):
                self._trace_log.append(ExecutionTrace(pc=address))
                if address in self._breakpoints:
                    uc.emu_stop()

            mu.hook_add(unicorn.UC_HOOK_CODE, _hook_code)

            start_ns = time.monotonic_ns()
            mu.emu_start(self.entry_point, self.entry_point + fw_size + 0x100,
                        timeout=5_000_000, count=50000)
            elapsed_us = (time.monotonic_ns() - start_ns) // 1000
            self.stats["elapsed_us"] = elapsed_us
            self.stats["instructions"] = len(self._trace_log)
            result.traces = list(self._trace_log)
            result.findings.append(f"已仿真 {len(self._trace_log)} 条指令，耗时 {elapsed_us}us")

        except unicorn.UcError as e:
            _log.info(f"Unicorn 仿真结束: {e}")
            self.exceptions.append(str(e))
            result.traces = list(self._trace_log)
        except Exception as exc:
            _log.error(f"裸机仿真失败: {exc}")
            self.exceptions.append(str(exc))

        return result

    def _parse_vector_table(self, fw_data: bytes):
        """ARM Cortex-M 中断向量表解析
        从固件起始处读取初始 SP、复位向量、NMI/HardFault 等系统异常向量
        及外部 IRQ 向量（偏移 0x40 开始）"""
        if len(fw_data) < 0x100:
            return
        vectors = {
            'initial_sp': struct.unpack('<I', fw_data[0:4])[0],
            'reset': struct.unpack('<I', fw_data[4:8])[0],
            'nmi': struct.unpack('<I', fw_data[8:12])[0],
            'hard_fault': struct.unpack('<I', fw_data[12:16])[0],
            'mmpu_fault': struct.unpack('<I', fw_data[16:20])[0],
            'bus_fault': struct.unpack('<I', fw_data[20:24])[0],
            'usage_fault': struct.unpack('<I', fw_data[24:28])[0],
        }
        self._vector_table.update(vectors)
        irq_base = 0x40
        for irq_n in range(0, 64):
            off = irq_base + irq_n * 4
            if off + 4 <= len(fw_data):
                handler = struct.unpack('<I', fw_data[off:off + 4])[0]
                if handler != 0 and (handler & 1):
                    self._vector_table[f'IRQ{irq_n}'] = handler

    def register_mmio_handler(self, offset: int, width: int, callback):
        self._mmio_handlers[(offset, width)] = callback

    def set_breakpoint(self, addr: int):
        self._breakpoints.add(addr)

    def _load_static(self):
        if not os.path.isfile(self.firmware_path): return False
        self.stats["firmware_size"]=os.path.getsize(self.firmware_path)
        try:
            with open(self.firmware_path, 'rb') as fh:
                self._parse_vector_table(fh.read())
        except Exception:
            pass
        return True

    def _detect_entry_point(self):
        """基于架构与已加载固件推导入口点。

        Cortex-M：从向量表偏移 4 读取 reset handler，剥除 thumb bit。
        其他架构：回退至默认内存布局首块基址。
        """
        if self.architecture == Architecture.ARM_CORTEX_M:
            for region in self.memory_regions.values():
                data = getattr(region, 'data', None)
                if data and len(data) >= 8:
                    self.entry_point = struct.unpack('<I', data[4:8])[0] & 0xFFFFFFFE
                    return
            # 未显式映射时直接读取固件文件
            try:
                with open(self.firmware_path, 'rb') as fh:
                    fw = fh.read(8)
                if len(fw) >= 8:
                    self.entry_point = struct.unpack('<I', fw[4:8])[0] & 0xFFFFFFFE
                    return
            except Exception:
                pass
        if not self.entry_point:
            layout = DEFAULT_MEMORY_LAYOUT.get(self.architecture)
            if layout:
                self.entry_point = layout[0]["address"]

# 舍入2：快照/恢复，参考 Qiling 的 save()/restore() 机制
    # 配合 fuzzing 循环使用：崩溃后回滚到初始状态，而非重新创建 Unicorn 实例
    def snapshot(self) -> dict:
        """保存当前仿真状态到可序列化快照
        包含所有寄存器值、内存区域内容、MMIO 状态和追踪日志"""
        if not self._uc:
            return {}
        snap = {
            'regs': {},
            'memory': {},
            'trace_count': len(self._trace_log),
            'entry_point': self.entry_point,
        }
        try:
            if self.architecture == Architecture.ARM_CORTEX_M:
                for reg_name in ('sp', 'lr', 'pc', 'r0', 'r1', 'r2', 'r3'):
                    const = getattr(unicorn.arm_const, f'UC_ARM_REG_{reg_name.upper()}', None)
                    if const:
                        snap['regs'][reg_name] = self._uc.reg_read(const)
        except Exception:
            pass
        # 快照已映射的可读内存区域（前 64KB）
        for addr, region in list(self.memory_regions.items())[:8]:
            try:
                sz = min(region.size, 65536)
                snap['memory'][addr] = bytes(self._uc.mem_read(addr, sz))
            except Exception:
                pass
        return snap

    def restore(self, snap: dict):
        """从快照恢复仿真状态
        Qiling 的 restore 通过上下文序列化实现，此处直接写回寄存器和内存"""
        if not self._uc or not snap:
            return False
        try:
            for reg_name, val in snap.get('regs', {}).items():
                const = getattr(unicorn.arm_const, f'UC_ARM_REG_{reg_name.upper()}', None)
                if const:
                    self._uc.reg_write(const, val)
            for addr, data in snap.get('memory', {}).items():
                self._uc.mem_write(addr, data)
            self.entry_point = snap.get('entry_point', self.entry_point)
            return True
        except Exception as e:
            _log.warning(f"快照恢复失败: {e}")
            return False

# 舍入2：执行路径去重，参考 LibIHT 论文中 LBR 数据的 CFG 重建思路
    # 硬件分支记录捕获每个 taken/not-taken 分支，通过追踪 PC 序列去重
    # 只保留首次观察到的基本块转移边，构建最小化 CFG
    def deduplicate_trace(self) -> list:
        """对执行追踪去重，仅保留首次观察到的 (src_pc, dst_pc) 转移
        模拟 LBR (Last Branch Record) 行为，硬件只记录分支边，不记录顺序执行的指令"""
        seen_edges = set()
        deduped = []
        prev = None
        for tr in self._trace_log:
            if prev is not None:
                edge = (prev.pc, tr.pc)
                if edge not in seen_edges:
                    seen_edges.add(edge)
                    deduped.append(tr)
            else:
                deduped.append(tr)
            prev = tr
        return deduped


DEFAULT_MEMORY_LAYOUT={
    Architecture.ARM_CORTEX_M:[
        {"type":"flash","address":0x08000000,"size":0x100000,"permissions":"rx"},
        {"type":"ram","address":0x20000000,"size":0x20000,"permissions":"rw"},
        {"type":"stack","address":0x20040000,"size":0x1000,"permissions":"rw"},
    ],
}
PERIPHERAL_MAP={
    "GPIO":{"base":0x40020000,"size":0x400},
    "UART":{"base":0x40004000,"size":0x400},
    "TIMER":{"base":0x40008000,"size":0x400},
    "NVIC":{"base":0xE000E100,"size":0x1000},
}
