"""Bare-metal firmware 仿真器 using Unicorn引擎
Qiling-style rootfs abstraction for OS-less firmware: 文件系统 mappers
系统调用 dispatch tables, peripheral 寄存器 maps loaded JSON profiles"""
import logging, os, struct, time, json
_log = logging.getLogger(__name__)
UNICORN_AVAILABLE = False
try:
    import unicorn
    UNICORN_AVAILABLE = True
except ImportError:
    _log.warning("Unicorn not installed")

class Architecture:
    ARM_CORTEX_M="arm_cortex_m"; ARM_CORTEX_A="arm_cortex_a"; MIPS="mips"; PPC="ppc"; X86="x86"

class MemoryRegionType:
    FLASH="flash"; RAM="ram"; ROM="rom"; MMIO="mmio"; STACK="stack"; PERIPHERAL="peripheral"

class MemoryRegion:
    def __init__(self,addr=0,size=0,type=None,permissions="rw"):
        self.address=addr; self.size=size; self.type=type; self.permissions=permissions

class ExecutionState:
    RUNNING="running"; STOPPED="stopped"; HALTED="halted"; COMPLETED="completed"; ERROR="error"

class ExecutionTrace:
    def __init__(self,pc=0,disassembly=""): self.pc=pc; self.disassembly=disassembly; self.steps=[]

class PeripheralState:
    def __init__(self,name="",base_address=0): self.name=name; self.base_address=base_address; self.registers={}

class FirmwareAnalysisResult:
    def __init__(self,firmware_path=""): self.firmware_path=firmware_path; self.architecture=None; self.findings=[]; self.traces=[]; self.vulnerabilities=[]

class BareMetalEmulator:
    """Bare-metal firmware 仿真 engine backed Unicorn
    实现MMIO读写分发、NVIC中断向量表解析、外设hook注册，以及执行追踪
    不依赖操作系统抽象层 — 直接操作物理地址空间的加载与执行
    
    舍入 2: Qiling-style rootfs abstraction — JSON profiles describe memory
    layouts, peripheral 寄存器 maps, 中断 vector tables. decouples
    hardware 配置 仿真器 core, enabling drop- 支持 for
    new MCU families code changes
    """

    # 配置文件搜索路径 — 按顺序查找固件平台描述文件
    _PROFILE_SEARCH = [".", "profiles", "data/profiles", "/opt/binmind/profiles"]

    def __init__(self,firmware_path="",arch=None):
        self.firmware_path=firmware_path; self.architecture=arch
        self.memory_regions={}; self.peripherals={}
        self.entry_point=0; self.stats={}; self.exceptions=[]
        self.UNICORN_AVAILABLE=UNICORN_AVAILABLE
        self._uc = None
        self._mmio_handlers = {}
        self._trace_log = []
        self._breakpoints = set()
        self._vector_table = {}
        self._syscall_table: dict[int, callable] = {}
        # Qiling风格: rootfs路径 — 固件运行时依赖的虚拟文件系统根目录
        self._rootfs_path: str = ""
        # 文件映射器: 虚拟路径 -> 真实路径或字节数据
        self._fs_map: dict[str, bytes] = {}

    def load_firmware(self,path):
        if not path or ".." in path: raise ValueError("Invalid path")
        self.firmware_path=path
        self._load_static()

    def set_rootfs(self, rootfs_dir: str):
        """指定Qiling风格的rootfs目录。固件内的open/read等syscall将映射到此目录
        例如 打开("配置.bin") 会实际读取 {rootfs}/配置.bin"""
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
            _log.info(f"rootfs loaded: {len(self._fs_map)} files from {rootfs_dir}")

    def register_syscall(self, num: int, handler: callable):
        """注册POSIX风格的syscall处理器
        处理器签名: fn(emu, *args) -> int (返回值，-1表示ENOSYS)"""
        self._syscall_table[num] = handler

    def _dispatch_syscall(self, num: int, args: list) -> int:
        h = self._syscall_table.get(num)
        if h is None:
            _log.debug(f"syscall {num} not implemented (ENOSYS)")
            return -1
        return h(self, *args)

    def load_hw_profile(self, profile_path: str) -> bool:
        """加载JSON格式的硬件平台描述文件
        包含memory_regions, peripherals, vector_table, 系统调用s 四个节
        Qiling框架使用Python脚本配置，这里用JSON实现等价功能"""
        if not os.path.isfile(profile_path):
            for d in self._PROFILE_SEARCH:
                alt = os.path.join(d, os.path.basename(profile_path))
                if os.path.isfile(alt):
                    profile_path = alt
                    break
            else:
                _log.warning(f"HW profile not found: {profile_path}")
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

        _log.info(f"HW profile loaded: {len(self.memory_regions)} regions, "
                  f"{len(self.peripherals)} peripherals")
        return True

    def run(self):
        """执行固件仿真主循环。加载二进制到Unicorn内存空间、配置MMIO区域、
        设置栈指针和入口点，然后启动仿真循环直到遇到断点或异常"""
        if not self.UNICORN_AVAILABLE:
            _log.warning("Unicorn absent; cannot run bare-metal emulation")
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
                    pass  # 可能已经映射过

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
            result.findings.append(f"Emulated {len(self._trace_log)} instructions in {elapsed_us}us")

        except unicorn.UcError as e:
            _log.info(f"Unicorn emulation ended: {e}")
            self.exceptions.append(str(e))
            result.traces = list(self._trace_log)
        except Exception as exc:
            _log.error(f"Bare-metal emulation failed: {exc}")
            self.exceptions.append(str(exc))

        return result

    def _parse_vector_table(self, fw_data: bytes):
        """ARM Cortex-M中断向量表解析
        从固件起始处读取初始SP、复位向量、NMI/HardFault等系统异常向量
        以及外部IRQ向量（偏移0x40开始）"""
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

    # --- 舍入 2: 快照/恢复 — 参考Qiling的ql.保存()/ql.恢复()机制 ---
    # 配合fuzzing循环使用：崩溃后回滚到初始状态，而非重新创建Unicorn实例
    def snapshot(self) -> dict:
        """保存当前仿真状态到可序列化的快照
        包含所有寄存器值、内存区域内容、MMIO状态和trace日志"""
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
        # 快照已映射的可读内存区域 (前64KB)
        for addr, region in list(self.memory_regions.items())[:8]:
            try:
                sz = min(region.size, 65536)
                snap['memory'][addr] = bytes(self._uc.mem_read(addr, sz))
            except Exception:
                pass
        return snap

    def restore(self, snap: dict):
        """从快照恢复仿真状态
        Qiling的restore通过上下文序列化实现；这里直接写回寄存器和内存"""
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
            _log.warning(f"Snapshot restore failed: {e}")
            return False

    # --- Round 2: 执行路径去重 — LibIHT论文中LBR数据的CFG重建思路 ---
    # 硬件分支记录捕获每个taken/-taken分支；我们通过追踪PC序列去重
    # 只保留首次观察到的基本块转移边，构建最小化CFG
    def deduplicate_trace(self) -> list:
        """对执行追踪去重，仅保留首次观察到的(src_pc, dst_pc)转移
        这模拟LBR (Last Branch Record) 的行为 — 硬件只记录分支边，不记录顺序执行的指令"""
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
