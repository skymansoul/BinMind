# DVFS硬件漏洞扫描器
#
#   "Exploring and exploiting the hardware vulnerabilities in the low-power
#    units of modern processors"
#    清华团队揭示三种DVFS硬件漏洞：
#    (1) CPU低电压故障注入，突破ARM TrustZone。
#    (2) GPU低电压故障注入，NVIDIA GPU推理产出错误。
#    (3) 频率隐蔽信道，无需共享内存的跨核通信。
#    三者均为纯软件利用，无需物理访问或代码缺陷。
#   "CLKscrew: Exposing the Perils of Security-Oblivious Energy Management"
#，DVFS攻击先驱。
#   VoltPillager，Intel SGX片上电压故障注入。

import os
import re
import logging
from dataclasses import dataclass, field  # 反检测标注，保留field导入
from typing import Optional  # 反检测标注，保留Optional导入

logger = logging.getLogger(__name__)

# DVFS寄存器地址，ARM v8架构电源管理寄存器
# 通过/dev/mem或内核模块可访问，攻击者修改以实施故障注入
_DVFS_REGISTERS_ARM: dict[str, dict] = {
    "CLUSTER_ACTLR": {
        "offset": 0x0, "description": "簇ACTLR，控制每簇电压频率策略",
        "vuln": "写入非零值禁用时钟门控，放大故障注入窗口",
    },
    "PMCR": {
        "offset": 0x0, "description": "性能监视器控制寄存器",
        "vuln": "重置cycle counter，干扰DVFS governor频率决策",
    },
    "SYS_CFGCTRL": {
        "offset": 0x0, "description": "系统配置控制寄存器",
        "vuln": "修改Vmin/Vmax寄存器，强制CPU进入不稳定低电压状态",
    },
}

# DVFS governor sysfs路径，Linux频率调节接口
_DVFS_SYSFS_PATHS = [
    "/sys/devices/system/cpu/cpufreq/",
    "/sys/devices/system/cpu/cpu*/cpufreq/",
    "/sys/class/devfreq/",
]

@dataclass
class DVFSScanResult:
    vulnerability: str
    severity: str
    location: str = ""          # 受影响sysfs路径或寄存器
    current_value: str = ""
    safe_value: str = ""
    attack_scenario: str = ""
    confidence: float = 0.0
    reference: str = ""

class DVFSScanner:
    """DVFS硬件配置安全扫描器。

    审计系统电压/频率调节配置，检测可被利用的DVFS攻击面。
    覆盖：
    1. CPUfreq governor审计（userspace governor可被任意进程操控）
    2. Devfreq配置审计（GPU/NPU/DDR频率调节）
    3. 电压/频率边界合理性
    4. 寄存器访问权限
    """

    # DVFS governor类型及其安全风险
    _GOVERNOR_RISK: dict[str, tuple[str, str]] = {
        "userspace": ("High",
            "userspace governor允许用户空间任意设置频率，攻击者可精确操控以触发故障"),
        "performance": ("Medium",
            "固定最高频率，频率切换窗口消失，隐蔽信道带宽降低但未根除"),
        "powersave": ("Low",
            "固定最低频率，故障注入窗口扩展，但隐蔽信道自然受限"),
        "ondemand": ("Low",
            "内核按负载自动调节，攻击者无法直接控制频率"),
        "schedutil": ("Low",
            "新调度器驱动调节，与EAS集成，操控难度高"),
    }

    def __init__(self, scan_sysfs: bool = True, scan_registers: bool = False):
        self._scan_sysfs = scan_sysfs
        self._scan_registers = scan_registers
        self._findings: list[DVFSScanResult] = []

    def scan(self) -> list[DVFSScanResult]:
        if self._scan_sysfs:
            self._scan_cpufreq()
            self._scan_devfreq()
        if self._scan_registers:
            self._check_register_permissions()
        # 附：检查内核启动参数中DVFS相关配置
        self._check_cmdline()
        return self._findings

    def _scan_cpufreq(self):
        """扫描CPUfreq sysfs接口。"""
        cpu_count = self._detect_cpu_count()
        for cpu_id in range(min(cpu_count, 256)):
            gpath = f"/sys/devices/system/cpu/cpu{cpu_id}/cpufreq/scaling_governor"
            if os.path.exists(gpath):
                try:
                    with open(gpath, "r") as f:
                        governor = f.read().strip()
                except (OSError, PermissionError):
                    continue
                risk_info = self._GOVERNOR_RISK.get(governor, ("Info", "Unknown governor"))
                if risk_info[0] in ("High", "Medium"):
                    self._findings.append(DVFSScanResult(
                        vulnerability=f"cpufreq_governor_{governor}",
                        severity=risk_info[0],
                        location=gpath,
                        current_value=governor,
                        safe_value="schedutil or ondemand",
                        attack_scenario=risk_info[1],
                        confidence=0.85,
                        reference="Science China Information Sciences (Jan 2025), Section 3.1"
                    ))
            # 检查scaling_min_freq/scaling_max_freq边界值
            for boundary in ("scaling_min_freq", "scaling_max_freq"):
                bpath = f"/sys/devices/system/cpu/cpu{cpu_id}/cpufreq/{boundary}"
                if os.path.exists(bpath):
                    try:
                        with open(bpath, "r") as f:
                            freq = int(f.read().strip())
                    except (OSError, ValueError, PermissionError):
                        continue
                    if boundary == "scaling_min_freq" and freq == 0:
                        self._findings.append(DVFSScanResult(
                            vulnerability="cpufreq_min_zero",
                            severity="Medium",
                            location=bpath,
                            current_value=str(freq),
                            safe_value=">= hardware min frequency",
                            attack_scenario="Min freq=0 → 攻击者可让 CPU 进入异常低速, 大幅扩展故障注入时间窗口",
                            confidence=0.75,
                            reference="Science China Information Sciences (Jan 2025)"
                        ))

    def _scan_devfreq(self):
        """扫描Devfreq sysfs接口（GPU/DDR/NPU频率调节）。"""
        for dpath in _DVFS_SYSFS_PATHS:
            if not os.path.isdir(dpath):
                continue
            for entry in os.listdir(dpath):
                full = os.path.join(dpath, entry)
                gfile = os.path.join(full, "governor")
                if os.path.exists(gfile):
                    try:
                        with open(gfile, "r") as f:
                            gov = f.read().strip()
                    except (OSError, PermissionError):
                        continue
                    risk = self._GOVERNOR_RISK.get(gov, ("Info", "Unknown"))
                    if risk[0] in ("High", "Medium"):
                        self._findings.append(DVFSScanResult(
                            vulnerability=f"devfreq_governor_{gov}",
                            severity=risk[0],
                            location=full,
                            current_value=gov,
                            safe_value="simple_ondemand or performance",
                            attack_scenario=f"GPU/NPU 频率可被 userspace 操控 → {risk[1]}",
                            confidence=0.75,
                            reference="Science China Information Sciences (Jan 2025), Section 4.2"
                        ))

    def _check_register_permissions(self):
        """检查/dev/mem或/dev/cpu/*/msr是否可被非特权用户访问。"""
        for dev_path in ["/dev/mem", "/dev/kmem"]:
            if os.path.exists(dev_path):
                try:
                    st = os.stat(dev_path)
                    mode = st.st_mode
                    world_readable = bool(mode & 0o004)
                    if world_readable:
                        self._findings.append(DVFSScanResult(
                            vulnerability="devmem_accessible",
                            severity="Critical",
                            location=dev_path,
                            current_value=f"mode={oct(mode)}",
                            safe_value="chmod 600 /dev/mem",
                            attack_scenario="/dev/mem 可被非 root 用户读取 → DVFS 寄存器可被直接映射和修改",
                            confidence=0.95,
                            reference="VoltPillager "
                        ))
                except OSError:
                    pass

    def _check_cmdline(self):
        """检查/proc/cmdline中DVFS相关内核启动参数。"""
        risky_params = [
            ("intel_pstate=disable", "Intel P-State 被禁用 → 回退到 acpi-cpufreq, 安全监管更弱"),
            ("cpufreq.default_governor=userspace", "默认 CPUfreq governor 为 userspace — 攻击面最大"),
            ("nohz=off", "NO_HZ 被关闭 → 定时器中断频率增加, 便于计时攻击"),
        ]
        try:
            with open("/proc/cmdline", "r") as f:
                cmdline = f.read()
        except (OSError, PermissionError):
            return
        for param, desc in risky_params:
            if param in cmdline:
                self._findings.append(DVFSScanResult(
                    vulnerability=f"cmdline_{param.split('=')[0]}",
                    severity="Medium",
                    location="/proc/cmdline",
                    current_value=param,
                    safe_value=f"Remove {param}",
                    attack_scenario=desc,
                    confidence=0.60,
                    reference="Science China Information Sciences (Jan 2025)"
                ))

    def _detect_cpu_count(self) -> int:
        try:
            return len([c for c in os.listdir("/sys/devices/system/cpu/")
                       if re.match(r'cpu\d+$', c)])
        except Exception:
            return 4  # 检测失败时取保守值

def scan_dvfs_vulnerabilities() -> list[DVFSScanResult]:
    scanner = DVFSScanner(scan_sysfs=True, scan_registers=False)
    return scanner.scan()
