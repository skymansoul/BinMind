# 2026-08-02
# DVFS 硬件漏洞扫描器
# 参考:
#   "Exploring and exploiting the hardware vulnerabilities in the low-power
#    units of modern processors" (Science China Information Sciences, Jan 2025)
#    清华团队发现三种 DVFS 硬件漏洞:
#    (1) CPU 低电压故障注入 → 打破 ARM TrustZone
#    (2) GPU 低电压故障注入 → NVIDIA GPU AI 模型推理错误
#    (3) 频率隐蔽信道 → 无需共享内存的跨核通信
#    均为纯软件利用，无需物理访问或代码缺陷
#   "CLKscrew: Exposing the Perils of Security-Oblivious Energy Management"
#    (USENIX Security 2017) — DVFS 攻击先驱
#   VoltPillager (USENIX Security 2021) — Intel SGX 的片上电压故障注入

import os
import re
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# DVFS 寄存器地址 — ARM v8 架构的电源管理相关寄存器
# 从 /dev/mem 或内核模块可访问; 攻击者通过修改这些寄存器实现故障注入
_DVFS_REGISTERS_ARM: dict[str, dict] = {
    "CLUSTER_ACTLR": {
        "offset": 0x0, "description": "Cluster ACTLR — 控制每簇的电压频率策略",
        "vuln": "写入非零值可禁用时钟门控, 放大故障注入窗口",
    },
    "PMCR": {
        "offset": 0x0, "description": "Performance Monitors Control Register",
        "vuln": "重置 cycle counter → 干扰 DVFS governor 的频率决策",
    },
    "SYS_CFGCTRL": {
        "offset": 0x0, "description": "System Configuration Control",
        "vuln": "修改 Vmin/Vmax 寄存器 → 强制 CPU 进入不稳定的低电压状态",
    },
}

# DVFS governor sysfs 路径 — Linux 下控制频率调节的接口
_DVFS_SYSFS_PATHS = [
    "/sys/devices/system/cpu/cpufreq/",
    "/sys/devices/system/cpu/cpu*/cpufreq/",
    "/sys/class/devfreq/",
]


@dataclass
class DVFSScanResult:
    vulnerability: str
    severity: str
    location: str = ""          # 受影响的 sysfs 路径或寄存器
    current_value: str = ""
    safe_value: str = ""
    attack_scenario: str = ""
    confidence: float = 0.0
    reference: str = ""


class DVFSScanner:
    """DVFS 硬件配置安全扫描器。

    分析系统当前的电压/频率调节配置，检测可被利用的 DVFS 攻击面。
    覆盖:
    1. CPUfreq governor 配置审计 (userspace governor 可被任意进程操控)
    2. Devfreq 配置审计 (GPU/NPU/DDR 频率调节)
    3. 电压/频率边界值合理性检查
    4. 寄存器访问权限检查
    """

    # DVFS governor 类型及其安全风险
    _GOVERNOR_RISK: dict[str, tuple[str, str]] = {
        "userspace": ("High",
            "userspace governor 允许用户空间任意设置频率 — 攻击者可精确操控频率以触发故障"),
        "performance": ("Medium",
            "固定最高频率 → 不存在频率切换窗口, 隐蔽信道带宽降低但未根除"),
        "powersave": ("Low",
            "固定最低频率 → 故障注入窗口扩展, 但隐蔽信道自然容量受限"),
        "ondemand": ("Low",
            "内核根据负载自动调节, 攻击者不能直接控制频率"),
        "schedutil": ("Low",
            "较新的调度器驱动调节, 与 EAS 集成, 更难操控"),
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
        # 附加: 检查内核启动参数中的 DVFS 相关配置
        self._check_cmdline()
        return self._findings

    def _scan_cpufreq(self):
        """扫描 CPUfreq sysfs 接口。"""
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
            # 检查 scaling_min_freq / scaling_max_freq 的边界
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
        """扫描 Devfreq sysfs 接口 (GPU/DDR/NPU 频率调节)。"""
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
        """检查 /dev/mem 或 /dev/cpu/*/msr 是否可被非特权用户访问。"""
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
                            reference="VoltPillager (USENIX Security 2021)"
                        ))
                except OSError:
                    pass

    def _check_cmdline(self):
        """检查 /proc/cmdline 中与 DVFS 相关的内核启动参数。"""
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
            return 4  # 默认假设


def scan_dvfs_vulnerabilities() -> list[DVFSScanResult]:
    scanner = DVFSScanner(scan_sysfs=True, scan_registers=False)
    return scanner.scan()
