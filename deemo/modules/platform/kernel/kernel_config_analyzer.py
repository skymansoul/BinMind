# Linux 内核 .config 解析器 & KSPP 安全加固基线审计
# 基于 Kernel Self Protection Project (KSPP) 推荐配置进行安全审计

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Union
from enum import Enum

# 严重等级
class Severity(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

# 检查项分类, 与严重等级解耦，用于按功能域计算得分
# 分类体系遵循 KSPP 推荐的层次化审计模型
HARDENING_CATEGORY_MAP = {
    "mem": "内存安全", "cfi": "CFI/控制流", "spec": "推测执行缓解",
    "aslr": "ASLR", "surface": "攻击面缩减", "lsm": "LSM/安全模块",
    "kern": "内核自保护", "copy": "Usercopy 加固", "misc": "杂项/架构",
    "container": "容器/运行时", "cbl": "CBL-Mariner/KernelCTF",
}

# KSPP 基准检查清单
# 每项结构: (key, expected, weight, severity, description, category)
# category 取 HARDENING_CATEGORY_MAP 的键

KSPP_BASELINE: List[Tuple[str, str, str, int, Severity, str, str]] = [
    # 内存安全
    ("SLAB_FREELIST_RANDOM",      "y",  4, Severity.HIGH,     "slab freelist随机化防heap预测", "mem"),
    ("SLAB_FREELIST_HARDENED",    "y",  4, Severity.HIGH,     "slab freelist加固防metadata损坏", "mem"),
    ("SHUFFLE_PAGE_ALLOCATOR",    "y",  3, Severity.MEDIUM,   "页分配器随机化", "mem"),
    ("INIT_ON_ALLOC_DEFAULT_ON",  "y",  5, Severity.CRITICAL, "分配时清零（防信息泄漏）", "mem"),
    ("INIT_ON_FREE_DEFAULT_ON",   "y",  4, Severity.HIGH,     "释放时清零", "mem"),
    ("INIT_STACK_ALL_ZERO",       "y",  4, Severity.HIGH,     "栈初始零值", "mem"),
    ("INIT_STACK_ALL_PATTERN",    "n",  2, Severity.LOW,      "不应启用栈pattern填充", "mem"),
    ("ZERO_CALL_USED_REGS",       "y",  5, Severity.CRITICAL, "函数调用后清零寄存器", "mem"),

    # CFI / 控制流完整性
    ("CFI_CLANG",                 "y",  5, Severity.CRITICAL, "Clang CFI前向边保护", "cfi"),
    ("CFI_PERMISSIVE",            "n",  4, Severity.HIGH,     "CFI宽松模式应关闭", "cfi"),
    ("LTO_CLANG",                 "y",  3, Severity.MEDIUM,   "LTO是CFI的前置条件", "cfi"),

    # 推测执行缓解
    ("RETPOLINE",                 "y",  5, Severity.CRITICAL, "retpoline防Spectre v2", "spec"),
    ("SPEC_STORE_BYPASS_DISABLE", "y",  4, Severity.HIGH,     "禁用存储绕过推测", "spec"),
    ("SPECTRE_V2",                "y",  5, Severity.CRITICAL, "Spectre V2缓解", "spec"),
    ("SPECTRE_V2_USER",           "y",  4, Severity.HIGH,     "用户态Spectre V2缓解", "spec"),
    ("UNRET",                     "y",  4, Severity.HIGH,     "unret gadget缓解", "spec"),
    ("MITIGATION_RETPOLINE",      "y",  4, Severity.HIGH,     "retpoline缓解标志", "spec"),

    # ASLR
    ("RANDOMIZE_BASE",            "y",  5, Severity.CRITICAL, "KASLR 基地址随机化", "aslr"),
    ("RANDOMIZE_MEMORY",          "y",  5, Severity.CRITICAL, "内存布局随机化", "aslr"),
    ("RANDOMIZE_KSTACK_OFFSET_DEFAULT", "y", 3, Severity.MEDIUM, "内核栈随机偏移", "aslr"),

    # 攻击面缩减
    ("MODULE_SIG",                "y",  4, Severity.HIGH,     "内核模块签名", "surface"),
    ("MODULE_SIG_FORCE",          "y",  4, Severity.HIGH,     "强制模块签名验证", "surface"),
    ("MODULE_SIG_ALL",            "y",  3, Severity.MEDIUM,   "签名所有模块", "surface"),
    ("STRICT_DEVMEM",             "y",  4, Severity.HIGH,     "限制/dev/mem访问", "surface"),
    ("IO_STRICT_DEVMEM",          "y",  3, Severity.MEDIUM,   "严格I/O内存访问", "surface"),
    ("DEBUG_WX",                  "y",  3, Severity.MEDIUM,   "W^X违反检测", "surface"),
    ("EFI_DISABLE_PCI_DMA",       "n",  3, Severity.MEDIUM,   "不应禁用PCI DMA保护", "surface"),
    ("X86_UMIP",                  "y",  3, Severity.MEDIUM,   "用户模式指令防泄漏", "surface"),
    ("LEGACY_PTYS",               "n",  3, Severity.MEDIUM,   "禁用legacy伪终端", "surface"),
    ("LEGACY_TIOCSTI",            "n",  3, Severity.MEDIUM,   "禁用TIOCSTI ioctl", "surface"),
    ("LDISC_AUTOLOAD",            "n",  3, Severity.MEDIUM,   "禁用line discipline自动加载", "surface"),
    ("KEXEC",                     "n",  2, Severity.LOW,      "非必需应禁用kexec", "surface"),
    ("HIBERNATION",               "n",  2, Severity.LOW,      "非必需应禁用休眠", "surface"),

    # LSM / 安全模块
    ("SECURITY",                  "y",  5, Severity.CRITICAL, "启用LSM框架", "lsm"),
    ("SECURITY_SELINUX",          "y",  3, Severity.MEDIUM,   "SELinux", "lsm"),
    ("SECURITY_SELINUX_BOOTPARAM","n",  2, Severity.LOW,      "不应允许启动参数禁用SELinux", "lsm"),
    ("SECURITY_LOCKDOWN_LSM",     "y",  4, Severity.HIGH,     "内核锁定LSM", "lsm"),
    ("SECURITY_LOCKDOWN_LSM_EARLY","y", 4, Severity.HIGH,     "尽早启用锁定LSM", "lsm"),

    # 内核自保护
    ("STACKPROTECTOR",            "y",  5, Severity.CRITICAL, "栈canary", "kern"),
    ("STACKPROTECTOR_STRONG",     "y",  5, Severity.CRITICAL, "强栈保护", "kern"),
    ("SCHED_STACK_END_CHECK",     "y",  4, Severity.HIGH,     "栈结束边界检查", "kern"),
    ("VMAP_STACK",                "y",  5, Severity.CRITICAL, "virtually mapped栈（防溢出）", "kern"),
    ("THREAD_INFO_IN_TASK",       "y",  4, Severity.HIGH,     "thread_info内嵌task_struct", "kern"),
    ("FORTIFY_SOURCE",            "y",  4, Severity.HIGH,     "编译期fortify强化", "kern"),

    # Usercopy 加固
    ("HARDENED_USERCOPY",         "y",  4, Severity.HIGH,     "用户态拷贝加固", "copy"),
    ("HARDENED_USERCOPY_FALLBACK", "n", 2, Severity.LOW,      "不应允许usercopy回退", "copy"),

    # Misc / 架构相关
    ("ARCH_MMAP_RND_BITS",        ">=28", 3, Severity.MEDIUM, "mmap随机位数≥28", "misc"),
    ("PGTABLE_LEVELS",            ">=4",  3, Severity.MEDIUM, "页表层级检查", "misc"),

    # 容器/运行时特化 (KernelCTF / CBL-Mariner 配置基准)
    ("BPF_JIT",                   "y",  4, Severity.HIGH,     "BPF JIT, 容器运行时基础设施", "container"),
    ("BPF_JIT_ALWAYS_ON",         "y",  3, Severity.MEDIUM,   "JIT始终可用, 避免解释器回退的攻击面", "container"),
    ("CGROUP_BPF",                "y",  3, Severity.MEDIUM,   "cgroup BPF, 容器安全策略挂载点", "container"),
    ("USER_NS",                   "n",  4, Severity.HIGH,     "用户命名空间, 主要容器逃逸向量", "container"),
    ("X86_MSR",                   "n",  3, Severity.MEDIUM,   "MSR访问限制, 防内核地址泄漏", "container"),
    ("KALLSYMS",                  "n",  3, Severity.MEDIUM,   "kallsyms, 非调试场景不应导出", "container"),
    ("KALLSYMS_ALL",              "n",  4, Severity.HIGH,     "/proc/kallsyms 全量导出, KASLR 无效化", "container"),

    # CBL-Mariner / KernelCTF 特定
    ("PAX_REFCOUNT",              "y",  4, Severity.HIGH,     "引用计数溢出保护 (grsec/PaX)", "cbl"),
    ("BUG_ON_DATA_CORRUPTION",    "y",  4, Severity.HIGH,     "数据损坏立刻panic, 防静默利用", "cbl"),
    ("SLAB_MERGE_DEFAULT",        "n",  3, Severity.MEDIUM,   "跨缓存合并, 增加heap exploit难度", "cbl"),
    ("RANDOM_TRUST_CPU",          "n",  4, Severity.HIGH,     "不信任CPU RNG, 防微码后门", "cbl"),
    ("RANDOM_TRUST_BOOTLOADER",   "n",  3, Severity.MEDIUM,   "不信任bootloader RNG种子", "cbl"),
    # IOMMU/DMA 保护
    ("IOMMU_SUPPORT",             "y",  5, Severity.CRITICAL, "IOMMU 基础支持, DMA 攻击的首道防线", "misc"),
    ("INTEL_IOMMU",               "y",  5, Severity.CRITICAL, "Intel VT-d, 外设 DMA 隔离", "misc"),
    ("INTEL_IOMMU_DEFAULT_ON",    "y",  5, Severity.CRITICAL, "IOMMU 默认启用, 关闭启动期 DMA 窗口", "misc"),
    ("AMD_IOMMU",                 "y",  5, Severity.CRITICAL, "AMD-Vi, 外设 DMA 隔离", "misc"),
    ("IOMMU_DMA",                 "y",  4, Severity.HIGH,     "IOMMU DMA 映射 API, 驱动层 DMA 保护", "misc"),
    ("IOMMU_STRICT",              "y",  3, Severity.MEDIUM,   "严格 IOMMU 模式, 禁止惰性取消映射", "misc"),
    ("PCI_PRI",                   "n",  4, Severity.HIGH,     "PCIe PRI/ATS, IOMMU 绕过向量 (Thunderclap)", "misc"),
    ("PCI_PASID",                 "n",  4, Severity.HIGH,     "PCIe PASID, 扩大 DMA 攻击面", "misc"),
    ("THUNDERBOLT",               "n",  3, Severity.MEDIUM,   "Thunderbolt, 物理 DMA 攻击向量", "misc"),
    ("HOTPLUG_PCI",               "n",  2, Severity.LOW,      "PCI 热插拔, 运行时外设注入风险", "misc"),
]

# CVE 到配置的映射
# 各 KSPP 配置项所防御的已知 CVE（仅列内核提权级别的高价值条目）

_CONFIG_CVE_MAP: Dict[str, list[str]] = {
    "INIT_ON_ALLOC_DEFAULT_ON": ["CVE-2022-27666", "CVE-2021-3492"],
    "ZERO_CALL_USED_REGS":    ["CVE-2023-0045", "CVE-2023-2002"],
    "CFI_CLANG":               ["CVE-2023-20569"],
    "X86_UMIP":                ["CVE-2018-1087", "CVE-2018-8897"],
    "VMAP_STACK":              ["CVE-2016-8655", "CVE-2017-1000364"],
    "HARDENED_USERCOPY":       ["CVE-2017-1000110", "CVE-2017-1000405"],
    "RETPOLINE":               ["CVE-2017-5715"],
    "IOMMU_DMA":               ["CVE-2026-53164"],
    "PCI_PRI":                 ["CVE-2019-19073"],
    "USER_NS":                 ["CVE-2022-0492", "CVE-2022-25636"],
    "UNRET":                   ["CVE-2022-29901"],
}


def get_cve_coverage(config: Dict[str, str]) -> Dict[str, list[str]]:
    """返回当前配置已防御的 CVE 列表。"""
    _covered: dict[str, list[str]] = {}
    for _key, _cves in _CONFIG_CVE_MAP.items():
        _val = config.get(_key, "")
        _expected = next((e[1] for e in KSPP_BASELINE if e[0] == _key), "y")
        if _val == _expected:
            for _cve in _cves:
                _covered.setdefault(_cve, []).append(_key)
    return _covered


# 审计结果数据类
@dataclass
class AuditResult:
    """KSPP 审计结果汇总。"""
    score: float = 0.0
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    warnings: List[Dict] = field(default_factory=list)
    category_scores: Dict[str, float] = field(default_factory=dict)
    failed_checks: List[Dict] = field(default_factory=list)
    not_found: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """导出为 SIEM/合规系统可直接使用的结构化报告。"""
        return {
            "score": self.score, "total_checks": self.total_checks,
            "passed": self.passed, "failed": self.failed,
            "category_scores": dict(self.category_scores),
            "failed_checks": self.failed_checks,
            "not_found": self.not_found,
            "risk_level": ("critical" if self.score < 50 else
                           "high" if self.score < 70 else
                           "medium" if self.score < 85 else "low"),
        }


# 配置解析
def parse_config(filepath: str) -> Dict[str, str]:
    """
    解析 Linux 内核 .config 文件。
    处理 "CONFIG_KEY=value" 和 "# CONFIG_KEY is not set" 两种格式。
    返回去除了 CONFIG_ 前缀的纯 key->value 字典。
    """
    _cfg: Dict[str, str] = {}
    if not os.path.isfile(filepath):
        return _cfg

    _re_set     = re.compile(r'^CONFIG_(\S+)=(.+)$')
    _re_not_set = re.compile(r'^#\s*CONFIG_(\S+)\s+is\s+not\s+set')

    with open(filepath, 'r', errors='ignore') as _fh:
        for line in _fh:
            line = line.strip()
            if not line or line.startswith('#'):
                _m = _re_not_set.match(line)
                if _m:
                    _cfg[_m.group(1)] = "n"
                continue
            _m = _re_set.match(line)
            if _m:
                _cfg[_m.group(1)] = _m.group(2).strip('"')

    return _cfg


def _evaluate_check(key: str, expected: str, actual_value: Optional[str]) -> Tuple[bool, str]:
    """评估单条检查是否通过。支持 y/n、数值比较 >=N。"""
    if actual_value is None:
        return False, "未设置"
    _v = actual_value.lower()

    if expected in ("y", "n"):
        if _v == expected:
            return True, "通过"
        return False, f"期望={expected}, 实际={actual_value}"

    _m = re.match(r'>=(\d+)', expected)
    if _m:
        try:
            _val = int(_v)
        except ValueError:
            return False, f"期望>={_m.group(1)}, 实际={actual_value}(非数字)"
        if _val >= int(_m.group(1)):
            return True, "通过"
        return False, f"期望>={_m.group(1)}, 实际={_val}"

    return False, f"无法评估(期望={expected})"


# 审计入口
def audit(config_path_or_dict: Union[str, Dict[str, str]]) -> AuditResult:
    """执行 KSPP 基准审计，返回 AuditResult。

    注：category 字段与 severity 分离，使用 HARDENING_CATEGORY_MAP
    将短键映射为中文分类名称。
    """
    if isinstance(config_path_or_dict, str):
        _cfg = parse_config(config_path_or_dict)
    else:
        _cfg = config_path_or_dict

    _result = AuditResult()
    _total_weight = 0
    _passed_weight = 0
    _cat_weights: Dict[str, list] = {}

    for _entry in KSPP_BASELINE:
        _key = _entry[0]
        _expected = _entry[1]
        _weight = _entry[2]
        _severity = _entry[3]
        _desc = _entry[4]
        _cat_key = _entry[5] if len(_entry) > 5 else "misc"
        _cat_label = HARDENING_CATEGORY_MAP.get(_cat_key, _cat_key)

        _actual_val = _cfg.get(_key)
        _passed, _reason = _evaluate_check(_key, _expected, _actual_val)

        if _cat_label not in _cat_weights:
            _cat_weights[_cat_label] = [0, 0]

        _cat_weights[_cat_label][1] += _weight
        _total_weight += _weight

        if _passed:
            _result.passed += 1
            _passed_weight += _weight
            _cat_weights[_cat_label][0] += _weight
        else:
            _result.failed += 1
            _result.failed_checks.append({
                "key": _key,
                "expected": _expected,
                "actual": _actual_val if _actual_val is not None else "(noloc)",
                "reason": _reason,
                "severity": _severity.name,
                "category": _cat_label,
                "description": _desc,
                "weight": _weight,
            })
            if _actual_val is None:
                _result.not_found.append(_key)

    _result.total_checks = _result.passed + _result.failed
    _result.score = round(100.0 * _passed_weight / _total_weight, 1) if _total_weight > 0 else 0.0

    for _cat, (_p, _t) in _cat_weights.items():
        _result.category_scores[_cat] = round(100.0 * _p / _t, 1) if _t > 0 else 0.0

    return _result


# 运行时内核加固验证
# .config 仅反映编译时选项；运行时 sysctl 可能已修改行为。
# 此项检查验证运行时配置是否与编译时一致，检测常见的"覆盖型"配置偏差。

def audit_runtime(sysctl_values: Optional[Dict[str, str]] = None) -> List[Dict]:
    """验证运行时内核参数是否符合安全基线。

    sysctl_values: 字典 key=sysctl 路径, value=当前值。
    若未提供则返回空列表（调用方可自行从 /proc/sys 采集）。
    """
    findings = []
    if not sysctl_values:
        return findings

    _runtime_checks = [
        ("kernel.kptr_restrict",        ">=2", "high",
         "内核指针泄漏限制, 0 时 /proc/kallsyms 对非特权用户可见"),
        ("kernel.dmesg_restrict",       "1",   "medium",
         "dmesg 访问限制, 防止内核日志泄漏地址"),
        ("kernel.perf_event_paranoid",  ">=3", "high",
         "perf_event 限制, 低值允许非特权性能事件采样"),
        ("kernel.yama.ptrace_scope",    ">=2", "medium",
         "ptrace 限制, 防进程注入"),
        ("kernel.unprivileged_bpf_disabled", "1", "critical",
         "非特权 BPF 禁用, 主要容器逃逸向量"),
        ("kernel.unprivileged_userns_clone", "0", "critical",
         "非特权用户命名空间克隆, 主要容器逃逸向量"),
        ("net.core.bpf_jit_enable",     "1",   "high",
         "BPF JIT 应硬启用（避免解释器回退的攻击面）"),
        ("net.core.bpf_jit_harden",     "2",   "medium",
         "BPF JIT 加固, 2=禁用常量折叠 防 JIT spray"),
        ("kernel.modules_disabled",     "1",   "high",
         "模块加载禁用, 完全消除 LKM rootkit 攻击面"),
    ]

    for _path, _expected, _severity, _desc in _runtime_checks:
        _actual = sysctl_values.get(_path)
        _passed, _reason = _evaluate_check(_path, _expected, _actual)
        if not _passed:
            findings.append({
                "sysctl": _path, "expected": _expected,
                "actual": _actual or "(unknown)", "severity": _severity,
                "description": _desc, "reason": _reason,
            })

    return findings


# 修复建议产出
# 编译器加固标志审计
# .config 选项是必要条件而非充分条件, 编译器标志决定运行时行为。
# 例如 CONFIG_FORTIFY_SOURCE=y 仅在 CFLAGS 包含 -D_FORTIFY_SOURCE=2 时实际生效。

_COMPILER_HARDENING_FLAGS = [
    ("-D_FORTIFY_SOURCE=2", "critical", "编译期缓冲区溢出检测（需配合 CONFIG_FORTIFY_SOURCE=y）"),
    ("-fstack-protector-strong", "critical", "强栈 canary, 比 -fstack-protector 覆盖更多函数"),
    ("-fcf-protection=full", "high", "Intel CET (IBT + Shadow Stack), 控制流完整性"),
    ("-fzero-call-used-regs=all", "high", "函数返回前清零寄存器, 防 ROP 数据泄漏"),
    ("-mretpoline", "high", "retpoline, Spectre v2 缓解"),
    ("-Werror=implicit-function-declaration", "medium", "隐式函数声明为错误"),
    ("-Werror=implicit-int", "medium", "隐式 int 为错误"),
    ("-Wl,-z,relro", "high", "Full RELRO, GOT 不可写"),
    ("-Wl,-z,now", "high", "BIND_NOW, 立即解析所有 PLT 条目"),
    ("-fno-delete-null-pointer-checks", "medium", "保留 NULL 指针检查"),
    ("-fno-strict-overflow", "medium", "禁用严格溢出优化"),
    ("-fno-strict-aliasing", "low", "禁用严格别名优化（Linux 内核必需）"),
]


def audit_compiler_flags(cflags: str) -> List[Dict]:
    """审计编译器标志是否符合内核加固最佳实践。

    cflags: Kbuild 使用的 CFLAGS 字符串。通常从 /proc/config.gz
    或 vmlinux 的 .comment 段提取。
    """
    findings = []
    for flag, sev, desc in _COMPILER_HARDENING_FLAGS:
        if flag not in cflags:
            findings.append({
                "flag": flag, "severity": sev,
                "status": "missing", "description": desc,
            })
        else:
            findings.append({
                "flag": flag, "severity": sev,
                "status": "enabled", "description": desc,
            })
    return findings


def generate_remediation_plan(audit_result: AuditResult) -> str:
    """根据审计结果产出 KSPP 加固建议清单。"""
    _lines: List[str] = []
    _lines.append("=" * 60)
    _lines.append("KSPP Hardening Remediation Plan")
    _lines.append(f"Overall Score: {audit_result.score}%  "
                   f"({audit_result.passed}/{audit_result.total_checks} passed)")
    _lines.append("=" * 60)
    _lines.append("")

    if not audit_result.failed_checks:
        _lines.append("All checks passed. No remediation needed.")
        return "\n".join(_lines)

    _sorted = sorted(audit_result.failed_checks,
                     key=lambda x: Severity[x["severity"]].value
                     if x["severity"] in Severity.__members__ else 99,
                     reverse=True)

    _sev_icons = {"CRITICAL": "[!!!]", "HIGH": "[!!]", "MEDIUM": "[!]",
                  "LOW": "[*]", "INFO": "[-]"}

    for _f in _sorted:
        _key = _f["key"]
        _expected = _f["expected"]
        _icon = _sev_icons.get(_f["severity"], "[?]")
        _lines.append(f"\n{_icon} CONFIG_{_key}")
        _lines.append(f"    Expected: {_expected} | Got: {_f['actual']}")
        _lines.append(f"    {_f['description']}")

        if _f["actual"] == "(noloc)":
            _lines.append(f"    Action: Add 'CONFIG_{_key}={_expected}' to .config")
        elif _expected == "n":
            _lines.append(f"    Action: Change CONFIG_{_key} to 'n' or comment out as '# CONFIG_{_key} is not set'")
        else:
            _lines.append(f"    Action: Set CONFIG_{_key}={_expected}")

    _lines.append("\n" + "-" * 40)
    _lines.append("Summary by category:")
    for _cat, _score in sorted(audit_result.category_scores.items()):
        _bar = "#" * int(_score / 10) + "-" * (10 - int(_score / 10))
        _lines.append(f"  {_cat:20s} [{_bar}] {_score}%")

    return "\n".join(_lines)


# 配置差异比对

def diff_configs(old: Union[str, Dict[str, str]],
                 new: Union[str, Dict[str, str]]) -> Dict:
    """比较两份内核配置的安全态势差异。"""
    _old_cfg = parse_config(old) if isinstance(old, str) else old
    _new_cfg = parse_config(new) if isinstance(new, str) else new
    _kspp_keys = {e[0] for e in KSPP_BASELINE}
    _changes = {"added": [], "removed": [], "changed": [], "score_delta": 0.0}
    _old_audit = audit(_old_cfg); _new_audit = audit(_new_cfg)
    _changes["score_delta"] = round(_new_audit.score - _old_audit.score, 1)
    for _key in _kspp_keys:
        _ov = _old_cfg.get(_key); _nv = _new_cfg.get(_key)
        if _ov is None and _nv is not None:
            _changes["added"].append({"key": _key, "value": _nv})
        elif _ov is not None and _nv is None:
            _changes["removed"].append({"key": _key, "old_value": _ov})
        elif _ov != _nv:
            _changes["changed"].append({"key": _key, "old": _ov, "new": _nv})
    return _changes
