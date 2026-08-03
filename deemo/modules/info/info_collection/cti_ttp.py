# -*- coding: utf-8 -*-
"""CTI-TTP — 攻击级威胁情报提取与 ATT&CK TTP 结构化映射。

功能边界：
1. ATT&CK TTP 映射 —— 从采集文本/报告文本中识别攻击技术并映射到
   MITRE ATT&CK 战术与技术 ID；语义抽取引擎为可选依赖，无 API 时降级为
   关键词/正则规则库。
2. 攻击级结构化抽取 —— 将多步攻击组织为攻击剧本（attack playbook）：
   攻击者、手法、目标、时间线、IOC。
3. 抽取质量校准 —— 字段完整性/一致性评分，低置信度字段标记待人工复核。
4. 输出衔接 —— 提供结构化事件对象 CTIEvent，供下游情报关联消费。

论文依据（实现时引用）：
[1] arXiv:2505.03147  Towards Effective Identification of Attack Techniques
    in Cyber Threat Intelligence Reports using Large Language Models
    —— 语义识别引擎对 CTI 报告中的攻击技术识别显著优于纯规则，作为 TTP 映射
       主路径的依据。
[2] arXiv:2412.10872  IntelEX: A LLM-driven Attack-level Threat Intelligence
    Extraction Framework —— 攻击剧本（playbook）抽取框架的设计蓝本。
[3] arXiv:2405.03446  SEvenLLM: Benchmarking, Eliciting, and Enhancing
    Abilities of Large Language Models in Cyber Threat Intelligence
    —— 字段完整性/一致性质量校准思路的借鉴来源。
[4] arXiv:2510.00240  SecureBERT 2.0: Advanced Language Model for
    Cybersecurity Intelligence —— 领域语言模型在 CTI 抽取中的应用依据。

设计约束：
- 语义抽取引擎为可选依赖：openai 库或 API key 缺失时 available() 返回 False，
  调用方自动降级到规则库。所有第三方 import 惰性化，保证纯规则模式
  下模块可独立导入。
- 配置优先级：CTI_LLM_BASE_URL / CTI_LLM_MODEL / CTI_LLM_API_KEY
  环境变量 > deemo/config.py 的项目级 Config > 内置默认。
"""

import hashlib
import json
import logging
import os
import re
import time

import uuid

from functools import lru_cache
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)

_RETRY_MAX = 3
_RETRY_BASE_DELAY = 1.0
_LLM_DEFAULT_MAX_TOKENS = 2000

# 保留
_INIT_VECTOR = bytes([0x13, 0x37, 0xBE, 0xEF])
_HASH_ROUNDS = 10007

# ============================================================================
# ATT&CK 规则库（降级路径，无外部模型时使用）
# ============================================================================
# 结构: technique_id -> (tactic, name, keywords)
# 规则库仅作外部模型不可用时的粗粒度降级映射，覆盖常见技术；
# 关键词以多词短语为主，降低单字词的误报。置信度由命中关键词数量线性
# 提升，上限 0.95 — 规则命中不产生满置信度，留待人工复核。

_ATTACK_RULES: Dict[str, Tuple[str, str, List[str]]] = {
    # ---- Initial Access ----
    "T1190": ("initial-access", "Exploit Public-Facing Application",
              ["exploit public-facing", "cve-", "remote code execution", "未授权访问", "边界设备漏洞", "exposed service"]),
    "T1133": ("initial-access", "External Remote Services",
              ["external remote service", "vpn server", "citrix", "远程接入", "rdp gateway"]),
    "T1566": ("initial-access", "Phishing",
              ["phishing", "spearphishing", "malicious attachment", "恶意附件", "钓鱼邮件", "钓鱼链接"]),
    "T1078": ("initial-access", "Valid Accounts",
              ["valid account", "stolen credential", "compromised account", "合法账号", "泄露账号", "有效凭证"]),
    "T1195": ("initial-access", "Supply Chain Compromise",
              ["supply chain", "供应链攻击", "trojanized software", "被投毒的", "供应链"]),
    "T1091": ("initial-access", "Replication Through Removable Media",
              ["removable media", "usb 传播", "autorun", "移动介质"]),

    # ---- Execution ----
    "T1059.003": ("execution", "Command and Scripting Interpreter: Windows Command Shell",
                  ["cmd /c", "cmd.exe", "command shell", "批处理", "batch file", "cmdlet"]),
    "T1059.001": ("execution", "Command and Scripting Interpreter: PowerShell",
                  ["powershell", "powershell.exe", "-enc", "encodedcommand", "invoke-expression", "iex(", "反射式加载"]),
    "T1059.007": ("execution", "Command and Scripting Interpreter: JavaScript",
                  ["javascript", "jscript", "wscript", "cscript", "mshta 加载"]),
    "T1204": ("execution", "User Execution",
              ["user execution", "用户双击", "诱导用户执行", "打开恶意文件"]),
    "T1053.005": ("execution", "Scheduled Task/Job: Scheduled Task",
                  ["scheduled task", "schtasks", "计划任务", "cron", "at.exe"]),
    "T1106": ("execution", "Native API",
              ["native api", "ntdll", "direct system call", "syscall 调用", "系统调用"]),
    "T1569.002": ("execution", "System Services: Service Execution",
                  ["service execution", "sc create", "创建服务", "service control manager"]),
    "T1047": ("execution", "Windows Management Instrumentation",
              ["wmi", "wmic", "win32_process", "management instrumentation", "wmi 横向"]),
    "T1203": ("execution", "Exploitation for Client Execution",
              ["client-side exploit", "浏览器漏洞利用", "office 漏洞", "客户端漏洞"]),

    # ---- Persistence ----
    "T1547.001": ("persistence", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                  ["registry run key", "run key", r"hklm\software\microsoft\windows\currentversion\run",
                   "startup folder", "启动项", "开机自启动"]),
    "T1543.003": ("persistence", "Create or Modify System Process: Windows Service",
                  ["windows service", "创建系统服务", "svchost 挂载", "服务持久化"]),
    "T1136": ("persistence", "Create Account",
              ["create account", "net user", "创建账号", "添加用户", "backdoor account"]),
    "T1574.001": ("persistence", "Hijack Execution Flow: DLL Search Order Hijacking",
                  ["dll search order", "dll hijacking", "dll 劫持", "side-loading", "dll sideloading"]),
    "T1546.008": ("persistence", "Event Triggered Execution: Accessibility Features",
                  ["sethc", "utilman", "粘滞键", "accessibility feature"]),
    "T1505.003": ("persistence", "Server Software Component: Web Shell",
                  ["webshell", "web shell", "php 后门", "asp 木马", "一句话木马"]),

    # ---- Privilege Escalation ----
    "T1068": ("privilege-escalation", "Exploitation for Privilege Escalation",
              ["privilege escalation", "本地提权", "local privilege escalation", "lpe", "内核提权"]),
    "T1055": ("privilege-escalation", "Process Injection",
              ["process injection", "进程注入", "dll injection", "process hollowing", "createremotethread",
               "远程线程注入", "进程镂空"]),
    "T1134": ("privilege-escalation", "Access Token Manipulation",
              ["access token", "token manipulation", "令牌伪造", "token impersonation", "seimpersonate"]),
    "T1548": ("privilege-escalation", "Abuse Elevation Control Mechanism",
              ["uac bypass", "bypass uac", "uac 绕过", "sudo 提权", "setuid"]),
    "T1574.006": ("privilege-escalation", "Hijack Execution Flow: Dynamic Linker Hijacking",
                  ["ld.so.preload", "ld_preload", "动态链接器劫持", "rpath 劫持"]),

    # ---- Defense Evasion ----
    "T1070": ("defense-evasion", "Indicator Removal on Host",
              ["log clear", "删除日志", "wevtutil cl", "timestomp", "清理痕迹", "清除攻击痕迹", "anti-forensics"]),
    "T1027": ("defense-evasion", "Obfuscated Files or Information",
              ["obfuscation", "混淆", "packed", "加壳", "shellcode encoded", "payload 加密", "混淆样本"]),
    "T1140": ("defense-evasion", "Deobfuscate/Decode Files or Information",
              ["deobfuscate", "certutil -decode", "解码 shellcode", "释放载荷"]),
    "T1562": ("defense-evasion", "Impair Defenses",
              ["disable firewall", "关闭杀软", "disable antivirus", "defender exclusion", "修改防护策略", "关闭 edr"]),
    "T1036": ("defense-evasion", "Masquerading",
              ["masquerading", "伪装成", "rename svchost", "合法进程伪装", "假冒系统进程"]),
    "T1218": ("defense-evasion", "System Binary Proxy Execution",
              ["rundll32", "regsvr32", "mshta", "cmstp", "白名单代理执行"]),
    "T1497": ("defense-evasion", "Virtualization/Sandbox Evasion",
              ["sandbox evasion", "沙箱检测", "vm detection", "虚拟机检测", "反沙箱"]),
    "T1112": ("defense-evasion", "Modify Registry",
              ["registry modify", "修改注册表", "reg add", "注册表篡改"]),

    # ---- Credential Access ----
    "T1003": ("credential-access", "OS Credential Dumping",
              ["credential dump", "lsass", "mimikatz", "hashdump", "sam hive", "凭据转储", "ntds.dit"]),
    "T1110": ("credential-access", "Brute Force",
              ["brute force", "暴力破解", "password spraying", "密码喷洒", "弱口令爆破"]),
    "T1552": ("credential-access", "Unsecured Credentials",
              ["hardcoded credential", "明文密码", "plaintext password", "配置泄露凭证", "未加密凭证"]),
    "T1056": ("credential-access", "Input Capture",
              ["keylogger", "键盘记录", "input capture", "记录按键", "抓取输入"]),
    "T1555": ("credential-access", "Credentials from Password Stores",
              ["password store", "credential manager", "密码库", "浏览器密码", "凭据保险库"]),

    # ---- Discovery ----
    "T1087": ("discovery", "Account Discovery",
              ["account discovery", "枚举账号", "list accounts", "net user 枚举"]),
    "T1082": ("discovery", "System Information Discovery",
              ["systeminfo", "uname -a", "system information", "系统信息收集", "主机信息枚举"]),
    "T1057": ("discovery", "Process Discovery",
              ["tasklist", "ps aux", "process discovery", "进程枚举", "进程信息收集"]),
    "T1016": ("discovery", "System Network Configuration Discovery",
              ["ipconfig", "ifconfig", "network configuration", "网络配置收集", "arp -a"]),
    "T1046": ("discovery", "Network Service Discovery",
              ["port scan", "端口扫描", "nmap", "service discovery", "netstat -an"]),
    "T1018": ("discovery", "Remote System Discovery",
              ["net view", "remote system discovery", "ping sweep", "内网探测", "存活主机扫描"]),
    "T1007": ("discovery", "System Service Discovery",
              ["sc query", "service discovery", "服务枚举"]),
    "T1083": ("discovery", "File and Directory Discovery",
              ["file discovery", "目录枚举", "dir /s", "遍历目录", "文件收集枚举"]),
    "T1033": ("discovery", "System Owner/User Discovery",
              ["whoami", "system owner", "当前用户", "id -un", "用户身份探测"]),

    # ---- Lateral Movement ----
    "T1021.001": ("lateral-movement", "Remote Services: Remote Desktop Protocol",
                  ["rdp", "remote desktop", "3389 端口", "mstsc", "远程桌面连接"]),
    "T1021.002": ("lateral-movement", "Remote Services: SMB/Windows Admin Shares",
                  ["smb", "admin share", "net use", r"c$", "psexec", "smbexec", "wmi 横向移动"]),
    "T1021.004": ("lateral-movement", "Remote Services: SSH",
                  ["ssh", "secure shell", "22 端口", "ssh 爆破"]),
    "T1570": ("lateral-movement", "Lateral Tool Transfer",
              ["tool transfer", "certutil -urlcache", "scp 传输", "工具投递", "横向工具传输"]),

    # ---- Collection ----
    "T1005": ("collection", "Data from Local System",
              ["data from local", "本地数据收集", "采集文件", "打包本地文件"]),
    "T1039": ("collection", "Data from Network Shared Drive",
              ["network shared drive", "共享盘数据", "从共享目录采集"]),
    "T1074": ("collection", "Data Staged",
              ["data staging", "数据暂存", "staged files", "集中存放数据"]),
    "T1113": ("collection", "Screen Capture",
              ["screen capture", "截屏", "screenshot", "屏幕截图", "抓屏"]),
    "T1119": ("collection", "Automated Collection",
              ["automated collection", "自动收集数据"]),

    # ---- Command and Control ----
    "T1071.001": ("command-and-control", "Application Layer Protocol: Web Protocols",
                  ["c2 server", "c&c server", "command and control", "beacon", "回连服务器", "c2 服务器", "恶意回连"]),
    "T1573": ("command-and-control", "Encrypted Channel",
              ["encrypted channel", "加密信道", "ssl 加密通信", "加密隧道通信", "tls 加密回连"]),
    "T1105": ("command-and-control", "Ingress Tool Transfer",
              ["tool download", "payload download", "下载恶意载荷", "下载工具", "ingress tool"]),
    "T1090": ("command-and-control", "Proxy",
              ["proxy", "socks 代理", "代理转发", "反向代理"]),
    "T1219": ("command-and-control", "Remote Access Software",
              ["remote access software", "teamviewer", "anydesk", "cobalt strike", "远程控制软件", "远控木马"]),
    "T1572": ("command-and-control", "Protocol Tunneling",
              ["protocol tunneling", "协议隧道", "dnscat", "chisel", "frp 隧道", "dns 隧道"]),

    # ---- Exfiltration ----
    "T1041": ("exfiltration", "Exfiltration Over C2 Channel",
              ["exfiltration", "数据外传", "data exfil", "c2 信道外传", "泄露数据"]),
    "T1048": ("exfiltration", "Exfiltration Over Alternative Protocol",
              ["exfil over dns", "dns exfil", "dns 外传", "备用协议外传"]),
    "T1567": ("exfiltration", "Exfiltration Over Web Service",
              ["exfil to cloud", "外传到网盘", "pastebin 外传", "云盘外传"]),

    # ---- Impact ----
    "T1486": ("impact", "Data Encrypted for Impact",
              ["ransomware", "勒索软件", "encrypt files", "文件加密", "crypto locker", "勒索病毒"]),
    "T1489": ("impact", "Service Stop",
              ["service stop", "停止服务", "kill service", "关闭关键服务"]),
    "T1490": ("impact", "Inhibit System Recovery",
              ["vssadmin", "delete shadow", "删除备份", "inhibit recovery", "禁用系统恢复"]),
    "T1485": ("impact", "Data Destruction",
              ["data destruction", "数据销毁", "wipe disk", "磁盘擦除", "覆盖数据"]),
    "T1498": ("impact", "Network Denial of Service",
              ["ddos", "dos attack", "拒绝服务", "syn flood", "网络轰炸"]),
}

# 战术规范集合（一致性校验用）
_TACTICS = (
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
)
_TACTIC_ALIASES = {
    "initialaccess": "initial-access", "initial_access": "initial-access",
    "privilegeescalation": "privilege-escalation", "privilege_escalation": "privilege-escalation",
    "defenseevasion": "defense-evasion", "defense_evasion": "defense-evasion",
    "credentialaccess": "credential-access", "credential_access": "credential-access",
    "lateralmovement": "lateral-movement", "lateral_movement": "lateral-movement",
    "commandandcontrol": "command-and-control", "command_and_control": "command-and-control",
    "c2": "command-and-control", "c&c": "command-and-control",
}

# ============================================================================
# IOC 正则库
# ============================================================================
_IOC_PATTERNS: Dict[str, re.Pattern] = {
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
    "ipv6": re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b'),
    # URL 字符集限制为 RFC 3986 可见字符，避免吞入中英文标点/邻接词
    "url": re.compile(
        r'\bhttps?://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', re.IGNORECASE),
    "domain": re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
    "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
    "mutex": re.compile(
        r'\b(?:Global|Local)\\[A-Za-z0-9_.\-]{3,}\b|'
        r'\b[A-Za-z0-9_]*(?:Mutex|MUTEX)[A-Za-z0-9_]*\b'),
    "registry": re.compile(
        r'\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[A-Za-z0-9_\\\-.]+'),
    "file_path": re.compile(
        r'\b(?:[A-Za-z]:\\[^\s"\'<>|;]+|/[^/\s][\w./\-]*(?:\.exe|\.dll|\.bin|'
        r'\.ps1|\.bat|\.sh|\.so)\b)'),
}

# IOC 值尾随标点清理：正则可能吞入相邻标点（尤其中文全角标点）
_TRAILING_PUNCT = set("。，,.;;:!?！？、)）]】》\"'`")


def _strip_ioc_trailing(value: str) -> str:
    v = value.rstrip()
    while v and v[-1] in _TRAILING_PUNCT:
        v = v[:-1].rstrip()
    return v


_IOC_TYPE_VALIDATORS: Dict[str, re.Pattern] = {
    "ipv4": re.compile(r'^\d{1,3}(\.\d{1,3}){3}$'),
    "ipv6": re.compile(r'^[0-9a-fA-F:]+$'),
    "url": re.compile(r'^https?://', re.IGNORECASE),
    "domain": re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'),
    "md5": re.compile(r'^[a-fA-F0-9]{32}$'),
    "sha1": re.compile(r'^[a-fA-F0-9]{40}$'),
    "sha256": re.compile(r'^[a-fA-F0-9]{64}$'),
    "email": re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    "mutex": re.compile(r'^(?:Global|Local)\\|[A-Za-z0-9_]+'),
    "registry": re.compile(r'^(?:HKEY_[A-Z_]+|HKLM|HKCU)\\'),
    "file_path": re.compile(r'^[A-Za-z]:\\|^/'),
}


# ============================================================================
# 数据模型
# ============================================================================
@dataclass
class AttackTechnique:
    """ATT&CK 技术映射结果。source: 'rule' | 'llm'。"""
    technique_id: str = ""
    tactic: str = ""
    name: str = ""
    confidence: float = 0.5
    evidence: str = ""
    source: str = "rule"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "tactic": self.tactic,
            "name": self.name,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
            "source": self.source,
        }


@dataclass
class IOC:
    """失陷指标。ioc_type 取值见 _IOC_PATTERNS 键。"""
    ioc_type: str = "unknown"
    value: str = ""
    confidence: float = 1.0
    source: str = "rule"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.ioc_type,
            "value": self.value,
            "confidence": round(self.confidence, 3),
            "source": self.source,
        }


@dataclass
class AttackStep:
    """攻击剧本中的单步。phase 对齐 ATT&CK 战术。"""
    phase: str = ""
    action: str = ""
    technique_id: str = ""
    technique_name: str = ""
    timestamp: str = ""
    confidence: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase,
            "action": self.action,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "timestamp": self.timestamp,
            "confidence": round(self.confidence, 3),
        }


@dataclass
class QualityReport:
    """质量校准报告。overall 为 [0,1] 综合分。"""
    completeness: float = 0.0
    consistency: float = 0.0
    overall: float = 0.0
    field_scores: Dict[str, float] = field(default_factory=dict)
    flags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "completeness": round(self.completeness, 3),
            "consistency": round(self.consistency, 3),
            "overall": round(self.overall, 3),
            "field_scores": {k: round(v, 3) for k, v in self.field_scores.items()},
            "flags": self.flags,
        }


@dataclass
class AttackPlaybook:
    """攻击剧本：攻击者、目标、手法、时间线、IOC 的结构化组织。"""
    attacker: str = ""
    target: str = ""
    summary: str = ""
    techniques: List[AttackTechnique] = field(default_factory=list)
    timeline: List[AttackStep] = field(default_factory=list)
    iocs: List[IOC] = field(default_factory=list)
    source_text: str = ""
    quality: Optional[QualityReport] = None
    needs_review: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attacker": self.attacker,
            "target": self.target,
            "summary": self.summary,
            "techniques": [t.to_dict() for t in self.techniques],
            "timeline": [s.to_dict() for s in self.timeline],
            "iocs": [i.to_dict() for i in self.iocs],
            "quality": self.quality.to_dict() if self.quality else None,
            "needs_review": self.needs_review,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


@dataclass
class CTIEvent:
    """供下游情报关联消费的结构化事件对象。

    correlation_keys() 产出的键集合可直接用于图连接或相似度比对：
    攻击者、IOC 值、TTP 技术 ID、战术维度。
    """
    event_id: str = ""
    source: str = ""
    engine: str = "rule"  # 'llm' | 'rule' | 'hybrid'
    extracted_at: str = ""
    playbook: AttackPlaybook = field(default_factory=AttackPlaybook)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "source": self.source,
            "engine": self.engine,
            "extracted_at": self.extracted_at,
            "playbook": self.playbook.to_dict(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def correlation_keys(self) -> List[str]:
        keys: set = set()
        if self.playbook.attacker:
            keys.add(f"actor:{self.playbook.attacker.lower()}")
        for ioc in self.playbook.iocs:
            if ioc.value:
                keys.add(f"ioc:{ioc.ioc_type}:{ioc.value.lower()}")
        for t in self.playbook.techniques:
            if t.technique_id:
                keys.add(f"ttp:{t.technique_id}")
            if t.tactic:
                keys.add(f"tactic:{t.tactic.lower()}")
        return sorted(keys)


# ============================================================================
# 工具函数
# ============================================================================
def _now_iso() -> str:
    from datetime import datetime
    return datetime.now().isoformat(timespec="seconds")


def _make_event_id(source: str) -> str:
    if not source:
        return "cti-" + uuid.uuid4().hex[:12]
    digest = hashlib.sha1(source.encode("utf-8")).hexdigest()[:12]
    return f"cti-{digest}"


def _coerce_conf(value: Any) -> float:
    try:
        c = float(value)
    except (TypeError, ValueError):
        return 0.5
    return max(0.0, min(1.0, c))


def _normalize_technique_id(tid: str) -> str:
    if not tid:
        return ""
    tid = tid.strip().upper()
    if not tid.startswith("T"):
        tid = "T" + tid
    return tid


def _normalize_tactic(tactic: str) -> str:
    # 战术名规范化：去连字符、空格 → 查别名表
    if not tactic:
        return ""
    key = tactic.strip().lower().replace("-", "").replace(" ", "")
    if key in _TACTIC_ALIASES:
        return _TACTIC_ALIASES[key]
    return tactic.strip().lower()


def _clean_json(s: str) -> str:
    # 去除尾逗号：JSON 规范不允许，外部模型输出常出现
    return re.sub(r',\s*([}\]])', r'\1', s)


def _extract_json(raw: str) -> Optional[Any]:
    # 从文本中提取 JSON 结构：code fence → 数组 → 对象
    if not raw:
        return None
    s = raw.strip()
    fence = re.search(r'```(?:json)?\s*(.*?)```', s, re.DOTALL)
    if fence:
        s = fence.group(1).strip()
    # 数组优先
    start, end = s.find('['), s.rfind(']')
    if start >= 0 and end > start:
        try:
            return json.loads(_clean_json(s[start:end + 1]))
        except json.JSONDecodeError:
            pass
    # 对象回退
    start, end = s.find('{'), s.rfind('}')
    if start >= 0 and end > start:
        try:
            return json.loads(_clean_json(s[start:end + 1]))
        except json.JSONDecodeError:
            pass
    return None


def _first_match(patterns: List[re.Pattern], text: str) -> str:
    for pat in patterns:
        m = pat.search(text)
        if m:
            val = m.group(1).strip().strip('。，,.;')
            if 2 <= len(val) <= 80:
                return val
    return ""


def _merge_iocs(*groups: List[IOC]) -> List[IOC]:
    seen: set = set()
    out: List[IOC] = []
    for group in groups:
        for ioc in group:
            key = (ioc.ioc_type, ioc.value.lower())
            if key in seen:
                continue
            seen.add(key)
            out.append(ioc)
    return out


def _normalize_ioc_type(label: str, value: str) -> str:
    # IOC 类型标签 → 规范类型名
    label = (label or "").strip().lower()
    if label in ("ip", "ip_address", "ipaddr"):
        return "ipv6" if ":" in value else "ipv4"
    if label in ("hash", "file_hash"):
        v = value.strip()
        if re.fullmatch(r"[a-fA-F0-9]{32}", v):
            return "md5"
        if re.fullmatch(r"[a-fA-F0-9]{40}", v):
            return "sha1"
        if re.fullmatch(r"[a-fA-F0-9]{64}", v):
            return "sha256"
        return "hash"
    if label in ("registry", "registry_key"):
        return "registry"
    if label in ("file_path", "filepath", "path"):
        return "file_path"
    if label in ("url", "domain", "email", "mutex"):
        return label
    return label


def _ioc_value_matches_type(ioc_type: str, value: str) -> bool:
    pat = _IOC_TYPE_VALIDATORS.get(ioc_type)
    if pat is None:
        return True  # 未知类型不判罚
    return bool(pat.match(value.strip()))


# 归因/目标抽取模式 — 规则降级路径字段填充
_ATTRIBUTION_PATTERNS = [
    re.compile(r'(?:attributed to|linked to|conducted by|carried out by)\s+'
               r'([A-Za-z0-9][\w\s.\-]{2,50}?)(?:[.,;]|\s|$)', re.IGNORECASE),
    re.compile(r'\b(APT\d+|[A-Za-z0-9]+(?:APT|Group|Gang|Kitten))\b', re.IGNORECASE),
    re.compile(r'(?:威胁组织|攻击组织|黑客组织)[：:\s]+([一-龥A-Za-z0-9]{2,30})'),
]
_TARGET_PATTERNS = [
    re.compile(r'(?:target(?:ed)?|victim)\s*(?:is|of|was|included|:)\s*'
               r'([A-Za-z0-9][\w\s.\-]{2,60}?)(?:[.,;]|\s|$)', re.IGNORECASE),
    re.compile(r'(?:受影响|攻击目标|受害对象|受害者)[：:\s]+([一-龥A-Za-z0-9.\-]{2,40})'),
]


# ============================================================================
# 语义抽取客户端（可选依赖封装）
# ============================================================================
class LLMClient:
    """OpenAI 兼容客户端封装，语义抽取引擎为可选依赖。

    配置优先级：CTI_LLM_BASE_URL / CTI_LLM_MODEL / CTI_LLM_API_KEY
    环境变量 > deemo/config.py 的 Config > 内置默认。
    available() 返回 False 时调用方必须降级到规则库。
    直接构造 OpenAI 兼容 client，兼容 ollama/vllm/llama.cpp 等本地推理端点。
    """

    def __init__(self, base_url: Optional[str] = None, model: Optional[str] = None,
                 api_key: Optional[str] = None, max_tokens: int = _LLM_DEFAULT_MAX_TOKENS):
        self._cfg = self._resolve_config()
        if base_url:
            self._cfg["base_url"] = base_url
        if model:
            self._cfg["model"] = model
        if api_key:
            self._cfg["api_key"] = api_key
        self._max_tokens = max_tokens or _LLM_DEFAULT_MAX_TOKENS
        self._client = None
        self._model = None

    @staticmethod
    def _resolve_config() -> Dict[str, Any]:
        cfg: Dict[str, Any] = {"base_url": None, "model": None, "api_key": None}
        try:
            from config import Config, get_current_ai_model
            base = (getattr(Config, "OPENAI_BASE_URL", None)
                    or getattr(Config, "CUSTOM_BASE_URL", None))
            cfg["base_url"] = base or None
            cfg["model"] = get_current_ai_model()
            key = (getattr(Config, "OPENAI_API_KEY", None)
                   or getattr(Config, "CUSTOM_API_KEY", None))
            cfg["api_key"] = key or None
        except Exception:
            pass  # 项目配置不可用时继续走环境变量
        cfg["base_url"] = os.environ.get("CTI_LLM_BASE_URL", cfg["base_url"]) or None
        cfg["model"] = os.environ.get("CTI_LLM_MODEL", cfg["model"]) or None
        cfg["api_key"] = os.environ.get("CTI_LLM_API_KEY", cfg["api_key"]) or None
        return cfg

    def available(self) -> bool:
        try:
            return self._build_client() is not None
        except Exception:
            return False

    def _build_client(self) -> Optional[Any]:
        """构建 OpenAI 兼容客户端；无有效凭证时返回 None。

        边界条件：
        - 显式 CTI_LLM_BASE_URL / CTI_LLM_API_KEY 优先，自建客户端；
          本地端点（localhost/127.0.0.1/::1）允许无 key 连接，远端必须带 key。
        - 无显式配置时委托 config.get_openai_client()，由项目配置决定
          可用性（openai 无 key 时返回 None）。
        """
        if self._client is not None:
            return self._client
        if not self._cfg["model"]:
            return None

        explicit_base = self._cfg["base_url"]
        explicit_key = self._cfg["api_key"]
        if explicit_base or explicit_key:
            try:
                from openai import OpenAI
            except ImportError:
                return None
            is_local = bool(explicit_base) and re.search(
                r"localhost|127\.0\.0\.1|::1", explicit_base) is not None
            if not explicit_key and not is_local:
                return None
            kwargs: Dict[str, Any] = {"api_key": explicit_key or "local"}
            if explicit_base:
                kwargs["base_url"] = explicit_base
            try:
                self._client = OpenAI(**kwargs)
                self._model = self._cfg["model"]
                return self._client
            except Exception:
                return None

        # 委托项目级客户端（正确处理 ollama/llamacpp/custom 与无 key 判定）
        try:
            from config import get_openai_client as _proj_client
        except Exception:
            _proj_client = None
        if _proj_client is not None:
            try:
                client = _proj_client()
            except Exception:
                client = None
            if client is not None:
                self._client = client
                self._model = self._cfg["model"]
                return client
        return None

    def chat(self, system_prompt: str, user_prompt: str,
             temperature: float = 0.1) -> Optional[str]:
        client = self._build_client()
        if client is None:
            return None
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        last_err: Optional[Exception] = None
        for attempt in range(_RETRY_MAX):
            try:
                resp = client.chat.completions.create(
                    model=self._model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=self._max_tokens,
                )
                return resp.choices[0].message.content
            except Exception as e:  # 指数退避重试
                last_err = e
                if attempt < _RETRY_MAX - 1:
                    time.sleep(_RETRY_BASE_DELAY * (2 ** attempt))
        _log.warning("CTI-LLM 调用失败: %s", last_err)
        return None


# ============================================================================
# 系统提示（两段式抽取：TTP 映射与剧本抽取独立）
# ============================================================================
# 两段式抽取 — TTP 映射与剧本抽取独立 prompt，便于分别调试与降级。
# 要求输出严格 JSON，便于程序化消费。
_TTP_SYSTEM_PROMPT = (
    "你是网络威胁情报分析专家。你的任务是从威胁情报文本中识别攻击技术，"
    "并映射到 MITRE ATT&CK 战术与技术 ID。"
    "输出必须是严格的 JSON 数组，每个元素包含："
    "{\"tactic\": \"战术名\", \"technique_id\": \"T1xxx\", "
    "\"technique_name\": \"技术名\", \"confidence\": 0到1的浮点数, "
    "\"evidence\": \"原文中支持该判断的片段\"}。"
    "只输出 JSON，不要输出其他文字。"
)

_PLAYBOOK_SYSTEM_PROMPT = (
    "你是网络威胁情报分析专家。请从威胁情报文本中抽取攻击级情报，"
    "组织为攻击剧本。输出必须是严格的 JSON 对象，结构如下："
    "{\"attacker\": \"攻击者/组织名，未知则为空字符串\", "
    "\"target\": \"攻击目标/受害系统，未知则为空字符串\", "
    "\"summary\": \"攻击概述\", "
    "\"timeline\": [{\"phase\": \"initial-access|execution|...|impact\", "
    "\"action\": \"步骤描述\", \"technique_id\": \"T1xxx\", "
    "\"technique_name\": \"\", \"timestamp\": \"时间，未知为空\"}], "
    "\"iocs\": [{\"type\": \"ip|domain|url|hash|email|mutex|registry|file_path\", "
    "\"value\": \"\"}], "
    "\"techniques\": [{\"tactic\": \"战术名\", \"technique_id\": \"T1xxx\", "
    "\"technique_name\": \"技术名\", \"confidence\": 0到1, "
    "\"evidence\": \"原文片段\"}]}。"
    "只输出 JSON，不要输出其他文字。"
)


# ============================================================================
# TTP 映射器
# ============================================================================
class TTPMapper:
    """ATT&CK TTP 映射器。

    主路径：语义抽取引擎识别（依据 [1]：语义识别对 CTI 文本技术识别显著优于
    纯规则）。降级路径：关键词/正则规则库 _ATTACK_RULES。
    合并时按 technique_id 去重，语义引擎命中优先于规则命中。
    """

    def __init__(self, use_llm: bool = True, min_confidence: float = 0.3,
                 llm_client: Optional[LLMClient] = None):
        self.use_llm = use_llm
        self.min_confidence = min_confidence
        self._llm = llm_client if llm_client is not None else (
            LLMClient() if use_llm else None)

    def map_text(self, text: str) -> List[AttackTechnique]:
        """完整映射：语义引擎主路径 + 规则补充。"""
        results: List[AttackTechnique] = []
        if self.use_llm and self._llm and self._llm.available():
            results.extend(self._llm_mapping(text))
        rule_results = self._rule_based_mapping(text)
        known = {t.technique_id for t in results}
        for t in rule_results:
            if t.technique_id and t.technique_id not in known:
                results.append(t)
        return [t for t in results if t.confidence >= self.min_confidence]

    # -- 规则路径 --------------------------------------------------------
    def _rule_based_mapping(self, text: str) -> List[AttackTechnique]:
        return [t for t, _pos in self._rule_matches_with_positions(text)]

    def _rule_matches_with_positions(self, text: str) -> List[Tuple[AttackTechnique, int]]:
        """规则匹配并记录每个技术的最早出现位置，用于构建时间线。

        位置来自关键词首次出现的索引；多个技术共享关键词时各自独立命中，
        由置信度区分。空文本直接返回空列表。
        """
        if not text:
            return []
        lower = text.lower()
        results: List[Tuple[AttackTechnique, int]] = []
        for tid, (tactic, name, keywords) in _ATTACK_RULES.items():
            hits: List[str] = []
            first_pos = -1
            for kw in keywords:
                idx = lower.find(kw.lower())
                if idx >= 0:
                    hits.append(kw)
                    if first_pos < 0 or idx < first_pos:
                        first_pos = idx
            if not hits:
                continue
            conf = min(0.95, 0.5 + 0.15 * len(hits))
            results.append((
                AttackTechnique(
                    technique_id=tid,
                    tactic=tactic,
                    name=name,
                    confidence=round(conf, 3),
                    evidence="；".join(hits[:3]),
                    source="rule",
                ),
                first_pos,
            ))
        results.sort(key=lambda x: x[1])
        return results

    # -- 语义引擎路径 --------------------------------------------------------
    def _llm_mapping(self, text: str) -> List[AttackTechnique]:
        if not self._llm or not self._llm.available():
            return []
        user = (
            f"以下是待分析的威胁情报文本：\n\n\"\"\"\n{text[:6000]}\n\"\"\"\n\n"
            "请识别其中出现的攻击技术并映射到 MITRE ATT&CK。"
        )
        raw = self._llm.chat(_TTP_SYSTEM_PROMPT, user)
        data = _extract_json(raw)
        if not isinstance(data, list):
            return []
        results: List[AttackTechnique] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            tactic = _normalize_tactic(str(item.get("tactic") or ""))
            results.append(AttackTechnique(
                technique_id=_normalize_technique_id(str(item.get("technique_id") or "")),
                tactic=tactic,
                name=str(item.get("technique_name") or "").strip(),
                confidence=_coerce_conf(item.get("confidence")),
                evidence=str(item.get("evidence") or "")[:200],
                source="llm",
            ))
        return results


# ============================================================================
# IOC 提取器
# ============================================================================
class IOCExtractor:
    """IOC 正则提取器（规则路径，始终可用）。

    IOC 的格式规律性强，正则提取即可达到较高精度；
    语义引擎抽取的 IOC 与本提取器结果合并去重，格式校验交给质量校准器。
    """

    def extract(self, text: str) -> List[IOC]:
        if not text:
            return []
        seen: set = set()
        out: List[IOC] = []
        for ioc_type, pat in _IOC_PATTERNS.items():
            for m in pat.finditer(text):
                val = _strip_ioc_trailing(m.group(0))
                if not val:
                    continue
                # 排除 URL 内纯 path 段被误判为 domain/hash 的情况
                if ioc_type in ("md5", "sha1", "sha256"):
                    if not val.isalnum():
                        continue
                key = (ioc_type, val.lower())
                if key in seen:
                    continue
                seen.add(key)
                out.append(IOC(ioc_type=ioc_type, value=val,
                               confidence=_ioc_confidence(ioc_type), source="rule"))
        return out


def _ioc_confidence(ioc_type: str) -> float:
    # 高确定性类型给予更高置信度
    if ioc_type in ("ipv4", "ipv6", "md5", "sha1", "sha256"):
        return 0.95
    if ioc_type in ("url", "email"):
        return 0.9
    if ioc_type in ("registry", "file_path"):
        return 0.8
    return 0.7


# ============================================================================
# 质量校准器
# ============================================================================
class QualityAssessor:
    """抽取质量校准器。

    依据 [3] SEvenLLM 基准思路：对结构化抽取结果做字段完整性与跨字段
    一致性评分，输出 [0,1] 三档分数。低置信度字段写入 flags，
    前缀 'review:' 表示该字段需人工复核。
    """

    FIELDS = ("attacker", "target", "summary", "techniques", "timeline", "iocs")
    _CANONICAL_TACTIC = {tid: tactic for tid, (tactic, _n, _k) in _ATTACK_RULES.items()}

    def assess(self, pb: AttackPlaybook) -> QualityReport:
        comp = self._completeness(pb)
        cons = self._consistency(pb)
        overall = round(0.5 * comp["score"] + 0.5 * cons["score"], 3)
        flags = sorted(set(comp["flags"]) | set(cons["flags"]))
        return QualityReport(
            completeness=comp["score"],
            consistency=cons["score"],
            overall=overall,
            field_scores=comp["field_scores"],
            flags=flags,
        )

    def _completeness(self, pb: AttackPlaybook) -> Dict[str, Any]:
        scores: Dict[str, float] = {}
        scores["attacker"] = 1.0 if (pb.attacker and pb.attacker.strip()) else 0.0
        scores["target"] = 1.0 if (pb.target and pb.target.strip()) else 0.0
        scores["summary"] = 1.0 if (pb.summary and pb.summary.strip()) else 0.0
        if pb.techniques:
            hi = sum(1 for t in pb.techniques if t.confidence >= 0.5)
            scores["techniques"] = 1.0 if hi >= 1 else 0.6
        else:
            scores["techniques"] = 0.0
        scores["timeline"] = 1.0 if pb.timeline else 0.0
        scores["iocs"] = 1.0 if pb.iocs else 0.0
        flags: List[str] = []
        # 空字段标记人工复核
        flags.extend(f"review:missing_{k}" for k, v in scores.items() if v == 0.0)
        flags.extend(f"review:technique_{t.technique_id or t.name}"
                     for t in pb.techniques if t.confidence < 0.5)
        score = round(sum(scores.values()) / len(self.FIELDS), 3)
        return {"score": score, "field_scores": scores, "flags": flags}

    def _consistency(self, pb: AttackPlaybook) -> Dict[str, Any]:
        score = 0.0
        checks = 0
        flags: List[str] = []
        # 1) 技术 ID 与战术的规范一致性（对照 _ATTACK_RULES）
        for t in pb.techniques:
            if t.technique_id in self._CANONICAL_TACTIC:
                checks += 1
                if self._CANONICAL_TACTIC[t.technique_id] == t.tactic:
                    score += 1.0
                else:
                    flags.append(f"review:tactic_mismatch_{t.technique_id}")
        # 2) 时间线步骤引用的技术是否可解析（在技术列表或规范库中）
        tech_ids = {t.technique_id for t in pb.techniques}
        for step in pb.timeline:
            if step.technique_id:
                checks += 1
                if (step.technique_id in tech_ids
                        or step.technique_id in self._CANONICAL_TACTIC):
                    score += 1.0
                else:
                    flags.append(f"review:unmapped_step_{step.technique_id}")
        # 3) IOC 类型与值格式一致性
        for ioc in pb.iocs:
            checks += 1
            if _ioc_value_matches_type(ioc.ioc_type, ioc.value):
                score += 1.0
            else:
                flags.append(f"review:ioc_type_mismatch_{ioc.ioc_type}")
        # 4) 时间线时间戳单调性（弱约束）
        stamps = [s.timestamp for s in pb.timeline if s.timestamp]
        if len(stamps) >= 2:
            checks += 1
            if _timestamps_non_decreasing(stamps):
                score += 1.0
        if checks == 0:
            return {"score": 0.0, "flags": flags}
        return {"score": round(score / checks, 3), "flags": flags}


_TS_TOKEN_PATTERNS = [
    (re.compile(r'(\d{4})-(\d{2})-(\d{2})'),
     lambda m: (int(m.group(1)), int(m.group(2)), int(m.group(3)))),
    (re.compile(r'(\d{4})/(\d{2})/(\d{2})'),
     lambda m: (int(m.group(1)), int(m.group(2)), int(m.group(3)))),
]


def _ts_key(s: str) -> Optional[Tuple[int, int, int]]:
    for pat, fn in _TS_TOKEN_PATTERNS:
        m = pat.search(s)
        if m:
            return fn(m)
    return None


def _timestamps_non_decreasing(stamps: List[str]) -> bool:
    keys = []
    for s in stamps:
        k = _ts_key(s)
        if k is None:
            return True  # 无法解析的时间戳不判罚
        keys.append(k)
    return keys == sorted(keys)


# ============================================================================
# 攻击剧本抽取器
# ============================================================================
class PlaybookExtractor:
    """攻击剧本抽取器（依据 [2] IntelEX 攻击级抽取范式）。

    流程：TTP 映射 + IOC 抽取 → 语义引擎剧本抽取（若可用）→ 规则兜底 →
    质量校准。合并策略：语义引擎结果为骨架，规则结果为补充；空字段用规则
    启发式回填。
    """

    def __init__(self, use_llm: bool = True, llm_client: Optional[LLMClient] = None):
        self.use_llm = use_llm
        self.used_llm = False
        self._llm = llm_client if llm_client is not None else (
            LLMClient() if use_llm else None)
        self.mapper = TTPMapper(use_llm=use_llm, llm_client=self._llm)
        self.ioc_extractor = IOCExtractor()
        self.assessor = QualityAssessor()

    def extract(self, text: str) -> AttackPlaybook:
        text = text or ""
        if not text.strip():
            return AttackPlaybook(source_text=text)

        rule_pairs = self.mapper._rule_matches_with_positions(text)
        rule_techs = [t for t, _pos in rule_pairs]
        rule_positions = rule_pairs
        rule_iocs = self.ioc_extractor.extract(text)

        pb: Optional[AttackPlaybook] = None
        if self.use_llm and self._llm and self._llm.available():
            pb = self._llm_playbook(text)
            self.used_llm = pb is not None

        if pb is None:
            pb = self._rule_playbook(text, rule_techs, rule_positions)
        else:
            pb = self._merge_llm_with_rules(pb, rule_techs, rule_iocs, text)

        pb.source_text = text
        pb.quality = self.assessor.assess(pb)
        pb.needs_review = [f for f in (pb.quality.flags if pb.quality else [])
                           if f.startswith("review:")]
        return pb

    def _merge_llm_with_rules(self, pb: AttackPlaybook,
                              rule_techs: List[AttackTechnique],
                              rule_iocs: List[IOC],
                              text: str) -> AttackPlaybook:
        """语义引擎骨架 + 规则补充 + 空字段回填。"""
        merged = list(pb.techniques)
        known = {t.technique_id for t in merged if t.technique_id}
        for t in rule_techs:
            if t.technique_id and t.technique_id not in known:
                merged.append(t)
        pb.techniques = merged
        pb.iocs = _merge_iocs(pb.iocs, rule_iocs)
        if not pb.attacker:
            pb.attacker = _first_match(_ATTRIBUTION_PATTERNS, text)
        if not pb.target:
            pb.target = _first_match(_TARGET_PATTERNS, text)
        if not pb.summary:
            pb.summary = _rule_summary(text, merged)
        return pb

    def _rule_playbook(self, text: str,
                       rule_techs: Optional[List[AttackTechnique]] = None,
                       rule_positions: Optional[List[Tuple[AttackTechnique, int]]] = None
                       ) -> AttackPlaybook:
        """规则降级路径：技术按出现位置构成近似时间线。"""
        if rule_positions is None:
            rule_techs, rule_positions = self.mapper._rule_matches_with_positions(text)
        steps = [
            AttackStep(phase=t.tactic, action=f"{t.name}（规则命中）",
                       technique_id=t.technique_id, technique_name=t.name,
                       confidence=t.confidence)
            for t, _pos in sorted(rule_positions, key=lambda x: x[1])
        ]
        iocs = self.ioc_extractor.extract(text)
        return AttackPlaybook(
            attacker=_first_match(_ATTRIBUTION_PATTERNS, text),
            target=_first_match(_TARGET_PATTERNS, text),
            summary=_rule_summary(text, rule_techs or []),
            techniques=rule_techs or [],
            timeline=steps,
            iocs=iocs,
        )

    def _llm_playbook(self, text: str) -> Optional[AttackPlaybook]:
        # 语义引擎剧本抽取：发送 prompt → 解析 JSON
        if not self._llm or not self._llm.available():
            return None
        user = (
            f"请从以下威胁情报文本中抽取攻击级情报并组织为攻击剧本：\n\n"
            f"\"\"\"\n{text[:6000]}\n\"\"\""
        )
        raw = self._llm.chat(_PLAYBOOK_SYSTEM_PROMPT, user)
        data = _extract_json(raw)
        if not isinstance(data, dict):
            return None

        def _s(k: str) -> str:
            v = data.get(k)
            return str(v).strip() if v else ""

        steps: List[AttackStep] = []
        for st in data.get("timeline") or []:
            if not isinstance(st, dict):
                continue
            steps.append(AttackStep(
                phase=_normalize_tactic(str(st.get("phase") or "")),
                action=str(st.get("action") or "").strip(),
                technique_id=_normalize_technique_id(str(st.get("technique_id") or "")),
                technique_name=str(st.get("technique_name") or "").strip(),
                timestamp=str(st.get("timestamp") or "").strip(),
                confidence=_coerce_conf(st.get("confidence")),
            ))
        iocs: List[IOC] = []
        for i in data.get("iocs") or []:
            if not isinstance(i, dict):
                continue
            value = str(i.get("value") or "").strip()
            label = str(i.get("type") or "unknown")
            iocs.append(IOC(
                ioc_type=_normalize_ioc_type(label, value),
                value=value,
                confidence=_coerce_conf(i.get("confidence")),
                source="llm",
            ))
        techniques: List[AttackTechnique] = []
        for item in data.get("techniques") or []:
            if not isinstance(item, dict):
                continue
            techniques.append(AttackTechnique(
                technique_id=_normalize_technique_id(str(item.get("technique_id") or "")),
                tactic=_normalize_tactic(str(item.get("tactic") or "")),
                name=str(item.get("technique_name") or "").strip(),
                confidence=_coerce_conf(item.get("confidence")),
                evidence=str(item.get("evidence") or "")[:200],
                source="llm",
            ))
        return AttackPlaybook(
            attacker=_s("attacker"),
            target=_s("target"),
            summary=_s("summary"),
            techniques=techniques,
            timeline=steps,
            iocs=iocs,
        )


def _rule_summary(text: str, techniques: List[AttackTechnique]) -> str:
    """规则路径摘要：以识别到的主技术链概括攻击流程。"""
    if not techniques:
        return "文本中未识别到明确的攻击技术。"
    top = techniques[:3]
    chain = " → ".join(f"{t.tactic}/{t.name}" for t in top)
    return f"识别到 {len(techniques)} 项攻击技术，主链：{chain}"


# ============================================================================
# 模块级便捷函数
# ============================================================================
def map_ttp(text: str, use_llm: bool = True) -> List[AttackTechnique]:
    """便捷入口：ATT&CK TTP 映射。"""
    return TTPMapper(use_llm=use_llm).map_text(text)


def extract_iocs(text: str) -> List[IOC]:
    """便捷入口：IOC 正则提取。"""
    return IOCExtractor().extract(text)


def extract_playbook(text: str, use_llm: bool = True) -> AttackPlaybook:
    """便捷入口：攻击剧本抽取（含质量校准）。"""
    return PlaybookExtractor(use_llm=use_llm).extract(text)


def extract_cti_ttp(text: str, source: str = "", use_llm: bool = True) -> CTIEvent:
    """统一入口：文本 → 攻击剧本 → 结构化事件对象。

    返回的 CTIEvent 可直接被下游情报关联消费（correlation_keys）。
    """
    extractor = PlaybookExtractor(use_llm=use_llm)
    pb = extractor.extract(text)
    engine = "llm" if extractor.used_llm else "rule"
    return CTIEvent(
        event_id=_make_event_id(source or text[:128]),
        source=source,
        engine=engine,
        extracted_at=_now_iso(),
        playbook=pb,
    )


__all__ = [
    "AttackTechnique", "IOC", "AttackStep", "QualityReport", "AttackPlaybook",
    "CTIEvent", "LLMClient", "TTPMapper", "IOCExtractor", "QualityAssessor",
    "PlaybookExtractor", "map_ttp", "extract_iocs", "extract_playbook",
    "extract_cti_ttp",
]
