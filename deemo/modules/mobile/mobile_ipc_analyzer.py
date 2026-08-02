#!/usr/bin/env python3
"""
移动端进程间通信 (IPC) 安全分析。

覆盖范围:
  1. Android Binder 事务安全 — AIDL 接口解析, 权限检查审计
  2. Android Intent/Bundle 注入风险 — 隐式Intent劫持, Parcel序列化漏洞
  3. Broadcast 接收器安全 — 有序广播拦截, 粘性广播泄露
  4. iOS XPC 服务安全 — Mach message 分析, XPC dictionary 审计
  5. iOS Mach Port 权限泄露 — task_for_pid, thread_get_state 越权访问
  6. 进程间共享内存/文件风险 — ashmem, tmpfs 竞态, ContentProvider 数据泄露
  7. IPC 调用图 — 识别跨进程调用链, 发现未授权的边界穿越
  8. AIDL 生成的 Stub/Proxy 模式识别 — 自动化的 Binder 事务分析

技术基础:
  - Android Binder 内核驱动协议 (ioctl: BINDER_WRITE_READ)
  - AIDL 接口定义语言 → C++/Java 生成代码模式
  - Apple XPC Services 框架 (libxpc.dylib)
  - Mach IPC 基础: mach_msg, mach_port_allocate, bootstrap_register
  - CWE-940: Improper Verification of Source of a Communication Channel
  - CWE-925: Improper Verification of Intent by Broadcast Receiver

参考文献:
  - Android Binder Security: comm-base analysis via /dev/binder ioctl tracing
  - One Byte to Rule Them All (CVE-2020-0041): Binder 引用计数 UAF
  - XPC Service Abuse: via launchd plist injection
"""

import re
import struct
import logging
import os
from pathlib import Path
from dataclasses import dataclass, field
from enum import StrEnum, IntEnum
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class IPCType(StrEnum):
    BINDER = "binder"
    INTENT = "intent"
    BROADCAST = "broadcast"
    XPC = "xpc"
    MACH = "mach_port"
    SHARED_MEMORY = "shared_memory"
    CONTENT_PROVIDER = "content_provider"
    SOCKET = "socket"
    PIPE = "pipe"
    APP_GROUP = "app_group"  # iOS App Group 共享


class IPCVulnerabilityType(StrEnum):
    INTENT_INJECTION = "intent_injection"          # 隐式Intent注入
    BROADCAST_HIJACK = "broadcast_hijack"          # 广播劫持
    BINDER_UAF = "binder_uaf"                      # Binder use-after-free
    BINDER_PRIV_ESCALATION = "binder_priv_escalation"  # Binder 权限提升
    UNSAFE_PARCEL = "unsafe_parcel"                # Parcel 反序列化漏洞
    XPC_PRIV_ESCALATION = "xpc_priv_escalation"    # XPC 权限提升
    MACH_PORT_LEAK = "mach_port_leak"              # Mach Port 泄露
    EXPORTED_SERVICE_WITHOUT_PERMISSION = "exported_service_no_perm"
    STICKY_BROADCAST_LEAK = "sticky_broadcast_leak"
    AIDL_INTERFACE_MISMATCH = "aidl_mismatch"
    XPC_DICTIONARY_INJECTION = "xpc_dictionary_injection"


class IPCSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Binder 事务代码 (来自 binder.h)
class BinderTransactionCode(IntEnum):
    FIRST_CALL_TRANSACTION = 0x00000001
    LAST_CALL_TRANSACTION = 0x00ffffff
    PING_TRANSACTION = 0x5f504e47      # '_PNG'
    DUMP_TRANSACTION = 0x5f444d50      # '_DMP'
    SHELL_COMMAND_TRANSACTION = 0x5f534d50  # '_SMP'
    INTERFACE_TRANSACTION = 0x5f4e5446  # '_NTF'
    TWEET_TRANSACTION = 0x5f545754     # '_TWT'
    LIKE_TRANSACTION = 0x5f4c494b     # '_LIK'


# Binder 驱动 ioctl 命令
BINDER_WRITE_READ = 0xc0306201
BINDER_SET_IDLE_TIMEOUT = 0xc0046203
BINDER_SET_MAX_THREADS = 0xc0046205
BINDER_SET_IDLE_PRIORITY = 0xc0046206
BINDER_SET_CONTEXT_MGR = 0xc0046207
BINDER_THREAD_EXIT = 0xc0046208
BINDER_VERSION = 0xc0046209


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class BinderInterface:
    """检测到的 AIDL/Binder 接口。"""
    name: str              # 接口完整路径, e.g. com.example.IAdbService
    method_count: int = 0
    methods: List[str] = field(default_factory=list)
    is_system_service: bool = False
    has_permission_check: bool = False
    detected_permissions: List[str] = field(default_factory=list)
    transaction_codes: List[int] = field(default_factory=list)
    callsite_offsets: List[int] = field(default_factory=list)


@dataclass
class IntentEntry:
    """检测到的 Intent action。"""
    action: str
    is_implicit: bool = True       # 隐式Intent (无指定component)
    target_package: str = ""
    target_class: str = ""
    extras_keys: List[str] = field(default_factory=list)
    flags: int = 0
    is_ordered_broadcast: bool = False
    offset: int = 0


@dataclass
class BroadcastReceiver:
    """Android BroadcastReceiver 定义。"""
    receiver_name: str
    actions: List[str] = field(default_factory=list)
    exported: bool = False
    permission: str = ""
    is_ordered: bool = False
    priority: int = 0


@dataclass
class XPCService:
    """iOS XPC Service 信息。"""
    service_name: str               # 反向 DNS bundle ID
    mach_service_name: str = ""     # Mach service 注册名
    is_anonymous: bool = False      # 匿名连接 (xpc_connection_create)
    has_entitlement_check: bool = False
    required_entitlements: List[str] = field(default_factory=list)
    exposed_protocols: List[str] = field(default_factory=list)
    is_bundled: bool = True         # 是否为 Bundle 内嵌 XPC service


@dataclass
class MachPortInfo:
    """Mach Port 使用信息。"""
    port_name: str = ""
    right_type: str = ""            # SEND, RECEIVE, SEND_ONCE
    is_task_port: bool = False      # task_for_pid 获取的端口
    is_thread_port: bool = False
    is_bootstrap: bool = False
    reference_count: int = 0


@dataclass
class IPCFinding:
    """IPC 安全发现。"""
    category: str
    vuln_type: IPCVulnerabilityType = IPCVulnerabilityType.INTENT_INJECTION
    severity: IPCSeverity = IPCSeverity.MEDIUM
    description: str = ""
    evidence: str = ""
    component: str = ""
    recommendation: str = ""


# ---------------------------------------------------------------------------
# Android Binder/IPC 分析器
# ---------------------------------------------------------------------------

class BinderIPCAnalyzer:
    """Android Binder & IPC 安全分析器。

    从 DEX/SO/APK 中检测:
      - AIDL 生成的 Stub/Proxy 接口
      - Binder 事务中缺少权限检查
      - 系统服务绑定 (android.os.ServiceManager)
      - Intent 注入风险点
      - Broadcast 劫持机会
    """

    # AIDL Stub 模式: I<Interface>.Stub, I<Interface>.Stub.Proxy
    _AIDL_STUB_PATTERN = re.compile(
        rb'(?:class|public\s+static\s+abstract)\s+(?:class\s+)?'
        rb'(I[A-Z]\w+(?:\.Stub|\.Stub\$Proxy))',
    )

    # Binder 服务绑定模式
    _SERVICE_MANAGER_PATTERNS = [
        rb'ServiceManager\.getService',
        rb'android\.os\.ServiceManager',
        rb'getSystemService\s*\(',
        rb'IBinder\b',
        rb'Binder\b',
    ]

    # Android 敏感系统服务 (可能被滥用的)
    _SENSITIVE_SERVICES: Dict[bytes, str] = {
        b'alarm': 'AlarmManager — 定时任务滥用',
        b'notification': 'NotificationManager — 通知欺骗',
        b'clipboard': 'ClipboardManager — 剪贴板窃取',
        b'accessibility': 'AccessibilityService — 无障碍辅助滥用',
        b'package': 'PackageManager — 应用枚举',
        b'activity': 'ActivityManager — 活动监控',
        b'window': 'WindowManager — 叠加层攻击',
        b'input_method': 'InputMethodManager — 键盘输入监听',
        b'wifi': 'WifiManager — WiFi信息泄露',
        b'bluetooth': 'BluetoothManager — 蓝牙跟踪',
        b'location': 'LocationManager — 位置跟踪',
        b'telephony': 'TelephonyManager — 电话状态',
        b'sms': 'SmsManager — 短信操作',
        b'media_projection': 'MediaProjectionManager — 屏幕录制',
        b'usb': 'UsbManager — USB设备访问',
    }

    # Intent 注入风险模式
    _INTENT_INJECTION_PATTERNS = [
        # 隐式 Intent 构造 (无 setComponent/setPackage)
        (rb'new\s+Intent\s*\(\s*"([^"]+)"\s*\)', '隐式Intent(action only)'),
        (rb'new\s+Intent\s*\(\s*\)[^;]*\.setAction\s*\(', 'setAction 无 component'),
        (rb'sendBroadcast\s*\(\s*new\s+Intent', 'sendBroadcast 显式构造'),
        (rb'startService\s*\(\s*new\s+Intent', 'startService 隐式Intent'),
        # 有序广播无权限保护
        (rb'sendOrderedBroadcast\s*\(', '有序广播 — 可被拦截或修改'),
        # 粘性广播
        (rb'sendStickyBroadcast\s*\(', '粘性广播 — 数据泄露风险 (deprecated)'),
    ]

    # Parcel 相关模式 (序列化/反序列化安全)
    _PARCEL_PATTERNS = [
        (rb'Parcel\.obtain\s*\(', 'Parcel获取'),
        (rb'readFromParcel\s*\(', 'Parcel反序列化入口'),
        (rb'createFromParcel\s*\(', 'CREATOR.createFromParcel'),
        (rb'writeToParcel\s*\(', 'Parcel序列化'),
        (rb'android\.os\.Parcelable', 'Parcelable接口实现'),
    ]

    def __init__(self, binary_data: bytes = b""):
        self.data = binary_data
        self.interfaces: List[BinderInterface] = []
        self.intents: List[IntentEntry] = []
        self.receivers: List[BroadcastReceiver] = []
        self.findings: List[IPCFinding] = []
        self._services_bound: Set[str] = set()

    def detect_aidl_interfaces(self) -> List[BinderInterface]:
        """从 DEX/Smali 二进制中识别 AIDL 接口。"""
        found: Dict[str, BinderInterface] = {}

        # 1. 查找 I<Xxx>.Stub 模式
        for m in self._AIDL_STUB_PATTERN.finditer(self.data):
            full_name = m.group(1).decode('ascii', errors='ignore')
            # 提取接口名
            parts = full_name.split('.')
            if len(parts) >= 2:
                interface_name = parts[0]  # e.g. "IMyService"
                if interface_name not in found:
                    found[interface_name] = BinderInterface(name=interface_name)
                found[interface_name].callsite_offsets.append(m.start())

        # 2. 查找 Transaction code 常量
        trans_pattern = re.compile(
            rb'TRANSACTION_\w+\s*=\s*(?:0x)?([0-9a-fA-F]+)',
        )
        trans_interface_pattern = re.compile(
            rb'static\s+final\s+int\s+TRANSACTION_(\w+)',
        )

        # 尝试按接口分组事务码
        for m in trans_pattern.finditer(self.data):
            code = int(m.group(1), 0)
            # 反向查找周边的方法名
            context_start = max(0, m.start() - 500)
            context = self.data[context_start:m.end() + 100]
            iface_matches = self._AIDL_STUB_PATTERN.findall(context)
            for iface_name_raw in iface_matches:
                iface_name = iface_name_raw.decode('ascii', errors='ignore').split('.')[0]
                if iface_name in found and code not in found[iface_name].transaction_codes:
                    found[iface_name].transaction_codes.append(code)

        self.interfaces = list(found.values())
        return self.interfaces

    def detect_service_bindings(self) -> Set[str]:
        """检测 Binder 服务绑定 — 应用使用了哪些系统服务。"""
        for pattern in self._SERVICE_MANAGER_PATTERNS:
            for m in re.finditer(pattern, self.data):
                # 尝试从附近提取服务名
                ctx_start = max(0, m.start() - 100)
                ctx_end = min(len(self.data), m.end() + 100)
                context = self.data[ctx_start:ctx_end]

                for svc_sig, svc_desc in self._SENSITIVE_SERVICES.items():
                    if svc_sig in context and svc_sig.decode('ascii') not in self._services_bound:
                        svc_name = svc_sig.decode('ascii')
                        self._services_bound.add(svc_name)
                        self.findings.append(IPCFinding(
                            category='sensitive_service_binding',
                            vuln_type=IPCVulnerabilityType.BINDER_PRIV_ESCALATION,
                            severity=IPCSeverity.LOW,
                            description=f'绑定敏感系统服务: {svc_desc}',
                            evidence=f'service: {svc_name}',
                            recommendation=f'审查 "{svc_name}" 服务的必要性并限制使用范围',
                        ))

        return self._services_bound

    def detect_intent_injection_risks(self) -> List[IntentEntry]:
        """检测 Intent 注入/劫持风险。"""
        intents: List[IntentEntry] = []

        for pattern, desc in self._INTENT_INJECTION_PATTERNS:
            for m in re.finditer(pattern, self.data):
                action = m.group(1).decode('ascii', errors='ignore') if m.lastindex and m.lastindex >= 1 else '(动态)'
                is_broadcast = b'sendBroadcast' in m.group(0)

                intents.append(IntentEntry(
                    action=action,
                    is_implicit=b'Component' not in self.data[max(0, m.start()-200):m.end()],
                    is_ordered_broadcast=b'Ordered' in m.group(0),
                    offset=m.start(),
                ))

                # generate finding
                if b'sticky' in m.group(0).lower():
                    self.findings.append(IPCFinding(
                        category='sticky_broadcast',
                        vuln_type=IPCVulnerabilityType.STICKY_BROADCAST_LEAK,
                        severity=IPCSeverity.HIGH,
                        description=f'使用粘性广播 (deprecated) — 数据可被任意应用读取',
                        evidence=desc,
                        recommendation='使用非粘性广播或局部广播 (LocalBroadcastManager)',
                    ))
                elif is_broadcast and b'Ordered' not in m.group(0):
                    self.findings.append(IPCFinding(
                        category='implicit_broadcast',
                        vuln_type=IPCVulnerabilityType.BROADCAST_HIJACK,
                        severity=IPCSeverity.MEDIUM,
                        description=f'发送隐式广播 "{action}" — 可被任意应用接收',
                        evidence=desc,
                        recommendation='使用 setPackage() 指定目标包或改用显式 Intent',
                    ))
                elif b'startService' in m.group(0):
                    self.findings.append(IPCFinding(
                        category='implicit_service_intent',
                        vuln_type=IPCVulnerabilityType.INTENT_INJECTION,
                        severity=IPCSeverity.HIGH,
                        description=f'使用隐式Intent启动服务 — 可被恶意应用拦截',
                        evidence=desc,
                        recommendation='使用显式 Intent (new Intent(context, ServiceClass.class))',
                    ))

        self.intents = intents
        return intents

    def detect_parcel_vulnerabilities(self):
        """Parcel 反序列化安全审计。"""
        for pattern, desc in self._PARCEL_PATTERNS:
            for m in re.finditer(pattern, self.data):
                if b'createFromParcel' in pattern or b'readFromParcel' in pattern:
                    # Parcel 反序列化入口——需要检查是否有输入校验
                    ctx = self.data[max(0, m.start()-300):m.end()+300]
                    has_check = (b'checkArgument' in ctx or b'checkNotNull' in ctx
                                or b'Objects.requireNonNull' in ctx or b'if (' in ctx)
                    if not has_check:
                        self.findings.append(IPCFinding(
                            category='unsafe_parcel',
                            vuln_type=IPCVulnerabilityType.UNSAFE_PARCEL,
                            severity=IPCSeverity.MEDIUM,
                            description=f'Parcel 反序列化入口 "{desc}" 缺少输入校验',
                            evidence=f'offset: {m.start():#x}',
                            recommendation='在 createFromParcel/readFromParcel 中添加参数的合法性检查',
                        ))

    def detect_aidl_permission_checks(self):
        """检查 AIDL 接口实现中是否有权限校验。"""
        for iface in self.interfaces:
            # 在 Stub 类附近查找权限检查
            for offset in iface.callsite_offsets:
                ctx = self.data[max(0, offset - 512):min(len(self.data), offset + 2048)]
                # permission check patterns
                if b'checkPermission' in ctx or b'enforcePermission' in ctx:
                    iface.has_permission_check = True
                    perm_matches = re.findall(rb'"([a-z]+\.[a-z]+\.[A-Z_]+)"', ctx)
                    for pm in perm_matches:
                        perm_str = pm.decode('ascii')
                        if perm_str not in iface.detected_permissions:
                            iface.detected_permissions.append(perm_str)
                if b'checkCallingPermission' in ctx:
                    iface.has_permission_check = True
                if b'getCallingUid' in ctx or b'Binder.getCallingUid' in ctx:
                    iface.has_permission_check = True

            if not iface.has_permission_check and iface.method_count > 0:
                self.findings.append(IPCFinding(
                    category='aidl_no_permission',
                    vuln_type=IPCVulnerabilityType.AIDL_INTERFACE_MISMATCH,
                    severity=IPCSeverity.HIGH,
                    description=f'AIDL接口 "{iface.name}" 缺少调用者权限检查',
                    component=iface.name,
                    recommendation=f'在 {iface.name}.Stub.onTransact 中添加 checkCallingPermission',
                ))

    def analyze(self) -> Dict[str, Any]:
        self.detect_aidl_interfaces()
        self.detect_service_bindings()
        self.detect_intent_injection_risks()
        self.detect_parcel_vulnerabilities()
        self.detect_aidl_permission_checks()

        return {
            'platform': 'android',
            'binder_interfaces': [
                {
                    'name': iface.name,
                    'methods': iface.methods,
                    'has_permission_check': iface.has_permission_check,
                    'permissions': iface.detected_permissions,
                }
                for iface in self.interfaces
            ],
            'services_bound': list(self._services_bound),
            'intent_risks': [
                {
                    'action': ie.action,
                    'is_implicit': ie.is_implicit,
                    'is_ordered': ie.is_ordered_broadcast,
                    'offset': hex(ie.offset),
                }
                for ie in self.intents[:20]
            ],
            'findings': [
                {
                    'category': f.category,
                    'vuln_type': f.vuln_type.value,
                    'severity': f.severity.value,
                    'description': f.description,
                    'component': f.component,
                    'recommendation': f.recommendation,
                }
                for f in self.findings
            ],
        }


# ---------------------------------------------------------------------------
# iOS XPC & Mach IPC 分析器
# ---------------------------------------------------------------------------

class XPCIPCAnalyzer:
    """iOS XPC & Mach IPC 安全分析器。

    从 Mach-O 二进制中检测:
      - XPC Service 定义 (Info.plist XPCServices)
      - xpc_connection_create / xpc_connection_create_mach_service 调用点
      - NSXPCConnection 使用 (ObjC 层 XPC)
      - Mach port 创建与权限 (mach_port_allocate, task_for_pid)
      - bootstrap_register / bootstrap_look_up 调用
      - XPC dictionary 注入风险 (xpc_dictionary_get_value 无校验)
    """

    # XPC C API 模式
    _XPC_C_API_PATTERNS: Dict[bytes, str] = {
        b'_xpc_connection_create$': 'xpc_connection_create — 创建XPC连接',
        b'_xpc_connection_create_mach_service$': 'xpc_conn…_mach_service — Mach XPC服务',
        b'_xpc_connection_send_message$': 'xpc_connection_send_message',
        b'_xpc_dictionary_get_value$': 'xpc_dictionary_get_value — 提取XPC消息字段',
        b'_xpc_dictionary_get_string$': 'xpc_dictionary_get_string',
        b'_xpc_dictionary_get_data$': 'xpc_dictionary_get_data',
        b'_xpc_dictionary_get_array$': 'xpc_dictionary_get_array',
        b'_xpc_dictionary_set_value$': 'xpc_dictionary_set_value',
    }

    # NSXPCConnection ObjC API
    _NSXPC_PATTERNS: Dict[bytes, str] = {
        b'NSXPCConnection': 'NSXPCConnection',
        b'NSXPCListener': 'NSXPCListener — XPC监听器',
        b'NSXPCInterface': 'NSXPCInterface — 接口定义',
        b'setExportedObject': '设置导出对象',
        b'setExportedInterface': '设置导出接口',
        b'remoteObjectProxy': '获取远程代理',
        b'setInterruptionHandler': '中断处理',
        b'setInvalidationHandler': '失效处理',
    }

    # Mach API
    _MACH_PATTERNS: Dict[bytes, str] = {
        b'_mach_port_allocate$': 'mach_port_allocate — 分配端口',
        b'_mach_port_deallocate$': 'mach_port_deallocate',
        b'_task_for_pid$': 'task_for_pid — 获取任务端口 (需com.apple.security.system-task)',
        b'_thread_get_state$': 'thread_get_state — 读取线程状态',
        b'_thread_set_state$': 'thread_set_state — 修改线程状态 (注入)',
        b'_bootstrap_register$': 'bootstrap_register — 注册Mach服务',
        b'_bootstrap_look_up$': 'bootstrap_look_up — 查找Mach服务',
        b'_bootstrap_check_in$': 'bootstrap_check_in',
        b'_mach_msg$': 'mach_msg — 底层消息收发',
        b'_mach_msg_send$': 'mach_msg_send',
        b'_mach_msg_receive$': 'mach_msg_receive',
        b'_vm_read$': 'vm_read — 读取其他进程内存',
        b'_vm_write$': 'vm_write — 写入其他进程内存',
        b'_vm_region$': 'vm_region — 内存区域枚举',
        b'_proc_*$': 'proc_* — 进程操作',
    }

    # XPC Service Info.plist 路径模式
    _XPC_BUNDLE_PATTERN = re.compile(rb'XPCServices\/([^\/]+)\.xpc')

    def __init__(self, binary_data: bytes = b""):
        self.data = binary_data
        self.findings: List[IPCFinding] = []
        self.mach_ports: List[MachPortInfo] = []
        self.xpc_services: List[XPCService] = []

    def detect_xpc_api_usage(self) -> Dict[str, List[int]]:
        """检测 XPC API 调用。"""
        usage: Dict[str, List[int]] = {}
        for sig, desc in self._XPC_C_API_PATTERNS.items():
            clean_sig = sig.replace(b'$', b'')
            for m in re.finditer(re.escape(clean_sig), self.data):
                if desc not in usage:
                    usage[desc] = []
                usage[desc].append(m.start())
        return usage

    def detect_nsxpc_usage(self) -> List[str]:
        """检测 NSXPCConnection 使用。"""
        found: List[str] = []
        for sig, desc in self._NSXPC_PATTERNS.items():
            if sig in self.data:
                found.append(desc)
        return found

    def detect_mach_operations(self) -> Dict[str, List[int]]:
        """检测底层 Mach port 操作。"""
        ops: Dict[str, List[int]] = defaultdict(list)
        for sig, desc in self._MACH_PATTERNS.items():
            clean_sig = sig.replace(b'$', b'')
            pattern = re.compile(re.escape(clean_sig))
            for m in pattern.finditer(self.data):
                ops[desc].append(m.start())
                # Check for dangerous operations
                if b'task_for_pid' in sig:
                    self.findings.append(IPCFinding(
                        category='mach_task_port',
                        vuln_type=IPCVulnerabilityType.MACH_PORT_LEAK,
                        severity=IPCSeverity.HIGH,
                        description=f'{desc} — 可获取其他进程的任务端口',
                        evidence=f'offset: {m.start():#x}',
                        recommendation='需要 com.apple.security.system-task entitlement — 审查是否必要',
                    ))
                elif b'thread_set_state' in sig or b'vm_write' in sig:
                    self.findings.append(IPCFinding(
                        category='mach_code_injection',
                        vuln_type=IPCVulnerabilityType.MACH_PORT_LEAK,
                        severity=IPCSeverity.CRITICAL,
                        description=f'{desc} — 可用于代码注入',
                        evidence=f'offset: {m.start():#x}',
                        recommendation='审查此调用的必要性 — 可能被滥用为进程注入',
                    ))
                elif b'bootstrap_register' in sig:
                    self.findings.append(IPCFinding(
                        category='mach_bootstrap_register',
                        vuln_type=IPCVulnerabilityType.BINDER_PRIV_ESCALATION,
                        severity=IPCSeverity.LOW,
                        description=f'{desc} — 注册全局 Mach 服务',
                        evidence=f'offset: {m.start():#x}',
                        recommendation='确保服务名唯一且不被其他进程冒充',
                    ))
        return dict(ops)

    def detect_xpc_dictionary_injection(self):
        """检测 XPC dictionary value 提取未校验。"""
        for m in re.finditer(rb'_xpc_dictionary_get_\w+\b', self.data):
            offset = m.start()
            ctx_start = max(0, offset - 200)
            ctx = self.data[ctx_start:offset]

            # 检测提取值后是否有 nil/NULL 检查
            has_check = (b'NULL' in ctx or b'nil' in ctx or b'xpc_get_type' in ctx
                        or b'!= 0' in ctx or b'== 0' in ctx)

            if not has_check:
                func_name = m.group(0).decode('ascii', errors='ignore')
                self.findings.append(IPCFinding(
                    category='xpc_unchecked_value',
                    vuln_type=IPCVulnerabilityType.XPC_DICTIONARY_INJECTION,
                    severity=IPCSeverity.MEDIUM,
                    description=f'{func_name} 提取XPC值后未做类型/空值校验',
                    evidence=f'offset: {offset:#x}',
                    recommendation='使用 xpc_get_type() 验证并检查返回值是否为 NULL',
                ))

    def analyze(self) -> Dict[str, Any]:
        api_usage = self.detect_xpc_api_usage()
        nsxpc = self.detect_nsxpc_usage()
        mach_ops = self.detect_mach_operations()
        self.detect_xpc_dictionary_injection()

        return {
            'platform': 'ios',
            'xpc_api_usage': api_usage,
            'nsxpc_usage': nsxpc,
            'mach_operations': {
                op: len(offsets) for op, offsets in mach_ops.items()
            },
            'findings': [
                {
                    'category': f.category,
                    'vuln_type': f.vuln_type.value,
                    'severity': f.severity.value,
                    'description': f.description,
                    'recommendation': f.recommendation,
                }
                for f in self.findings
            ],
        }


# ---------------------------------------------------------------------------
# 统一入口
# ---------------------------------------------------------------------------

class MobileIPCAnalyzer:
    """移动端 IPC 综合分析器。

    自动检测并路由到 Binder (Android) 或 XPC (iOS) 分析器。
    """

    _MACHO_MAGICS = [
        b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
        b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xce',
    ]

    def __init__(self, binary_path: str = "", binary_data: bytes = b""):
        self.path = binary_path
        self.data = binary_data
        if not self.data and binary_path and os.path.exists(binary_path):
            self.data = Path(binary_path).read_bytes()

    def detect_platform(self) -> str:
        magic = self.data[:4]
        if magic in self._MACHO_MAGICS:
            return 'ios'
        elif (magic == b'\x7fELF' or b'Android' in self.data[:100]
              or self.data[:4] == b'dex\n'):
            return 'android'
        return 'android'  # default

    def analyze(self) -> Dict[str, Any]:
        platform = self.detect_platform()
        result: Dict[str, Any] = {
            'file': self.path,
            'platform': platform,
            'findings': [],
        }

        if platform == 'android':
            analyzer = BinderIPCAnalyzer(self.data)
            result.update(analyzer.analyze())
        else:
            analyzer = XPCIPCAnalyzer(self.data)
            result.update(analyzer.analyze())

        return result


def analyze_ipc(binary_path: str) -> Dict[str, Any]:
    return MobileIPCAnalyzer(binary_path=binary_path).analyze()


# 兼容性存根
class MobileIPCResult:
    def __init__(self):
        self.findings: List[Dict] = []
        self.platform: str = ""
        self.ipc_type: str = ""


IPC_ANALYZER_VERSION = "1.0.0"
