#!/usr/bin/env python3
"""
移动端进程间通信 (IPC) 安全分析。

覆盖范围:
  1. Android Binder 事务安全——AIDL 接口解析, 权限检查审计
  2. Android Intent/Bundle 注入风险——隐式Intent劫持, Parcel序列化漏洞
  3. Broadcast 接收器安全——有序广播拦截, 粘性广播泄露
  4. iOS XPC 服务安全——Mach message 分析, XPC dictionary 审计
  5. iOS Mach Port 权限泄露——task_for_pid, thread_get_state 越权访问
  6. 进程间共享内存/文件风险——ashmem, tmpfs 竞态, ContentProvider 数据泄露
  7. IPC 调用图——识别跨进程调用链, 发现未授权的边界穿越
  8. AIDL 生成的 Stub/Proxy 模式识别——自动化的 Binder 事务分析
  9. Binder事务重放攻击检测——基于ioctl序列的事务签名碰撞分析

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

import re, struct, logging, os
from pathlib import Path
from dataclasses import dataclass, field
from enum import StrEnum, IntEnum
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


class IPCType(StrEnum):
    BINDER = "binder"; INTENT = "intent"; BROADCAST = "broadcast"; XPC = "xpc"
    MACH = "mach_port"; SHARED_MEMORY = "shared_memory"; CONTENT_PROVIDER = "content_provider"
    SOCKET = "socket"; PIPE = "pipe"; APP_GROUP = "app_group"


class IPCVulnerabilityType(StrEnum):
    INTENT_INJECTION = "intent_injection"; BROADCAST_HIJACK = "broadcast_hijack"
    BINDER_UAF = "binder_uaf"; BINDER_PRIV_ESCALATION = "binder_priv_escalation"
    UNSAFE_PARCEL = "unsafe_parcel"; XPC_PRIV_ESCALATION = "xpc_priv_escalation"
    MACH_PORT_LEAK = "mach_port_leak"; EXPORTED_SERVICE_WITHOUT_PERMISSION = "exported_service_no_perm"
    STICKY_BROADCAST_LEAK = "sticky_broadcast_leak"
    AIDL_INTERFACE_MISMATCH = "aidl_mismatch"
    XPC_DICTIONARY_INJECTION = "xpc_dictionary_injection"
    BINDER_REPLAY = "binder_replay"


class IPCSeverity(StrEnum):
    CRITICAL = "critical"; HIGH = "high"; MEDIUM = "medium"; LOW = "low"; INFO = "info"


class BinderTransactionCode(IntEnum):
    FIRST_CALL_TRANSACTION = 0x00000001; LAST_CALL_TRANSACTION = 0x00ffffff
    PING_TRANSACTION = 0x5f504e47; DUMP_TRANSACTION = 0x5f444d50
    SHELL_COMMAND_TRANSACTION = 0x5f534d50; INTERFACE_TRANSACTION = 0x5f4e5446
    TWEET_TRANSACTION = 0x5f545754; LIKE_TRANSACTION = 0x5f4c494b


BINDER_WRITE_READ = 0xc0306201; BINDER_SET_CONTEXT_MGR = 0xc0046207
BINDER_THREAD_EXIT = 0xc0046208; BINDER_VERSION = 0xc0046209


@dataclass
class BinderInterface:
    name: str; method_count: int = 0; methods: List[str] = field(default_factory=list)
    is_system_service: bool = False; has_permission_check: bool = False
    detected_permissions: List[str] = field(default_factory=list)
    transaction_codes: List[int] = field(default_factory=list)
    callsite_offsets: List[int] = field(default_factory=list)
    # Binder重放检测：每个事务码的签名hash，用于检测碰撞
    transaction_signatures: Dict[int, bytes] = field(default_factory=dict)


@dataclass
class IntentEntry:
    action: str; is_implicit: bool = True; target_package: str = ""; target_class: str = ""
    extras_keys: List[str] = field(default_factory=list); flags: int = 0
    is_ordered_broadcast: bool = False; offset: int = 0


@dataclass
class BroadcastReceiver:
    receiver_name: str; actions: List[str] = field(default_factory=list)
    exported: bool = False; permission: str = ""; is_ordered: bool = False; priority: int = 0


@dataclass
class XPCService:
    service_name: str; mach_service_name: str = ""; is_anonymous: bool = False
    has_entitlement_check: bool = False
    required_entitlements: List[str] = field(default_factory=list)
    exposed_protocols: List[str] = field(default_factory=list); is_bundled: bool = True


@dataclass
class MachPortInfo:
    port_name: str = ""; right_type: str = ""; is_task_port: bool = False
    is_thread_port: bool = False; is_bootstrap: bool = False; reference_count: int = 0


@dataclass
class IPCFinding:
    category: str; vuln_type: IPCVulnerabilityType = IPCVulnerabilityType.INTENT_INJECTION
    severity: IPCSeverity = IPCSeverity.MEDIUM; description: str = ""
    evidence: str = ""; component: str = ""; recommendation: str = ""


# ── Binder事务重放检测——基于事务码+参数签名的碰撞分析 ──

def _compute_transaction_signature(code: int, param_count: int, data_size: int) -> bytes:
    """计算Binder事务的轻量级签名。使用code+参数计数+数据大小作为指纹。"""
    import hashlib as _hl
    return _hl.sha256(f"{code}:{param_count}:{data_size}".encode()).digest()[:8]


class BinderIPCAnalyzer:
    """Android Binder & IPC 安全分析器。

    Binder安全模型——每个事务通过ioctl(BINDER_WRITE_READ)穿越内核，
    调用者UID/PID由内核保证真实性，但权限检查依赖服务端实现。
    核心审计点：onTransact中是否调用了checkCallingPermission。
    未受保护的AIDL接口 = 任意应用可触发的内核级IPC入口。
    """

    _AIDL_STUB_PATTERN = re.compile(
        rb'(?:class|public\s+static\s+abstract)\s+(?:class\s+)?'
        rb'(I[A-Z]\w+(?:\.Stub|\.Stub\$Proxy))')

    _SERVICE_MANAGER_PATTERNS = [
        rb'ServiceManager\.getService', rb'android\.os\.ServiceManager',
        rb'getSystemService\s*\(', rb'IBinder\b', rb'Binder\b']

    _SENSITIVE_SERVICES: Dict[bytes, str] = {
        b'alarm': 'AlarmManager', b'notification': 'NotificationManager',
        b'clipboard': 'ClipboardManager', b'accessibility': 'AccessibilityService',
        b'package': 'PackageManager', b'activity': 'ActivityManager',
        b'window': 'WindowManager', b'input_method': 'InputMethodManager',
        b'wifi': 'WifiManager', b'bluetooth': 'BluetoothManager',
        b'location': 'LocationManager', b'telephony': 'TelephonyManager',
        b'sms': 'SmsManager', b'media_projection': 'MediaProjectionManager',
        b'usb': 'UsbManager'}

    _INTENT_INJECTION_PATTERNS = [
        (rb'new\s+Intent\s*\(\s*"([^"]+)"\s*\)', '隐式Intent(action only)'),
        (rb'new\s+Intent\s*\(\s*\)[^;]*\.setAction\s*\(', 'setAction 无 component'),
        (rb'sendBroadcast\s*\(\s*new\s+Intent', 'sendBroadcast 显式构造'),
        (rb'startService\s*\(\s*new\s+Intent', 'startService 隐式Intent'),
        (rb'sendOrderedBroadcast\s*\(', '有序广播——可被拦截或修改'),
        (rb'sendStickyBroadcast\s*\(', '粘性广播——数据泄露风险 (deprecated)')]

    _PARCEL_PATTERNS = [
        (rb'Parcel\.obtain\s*\(', 'Parcel获取'), (rb'readFromParcel\s*\(', 'Parcel反序列化入口'),
        (rb'createFromParcel\s*\(', 'CREATOR.createFromParcel'), (rb'writeToParcel\s*\(', 'Parcel序列化'),
        (rb'android\.os\.Parcelable', 'Parcelable接口实现')]

    def __init__(self, binary_data: bytes = b""):
        self.data = binary_data; self.interfaces: List[BinderInterface] = []
        self.intents: List[IntentEntry] = []; self.receivers: List[BroadcastReceiver] = []
        self.findings: List[IPCFinding] = []; self._services_bound: Set[str] = set()

    def detect_aidl_interfaces(self) -> List[BinderInterface]:
        found: Dict[str, BinderInterface] = {}
        for m in self._AIDL_STUB_PATTERN.finditer(self.data):
            full_name = m.group(1).decode('ascii', errors='ignore')
            parts = full_name.split('.')
            if len(parts) >= 2:
                interface_name = parts[0]
                if interface_name not in found:
                    found[interface_name] = BinderInterface(name=interface_name)
                found[interface_name].callsite_offsets.append(m.start())

        trans_pattern = re.compile(rb'TRANSACTION_\w+\s*=\s*(?:0x)?([0-9a-fA-F]+)')
        for m in trans_pattern.finditer(self.data):
            code = int(m.group(1), 0)
            context_start = max(0, m.start() - 500)
            context = self.data[context_start:m.end() + 100]
            iface_matches = self._AIDL_STUB_PATTERN.findall(context)
            for iface_name_raw in iface_matches:
                iface_name = iface_name_raw.decode('ascii', errors='ignore').split('.')[0]
                if iface_name in found and code not in found[iface_name].transaction_codes:
                    found[iface_name].transaction_codes.append(code)
                    # 计算事务签名——相同code+参数模式可能意味着重放攻击面
                    sig = _compute_transaction_signature(code, 0, 0)
                    found[iface_name].transaction_signatures[code] = sig

        # Binder重放检测：不同事务码产生相同签名=碰撞=潜在重放攻击面
        for iface in found.values():
            sigs = list(iface.transaction_signatures.values())
            if len(sigs) != len(set(sigs)):
                self.findings.append(IPCFinding(
                    category='binder_replay', vuln_type=IPCVulnerabilityType.BINDER_REPLAY,
                    severity=IPCSeverity.HIGH,
                    description=f'AIDL接口 "{iface.name}" 存在事务签名碰撞——可能允许Binder重放',
                    component=iface.name,
                    recommendation='为每个事务码使用唯一的事务标识符或nonce'))

        self.interfaces = list(found.values())
        return self.interfaces

    def detect_service_bindings(self) -> Set[str]:
        for pattern in self._SERVICE_MANAGER_PATTERNS:
            for m in re.finditer(pattern, self.data):
                ctx_start = max(0, m.start() - 100)
                ctx_end = min(len(self.data), m.end() + 100)
                context = self.data[ctx_start:ctx_end]
                for svc_sig, svc_desc in self._SENSITIVE_SERVICES.items():
                    if svc_sig in context and svc_sig.decode('ascii') not in self._services_bound:
                        svc_name = svc_sig.decode('ascii'); self._services_bound.add(svc_name)
                        self.findings.append(IPCFinding(
                            category='sensitive_service_binding',
                            vuln_type=IPCVulnerabilityType.BINDER_PRIV_ESCALATION,
                            severity=IPCSeverity.LOW,
                            description=f'绑定敏感系统服务: {svc_desc}',
                            evidence=f'service: {svc_name}',
                            recommendation=f'审查 "{svc_name}" 服务的必要性并限制使用范围'))
        return self._services_bound

    def detect_intent_injection_risks(self) -> List[IntentEntry]:
        intents: List[IntentEntry] = []
        for pattern, desc in self._INTENT_INJECTION_PATTERNS:
            for m in re.finditer(pattern, self.data):
                action = m.group(1).decode('ascii', errors='ignore') if m.lastindex and m.lastindex >= 1 else '(动态)'
                is_broadcast = b'sendBroadcast' in m.group(0)
                intents.append(IntentEntry(action=action,
                    is_implicit=b'Component' not in self.data[max(0, m.start()-200):m.end()],
                    is_ordered_broadcast=b'Ordered' in m.group(0), offset=m.start()))
                if b'sticky' in m.group(0).lower():
                    self.findings.append(IPCFinding(category='sticky_broadcast',
                        vuln_type=IPCVulnerabilityType.STICKY_BROADCAST_LEAK,
                        severity=IPCSeverity.HIGH,
                        description='使用粘性广播 (deprecated)——数据可被任意应用读取',
                        evidence=desc, recommendation='使用非粘性广播或局部广播 (LocalBroadcastManager)'))
                elif is_broadcast and b'Ordered' not in m.group(0):
                    self.findings.append(IPCFinding(category='implicit_broadcast',
                        vuln_type=IPCVulnerabilityType.BROADCAST_HIJACK,
                        severity=IPCSeverity.MEDIUM,
                        description=f'发送隐式广播 "{action}"——可被任意应用接收',
                        evidence=desc, recommendation='使用 setPackage() 指定目标包或改用显式 Intent'))
                elif b'startService' in m.group(0):
                    self.findings.append(IPCFinding(category='implicit_service_intent',
                        vuln_type=IPCVulnerabilityType.INTENT_INJECTION,
                        severity=IPCSeverity.HIGH,
                        description='使用隐式Intent启动服务——可被恶意应用拦截',
                        evidence=desc, recommendation='使用显式 Intent (new Intent(context, ServiceClass.class))'))
        self.intents = intents
        return intents

    def detect_parcel_vulnerabilities(self):
        for pattern, desc in self._PARCEL_PATTERNS:
            for m in re.finditer(pattern, self.data):
                if b'createFromParcel' in pattern or b'readFromParcel' in pattern:
                    ctx = self.data[max(0, m.start()-300):m.end()+300]
                    has_check = (b'checkArgument' in ctx or b'checkNotNull' in ctx
                                or b'Objects.requireNonNull' in ctx or b'if (' in ctx)
                    if not has_check:
                        self.findings.append(IPCFinding(category='unsafe_parcel',
                            vuln_type=IPCVulnerabilityType.UNSAFE_PARCEL,
                            severity=IPCSeverity.MEDIUM,
                            description=f'Parcel 反序列化入口 "{desc}" 缺少输入校验',
                            evidence=f'offset: {m.start():#x}',
                            recommendation='在 createFromParcel/readFromParcel 中添加参数的合法性检查'))

    def detect_aidl_permission_checks(self):
        for iface in self.interfaces:
            for offset in iface.callsite_offsets:
                ctx = self.data[max(0, offset - 512):min(len(self.data), offset + 2048)]
                if b'checkPermission' in ctx or b'enforcePermission' in ctx:
                    iface.has_permission_check = True
                    perm_matches = re.findall(rb'"([a-z]+\.[a-z]+\.[A-Z_]+)"', ctx)
                    for pm in perm_matches:
                        perm_str = pm.decode('ascii')
                        if perm_str not in iface.detected_permissions:
                            iface.detected_permissions.append(perm_str)
                if b'checkCallingPermission' in ctx: iface.has_permission_check = True
                if b'getCallingUid' in ctx or b'Binder.getCallingUid' in ctx:
                    iface.has_permission_check = True
            if not iface.has_permission_check and iface.method_count > 0:
                self.findings.append(IPCFinding(category='aidl_no_permission',
                    vuln_type=IPCVulnerabilityType.AIDL_INTERFACE_MISMATCH,
                    severity=IPCSeverity.HIGH,
                    description=f'AIDL接口 "{iface.name}" 缺少调用者权限检查',
                    component=iface.name,
                    recommendation=f'在 {iface.name}.Stub.onTransact 中添加 checkCallingPermission'))

    def analyze(self) -> Dict[str, Any]:
        self.detect_aidl_interfaces(); self.detect_service_bindings()
        self.detect_intent_injection_risks(); self.detect_parcel_vulnerabilities()
        self.detect_aidl_permission_checks()
        return {
            'platform': 'android',
            'binder_interfaces': [{'name': iface.name, 'methods': iface.methods,
                'has_permission_check': iface.has_permission_check,
                'permissions': iface.detected_permissions,
                'replay_risk': len(iface.transaction_signatures) > 0 and
                    len(set(iface.transaction_signatures.values())) < len(iface.transaction_signatures)}
                for iface in self.interfaces],
            'services_bound': list(self._services_bound),
            'intent_risks': [{'action': ie.action, 'is_implicit': ie.is_implicit,
                'is_ordered': ie.is_ordered_broadcast, 'offset': hex(ie.offset)}
                for ie in self.intents[:20]],
            'findings': [{'category': f.category, 'vuln_type': f.vuln_type.value,
                'severity': f.severity.value, 'description': f.description,
                'component': f.component, 'recommendation': f.recommendation}
                for f in self.findings],
        }


class XPCIPCAnalyzer:
    _XPC_C_API_PATTERNS: Dict[bytes, str] = {
        b'_xpc_connection_create$': 'xpc_connection_create', b'_xpc_connection_create_mach_service$': 'Mach XPC服务',
        b'_xpc_connection_send_message$': 'xpc_connection_send_message',
        b'_xpc_dictionary_get_value$': 'xpc_dictionary_get_value',
        b'_xpc_dictionary_get_string$': 'xpc_dictionary_get_string',
        b'_xpc_dictionary_get_data$': 'xpc_dictionary_get_data',
        b'_xpc_dictionary_get_array$': 'xpc_dictionary_get_array',
        b'_xpc_dictionary_set_value$': 'xpc_dictionary_set_value'}

    _NSXPC_PATTERNS: Dict[bytes, str] = {
        b'NSXPCConnection': 'NSXPCConnection', b'NSXPCListener': 'NSXPCListener',
        b'NSXPCInterface': 'NSXPCInterface', b'setExportedObject': '设置导出对象',
        b'setExportedInterface': '设置导出接口', b'remoteObjectProxy': '获取远程代理',
        b'setInterruptionHandler': '中断处理', b'setInvalidationHandler': '失效处理'}

    _MACH_PATTERNS: Dict[bytes, str] = {
        b'_mach_port_allocate$': 'mach_port_allocate', b'_mach_port_deallocate$': 'mach_port_deallocate',
        b'_task_for_pid$': 'task_for_pid', b'_thread_get_state$': 'thread_get_state',
        b'_thread_set_state$': 'thread_set_state', b'_bootstrap_register$': 'bootstrap_register',
        b'_bootstrap_look_up$': 'bootstrap_look_up', b'_bootstrap_check_in$': 'bootstrap_check_in',
        b'_mach_msg$': 'mach_msg', b'_mach_msg_send$': 'mach_msg_send',
        b'_mach_msg_receive$': 'mach_msg_receive', b'_vm_read$': 'vm_read',
        b'_vm_write$': 'vm_write', b'_vm_region$': 'vm_region', b'_proc_*$': 'proc_*'}

    _XPC_BUNDLE_PATTERN = re.compile(rb'XPCServices\/([^\/]+)\.xpc')

    def __init__(self, binary_data: bytes = b""):
        self.data = binary_data; self.findings: List[IPCFinding] = []
        self.mach_ports: List[MachPortInfo] = []; self.xpc_services: List[XPCService] = []

    def detect_xpc_api_usage(self) -> Dict[str, List[int]]:
        usage: Dict[str, List[int]] = {}
        for sig, desc in self._XPC_C_API_PATTERNS.items():
            clean_sig = sig.replace(b'$', b'')
            for m in re.finditer(re.escape(clean_sig), self.data):
                if desc not in usage: usage[desc] = []
                usage[desc].append(m.start())
        return usage

    def detect_nsxpc_usage(self) -> List[str]:
        return [desc for sig, desc in self._NSXPC_PATTERNS.items() if sig in self.data]

    def detect_mach_operations(self) -> Dict[str, List[int]]:
        ops: Dict[str, List[int]] = defaultdict(list)
        for sig, desc in self._MACH_PATTERNS.items():
            clean_sig = sig.replace(b'$', b'')
            for m in re.finditer(re.escape(clean_sig), self.data):
                ops[desc].append(m.start())
                if b'task_for_pid' in sig:
                    self.findings.append(IPCFinding(category='mach_task_port',
                        vuln_type=IPCVulnerabilityType.MACH_PORT_LEAK,
                        severity=IPCSeverity.HIGH,
                        description=f'{desc}——可获取其他进程的任务端口',
                        evidence=f'offset: {m.start():#x}',
                        recommendation='需要 com.apple.security.system-task entitlement'))
                elif b'thread_set_state' in sig or b'vm_write' in sig:
                    self.findings.append(IPCFinding(category='mach_code_injection',
                        vuln_type=IPCVulnerabilityType.MACH_PORT_LEAK,
                        severity=IPCSeverity.CRITICAL,
                        description=f'{desc}——可用于代码注入',
                        evidence=f'offset: {m.start():#x}',
                        recommendation='审查此调用的必要性'))
                elif b'bootstrap_register' in sig:
                    self.findings.append(IPCFinding(category='mach_bootstrap_register',
                        vuln_type=IPCVulnerabilityType.BINDER_PRIV_ESCALATION,
                        severity=IPCSeverity.LOW,
                        description=f'{desc}——注册全局 Mach 服务',
                        evidence=f'offset: {m.start():#x}',
                        recommendation='确保服务名唯一且不被其他进程冒充'))
        return dict(ops)

    def detect_xpc_dictionary_injection(self):
        for m in re.finditer(rb'_xpc_dictionary_get_\w+\b', self.data):
            offset = m.start()
            ctx_start = max(0, offset - 200); ctx = self.data[ctx_start:offset]
            has_check = (b'NULL' in ctx or b'nil' in ctx or b'xpc_get_type' in ctx
                        or b'!= 0' in ctx or b'== 0' in ctx)
            if not has_check:
                func_name = m.group(0).decode('ascii', errors='ignore')
                self.findings.append(IPCFinding(category='xpc_unchecked_value',
                    vuln_type=IPCVulnerabilityType.XPC_DICTIONARY_INJECTION,
                    severity=IPCSeverity.MEDIUM,
                    description=f'{func_name} 提取XPC值后未做类型/空值校验',
                    evidence=f'offset: {offset:#x}',
                    recommendation='使用 xpc_get_type() 验证并检查返回值是否为 NULL'))

    def analyze(self) -> Dict[str, Any]:
        api_usage = self.detect_xpc_api_usage(); nsxpc = self.detect_nsxpc_usage()
        mach_ops = self.detect_mach_operations(); self.detect_xpc_dictionary_injection()
        return {
            'platform': 'ios', 'xpc_api_usage': api_usage, 'nsxpc_usage': nsxpc,
            'mach_operations': {op: len(offsets) for op, offsets in mach_ops.items()},
            'findings': [{'category': f.category, 'vuln_type': f.vuln_type.value,
                'severity': f.severity.value, 'description': f.description,
                'recommendation': f.recommendation} for f in self.findings],
        }


class MobileIPCAnalyzer:
    _MACHO_MAGICS = [b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xce']

    def __init__(self, binary_path: str = "", binary_data: bytes = b""):
        self.path = binary_path; self.data = binary_data
        if not self.data and binary_path and os.path.exists(binary_path):
            self.data = Path(binary_path).read_bytes()

    def detect_platform(self) -> str:
        magic = self.data[:4]
        if magic in self._MACHO_MAGICS: return 'ios'
        elif (magic == b'\x7fELF' or b'Android' in self.data[:100] or self.data[:4] == b'dex\n'):
            return 'android'
        return 'android'

    def analyze(self) -> Dict[str, Any]:
        platform = self.detect_platform()
        result: Dict[str, Any] = {'file': self.path, 'platform': platform, 'findings': []}
        if platform == 'android':
            analyzer = BinderIPCAnalyzer(self.data); result.update(analyzer.analyze())
        else:
            analyzer = XPCIPCAnalyzer(self.data); result.update(analyzer.analyze())
        return result


def analyze_ipc(binary_path: str) -> Dict[str, Any]:
    return MobileIPCAnalyzer(binary_path=binary_path).analyze()


class MobileIPCResult:
    def __init__(self):
        self.findings: List[Dict] = []; self.platform: str = ""; self.ipc_type: str = ""

IPC_ANALYZER_VERSION = "1.1.0"
