#!/usr/bin/env python3
# 攻击面枚举器。从二进制目标提取导出函数、网络端点、文件路径、IPC/RPC接口。
# 风险评分按远程可达性、鉴权门控、危险函数暴露度、攻击面类型加权。
# 端口→协议对照表手工维护，非完备，覆盖常见场景。
# 积分公式: type_weight + remote*30 + no_auth*20 + params>3*15 + bufsize>1k*10 + danger_name*25
# 总分/1.2调校因子后钳位至[0,100]。

import logging, os, re, subprocess
from datetime import datetime
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Optional

logger = logging.getLogger(__name__)


class AttackSurfaceType(StrEnum):
    EXPORT = 'exported_function'
    NET = 'network_interface'
    FILE = 'file_operation'
    IPC = 'ipc_endpoint'
    RPC = 'rpc_interface'
    CLI = 'command_line'
    CONFIG = 'configuration'


class RiskLevel(StrEnum):
    CRIT = 'Critical'
    HIGH = 'High'
    MED = 'Medium'
    LOW = 'Low'
    INFO = 'Info'


@dataclass
class AttackSurfacePoint:
    name: str = ''
    addr: int = 0
    type: str = AttackSurfaceType.EXPORT
    desc: str = ''
    params: list = field(default_factory=list)
    bufsz: Optional[int] = None
    auth: bool = False
    remote: bool = False
    score: float = 0.0
    level: str = RiskLevel.LOW
    evidence: list = field(default_factory=list)
    relvulns: list = field(default_factory=list)


@dataclass
class AttackSurfaceReport:
    path: str = ''
    points: list = field(default_factory=list)
    nhigh: int = 0
    nmed: int = 0
    nlow: int = 0
    ok: bool = False
    err: str = ''

    def to_dict(self):
        pts = []
        for p in self.points:
            pts.append({
                'name': p.name, 'address': hex(p.addr),
                'surface_type': p.type, 'description': p.desc,
                'parameters': p.params, 'buffer_size': p.bufsz,
                'requires_auth': p.auth, 'is_remote': p.remote,
                'risk_score': p.score, 'risk_level': p.level,
                'evidence': p.evidence, 'related_vulnerabilities': p.relvulns})
        return {'binary_path': self.path, 'surface_points': pts,
                'high_risk_count': self.nhigh, 'medium_risk_count': self.nmed,
                'low_risk_count': self.nlow, 'analysis_success': self.ok,
                'error_message': self.err}


class AttackSurfaceMapper:
    """枚举二进制所有对外暴露的接口，构建攻击面拓扑。"""

    NET_FUNCS = {
        'bind', 'listen', 'accept', 'accept4', 'recv', 'recvfrom', 'recvmsg',
        'send', 'sendto', 'sendmsg', 'socket', 'connect',
        'getaddrinfo', 'gethostbyname', 'gethostbyname2'}
    FILE_FUNCS = {
        'open', 'openat', 'creat', 'fopen', 'fopen64', 'freopen',
        'read', 'write', 'pread', 'pwrite', 'fread', 'fwrite', 'fgets', 'fputs',
        'stat', 'lstat', 'fstat', 'access', 'chmod', 'chown'}
    IPC_FUNCS = {
        'shmget', 'shmat', 'shmdt', 'shmctl', 'mq_open', 'mq_close',
        'mq_send', 'mq_receive', 'semget', 'semop', 'semctl',
        'socketpair', 'pipe', 'pipe2', 'msgget', 'msgsnd', 'msgrcv', 'msgctl'}
    RPC_PATS = (r'RpcServerRegister', r'RpcServerListen', r'RpcBinding',
                r'grpc_', r'__rpc_')
    DANGER = {'gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf',
              'system', 'execve', 'popen', 'fork'}

    def __init__(self, bin_path, info=None):
        self._path = str(bin_path) if bin_path else ''
        self._info = dict(info) if info else {}
        self._pts = []
        self._strs = []

    def _ok(self):
        if not os.path.exists(self._path):
            logger.error(f'file not found: {self._path}')
            return False
        if not os.path.isfile(self._path):
            logger.error(f'not a file: {self._path}')
            return False
        return True

    def _extract_strs(self):
        if self._strs:
            return self._strs
        try:
            with open(self._path, 'rb') as fh:
                data = fh.read()
            cur = []
            off = 0
            for bi in range(len(data)):
                b = data[bi]
                if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D):
                    cur.append(chr(b))
                else:
                    if len(cur) >= 4:
                        self._strs.append((off, ''.join(cur)))
                    cur = []
                    off = bi + 1
            if len(cur) >= 4:
                self._strs.append((off, ''.join(cur)))
            logger.debug(f'extracted {len(self._strs)} strings')
        except Exception as e:
            logger.error(f'string extract failed: {e}')
        return self._strs

    def _extract_exports(self, rpt):
        logger.debug('extracting exports')
        try:
            r = subprocess.run(['readelf', '-s', self._path],
                               capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                for line in r.stdout.split('\n'):
                    parts = line.split()
                    if len(parts) >= 8 and parts[2] == 'FUNC' and parts[6] == 'Global':
                        addr = int(parts[1], 16)
                        name = parts[-1]
                        if not name.startswith('_') and not name.startswith('.'):
                            pt = AttackSurfacePoint(
                                name=name, addr=addr,
                                type=AttackSurfaceType.EXPORT,
                                desc=f'export: {name}', auth=False)
                            self._calc_risk(pt)
                            rpt.points.append(pt)
            else:
                r2 = subprocess.run(['nm', '-D', self._path],
                                    capture_output=True, text=True, timeout=30)
                if r2.returncode == 0:
                    for line in r2.stdout.split('\n'):
                        parts = line.split()
                        if len(parts) >= 3 and parts[1] == 'T':
                            addr = int(parts[0], 16)
                            name = parts[-1]
                            pt = AttackSurfacePoint(
                                name=name, addr=addr,
                                type=AttackSurfaceType.EXPORT,
                                desc=f'export: {name}', auth=False)
                            self._calc_risk(pt)
                            rpt.points.append(pt)
        except Exception as e:
            logger.debug(f'export extract failed: {e}')
            self._exports_from_strs(rpt)

    def _exports_from_strs(self, rpt):
        strs = self._extract_strs()
        func_re = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')
        seen = set()
        for off, s in strs:
            if func_re.match(s) and len(s) > 3 and s not in seen:
                seen.add(s)
                pt = AttackSurfacePoint(
                    name=s, addr=off, type=AttackSurfaceType.EXPORT,
                    desc=f'potential export: {s}',
                    auth=False, evidence=[f'string match: {s}'])
                self._calc_risk(pt)
                rpt.points.append(pt)

    def _extract_net(self, rpt):
        strs = self._extract_strs()
        port_re = re.compile(r':(\d{1,5})\b')
        ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        url_re = re.compile(r'https?://[\w.-]+(?::\d+)?')
        for off, s in strs:
            for m in port_re.finditer(s):
                port = int(m.group(1))
                if 1 <= port <= 65535:
                    proto = self._guess_proto(port)
                    pt = AttackSurfacePoint(
                        name=f'net_port_{port}', addr=off,
                        type=AttackSurfaceType.NET,
                        desc=f'port {port} ({proto})',
                        remote=True, evidence=[f'string: {s}'])
                    self._calc_risk(pt)
                    rpt.points.append(pt)
            if ip_re.search(s):
                pt = AttackSurfacePoint(
                    name=f'net_ip_{s[:20]}', addr=off,
                    type=AttackSurfaceType.NET,
                    desc=f'IP: {s}', remote=True, evidence=[f'string: {s}'])
                self._calc_risk(pt)
                rpt.points.append(pt)
            if url_re.search(s):
                pt = AttackSurfacePoint(
                    name=f'net_url_{s[:20]}', addr=off,
                    type=AttackSurfaceType.NET,
                    desc=f'URL: {s}', remote=True, evidence=[f'string: {s}'])
                self._calc_risk(pt)
                rpt.points.append(pt)

    @staticmethod
    def _guess_proto(port):
        _MAP = {80: 'HTTP', 443: 'HTTPS', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
                53: 'DNS', 110: 'POP3', 143: 'IMAP', 3306: 'MySQL',
                5432: 'PostgreSQL', 27017: 'MongoDB', 6379: 'Redis',
                1521: 'Oracle', 389: 'LDAP', 445: 'SMB', 139: 'NetBIOS'}
        return _MAP.get(port, 'TCP/UDP')

    def _extract_file(self, rpt):
        strs = self._extract_strs()
        pats = (r'\.(txt|log|conf|cfg|dat|json|xml|bin|exe|dll|so)$',
                r'/etc/', r'/var/', r'/home/', r'/tmp/', r'C:\\', r'D:\\')
        for off, s in strs:
            for pat in pats:
                if re.search(pat, s, re.IGNORECASE):
                    pt = AttackSurfacePoint(
                        name=f'file_{s[:20]}', addr=off,
                        type=AttackSurfaceType.FILE,
                        desc=f'file path: {s}', remote=False,
                        evidence=[f'string: {s}'])
                    self._calc_risk(pt)
                    rpt.points.append(pt)
                    break

    def _extract_ipc(self, rpt):
        strs = self._extract_strs()
        pats = (r'/tmp/', r'/run/', r'shm_', r'mq_', r'sem_', r'pipe_',
                r'^IPC_', r'^MSG_')
        for off, s in strs:
            for pat in pats:
                if re.search(pat, s, re.IGNORECASE):
                    pt = AttackSurfacePoint(
                        name=f'ipc_{s[:20]}', addr=off,
                        type=AttackSurfaceType.IPC,
                        desc=f'IPC: {s}', remote=False,
                        evidence=[f'string: {s}'])
                    self._calc_risk(pt)
                    rpt.points.append(pt)
                    break

    def _extract_rpc(self, rpt):
        strs = self._extract_strs()
        for off, s in strs:
            for pat in self.RPC_PATS:
                if re.search(pat, s):
                    pt = AttackSurfacePoint(
                        name=f'rpc_{s[:20]}', addr=off,
                        type=AttackSurfaceType.RPC,
                        desc=f'RPC: {s}', remote=True,
                        evidence=[f'string: {s}'])
                    self._calc_risk(pt)
                    rpt.points.append(pt)
                    break

    def _extract_cli(self, rpt):
        strs = self._extract_strs()
        pats = (r'^--\w+', r'^-\w', r'^/\w+', r'^-h$', r'^--help$',
                r'^-v$', r'^--version$', r'^--config=', r'^-c=')
        for off, s in strs:
            for pat in pats:
                if re.match(pat, s):
                    pt = AttackSurfacePoint(
                        name=f'cli_{s[:20]}', addr=off,
                        type=AttackSurfaceType.CLI,
                        desc=f'CLI option: {s}', remote=False,
                        evidence=[f'string: {s}'])
                    self._calc_risk(pt)
                    rpt.points.append(pt)
                    break

    def _calc_risk(self, pt):
        score = 0.0
        if pt.remote:
            score += 30
        if not pt.auth:
            score += 20
        if len(pt.params) > 3:
            score += 15
        if pt.bufsz is not None and pt.bufsz > 1024:
            score += 10
        if pt.name.lower() in self.DANGER:
            score += 25
        type_weights = {
            AttackSurfaceType.NET: 20, AttackSurfaceType.RPC: 15,
            AttackSurfaceType.EXPORT: 10, AttackSurfaceType.FILE: 10,
            AttackSurfaceType.IPC: 5, AttackSurfaceType.CLI: 5}
        score += type_weights.get(pt.type, 0)
        score = score / 1.2
        if score > 100:
            score = 100
        pt.score = round(score, 2)
        if score >= 80:
            pt.level = RiskLevel.CRIT
        elif score >= 60:
            pt.level = RiskLevel.HIGH
        elif score >= 40:
            pt.level = RiskLevel.MED
        elif score >= 20:
            pt.level = RiskLevel.LOW
        else:
            pt.level = RiskLevel.INFO

    def _categorize(self, rpt):
        hi = 0; med = 0; lo = 0
        for p in rpt.points:
            lv = p.level
            if lv in (RiskLevel.CRIT, RiskLevel.HIGH):
                hi += 1
            elif lv == RiskLevel.MED:
                med += 1
            else:
                lo += 1
        rpt.nhigh = hi; rpt.nmed = med; rpt.nlow = lo

    def analyze(self):
        logger.info(f'attack surface analysis: {self._path}')
        rpt = AttackSurfaceReport(path=self._path)
        if not self._ok():
            rpt.err = f'invalid path: {self._path}'
            return rpt
        try:
            self._extract_exports(rpt)
            self._extract_net(rpt)
            self._extract_file(rpt)
            self._extract_ipc(rpt)
            self._extract_rpc(rpt)
            self._extract_cli(rpt)
            seen = set()
            uniq = []
            for p in rpt.points:
                key = (p.name, p.type)
                if key not in seen:
                    seen.add(key)
                    uniq.append(p)
            rpt.points = uniq
            self._categorize(rpt)
            rpt.points.sort(key=lambda p: p.score, reverse=True)
            rpt.ok = True
            logger.info(f'analysis done: {len(rpt.points)} surface points')
        except Exception as e:
            logger.error(f'analysis failed: {e}')
            rpt.err = str(e)
        return rpt

    def gen_report(self, out=None):
        rpt = self.analyze()
        if not rpt.ok:
            return None
        lines = [
            '# Attack Surface Report', '',
            f'**Target**: `{rpt.path}`',
            f'**Time**: {datetime.now().isoformat()}', '',
            '## Overview', '',
            f'- Critical/High: {rpt.nhigh}',
            f'- Medium: {rpt.nmed}',
            f'- Low/Info: {rpt.nlow}',
            f'- Total: {len(rpt.points)}', '',
            '## Details', '',
            '| Name | Type | Risk | Score | Remote | Auth |',
            '|------|------|------|-------|--------|------|']
        for p in rpt.points:
            lines.append(
                f'| `{p.name}` | {p.type} | {p.level} | '
                f'{p.score} | {"Y" if p.remote else "N"} | '
                f'{"Y" if p.auth else "N"} |')
        content = '\n'.join(lines)
        if out:
            with open(out, 'w', encoding='utf-8') as fh:
                fh.write(content)
            return out
        return content
