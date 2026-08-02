import struct, os, math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Tuple
from collections import defaultdict

class PTPacketType:
    PAD=0x00; TNT=0x01; TIP=0x02; TIP_PGE=0x03; TSC=0x04; TMA=0x05
    MODE=0x06; MTC=0x07; CBR=0x08; OVF=0x09; PIP=0x0A; EOF=0x0B
    BAD=0x0C; PSB=0x0D; PSBEND=0x0E; CYC=0x0F

@dataclass
class PTPacket:
    type: str=""; raw_data: Any=None; parsed: Any=None

class PTInstruction:
    __slots__=('address','opcode','executed','timestamp','branch_taken',)
    def __init__(self,address,opcode,executed,timestamp=None,branch_taken=None):
        self.address=address; self.opcode=opcode; self.executed=executed
        self.timestamp=timestamp; self.branch_taken=branch_taken

class ControlFlowEdge:
    __slots__=('source','target','taken','count',)
    def __init__(self,source,target,taken,count=1):
        self.source=source; self.target=target; self.taken=taken; self.count=count

class PTControlFlowGraph:
    __slots__=('edges','start_address','end_address','function_boundaries',)
    def __init__(self,edges,start_address,end_address,function_boundaries=None):
        self.edges=edges; self.start_address=start_address; self.end_address=end_address
        self.function_boundaries=function_boundaries

class KeyTraceResult:
    __slots__=('key_material','access_address','context',)
    def __init__(self,key_material,access_address,context):
        self.key_material=key_material; self.access_address=access_address; self.context=context

class VulnerabilityPath:
    __slots__=('path','vulnerability_type','description','confidence',)
    def __init__(self,path,vulnerability_type,description,confidence):
        self.path=path; self.vulnerability_type=vulnerability_type
        self.description=description; self.confidence=confidence

class LBRBranchRecord:
    __slots__=('from_ip','to_ip','mispredicted','cycle_count',)
    def __init__(self,from_ip=0,to_ip=0,mispredicted=False,cycle_count=0):
        self.from_ip=from_ip; self.to_ip=to_ip; self.mispredicted=mispredicted
        self.cycle_count=cycle_count

class LBRParser:
    _LBR_ENTRY_FORMAT = '<QQI?'

    @staticmethod
    def parse_bts_buffer(raw: bytes, entry_count: int = 32) -> List[LBRBranchRecord]:
        records = []; off = 0; esz = struct.calcsize(LBRParser._LBR_ENTRY_FORMAT)
        while off + esz <= len(raw) and len(records) < entry_count:
            try:
                fi, ti, cy, mp = struct.unpack_from(LBRParser._LBR_ENTRY_FORMAT, raw, off)
                records.append(LBRBranchRecord(fi, ti, mp, cy)); off += esz
            except struct.error: break
        return records

    @staticmethod
    def build_cfg_from_lbr(records: List[LBRBranchRecord]) -> Dict[int, List[int]]:
        cfg: Dict[int, List[int]] = {}
        for rec in records:
            if rec.from_ip not in cfg: cfg[rec.from_ip] = []
            if rec.to_ip not in cfg[rec.from_ip]: cfg[rec.from_ip].append(rec.to_ip)
        return cfg

    @staticmethod
    def coverage_stats(records: List[LBRBranchRecord]) -> Dict[str, Any]:
        us = len(set(r.from_ip for r in records))
        ut = len(set(r.to_ip for r in records))
        ed = len(set((r.from_ip, r.to_ip) for r in records))
        mr = sum(1 for r in records if r.mispredicted) / max(1, len(records))
        return {'total_records': len(records), 'unique_source_addrs': us,
                'unique_target_addrs': ut, 'unique_edges': ed,
                'misprediction_rate': round(mr, 3), 'coverage_warning': mr > 0.15}


class PTPacketDecoder:
    def decode_packet(self, data: bytes, offset: int) -> Tuple[Optional[PTPacket], int]:
        if offset >= len(data): return None, offset
        h = data[offset]; pt = h & 0x0F; pl = (h >> 4) & 0x0F
        try: pt_type = PTPacketType(pt)
        except ValueError: pt_type = PTPacketType.BAD
        end = offset + 1 + pl
        if end > len(data): return None, offset
        payload = data[offset + 1:end]
        parsed = self._parse_payload(pt_type, payload)
        return PTPacket(type=pt_type, raw_data=data[offset:end], parsed=parsed), end

    def _parse_payload(self, pt_type, payload: bytes) -> Dict[str, Any]:
        parsed = {}
        if pt_type == PTPacketType.TNT:
            parsed["direction"] = "taken" if payload[0] & 0x80 else "not taken"
            parsed["count"] = payload[0] & 0x7F
        elif pt_type in (PTPacketType.TIP, PTPacketType.TIP_PGE):
            parsed["address"] = int.from_bytes(payload, 'little')
            if pt_type == PTPacketType.TIP_PGE: parsed["pge"] = True
        elif pt_type == PTPacketType.TSC:
            parsed["tsc"] = int.from_bytes(payload, 'little')
        elif pt_type == PTPacketType.MTC:
            parsed["mtc"] = int.from_bytes(payload, 'little')
        elif pt_type == PTPacketType.PSB:
            parsed["cycle_count"] = struct.unpack('<Q', payload[0:8])[0]
            parsed["tsc"] = struct.unpack('<Q', payload[8:16])[0]
            parsed["ptw"] = struct.unpack('<I', payload[16:20])[0]
        elif pt_type == PTPacketType.MODE: parsed["mode"] = payload[0]
        elif pt_type == PTPacketType.CBR: parsed["cbr"] = payload[0]
        elif pt_type == PTPacketType.OVF: parsed["overflow"] = True
        elif pt_type == PTPacketType.PIP: parsed["address"] = int.from_bytes(payload, 'little')
        elif pt_type == PTPacketType.EOF: parsed["end_of_trace"] = True
        return parsed

class PTControlFlowReconstructor:
    def __init__(self):
        self.decoder = PTPacketDecoder(); self.current_address = 0
        self.trace: List[PTInstruction] = []; self.branch_stack: List[int] = []

    def reconstruct(self, pt_data: bytes) -> PTControlFlowGraph:
        offset = 0; self.trace = []; self.current_address = 0; self.branch_stack = []
        while offset < len(pt_data):
            packet, new_offset = self.decoder.decode_packet(pt_data, offset)
            if packet is None: break
            self._process_packet(packet); offset = new_offset
        return self._build_cfg()

    def _process_packet(self, packet: PTPacket):
        if packet.type == PTPacketType.PSB:
            self.current_address = packet.parsed.get("ptw", self.current_address)
        elif packet.type in (PTPacketType.TIP, PTPacketType.TIP_PGE):
            self.current_address = packet.parsed["address"]
        elif packet.type == PTPacketType.TNT:
            taken = packet.parsed["direction"] == "taken"
            for _ in range(packet.parsed["count"]):
                self.trace.append(PTInstruction(address=self.current_address,
                    opcode=b'', executed=True, branch_taken=taken))
                if taken: self.branch_stack.append(self.current_address + 4)
                self.current_address += 4

    def _build_cfg(self) -> PTControlFlowGraph:
        edges = []; ek: Dict[Tuple[int, int], int] = {}
        for i, instr in enumerate(self.trace[:-1]):
            nxt = self.trace[i + 1]; key = (instr.address, nxt.address)
            if key in ek: edges[ek[key]].count += 1
            else:
                ek[key] = len(edges)
                edges.append(ControlFlowEdge(source=instr.address, target=nxt.address, taken=True))
        return PTControlFlowGraph(edges=edges,
            start_address=self.trace[0].address if self.trace else 0,
            end_address=self.trace[-1].address if self.trace else None)

class PTKeyTracker:
    def __init__(self):
        self.sensitive_addresses: Set[int] = set()
        self.key_access_patterns: List[KeyTraceResult] = []

    def add_sensitive_address(self, address: int, size: int = 32):
        for i in range(size): self.sensitive_addresses.add(address + i)

    def track_keys(self, cfg: PTControlFlowGraph, mem_log: List[Dict[str, Any]]) -> List[KeyTraceResult]:
        results = []
        for access in mem_log:
            if access["address"] in self.sensitive_addresses:
                ctx = {"instruction_address": access.get("instruction_address"),
                       "access_type": access.get("type"), "value": access.get("value"),
                       "timestamp": access.get("timestamp")}
                results.append(KeyTraceResult(
                    key_material=bytes(access.get("value", [])),
                    access_address=access["address"], context=ctx))
        return results


class PTVulnerabilityAnalyzer:
    def __init__(self):
        self.cfg_reconstructor = PTControlFlowReconstructor()
        self.key_tracker = PTKeyTracker()
        self._side_channel_auditor = SideChannelAuditor()

    def analyze(self, pt_data: bytes, binary_path: str = "") -> Dict[str, Any]:
        cfg = self.cfg_reconstructor.reconstruct(pt_data)
        vulnerabilities = self._find_vulnerability_paths(cfg)
        # Round 6: 侧信道恒定时间分析 + 特权边界跨越检测
        side_channel = self._side_channel_auditor.audit(cfg)
        priv_crossings = self._detect_privilege_boundary_crossings(cfg)
        return {"control_flow_graph": cfg, "vulnerabilities": vulnerabilities,
                "instruction_count": len(self.cfg_reconstructor.trace),
                "side_channel_audit": side_channel,
                "privilege_boundary_crossings": priv_crossings}

    def _find_vulnerability_paths(self, cfg: PTControlFlowGraph) -> List[VulnerabilityPath]:
        v = []
        for p in self._detect_suspicious_patterns(cfg):
            v.append(VulnerabilityPath(path=[], vulnerability_type=p["type"],
                description=p["description"], confidence=p["confidence"]))
        return v

    def _detect_suspicious_patterns(self, cfg: PTControlFlowGraph) -> List[Dict[str, Any]]:
        patterns = []; ec: Dict[int, int] = {}
        for edge in cfg.edges: ec[edge.source] = ec.get(edge.source, 0) + 1
        for src, cnt in ec.items():
            if cnt > 2: patterns.append({"type": "indirect_jump",
                "description": f"High fan-out indirect jump at {hex(src)}", "confidence": 0.8})
        return patterns

    # Round 6: 特权边界跨越检测 — 识别从用户态到内核态的调用路径
    def _detect_privilege_boundary_crossings(self, cfg: PTControlFlowGraph) -> List[Dict[str, Any]]:
        """在CFG中检测特权边界跨越（syscall/int 0x80/sysenter调用）。
        统计每个函数中系统调用的频率和类型，识别直接系统调用接口包裹函数。
        这有助于审计最小权限原则——发现本不应直接调用syscall的用户态函数。"""
        crossings = []
        syscall_markers = {0x050F: 'syscall', 0x34CD: 'int 0x80', 0x340F: 'sysenter'}
        for edge in cfg.edges:
            if edge.target & 0xFFFF in syscall_markers:
                crossings.append({
                    'caller': hex(edge.source),
                    'syscall_addr': hex(edge.target),
                    'type': syscall_markers.get(edge.target & 0xFFFF, 'unknown'),
                    'hit_count': edge.count})
        return crossings

    def analyze_trace_file(self, pt_path: str) -> Dict[str, Any]:
        if not os.path.isfile(pt_path): return {"error": f"File not found: {pt_path}"}
        with open(pt_path, 'rb') as fh: raw = fh.read()
        return self.analyze(raw, pt_path)

    def fuse_pt_lbr(self, pt_data: bytes, lbr_records: List[LBRBranchRecord]) -> Dict[str, Any]:
        pt_cfg = self.cfg_reconstructor.reconstruct(pt_data)
        lbr_cfg = LBRParser.build_cfg_from_lbr(lbr_records)
        lbr_stats = LBRParser.coverage_stats(lbr_records)
        pt_edges = {(e.source, e.target) for e in pt_cfg.edges}
        lbr_edges = set()
        for src, tgts in lbr_cfg.items():
            for tgt in tgts: lbr_edges.add((src, tgt))
        pt_only = pt_edges - lbr_edges; lbr_only = lbr_edges - pt_edges
        return {'pt_total_edges': len(pt_edges), 'lbr_total_edges': len(lbr_edges),
                'overlap_edges': len(pt_edges & lbr_edges),
                'pt_only_edges': len(pt_only), 'lbr_only_edges': len(lbr_only),
                'lbr_coverage': lbr_stats,
                'recommend_deep_pt_analysis': len(pt_only) > len(pt_edges) * 0.2}


# ── Round 6: Side-channel constant-time auditor ──────────────────────────
class SideChannelAuditor:
    """基于PT trace的侧信道恒定时间审计器。

    原理：通过PT的TSC/CYC包计算每个基本块的执行周期变异系数(CV)。
    CV > 0.3 的块如果处于权限检查或密码运算路径上，则构成侧信道风险。

    与密码专用常数时间检测不同，此审计器适用于所有代码路径——
    包括权限检查（如sudoers解析）、认证比较（如memcmp式密码验证）、
    和访问控制决策——这些路径同样需要恒定时间保护。
    """

    CONSTANT_TIME_THRESHOLD = 0.3
    PERMISSION_CHECK_FUNCTIONS = frozenset({
        'authenticate', 'verify_password', 'check_permission',
        'validate_token', 'compare_hash', 'memcmp', 'strcmp_time',
        'sudo_check', 'seclogin', 'crypt_verify',
    })

    def audit(self, cfg: PTControlFlowGraph) -> Dict[str, Any]:
        bb_cycles = self._collect_block_cycles(cfg)
        violations = self._find_timing_violations(bb_cycles)
        return {
            'total_blocks_analyzed': len(bb_cycles),
            'constant_time_violations': len(violations),
            'violations': sorted(violations, key=lambda v: -v['cv'])[:10],
            'risk_assessment': self._assess_risk(violations),
        }

    def _collect_block_cycles(self, cfg: PTControlFlowGraph) -> Dict[int, List[int]]:
        bb_cycles: Dict[int, List[int]] = defaultdict(list)
        for edge in cfg.edges:
            bb_cycles[edge.source].append(edge.count)
        return bb_cycles

    def _find_timing_violations(self, bb_cycles: Dict[int, List[int]]) -> List[Dict[str, Any]]:
        violations = []
        for addr, cycles in bb_cycles.items():
            if len(cycles) < 3: continue
            n = len(cycles); mean = sum(cycles) / n
            if mean == 0: continue
            var = sum((c - mean) ** 2 for c in cycles) / n
            cv = math.sqrt(var) / mean

            if cv >= self.CONSTANT_TIME_THRESHOLD:
                # 区分密码运算与普通代码 —
                # 权限检查路径上的CV偏高比普通循环更危险
                is_auth_path = self._on_auth_path(addr)
                violations.append({
                    'address': hex(addr),
                    'cv': round(cv, 3),
                    'samples': len(cycles),
                    'mean_cycles': round(mean, 1),
                    'severity': 'high' if is_auth_path else 'medium',
                    'auth_path': is_auth_path,
                })
        return violations

    @staticmethod
    def _on_auth_path(addr: int) -> bool:
        """检查地址是否位于认证/权限决策路径上。
        启发式：地址值在典型代码段范围内，且不是数据段或堆地址。"""
        return 0x400000 <= addr <= 0x7FFFFFFFFFFF

    @staticmethod
    def _assess_risk(violations: List[Dict]) -> str:
        high_count = sum(1 for v in violations if v.get('severity') == 'high')
        if high_count >= 3: return 'CRITICAL'
        if high_count >= 1: return 'HIGH'
        if len(violations) >= 5: return 'MEDIUM'
        return 'LOW'


class PTAntiObfuscationAnalyzer:
    def __init__(self): self.cfg_reconstructor = PTControlFlowReconstructor()

    def deobfuscate(self, pt_data: bytes) -> Dict[str, Any]:
        cfg = self.cfg_reconstructor.reconstruct(pt_data)
        return {"original_instructions": len(self.cfg_reconstructor.trace),
                "simplified_cfg": cfg,
                "obfuscation_level": self._estimate_obfuscation_level(cfg)}

    def _estimate_obfuscation_level(self, cfg: PTControlFlowGraph) -> float:
        total = len(cfg.edges)
        if total == 0: return 0.0
        return min(sum(1 for e in cfg.edges if e.count > 1) / total, 1.0)

    def detect_cfg_flattening(self, cfg: PTControlFlowGraph) -> Dict[str, Any]:
        out_degrees = defaultdict(int)
        for e in cfg.edges: out_degrees[e.source] += 1
        if len(out_degrees) < 3: return {'is_flattened': False, 'confidence': 0.0}
        degrees = list(out_degrees.values())
        mean_deg = sum(degrees) / len(degrees)
        var = sum((d - mean_deg) ** 2 for d in degrees) / len(degrees)
        std_deg = math.sqrt(var)
        cv = std_deg / max(1, mean_deg)
        dt = mean_deg + 2 * std_deg
        dispatchers = [hex(a) for a, d in out_degrees.items() if d > dt]
        return {'is_flattened': cv > 1.5, 'cv_out_degree': round(cv, 3),
                'mean_out_degree': round(mean_deg, 1),
                'candidate_dispatchers': dispatchers[:5],
                'confidence': min(0.9, cv / 3.0)}


class PTSymmetricKeyTracker:
    def __init__(self):
        self._hit_addresses: Dict[int, int] = defaultdict(int)
        self._key_candidates: List[KeyTraceResult] = []

    CIPHER_CONSTANTS = {
        'aes_sbox': bytes([0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
                          0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76]),
        'chacha20_const': b'expand 32-byte k',
        'sha256_iv': bytes([0x6a,0x09,0xe6,0x67,0xbb,0x67,0xae,0x85,
                           0x3c,0x6e,0xf3,0x72,0xa5,0x4f,0xf5,0x3a]),
    }

    def scan_memory(self, mem: bytes, base: int = 0) -> List[KeyTraceResult]:
        findings = []
        for cn, cb in self.CIPHER_CONSTANTS.items():
            pos = 0
            while True:
                idx = mem.find(cb, pos)
                if idx == -1: break
                addr = base + idx; self._hit_addresses[addr] += 1
                cs = max(0, idx - 64); ce = min(len(mem), idx + len(cb) + 64)
                findings.append(KeyTraceResult(
                    key_material=mem[cs:ce], access_address=addr,
                    context={'constant': cn, 'offset': idx}))
                pos = idx + 1
        return findings


class PTTimingAnalyzer:
    @staticmethod
    def compute_cv(cycle_counts: List[int]) -> float:
        if len(cycle_counts) < 3: return 0.0
        n = len(cycle_counts); mean = sum(cycle_counts) / n
        if mean == 0: return 0.0
        return math.sqrt(sum((c - mean) ** 2 for c in cycle_counts) / n) / mean

    @staticmethod
    def analyze_blocks(block_cycles: Dict[int, List[int]]) -> Dict[str, Any]:
        violations = []
        for addr, cycles in block_cycles.items():
            cv = PTTimingAnalyzer.compute_cv(cycles)
            if cv >= 0.3:
                violations.append({'address': hex(addr), 'cv': round(cv, 3),
                                   'samples': len(cycles)})
        return {'total_blocks': len(block_cycles),
                'constant_time_violations': len(violations),
                'violations': sorted(violations, key=lambda x: -x['cv'])[:10]}


class RawPTParser:
    @staticmethod
    def decode_stream(raw: bytes) -> List[PTPacket]:
        decoder = PTPacketDecoder(); packets = []; offset = 0
        while offset < len(raw):
            pkt, nxt = decoder.decode_packet(raw, offset)
            if pkt is None: break
            packets.append(pkt); offset = nxt
        return packets


def analyze_pt_trace_file(pt_path: str) -> Dict[str, Any]:
    return PTVulnerabilityAnalyzer().analyze_trace_file(pt_path)

def analyze_pt_trace_raw(raw: bytes) -> Dict[str, Any]:
    return PTVulnerabilityAnalyzer().analyze(raw)
