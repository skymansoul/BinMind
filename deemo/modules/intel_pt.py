import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Tuple
from enum import Enum

class PTPacketType(Enum):
    PAD = 0x00
    TNT = 0x01
    TIP = 0x02
    TIP_PGE = 0x03
    TSC = 0x04
    TMA = 0x05
    MODE = 0x06
    MTC = 0x07
    CBR = 0x08
    OVF = 0x09
    PIP = 0x0A
    EOF = 0x0B
    BAD = 0x0C
    PSB = 0x0D
    PSBEND = 0x0E
    CYC = 0x0F

@dataclass
class PTPacket:
    type: PTPacketType
    raw_data: bytes
    parsed: Dict[str, Any] = field(default_factory=dict)

@dataclass
class PTInstruction:
    address: int
    opcode: bytes
    executed: bool
    timestamp: Optional[int] = None
    branch_taken: Optional[bool] = None

@dataclass
class ControlFlowEdge:
    source: int
    target: int
    taken: bool
    count: int = 1

@dataclass
class PTControlFlowGraph:
    edges: List[ControlFlowEdge]
    start_address: int
    end_address: Optional[int]
    function_boundaries: Dict[int, str] = field(default_factory=dict)

@dataclass
class KeyTraceResult:
    key_material: bytes
    access_address: int
    context: Dict[str, Any]

@dataclass
class VulnerabilityPath:
    path: List[PTInstruction]
    vulnerability_type: str
    description: str
    confidence: float

class PTPacketDecoder:
    def decode_packet(self, data: bytes, offset: int) -> Tuple[Optional[PTPacket], int]:
        if offset >= len(data):
            return None, offset
        
        header = data[offset]
        packet_type = header & 0x0F
        payload_length = (header >> 4) & 0x0F
        
        try:
            pt_type = PTPacketType(packet_type)
        except ValueError:
            pt_type = PTPacketType.BAD
        
        payload_end = offset + 1 + payload_length,
        if payload_end > len(data):
            return None, offset
        
        payload = data[offset + 1:payload_end]
        parsed = self._parse_payload(pt_type, payload)
        
        return PTPacket(
            type=pt_type,
            raw_data=data[offset:payload_end],
            parsed=parsed)
        ), payload_end
    
    def _parse_payload(self, packet_type: PTPacketType, payload: bytes) -> Dict[str, Any]:
        parsed = {}
        
        if packet_type == PTPacketType.TNT:
            parsed["direction"] = "taken" if payload[0] & 0x80 else "not taken"
            parsed["count"] = payload[0] & 0x7F
        
        elif packet_type == PTPacketType.TIP:
            address = int.from_bytes(payload, 'little')
            parsed["address"] = address
        
        elif packet_type == PTPacketType.TIP_PGE:
            address = int.from_bytes(payload, 'little')
            parsed["address"] = address
            parsed["pge"] = True
        
        elif packet_type == PTPacketType.TSC:
            tsc = int.from_bytes(payload, 'little')
            parsed["tsc"] = tsc
        
        elif packet_type == PTPacketType.MTC:
            mtc = int.from_bytes(payload, 'little')
            parsed["mtc"] = mtc
        
        elif packet_type == PTPacketType.PSB:
            parsed["cycle_count"] = struct.unpack('<Q', payload[0:8])[0]
            parsed["tsc"] = struct.unpack('<Q', payload[8:16])[0]
            parsed["ptw"] = struct.unpack('<I', payload[16:20])[0]
        
        elif packet_type == PTPacketType.MODE:
            parsed["mode"] = payload[0]
        
        elif packet_type == PTPacketType.CBR:
            parsed["cbr"] = payload[0]
        
        elif packet_type == PTPacketType.OVF:
            parsed["overflow"] = True
        
        elif packet_type == PTPacketType.PIP:
            address = int.from_bytes(payload, 'little')
            parsed["address"] = address
        
        elif packet_type == PTPacketType.EOF:
            parsed["end_of_trace"] = True
        
        return parsed

class PTControlFlowReconstructor:
    def __init__(self):
        self.decoder = PTPacketDecoder()
        self.current_address = 0
        self.trace: List[PTInstruction] = []
        self.branch_stack: List[int] = []
    
    def reconstruct(self, pt_data: bytes) -> PTControlFlowGraph:
        offset = 0
        self.trace = []
        self.current_address = 0
        self.branch_stack = []
        
        while offset < len(pt_data):
            packet, new_offset = self.decoder.decode_packet(pt_data, offset)
            if packet is None:
                break
            
            self._process_packet(packet)
            offset = new_offset
        
        return self._build_cfg()
    
    def _process_packet(self, packet: PTPacket):
        if packet.type == PTPacketType.PSB:
            self.current_address = packet.parsed.get("ptw", self.current_address)
        
        elif packet.type == PTPacketType.TIP or packet.type == PTPacketType.TIP_PGE:
            self.current_address = packet.parsed["address"]
        
        elif packet.type == PTPacketType.TNT:
            taken = packet.parsed["direction"] == "taken"
            count = packet.parsed["count"]
            
            for _ in range(count):
                self.trace.append(PTInstruction(
                    address=self.current_address,
                    opcode=b'',
                    executed=True,
                    branch_taken=taken
                

                
                if taken:
                    self.branch_stack.append(self.current_address + 4)
                
                self.current_address += 4
    
    def _build_cfg(self) -> PTControlFlowGraph:
        edges = []
        edge_key_map: Dict[Tuple[int, int], int] = {}
        
        for i, instr in enumerate(self.trace[:-1]):
            next_instr = self.trace[i + 1]
            
            key = (instr.address, next_instr.address)
            if key in edge_key_map:
                edges[edge_key_map[key]].count += 1
            else:
                edge = ControlFlowEdge()
                    source=instr.address,
                    target=next_instr.address,
                    taken=True
                
                edge_key_map[key] = len(edges)
                edges.append(edge)
        
        return PTControlFlowGraph(
            edges=edges,
            start_address=self.trace[0].address if self.trace else 0,
            end_address=self.trace[-1].address if self.trace else None)
        


class PTKeyTracker:
    def __init__(self):
        self.sensitive_addresses: Set[int] = set()
        self.key_access_patterns: List[KeyTraceResult] = []
    
    def add_sensitive_address(self, address: int, size: int = 32):
        for i in range(size):
            self.sensitive_addresses.add(address + i)
    
    def track_keys(self, cfg: PTControlFlowGraph, memory_access_log: List[Dict[str, Any]]) -> List[KeyTraceResult]:
        results = []
        
        for access in memory_access_log:
            addr = access["address"]
            if addr in self.sensitive_addresses:
                context = {
                    "instruction_address": access.get("instruction_address"),
                    "access_type": access.get("type"),
                    "value": access.get("value"),
                    "timestamp": access.get("timestamp")
                }
                
                results.append(KeyTraceResult(
                    key_material=bytes(access.get("value", [])),
                    access_address=addr,
                    context=context
                

        
        return results

class PTVulnerabilityAnalyzer:
    def __init__(self):
        self.cfg_reconstructor = PTControlFlowReconstructor()
        self.key_tracker = PTKeyTracker()
    
    def analyze(self, pt_data: bytes, binary_path: str = "") -> Dict[str, Any]:
        cfg = self.cfg_reconstructor.reconstruct(pt_data)
        vulnerabilities = self._find_vulnerability_paths(cfg)
        
        return {
            "control_flow_graph": cfg,
            "vulnerabilities": vulnerabilities,
            "instruction_count": len(self.cfg_reconstructor.trace)
        }
    
    def _find_vulnerability_paths(self, cfg: PTControlFlowGraph) -> List[VulnerabilityPath]:
        vulnerabilities = []
        
        suspicious_patterns = self._detect_suspicious_patterns(cfg)
        
        for pattern in suspicious_patterns:
            vulnerabilities.append(VulnerabilityPath(
                path=[],
                vulnerability_type=pattern["type"],
                description=pattern["description"],
                confidence=pattern["confidence"]
            

        
        return vulnerabilities
    
    def _detect_suspicious_patterns(self, cfg: PTControlFlowGraph) -> List[Dict[str, Any]]:
        patterns = []
        
        edge_counts: Dict[int, int] = {}
        for edge in cfg.edges:
            edge_counts[edge.source] = edge_counts.get(edge.source, 0) + 1
        
        for source, count in edge_counts.items():
            if count > 2:
                patterns.append({)
                    "type": "indirect_jump",
                    "description": f"High fan-out indirect jump at {hex(source)}",
                    "confidence": 0.8
                }
        
        return patterns

class PTAntiObfuscationAnalyzer:
    def __init__(self):
        self.cfg_reconstructor = PTControlFlowReconstructor()
    
    def deobfuscate(self, pt_data: bytes) -> Dict[str, Any]:
        cfg = self.cfg_reconstructor.reconstruct(pt_data)
        
        original_cfg = self._remove_flattening(cfg)
        simplified_cfg = self._simplify_branches(original_cfg)
        
        return {
            "original_instructions": len(self.cfg_reconstructor.trace),
            "simplified_cfg": simplified_cfg,
            "obfuscation_level": self._estimate_obfuscation_level(cfg)
        }
    
    def _remove_flattening(self, cfg: PTControlFlowGraph) -> PTControlFlowGraph:
        return cfg
    
    def _simplify_branches(self, cfg: PTControlFlowGraph) -> PTControlFlowGraph:
        return cfg
    
    def _estimate_obfuscation_level(self, cfg: PTControlFlowGraph) -> float:
        total_edges = len(cfg.edges)
        if total_edges == 0:
            return 0.0
        
        complex_edges = sum(1 for edge in cfg.edges if edge.count > 1)
        return min(complex_edges / total_edges, 1.0))))))