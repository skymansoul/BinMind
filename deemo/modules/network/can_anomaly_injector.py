"""
CAN 总线异常注入——汽车安全测试。
构造畸形CAN帧、注入仲裁错误、生成模糊测试序列，评估ECU韧性。

entropy-guided seed scheduling based on AFL++'s update_bitmap_score() —
high-entropy mutation outputs get more fuzz budget because they reach
deeper parser paths. Also added a LibAFL-style differential fuzzer
for dual-input ECU response comparison.
"""
import struct as _st
import random as _rnd
import time as _t
import math
from collections import Counter
from enum import IntEnum
from dataclasses import dataclass, field
from typing import Optional

# compat placeholders — these used to be defined at module level by older code
ResponseType = None
CANAnalysisResult = None
Vulnerability = None

class CANFrameType(IntEnum):
    STANDARD = 0
    EXTENDED = 1
    FD_STANDARD = 2
    FD_EXTENDED = 3

class AnomalyType(IntEnum):
    DLC_MISMATCH = 1
    BIT_FLIP = 2
    TIMING_ATTACK = 3
    CRC_ERROR = 4
    ACK_ERROR = 5
    FORM_ERROR = 6
    STUFF_ERROR = 7
    ARBITRATION_GLITCH = 8
    REMOTE_FRAME_FLOOD = 9
    OVERLOAD_FRAME_INJECT = 10

class SeverityLevel(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class CANFrame:
    arbitration_id: int
    frame_type: CANFrameType = CANFrameType.STANDARD
    dlc: int = 0
    data: bytes = b""
    is_extended: bool = False
    is_fd: bool = False
    bit_rate_switch: bool = False
    error_state: bool = False
    timestamp: float = field(default_factory=_t.time)

    @property
    def actual_len(self) -> int:
        return len(self.data)

    @property
    def dlc_valid(self) -> bool:
        if not self.is_fd:
            return self.dlc <= 8
        # CAN FD DLC encoding: values 9-15 map to 12/16/20/24/32/48/64 bytes
        dlc_map = {9: 12, 10: 16, 11: 20, 12: 24, 13: 32, 14: 48, 15: 64}
        return self.actual_len == dlc_map.get(self.dlc, self.dlc)

@dataclass
class InjectionResult:
    original: CANFrame
    mutated: CANFrame
    anomaly: AnomalyType
    severity: SeverityLevel
    description: str = ""

@dataclass
class FuzzCoverage:
    anomaly_dist: dict          # AnomalyType -> count
    unique_crash_sigs: int      # unique crash-inducing anomaly combos
    total_iter: int
    entropy_score: float = 0.0  # avg byte entropy across all mutations


# byte-level shannon entropy — quick proxy for "how interesting is this mutation"
def _byte_entropy(payload: bytes) -> float:
    if not payload:
        return 0.0
    freq = Counter(payload)
    n = len(payload)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ===========================================================================
class CANAnomalyInjector:
    """inject malformed CAN frames. uses entropy-guided scheduling.

    The core idea from AFL++: mutations that produce "interesting" state
    transitions (here: high-entropy byte distributions) get more iterations.
    This is a cheap approximation of coverage-guided fuzzing — we can't
    instrument the ECU, but we can measure output diversity.
    """

    DLC_EXPANSION = {9: 12, 10: 16, 11: 20, 12: 24, 13: 32, 14: 48, 15: 64}

    def __init__(self, seed: int = 0):
        self._rng = _rnd.Random(seed)
        self._log: list[InjectionResult] = []
        # anomaly weights — uniform init, drift with entropy feedback
        self._weights: dict[AnomalyType, float] = {at: 1.0 for at in AnomalyType}
        self._entropy_acc: dict[AnomalyType, float] = {at: 0.0 for at in AnomalyType}

    # -- public API --

    def inject(self, frame: CANFrame, anomaly: Optional[AnomalyType] = None) -> InjectionResult:
        if anomaly is None:
            anomaly = self._pick_weighted()

        mutated = self._mutate(frame, anomaly)
        r = InjectionResult(
            original=frame,
            mutated=mutated,
            anomaly=anomaly,
            severity=self._severity_for(anomaly),
            description=anomaly.name,
        )
        self._log.append(r)

        # feedback: accumulate entropy to guide future scheduling
        ent = _byte_entropy(mutated.data)
        self._entropy_acc[anomaly] += ent

        return r

    def inject_burst(self, frame: CANFrame, count: int = 10,
                     anomalies: Optional[list[AnomalyType]] = None) -> list[InjectionResult]:
        out = []
        for _ in range(count):
            k = self._rng.choice(anomalies) if anomalies else self._pick_weighted()
            out.append(self.inject(frame, k))
        return out

    def fuzz_sequence(self, base_frame: CANFrame, iterations: int = 100,
                      target_ids: Optional[list[int]] = None) -> list[InjectionResult]:
        """generate a full fuzz sequence with varying IDs and payloads"""
        out = []
        ids = target_ids or [
            base_frame.arbitration_id,
            base_frame.arbitration_id ^ 0x1FF,
            base_frame.arbitration_id ^ 0x3FF,
        ]

        for _ in range(iterations):
            fid = self._rng.choice(ids)
            plen = self._rng.randint(0, 64)
            payload = bytes(self._rng.getrandbits(8) for _ in range(plen))
            dummy = CANFrame(
                arbitration_id=fid,
                dlc=min(plen, 15),
                data=payload,
                is_fd=(plen > 8),
            )
            out.append(self.inject(dummy))

        return out

    def coverage_summary(self) -> FuzzCoverage:
        dist = {}
        for r in self._log:
            dist[r.anomaly] = dist.get(r.anomaly, 0) + 1

        return FuzzCoverage(
            anomaly_dist={k.name: v for k, v in dist.items()},
            unique_crash_sigs=sum(1 for r in self._log if r.severity >= SeverityLevel.HIGH),
            total_iter=len(self._log),
            entropy_score=sum(self._entropy_acc.values()) / max(1, len(self._log)),
        )

    # -- internal --

    def _pick_weighted(self) -> AnomalyType:
        """weighted random: entropy-rich anomaly types get picked more often"""
        items = list(self._weights.keys())
        w = [self._weights[a] + self._entropy_acc[a] for a in items]
        total = sum(w)
        if total <= 0:
            return self._rng.choice(items)

        r = self._rng.uniform(0, total)
        acc = 0.0
        for it, wt in zip(items, w):
            acc += wt
            if r <= acc:
                return it
        return items[-1]  # fallback, shouldn't happen

    def _mutate(self, frame: CANFrame, anomaly: AnomalyType) -> CANFrame:
        data = bytearray(frame.data)
        dlc = frame.dlc
        fid = frame.arbitration_id
        is_fd = frame.is_fd

        if anomaly == AnomalyType.DLC_MISMATCH:
            for cand in (9, 10, 11, 12, 13, 14, 15):
                expected = self.DLC_EXPANSION[cand]
                if len(data) != expected:
                    dlc = cand
                    is_fd = True
                    break

        elif anomaly == AnomalyType.BIT_FLIP:
            if data:
                idx = self._rng.randrange(len(data))
                bit = self._rng.randrange(8)
                data[idx] ^= (1 << bit)

        elif anomaly == AnomalyType.TIMING_ATTACK:
            pass  # timing is handled by the injector host, not the frame

        elif anomaly == AnomalyType.CRC_ERROR:
            if data:
                data[-1] ^= 0xFF  # corrupt last byte

        elif anomaly == AnomalyType.FORM_ERROR:
            # flip a random bit in the arbitration field
            fid ^= (1 << self._rng.randrange(29))

        elif anomaly == AnomalyType.STUFF_ERROR:
            if len(data) >= 3:
                idx = self._rng.randrange(len(data) - 2)
                for _ in range(5):  # try a few spots to find a stuffable triplet
                    if data[idx] == data[idx+1] == data[idx+2]:
                        data[idx+2] ^= 0xFF
                        break

        elif anomaly == AnomalyType.ARBITRATION_GLITCH:
            fid |= 0x7FF  # all recessive bits — guaranteed arbitration loss

        elif anomaly in (AnomalyType.REMOTE_FRAME_FLOOD,
                         AnomalyType.ACK_ERROR,
                         AnomalyType.OVERLOAD_FRAME_INJECT):
            pass  # these are physical-layer / controller-level anomalies

        return CANFrame(
            arbitration_id=fid,
            frame_type=frame.frame_type,
            dlc=dlc,
            data=bytes(data),
            is_extended=frame.is_extended,
            is_fd=is_fd,
            bit_rate_switch=frame.bit_rate_switch,
            error_state=anomaly != AnomalyType.TIMING_ATTACK,
        )

    @staticmethod
    def _severity_for(a: AnomalyType) -> SeverityLevel:
        _MAP = {
            AnomalyType.DLC_MISMATCH: SeverityLevel.MEDIUM,
            AnomalyType.BIT_FLIP: SeverityLevel.HIGH,
            AnomalyType.TIMING_ATTACK: SeverityLevel.CRITICAL,
            AnomalyType.CRC_ERROR: SeverityLevel.HIGH,
            AnomalyType.ACK_ERROR: SeverityLevel.CRITICAL,
            AnomalyType.FORM_ERROR: SeverityLevel.HIGH,
            AnomalyType.STUFF_ERROR: SeverityLevel.MEDIUM,
            AnomalyType.ARBITRATION_GLITCH: SeverityLevel.CRITICAL,
            AnomalyType.REMOTE_FRAME_FLOOD: SeverityLevel.LOW,
            AnomalyType.OVERLOAD_FRAME_INJECT: SeverityLevel.LOW,
        }
        return _MAP.get(a, SeverityLevel.INFO)

    @property
    def injection_count(self) -> int:
        return len(self._log)


# ===========================================================================
class ArbitrationErrorInjector:
    """simulate CAN arbitration failures and bus contention"""

    def __init__(self, bus_speed_hz: int = 500000):
        self._bus_speed = bus_speed_hz
        self._nodes: dict[int, float] = {}  # node_id -> priority weight

    def register_node(self, node_id: int, priority: float = 0.5):
        self._nodes[node_id] = max(0.0, min(1.0, priority))

    def inject(self, frame: CANFrame) -> CANFrame:
        if not self._nodes:
            return frame
        # simulate losing arbitration: force the frame to a low-priority ID
        highest = min(self._nodes, key=self._nodes.get)
        loser_id = highest ^ 0x7FF
        return CANFrame(
            arbitration_id=loser_id,
            frame_type=frame.frame_type,
            dlc=frame.dlc,
            data=frame.data,
            is_extended=frame.is_extended,
            is_fd=frame.is_fd,
            error_state=True,
        )

    def simulate_bus_load(self, frame_rate: int = 2000) -> float:
        """estimate bus utilization as a percentage"""
        # worst-case extended frame: 129 bits overhead + 64 bytes payload
        worst_case = 129
        bits_per_frame = worst_case + (64 * 8)
        bits_per_second = bits_per_frame * frame_rate
        return min(100.0, (bits_per_second / self._bus_speed) * 100)


# ===========================================================================
class FrameDifferentialFuzzer:
    """generate mutation pairs for differential ECU testing.

    Two mutations, one field different — if the ECU responds differently
    to the pair, that's a behavior divergence worth investigating.
    This is the core insight from LibAFL's differential fuzzing module:
    divergence IS the signal.
    """

    def __init__(self, seed: int = 0):
        self._rng = _rnd.Random(seed)

    def diff_pair(self, frame: CANFrame) -> tuple[CANFrame, CANFrame, str]:
        """returns (frame_a, frame_b, strategy_name)"""
        strat = self._rng.choice(["dlc_vs_payload", "id_flip", "payload_boundary"])

        if strat == "dlc_vs_payload":
            # A: legal DLC, full payload. B: same payload, inflated DLC.
            a = CANFrame(
                arbitration_id=frame.arbitration_id,
                dlc=min(len(frame.data), 8),
                data=frame.data,
            )
            b_dlc = min(len(frame.data), 15)
            if b_dlc <= 8:
                b_dlc = self._rng.choice([12, 16, 20, 24, 32])
            b = CANFrame(
                arbitration_id=frame.arbitration_id,
                dlc=b_dlc,
                data=frame.data,
                is_fd=b_dlc > 8,
            )
            return a, b, "dlc_vs_payload"

        elif strat == "id_flip":
            # A: original ID. B: one bit flipped.
            a = CANFrame(arbitration_id=frame.arbitration_id, data=frame.data, dlc=frame.dlc)
            flipped = frame.arbitration_id ^ (1 << self._rng.randrange(11))
            b = CANFrame(arbitration_id=flipped, data=frame.data, dlc=frame.dlc)
            return a, b, "id_flip"

        else:  # payload_boundary
            # A: payload at exact edge. B: payload padded with 0xFF.
            edge = frame.data[:min(len(frame.data), 8)]
            a = CANFrame(arbitration_id=frame.arbitration_id, data=edge,
                         dlc=min(len(edge), 8))
            pad = edge + b"\xFF" * self._rng.randint(1, 64)
            b = CANFrame(arbitration_id=frame.arbitration_id, data=pad,
                         dlc=min(len(pad), 15), is_fd=len(pad) > 8)
            return a, b, "payload_boundary"


# legacy compat — these were module-level bindings in old code
class BitFlipInjector:
    def __init__(self):
        pass
    def inject(self, msg):
        return msg

CRCErrorInjector = None
AnomalyConfig = None
