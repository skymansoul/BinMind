import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)



class RegisterSnapshot:
    __slots__ = ('snapshot_id', 'timestamp', 'regs',)

    def __init__(self, snapshot_id, timestamp=0.0, regs=None):
        self.snapshot_id = snapshot_id
        self.timestamp = timestamp
        self.regs = regs if regs is not None else {}


    def to_dict(self) -> Dict[str, Any]:
        return {
            'snapshot_id': self.snapshot_id,
            'regs': {k: hex(v) for k, v in self.regs.items()}
        }


class RegisterDiff:
    __slots__ = ('reg_name', 'before', 'after', 'delta', 'changed', 'suspicious',)

    def __init__(self, reg_name, before, after, delta, changed=True, suspicious=False):
        self.reg_name = reg_name
        self.before = before
        self.after = after
        self.delta = delta
        self.changed = changed
        self.suspicious = suspicious


    def to_dict(self) -> Dict[str, Any]:
        return {
            'reg': self.reg_name,
            'before': hex(self.before),
            'after': hex(self.after),
            'delta': hex(self.delta) if self.delta != 0 else '0',
            'changed': self.changed,
            'suspicious': self.suspicious
        }


class RegisterSnapshotComparator:

    X86_REGS = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp',
                'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
                'rip', 'rflags', 'cs', 'ds', 'es', 'fs', 'gs', 'ss']
    CRITICAL_REGS = {'rsp', 'rip', 'rbp', 'rflags'}

    def __init__(self):
        self._snapshots: Dict[str, RegisterSnapshot] = {}
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"SNAP-{self._counter:04d}"

    def take_snapshot(self, reg_values: Dict[str, int]) -> RegisterSnapshot:
        import time
        snap = RegisterSnapshot(snapshot_id=self._next_id(),
                               timestamp=time.time(), regs=dict(reg_values))
        self._snapshots[snap.snapshot_id] = snap
        return snap

    def compare(self, snap_a: str, snap_b: str) -> List[RegisterDiff]:
        a = self._snapshots.get(snap_a)
        b = self._snapshots.get(snap_b)
        if not a or not b:
            return []

        all_regs = set(a.regs.keys()) | set(b.regs.keys())
        diffs = []
        for reg in sorted(all_regs):
            before_val = a.regs.get(reg, 0)
            after_val = b.regs.get(reg, 0)
            delta = after_val - before_val
            changed = before_val != after_val
            suspicious = changed and reg in self.CRITICAL_REGS

            diffs.append(RegisterDiff(
                reg_name=reg, before=before_val, after=after_val,
                delta=delta, changed=changed, suspicious=suspicious))

        return diffs

    def analyze(self, snapshots: Optional[List[Dict[str, int]]] = None,
                **kwargs) -> Dict[str, Any]:
        if snapshots:
            for regs in snapshots:
                self.take_snapshot(regs)

        snap_ids = list(self._snapshots.keys())
        diffs = self.compare(snap_ids[0], snap_ids[-1]) if len(snap_ids) >= 2 else []

        critical_changes = [d for d in diffs if d.suspicious]
        return {
            'success': True,
            'total_snapshots': len(self._snapshots),
            'changed_regs': sum(1 for d in diffs if d.changed),
            'total_regs': len(diffs),
            'critical_changes': [d.to_dict() for d in critical_changes],
            'diffs': [d.to_dict() for d in diffs[:32]],
            'risk_flag': len(critical_changes) > 0
        }


def compare_register_snapshots(snapshots: List[Dict[str, int]],
                                **kwargs) -> Dict[str, Any]:
    comparator = RegisterSnapshotComparator()
    return comparator.analyze(snapshots=snapshots)


__all__ = ["RegisterSnapshotComparator", "RegisterSnapshot", "RegisterDiff",
           "compare_register_snapshots"]
