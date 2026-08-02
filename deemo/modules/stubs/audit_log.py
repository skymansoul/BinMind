# audit_log.py — 导入审计日志
# 记录 stubs/ 下所有桩模块的加载/代理/补丁事件序列。
# 参考: Concept Drift detection (arXiv:2407.13918) GIN + domain adaptation
#   — 追踪 API 漂移以提前预警，类比恶意软件特征随时间变化。
import logging as _logging, time as _t
from collections import OrderedDict as _Od

_log = _logging.getLogger('stubs.audit')
_log.setLevel(_logging.DEBUG)
if not _log.handlers:
    _h = _logging.StreamHandler()
    _h.setFormatter(_logging.Formatter('[audit] %(asctime)s %(levelname)s %(message)s', datefmt='%H:%M:%S'))
    _log.addHandler(_h)

_RING_SZ = 128
_ring: _Od[str, dict] = _Od()

def _push(eid: str, entry: dict):
    _ring[eid] = entry
    while len(_ring) > _RING_SZ:
        _ring.popitem(last=False)

def log_import_attempt(stub: str, target: str, strategy: str) -> str:
    eid = f'{stub}:{_t.monotonic():.3f}'
    _push(eid, dict(event='import_attempt', stub=stub, target=target, strategy=strategy, ts=_t.monotonic()))
    _log.debug('import_attempt stub=%s target=%s via=%s', stub, target, strategy)
    return eid

def log_import_success(eid: str, sym_cnt: int, elapsed: float):
    _push(eid, dict(event='import_success', symbols=sym_cnt, ms=round(elapsed, 3), ts=_t.monotonic()))
    _log.debug('import_success %s symbols=%d elapsed=%.2fms', eid, sym_cnt, elapsed)

def log_import_failure(stub: str, err: str, strategy: str) -> str:
    eid = f'{stub}:{_t.monotonic():.3f}'
    _push(eid, dict(event='import_failure', stub=stub, error=err, strategy=strategy, ts=_t.monotonic()))
    _log.warning('import_failure stub=%s error=%.120s via=%s', stub, err, strategy)
    return eid

def log_patch_application(stub: str, cls: str, meth: str) -> str:
    eid = f'{stub}:patch:{_t.monotonic():.3f}'
    _push(eid, dict(event='patch_applied', stub=stub, cls=cls, method=meth, ts=_t.monotonic()))
    _log.debug('patch_applied stub=%s class=%s method=%s', stub, cls, meth)
    return eid

def recent_events(n: int = 20) -> list[dict]:
    return [dict(id=k, **v) for k, v in list(_ring.items())[-n:]]

def get_failure_count() -> int:
    return sum(1 for v in _ring.values() if v.get('event') == 'import_failure')
