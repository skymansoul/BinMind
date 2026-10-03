import logging
import time
from collections import deque

logger = logging.getLogger(__name__)

_DEFAULT_ALPHA = 0.3
_MAX_RECENT = 100

class ProgressState:
    __slots__ = ('total_items', 'completed_items', 'failed_items',
                 'start_time', 'elapsed_seconds', 'items_per_second',
                 'eta_seconds', 'percent_complete')

    def __init__(self, total_items=0, completed_items=0, failed_items=0,
                 start_time=0.0, elapsed_seconds=0.0, items_per_second=0.0,
                 eta_seconds=0.0, percent_complete=0.0):
        self.total_items = total_items
        self.completed_items = completed_items
        self.failed_items = failed_items
        self.start_time = start_time
        self.elapsed_seconds = elapsed_seconds
        self.items_per_second = items_per_second
        self.eta_seconds = eta_seconds
        self.percent_complete = percent_complete

class EWMAEstimator:
    def __init__(self, alpha=_DEFAULT_ALPHA):
        self.alpha = alpha
        self._fRate = 0.0
        self._bReady = False

    def update(self, new_rate):
        if new_rate is None:
            return
        if not self._bReady:
            self._fRate = new_rate
            self._bReady = True
        else:
            self._fRate = self.alpha * new_rate + (1 - self.alpha) * self._fRate

    @property
    def current_rate(self):
        return self._fRate

class ProgressEstimator:
    def __init__(self):
        self.ewma = EWMAEstimator(alpha=_DEFAULT_ALPHA)
        self._recent_times = deque(maxlen=_MAX_RECENT)
        self._fStartTime = 0.0
        self._iTotal = 0
        self._iDone = 0
        self._iFailed = 0
        self._callbacks = []

    def start(self, total_items):
        if total_items is None:
            total_items = 0
        self._fStartTime = time.time()
        self._iTotal = total_items
        self._iDone = 0
        self._iFailed = 0

    def tick(self, items_completed=1, failed=0):
        if items_completed is None:
            items_completed = 1
        if failed is None:
            failed = 0
        self._iDone += items_completed
        self._iFailed += failed
        fNow = time.time()
        self._recent_times.append((fNow, items_completed))

        iSz = len(self._recent_times)
        if iSz >= 2:
            first_t, first_n = self._recent_times[0]
            last_t, last_n = self._recent_times[-1]
            if last_t > first_t:
                fRate = (last_n - first_n) / (last_t - first_t)
                self.ewma.update(fRate)

        self._notify()

    def get_state(self):
        fElapsed = time.time() - self._fStartTime if self._fStartTime > 0 else 0
        fRate = self.ewma.current_rate
        iRemaining = self._iTotal - self._iDone
        fEta = iRemaining / max(0.001, fRate) if fRate > 0 else 0
        fPct = (self._iDone / max(1, self._iTotal)) * 100

        return ProgressState(
            total_items=self._iTotal,
            completed_items=self._iDone,
            failed_items=self._iFailed,
            start_time=self._fStartTime,
            elapsed_seconds=fElapsed,
            items_per_second=fRate,
            eta_seconds=fEta,
            percent_complete=fPct)

    def on_progress(self, callback):
        if callback is not None:
            self._callbacks.append(callback)

    def _notify(self):
        state = self.get_state()
        iSz = len(self._callbacks)
        i = 0
        while i < iSz:
            cb = self._callbacks[i]
            try:
                cb(state)
            except Exception:
                logger.debug("suppressed", exc_info=True)
            i += 1

    def predict_completion_time(self):
        state = self.get_state()
        return time.time() + state.eta_seconds

    def analyze(self, total_items=0, completed=0, **kwargs):
        if total_items is None:
            total_items = 0
        if completed is None:
            completed = 0
        if total_items > 0 and self._iTotal == 0:
            self.start(total_items)
        if completed > 0:
            self.tick(completed)
        state = self.get_state()
        dRet = {
            'success': True,
            'progress': {
                'percent': round(state.percent_complete, 1),
                'completed': state.completed_items,
                'total': state.total_items,
                'failed': state.failed_items,
                'elapsed_seconds': round(state.elapsed_seconds, 1),
                'items_per_second': round(state.items_per_second, 3),
                'eta_seconds': round(state.eta_seconds, 1),
                'eta_formatted': f"{int(state.eta_seconds // 60)}m {int(state.eta_seconds % 60)}s"
            },
            'throughput_report': {}
        }

        if state.items_per_second > 0:
            dRet['throughput_report'] = {
                'estimated_total_seconds': round(
                    self._iTotal / max(0.001, state.items_per_second), 1),
                'completion_time': time.strftime(
                    '%H:%M:%S', time.localtime(self.predict_completion_time()))
            }
        return dRet

def estimate_progress(total_items=0, completed=0, **kwargs):
    estimator = ProgressEstimator()
    return estimator.analyze(total_items=total_items, completed=completed)

__all__ = ["ProgressEstimator", "EWMAEstimator", "ProgressState", "estimate_progress"]
