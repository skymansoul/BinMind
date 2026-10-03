import logging
import time
import os
import json
import cProfile
import pstats
import io

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class PerformanceProfiler(BaseAnalyzer):

    def __init__(self, config=None):
        self._config = config if config is not None else {}
        self._profiler = None
        self._timings = []
        self._baseline = {}

    def start_profiling(self):
        self._profiler = cProfile.Profile()
        self._profiler.enable()
        logger.info("performance剖析已启动")

    def stop_profiling(self):
        if self._profiler is None:
            return {'error': 'profiler not started'}
        self._profiler.disable()
        s = io.StringIO()
        ps = pstats.Stats(self._profiler, stream=s).sort_stats('cumulative')
        ps.print_stats(30)
        return {
            'stats': s.getvalue(),
            'total_calls': ps.total_calls,
            'total_time': ps.total_tt,
        }

    def time_step(self, step_name, func, *args, **kwargs):
        sName = step_name if step_name is not None else "unnamed_step"
        fStart = time.perf_counter()
        fMemBefore = self._get_memory_usage()
        try:
            result = func(*args, **kwargs)
            bOk = True
        except Exception as e:
            result = None
            bOk = False
            logger.debug(f"步骤 {sName} failed: {e}")
        fElapsed = time.perf_counter() - fStart
        fMemAfter = self._get_memory_usage()
        self._timings.append({
            'step': sName,
            'elapsed': round(fElapsed, 4),
            'mem_before_mb': round(fMemBefore, 2),
            'mem_after_mb': round(fMemAfter, 2),
            'mem_delta_mb': round(fMemAfter - fMemBefore, 2),
            'success': bOk,
            'timestamp': time.time(),
        })
        return result

    def _get_memory_usage(self):
        fSize = 0.0
        try:
            import psutil
            proc = psutil.Process(os.getpid())
            fSize = proc.memory_info().rss / (1024 * 1024)
        except ImportError:
            pass
        return fSize

    def save_baseline(self, name="default"):
        sName = name if name is not None else "default"
        baseline = {}
        iSz = len(self._timings)
        i = 0
        while i < iSz:
            t = self._timings[i]
            baseline[t['step']] = t['elapsed']
            i += 1
        self._baseline = baseline
        path = os.path.join(
            os.path.dirname(__file__), '..', '.binmind_cache',
            f'perf_baseline_{sName}.json'
        )
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as f:
                json.dump(baseline, f, indent=2)
            logger.info(f"performance基线已save: {sName}")
        except Exception as e:
            logger.warning(f"save基线failed: {e}")

    def load_baseline(self, name="default"):
        sName = name if name is not None else "default"
        path = os.path.join(
            os.path.dirname(__file__), '..', '.binmind_cache',
            f'perf_baseline_{sName}.json'
        )
        try:
            with open(path, 'r') as f:
                self._baseline = json.load(f)
        except FileNotFoundError:
            logger.info(f"基线 {sName} does not exist")
        except Exception as e:
            logger.warning(f"load基线failed: {e}")
        return self._baseline

    def check_regression(self, threshold_pct=20.0):
        fThresh = min(max(threshold_pct, 0.0), 100.0)
        regressions = []
        iSz = len(self._timings)
        i = 0
        while i < iSz:
            t = self._timings[i]
            sStep = t['step']
            if sStep in self._baseline:
                fBase = self._baseline[sStep]
                if fBase > 0:
                    fPct = ((t['elapsed'] - fBase) / fBase) * 100
                    if fPct > fThresh:
                        regressions.append({
                            'step': sStep,
                            'baseline': round(fBase, 4),
                            'current': t['elapsed'],
                            'pct_increase': round(fPct, 1),
                            'severity': 'HIGH' if fPct > 50 else 'MEDIUM',
                        })
            i += 1
        if regressions:
            logger.warning(f"detected {len(regressions)} 个performance衰退")
        return regressions

    def generate_flamegraph_data(self):
        lines = []
        iSz = len(self._timings)
        i = 0
        while i < iSz:
            t = self._timings[i]
            sStep = t['step'].replace(' ', '_')
            iMs = int(t['elapsed'] * 1000)
            lines.append(f"{sStep} {iMs}")
            i += 1
        return "\n".join(lines)

    def analyze(self, **kwargs):
        self.load_baseline()
        regressions = self.check_regression()

        fTotalTime = sum(t['elapsed'] for t in self._timings)
        fPeakMem = max(
            (t.get('mem_after_mb', 0) for t in self._timings), default=0
        )

        iFailed = 0
        iSz = len(self._timings)
        j = 0
        while j < iSz:
            if not self._timings[j]['success']:
                iFailed += 1
            j += 1

        aSorted = list(self._timings)
        iN = len(aSorted)
        for iIdx in range(iN):
            for k in range(0, iN - iIdx - 1):
                if aSorted[k]['elapsed'] < aSorted[k + 1]['elapsed']:
                    aSorted[k], aSorted[k + 1] = aSorted[k + 1], aSorted[k]

        return {
            "success": True,
            "report": {
                "total_time": round(fTotalTime, 3),
                "peak_memory_mb": round(fPeakMem, 2),
                "steps": len(self._timings),
                "failed_steps": iFailed,
                "regressions": regressions,
                "timeline": self._timings,
                "flamegraph_data": self.generate_flamegraph_data(),
                "top_slow_steps": aSorted[:5],
            }
        }

    @classmethod
    def get_metadata(cls):
        return AnalyzerMetadata(
            name="PerformanceProfiler",
            type=AnalyzerType.PROFILING_TOOL,
            version="1.0.0",
            description="Full pipeline performance profiling with flame graph data and regression detection",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["any"])


__all__ = ["PerformanceProfiler"]
