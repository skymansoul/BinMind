#!/usr/bin/env python3

import logging
import os
import json
import math
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class DepthProfile:
    sz: int = 0
    nfuns: int = 0
    cpx: float = 0.0
    depth: int = 1
    est_sec: float = 0.0
    conf: float = 0.0

    def as_dict(self):
        return {
            'size': self.sz, 'functions': self.nfuns,
            'complexity': self.cpx, 'recommended_depth': self.depth,
            'estimated_time_sec': self.est_sec, 'confidence': self.conf,
        }


class AnalysisDepthEstimator:

    _SZ_LUT = (
        (10 * 1024,        1),
        (100 * 1024,       2),
        (1024 * 1024,      3),
        (100 * 1024 * 1024, 4),
    )
    _FN_LUT = (
        (50,   1),
        (200,  2),
        (1000, 3),
        (10000, 4),
    )

    def __init__(self, hist_path=''):
        self._history = []
        self._load_history(hist_path)

    def _load_history(self, path):
        if not path:
            return
        if not os.path.isfile(path):
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                raw = json.load(f)
            if isinstance(raw, list):
                self._history = raw
                logger.debug(f"loaded {len(raw)} historical records")
        except Exception:
            logger.debug("suppressed", exc_info=True)

    def _lookup(self, val, lut):
        for thresh, level in lut:
            if val <= thresh:
                return level
        return lut[-1][1]

    def extract_features(self, binpath):
        if binpath is None:
            return 0, 0, 0.0
        sz = 0
        if os.path.isfile(binpath):
            sz = os.path.getsize(binpath)
        nfuns = 0
        cpx = 1.0
        try:
            import subprocess as sp
            r = sp.run(
                ['r2', '-q', '-c', 'aflj; q', binpath],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace',
            )
            raw_out = r.stdout.strip() if r.stdout else ''
            funcs = json.loads(raw_out) if raw_out else []
            nfuns = len(funcs)
            if nfuns > 0:
                total = 0
                for f in funcs:
                    total += f.get('ninstr', 0) + f.get('numargs', 0)
                cpx = (total / nfuns) / 10.0
        except Exception:
            logger.debug("suppressed", exc_info=True)
        cpx = min(max(cpx, 0.1), 10.0)
        return sz, nfuns, cpx

    def estimate_depth(self, binpath):
        sz, nfuns, cpx = self.extract_features(binpath)

        d_sz = self._lookup(sz, self._SZ_LUT)
        d_fn = self._lookup(nfuns, self._FN_LUT)
        depth = d_sz if d_sz > d_fn else d_fn

        est_t = nfuns * 30.0 * depth * (cpx / 5.0)

        conf = min(0.3 + len(self._history) * 0.05, 0.9)

        _LABELS = {1: 'quick_scan', 2: 'normal', 3: 'deep_analysis', 4: 'exhaustive'}
        logger.info(
            f"depth estimate: {_LABELS.get(depth, '?')} "
            f"(sz={sz}, funcs={nfuns}, cpx={cpx:.1f})"
        )
        return DepthProfile(sz=sz, nfuns=nfuns, cpx=round(cpx, 1),
                           depth=depth, est_sec=round(est_t, 1), conf=round(conf, 2))


def estimate_analysis_depth(binpath):
    est = AnalysisDepthEstimator()
    prof = est.estimate_depth(binpath)
    return prof.as_dict()
