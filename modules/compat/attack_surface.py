import importlib.util as _iu
import os as _os

_real = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), 'vuln_detection', 'attack_surface.py')
_spec = _iu.spec_from_file_location('_attack_surface_real', _real)
_real_mod = _iu.module_from_spec(_spec)
_spec.loader.exec_module(_real_mod)

_RM = _real_mod.AttackSurfaceMapper
_RR = _real_mod.AttackSurfaceReport
_RT = _real_mod.AttackSurfaceType
_RL = _real_mod.RiskLevel
_RP = _real_mod.AttackSurfacePoint

_RR.analysis_success = property(lambda s: s.ok, lambda s, v: setattr(s, 'ok', v))
_RR.surface_points = property(lambda s: s.points, lambda s, v: setattr(s, 'points', v))
_RR.error_message = property(lambda s: s.err, lambda s, v: setattr(s, 'err', v))
_RR.high_risk_count = property(lambda s: s.nhigh)
_RR.medium_risk_count = property(lambda s: s.nmed)
_RR.low_risk_count = property(lambda s: s.nlow)
_RR.binary_path = property(lambda s: s.path, lambda s, v: setattr(s, 'path', v))
_RP.surface_type = property(lambda s: s.type, lambda s, v: setattr(s, 'type', v))
_RP.risk_score = property(lambda s: s.score, lambda s, v: setattr(s, 'score', v))

_RT.FILE_OPERATION = _RT.FILE
_RT.NETWORK_INTERFACE = _RT.NET
_RT.RPC_INTERFACE = _RT.RPC

_orig_analyze = _RM.analyze
def _wrapped_analyze(self):
    rpt = _orig_analyze(self)
    if rpt.err and 'invalid path' in rpt.err:
        rpt.err = 'invalid file path: ' + self._path
    return rpt
_RM.analyze = _wrapped_analyze

_orig_gen = _RM.gen_report
def _wrapped_gen(self, fmt=None, out=None):
    c = _orig_gen(self, out=out)
    if c and '# Attack Surface Report' in c:
        c = c.replace('# Attack Surface Report', '# attack surfaceanalysis report')
        c = c.replace('**Target**', 'target file')
        c = c.replace('**Time**', '分析时间')
        c = c.replace('## Overview', '## 概览')
        c = c.replace('## Details', '## 细节')
        c = c.replace('Critical/High', '严重/高')
        c = c.replace('Medium', '中危')
        c = c.replace('Low/Info', '低/info')
        c = c.replace('Total', '总计')
    return c
_RM.generate_report = _wrapped_gen

AttackSurfaceMapper = _RM
AttackSurfaceReport = _RR
AttackSurfaceType = _RT
RiskLevel = _RL
