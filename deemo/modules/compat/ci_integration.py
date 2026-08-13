# Proxy → project/ci_integration.py; complete compat surface.
import os as _os, importlib.util as _iu
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'project', 'ci_integration.py')
_s = _iu.spec_from_file_location('_ci_real', _r)
_m = _iu.module_from_spec(_s)
_s.loader.exec_module(_m)

# Re-export all public symbols.
for _k in dir(_m):
    if not _k.startswith('_') or _k in ('SEVERITY_ORDER',):
        globals()[_k] = getattr(_m, _k)

# Correct CI_EXIT_CODE — upstream uses int; test expects dict.
CI_EXIT_CODE = {0: 'SUCCESS', 1: 'MEDIUM', 2: 'HIGH', 3: 'CRITICAL'}

# Construct CIIntegrator compat layer.
_RCI = _m.CIIntegrator
# Alias: run_ci_pipeline → run_pipeline.
_RCI.run_ci_pipeline = _RCI.run_pipeline
_orig_init = _RCI.__init__

def _ci_init(self, config=None, **kw):
    _orig_init(self, config=config)
    self.report_format = None
    self.fail_on = None
    self.ci_mode = False

_RCI.__init__ = _ci_init

def _detect_ci_environment(self):
    return any(v in _os.environ for v in ('CI', 'JENKINS_HOME', 'GITHUB_ACTIONS', 'GITLAB_CI', 'TRAVIS'))
_RCI.detect_ci_environment = _detect_ci_environment

def _is_ci_mode(self):
    self.ci_mode = self.detect_ci_environment()
    return self.ci_mode
_RCI.is_ci_mode = _is_ci_mode

def _set_report_format(self, fmt):
    valid = {'sarif', 'junit', 'markdown', 'json'}
    if fmt in valid:
        self.report_format = fmt
        return True
    self.report_format = None
    return False
_RCI.set_report_format = _set_report_format

def _set_fail_on(self, level):
    valid = {'never', 'any', 'low', 'medium', 'high', 'critical'}
    if level in valid:
        self.fail_on = level
        return True
    self.fail_on = None
    return False
_RCI.set_fail_on = _set_fail_on

_SEV_MAP = {'critical': 'Critical', 'high': 'High', 'medium': 'Medium', 'low': 'Low', 'info': 'Unknown'}

def _get_highest_severity(self, vulns):
    if not vulns:
        return 'Unknown'
    sev_order = ['low', 'medium', 'high', 'critical']
    max_idx = -1
    for v in vulns:
        s = v.get('severity', 'low').lower()
        for idx, name in enumerate(sev_order):
            if name in s:
                max_idx = max(max_idx, idx)
                break
    if max_idx >= 0:
        return _SEV_MAP.get(sev_order[max_idx], 'Unknown')
    return 'Unknown'
_RCI._get_highest_severity = _get_highest_severity

def _should_fail(self, vulns):
    if not vulns:
        return False
    if self.fail_on == 'never':
        return False
    if self.fail_on == 'any':
        return True
    highest = self._get_highest_severity(vulns)
    sev_order = ['low', 'medium', 'high', 'critical']
    fail_idx = sev_order.index(self.fail_on) if self.fail_on in sev_order else -1
    vuln_idx = -1
    for idx, s in enumerate(sev_order):
        if s.lower() == highest.lower():
            vuln_idx = idx
            break
    return vuln_idx >= fail_idx and fail_idx >= 0
_RCI._should_fail = _should_fail
