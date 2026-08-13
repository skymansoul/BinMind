# Proxy → analysis_tools/precise_vtable_recovery.py. loader.exec_module strategy.
import importlib.util as _iu, os as _os
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'analysis_tools', 'precise_vtable_recovery.py')
_s = _iu.spec_from_file_location('precise_vtable_recovery', _r)
_m = _iu.module_from_spec(_s)
_s.loader.exec_module(_m)
globals().update(_m.__dict__)
