import os, importlib.util
_r = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'symbolic', 'concolic_execution.py')
_m = importlib.util.module_from_spec(importlib.util.spec_from_file_location('ce', _r))
importlib.util.spec_from_file_location('ce', _r).loader.exec_module(_m)
globals().update({k: v for k, v in _m.__dict__.items() if not k.startswith('_')})

# Remap methods — "Cx" suffix appended during refactor; restore original names.
if hasattr(_m, 'ConcolicExecutor'):
    _CE = _m.ConcolicExecutor
    _aliases = {
        '_calculate_coverage': '_calculate_coverageCx',
        '_classify_source_type': '_classify_source_typeCx',
        '_count_new_paths': '_count_new_pathsCx',
        '_generate_seed_value': '_generate_seed_valueCx',
        '_validate_symbolic_paths': '_validate_symbolic_pathsCx',
        'export_seeds': 'export_seedsCx',
        'generate_report': 'generate_reportCx',
        'is_available': 'is_availableCx',
        'run_concolic_analysis': 'run_concolic_analysisCx',
        'run_dynamic_seeding': 'run_dynamic_seedingCx',
        'save_report': 'save_reportCx',
        'seed_symbolic_executor': 'seed_symbolic_executorCx',
    }
    for _old, _new in _aliases.items():
        if not hasattr(_CE, _old) and hasattr(_CE, _new):
            setattr(_CE, _old, getattr(_CE, _new))
