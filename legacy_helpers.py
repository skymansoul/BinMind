# 旧模块路径兼容层，将 modules.* 导入重定向到新包布局
import sys as _sys
import logging as _logging

_log = _logging.getLogger(__name__)


# map old module paths to new locations

_COMPAT_MAP = {
    'modules.info_collect':          'core.binary_info',
    'modules.decomp_ai':             'core.decompiler',
    'modules.symbolic_exe':          'core.symexec',
    'modules.crash_analysis':        'core.crash_analysis',
    'modules.exploit_gen':           'core.exploit_gen',
    'modules.vuln_db':               'core.vuln_db',
    'modules.report':                'core.report',
    'modules.hooks':                 'core.hooks',
    'modules.static_analysis':       'core.static_analysis',
    'modules.dynamic_taint':         'plugins.taint',
    'modules.rop_grader':            'plugins.rop_tools',
    'modules.rop_optimizer':         'plugins.rop_tools',
    'modules.heap_feng_shui':        'plugins.heap_tools',
    'modules.crypto_detector':       'plugins.crypto_scan',
    'modules.fuzz_integration':      'plugins.fuzz_harness',
    'modules.llm_manager':           'core.ai_backends',
    'modules.prompts':               'core.decompiler',
    'modules.cli':                   'cli.commands',
    'modules.logging_config':        'utils.logging_setup',
    'modules.config_manager':        'config',
}


class _CompatFinder:
# 旧 modules.xxx 导入拦截器，重定向到新包布局，首次使用时注册
    _installed = False

    @classmethod
    def install(cls):
        if cls._installed:
            return
        _sys.meta_path.insert(0, cls)
        cls._installed = True

    def find_module(self, fullname, path=None):
        if fullname in _COMPAT_MAP:
            return self
        return None

    def load_module(self, fullname):
        if fullname in _sys.modules:
            return _sys.modules[fullname]

        new_name = _COMPAT_MAP[fullname]
        try:
            mod = __import__(new_name, fromlist=['*'])
        except ImportError:
            _log.warning("Compat import failed: %s -> %s", fullname, new_name)
            raise

        _sys.modules[fullname] = mod
        return mod


_CompatFinder.install()
