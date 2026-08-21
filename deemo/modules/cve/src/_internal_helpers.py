# 共享内部辅助 — cve/src 各模块的私有访问器与可选依赖探测.
#
# _get_str/_get_num/_get_bool 原分布于 14 个文件, 存在单行/多行无注解/
# 多行带注解三种文本形式, 行为等价, 此处收敛为多行形式.
#

def _get_str(entry, field: str, default: str = ""):
    if hasattr(entry, field):
        return str(getattr(entry, field) or default)
    if isinstance(entry, dict):
        return str(entry.get(field, default))
    return default


def _get_num(entry, field: str):
    if hasattr(entry, field):
        return getattr(entry, field)
    if isinstance(entry, dict):
        return entry.get(field)
    return None


def _get_bool(entry, field: str) -> bool:
    if hasattr(entry, field):
        return bool(getattr(entry, field))
    if isinstance(entry, dict):
        return bool(entry.get(field, False))
    return False


def _probe_urllib():
    try:
        import urllib.request
        import urllib.error
        return True
    except ImportError:
        return False


_HAS_URLLIB = _probe_urllib()
