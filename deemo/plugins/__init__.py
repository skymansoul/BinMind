import importlib, os


def discover_plugins():
    """return {name: module} for all .py files in this directory"""
    plugins = {}
    _dir = os.path.dirname(__file__)
    for fname in sorted(os.listdir(_dir)):
        if fname.startswith('_') or not fname.endswith('.py'):
            continue
        name = fname[:-3]
        try:
            mod = importlib.import_module('plugins.' + name)
            plugins[name] = mod
        except ImportError:
            pass
    return plugins


def list_plugins():
    """return sorted list of available plugin names"""
    return sorted(discover_plugins().keys())
