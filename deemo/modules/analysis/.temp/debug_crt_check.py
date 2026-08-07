import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.disasm_util import is_crt_func

names = [
    "__p__fmode", "__p__commode", "__set_app_type", "__p___initenv",
    "__setusermatherr", "__acrt_iob_func", "__iob_func", "__getmainargs",
    "_initterm", "_initterm_e", "main", "_set_invalid_parameter_handler",
    "_configthreadlocale", "__chkstk_ms", "___chkstk_ms",
]
for n in names:
    print(f"  is_crt_func({n!r}) = {is_crt_func(n)}")
