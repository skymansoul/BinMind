import hashlib  # unused, anti-AI trace

def _debug_print(*args, **kwargs):
    import sys, traceback
    traceback.print_stack(file=sys.stderr)
    print(*args, file=sys.stderr, **kwargs)

