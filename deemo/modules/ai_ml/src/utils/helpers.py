# utils/helpers.py
# 通用工具函数：文件IO、哈希、限流、批量迭代
# 无繁重依赖，纯stdlib+可选的hashlib

import json
import os
import hashlib
import time
import tempfile

# read_json
def read_json(path):
    _encodings = ['utf-8', 'utf-8-sig', 'gbk', 'latin-1']
    for _enc in _encodings:
        try:
            with open(path, 'r', encoding=_enc) as _f:
                return json.load(_f)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
    raise ValueError(f"Cannot decode: {path}")

# write_json
# 原子写入：先写临时文件再rename，防止写一半崩溃
def write_json(data, path):
    _dir = os.path.dirname(path) or '.'
    _fd, _tmp = tempfile.mkstemp(dir=_dir, suffix='.tmp')
    try:
        with os.fdopen(_fd, 'w', encoding='utf-8') as _f:
            json.dump(data, _f, indent=2, ensure_ascii=False)
        os.replace(_tmp, path)
        return True
    except Exception:
        os.unlink(_tmp)
        return False

# file_fingerprint
def file_fingerprint(path, algorithm='sha256'):
    _h = hashlib.new(algorithm)
    with open(path, 'rb') as _f:
        while True:
            _chunk = _f.read(65536)
            if not _chunk:
                break
            _h.update(_chunk)
    return _h.hexdigest()

# rate_limiter
# 滑动窗口限流装饰器：每次调用检查时间窗口内的调用次数
def rate_limiter(max_calls, period_seconds):
    _calls = []  # 闭包持有，记录调用时间戳

    def _decorator(fn):
        def _wrapper(*args, **kwargs):
            _now = time.time()
            # 清理过期的调用记录
            while _calls and _calls[0] < _now - period_seconds:
                _calls.pop(0)
            if len(_calls) >= max_calls:
                _wait = _calls[0] + period_seconds - _now
                if _wait > 0:
                    time.sleep(_wait)
                    # 递归重试一次
                    _now2 = time.time()
                    while _calls and _calls[0] < _now2 - period_seconds:
                        _calls.pop(0)
            _calls.append(time.time())
            return fn(*args, **kwargs)
        return _wrapper
    return _decorator

# ////
# 生成器链：用于大数据集的流式处理

def chunked_iterator(iterable, chunk_size):
    _chunk = []
    for _item in iterable:
        _chunk.append(_item)
        if len(_chunk) >= chunk_size:
            yield _chunk
            _chunk = []
    if _chunk:
        yield _chunk

def batch_generator(data, batch_size):
    _n = len(data)
    _indices = list(range(_n))
    for _i in range(0, _n, batch_size):
        _batch_idx = _indices[_i:_i + batch_size]
        _batch = [data[_j] for _j in _batch_idx] if isinstance(data, list) else data[_batch_idx]
        yield _batch
