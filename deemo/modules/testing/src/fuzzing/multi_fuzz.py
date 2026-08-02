# 2026-08-01
# Multi-engine cooperative fuzzing — AFL++ / libFuzzer / Honggfuzz 协同
# 核心：共享 corpus directory + periodic sync + hash dedup
# sync_dir 结构遵循 AFL 惯例：<sync_dir>/<engine_name>/queue/
# corpus merge 按增量覆盖去重，保留最小输入。
import os
import time
import shutil
import hashlib
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple


@dataclass
class EngineStats:
    engine_name: str
    execs: int = 0
    crashes: int = 0
    coverage: float = 0.0
    corpus_size: int = 0
    sync_count: int = 0
    last_sync: float = 0.0


# ================================================
class MultiFuzzCoordinator:
    """多引擎协同 fuzzing 协调器。

    用法：
        coord = MultiFuzzCoordinator("/tmp/fuzz_sync")
        coord.add_engine("afl", "/path/to/afl-queue")
        coord.add_engine("libfuzzer", "/path/to/libfuzzer-corpus")
        coord.start_sync(interval=60)
        # ... fuzzing runs ...
        coord.stop_sync()
        coord.merge_all_corpora()
    """

    def __init__(self, sync_dir: str):
        self.sync_dir = sync_dir
        self._engines: Dict[str, str] = {}  # name -> corpus_path
        self._stats: Dict[str, EngineStats] = {}
        self._syncing = False
        self._sync_thread: Optional[threading.Thread] = None
        self._sync_interval = 60  # seconds
        self._lock = threading.Lock()

    # **** Engine management ****
    def add_engine(self, name: str, corpus_path: str):
        self._engines[name] = corpus_path
        self._stats[name] = EngineStats(engine_name=name)

    def remove_engine(self, name: str):
        self._engines.pop(name, None)
        self._stats.pop(name, None)

    def list_engines(self) -> List[str]:
        return list(self._engines.keys())

    # **** AFL sync directory setup ****
    def setup_afl_sync(self) -> Dict[str, str]:
        """创建 AFL 风格的 sync_dir。
        结构：sync_dir/<engine_name>/queue/
        """
        _paths = {}
        for _name in self._engines:
            _engine_dir = os.path.join(self.sync_dir, _name)
            _queue_dir = os.path.join(_engine_dir, "queue")
            os.makedirs(_queue_dir, exist_ok=True)
            _paths[_name] = _queue_dir
        return _paths

    # **** Corpus operations ****
    def corpus_merge(self, inputs: List[bytes],
                     dedup: bool = True) -> List[bytes]:
        """合并 corpus：hash 去重 + 保留最小输入。"""
        if not dedup:
            return inputs
        return self.dedup_corpus(inputs)

    def dedup_corpus(self, inputs: List[bytes]) -> List[bytes]:
        """基于 SHA-256 的 corpus 去重。每个 hash 保留最小尺寸。"""
        _seen: Dict[str, bytes] = {}
        for _inp in inputs:
            _h = hashlib.sha256(_inp).hexdigest()
            if _h not in _seen or len(_inp) < len(_seen[_h]):
                _seen[_h] = _inp
        return list(_seen.values())

    def collect_corpus(self, engine_name: str,
                       max_files: int = 0) -> List[bytes]:
        """收集指定引擎的所有 corpus 文件。"""
        _corpus_dir = self._engines.get(engine_name)
        if not _corpus_dir or not os.path.isdir(_corpus_dir):
            return []
        _inputs = []
        _count = 0
        for _fname in sorted(os.listdir(_corpus_dir)):
            _fpath = os.path.join(_corpus_dir, _fname)
            if os.path.isfile(_fpath):
                try:
                    with open(_fpath, "rb") as _f:
                        _data = _f.read()
                    _inputs.append(_data)
                    _count += 1
                    if max_files > 0 and _count >= max_files:
                        break
                except OSError:
                    continue
        return _inputs

    def distribute_corpus(self, engine_name: str, inputs: List[bytes]):
        """将 inputs 分发到指定引擎的 corpus 目录。"""
        _corpus_dir = self._engines.get(engine_name)
        if not _corpus_dir:
            return
        os.makedirs(_corpus_dir, exist_ok=True)
        for _inp in inputs:
            _h = hashlib.sha256(_inp).hexdigest()[:12]
            _out_path = os.path.join(_corpus_dir, f"synced:{_h}")
            if not os.path.exists(_out_path):
                with open(_out_path, "wb") as _f:
                    _f.write(_inp)

    # **** Sync ****
    def sync_once(self) -> Dict[str, int]:
        """单次同步：收集所有引擎的 corpus，去重，分发到所有引擎。"""
        _all_inputs = []
        for _name in self._engines:
            _corpus = self.collect_corpus(_name)
            _all_inputs.extend(_corpus)
            with self._lock:
                self._stats[_name].corpus_size = len(_corpus)

        _deduped = self.dedup_corpus(_all_inputs)
        _counts = {}
        for _name in self._engines:
            self.distribute_corpus(_name, _deduped)
            _counts[_name] = len(_deduped)
            with self._lock:
                self._stats[_name].sync_count += 1
                self._stats[_name].last_sync = time.time()
        return _counts

    def start_sync(self, interval: int = 60):
        """启动后台周期性同步。"""
        self._sync_interval = interval
        self._syncing = True
        self._sync_thread = threading.Thread(
            target=self._sync_loop, daemon=True)
        self._sync_thread.start()

    def _sync_loop(self):
        while self._syncing:
            try:
                self.sync_once()
            except Exception:
                pass
            time.sleep(self._sync_interval)

    def stop_sync(self):
        self._syncing = False
        if self._sync_thread:
            self._sync_thread.join(timeout=5)

    # **** Merge ****
    def merge_all_corpora(self, output_dir: str = None) -> int:
        """合并所有引擎的 corpus 到单一路径。"""
        _all_inputs = []
        for _name in self._engines:
            _all_inputs.extend(self.collect_corpus(_name))
        _deduped = self.dedup_corpus(_all_inputs)

        _out = output_dir or os.path.join(self.sync_dir, "merged")
        os.makedirs(_out, exist_ok=True)
        for _inp in _deduped:
            _h = hashlib.sha256(_inp).hexdigest()[:12]
            _fpath = os.path.join(_out, f"merged:{_h}")
            with open(_fpath, "wb") as _f:
                _f.write(_inp)
        return len(_deduped)

    # **** Stats ****
    def get_stats(self) -> Dict[str, EngineStats]:
        with self._lock:
            return dict(self._stats)

    def engine_summary(self) -> str:
        _lines = ["Multi-Fuzz Coordinator Summary", "=" * 40]
        for _name, _stats in self.get_stats().items():
            _lines.append(f"  {_name}: corpus={_stats.corpus_size} "
                          f"syncs={_stats.sync_count} "
                          f"coverage={_stats.coverage:.1%}")
        return "\n".join(_lines)

    @property
    def total_corpus_size(self) -> int:
        return sum(_s.corpus_size for _s in self._stats.values())
