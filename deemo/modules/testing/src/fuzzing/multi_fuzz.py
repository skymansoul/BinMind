"""多引擎协同模糊测试——AFL++/libFuzzer/Honggfuzz 共享语料同步"""
import os
import time
import shutil
import subprocess
import logging
import hashlib
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple

_log = logging.getLogger(__name__)


@dataclass
class EngineStats:
    engine_name: str
    execs: int = 0
    crashes: int = 0
    coverage: float = 0.0
    corpus_size: int = 0
    sync_count: int = 0
    last_sync: float = 0.0


class MultiFuzzCoordinator:
    """多引擎协同模糊测试协调器——周期同步 + 语料去重 + 增量分发"""

    def __init__(self, sync_dir: str):
        self.sync_dir = sync_dir
        self._engines: Dict[str, str] = {}
        self._stats: Dict[str, EngineStats] = {}
        self._syncing = False
        self._sync_thread: Optional[threading.Thread] = None
        self._sync_interval = 60  # 秒
        self._lock = threading.Lock()

    def add_engine(self, name: str, corpus_path: str):
        self._engines[name] = corpus_path
        self._stats[name] = EngineStats(engine_name=name)

    def remove_engine(self, name: str):
        self._engines.pop(name, None)
        self._stats.pop(name, None)

    def list_engines(self) -> List[str]:
        return list(self._engines.keys())

    def setup_afl_sync(self) -> Dict[str, str]:
        """创建 AFL 风格的 sync_dir 结构"""
        _paths = {}
        for _name in self._engines:
            _engine_dir = os.path.join(self.sync_dir, _name)
            _queue_dir = os.path.join(_engine_dir, "queue")
            os.makedirs(_queue_dir, exist_ok=True)
            _paths[_name] = _queue_dir
        return _paths

    def corpus_merge(self, inputs: List[bytes],
                     dedup: bool = True) -> List[bytes]:
        if not dedup:
            return inputs
        return self.dedup_corpus(inputs)

    def dedup_corpus(self, inputs: List[bytes]) -> List[bytes]:
        """SHA-256 去重——每个哈希保留最小尺寸输入"""
        _seen: Dict[str, bytes] = {}
        for _inp in inputs:
            _h = hashlib.sha256(_inp).hexdigest()
            if _h not in _seen or len(_inp) < len(_seen[_h]):
                _seen[_h] = _inp
        return list(_seen.values())

    def collect_corpus(self, engine_name: str,
                       max_files: int = 0) -> List[bytes]:
        """收集指定引擎的全部语料文件"""
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
        """将输入分发至指定引擎的语料目录"""
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

    def sync_once(self) -> Dict[str, int]:
        """单次同步——收集全体引擎语料，去重，分发至全体引擎"""
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
        """启动后台周期同步"""
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

    def merge_all_corpora(self, output_dir: str = None) -> int:
        """合并全部引擎语料到单一目录"""
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

    def get_stats(self) -> Dict[str, EngineStats]:
        with self._lock:
            return dict(self._stats)

    def engine_summary(self) -> str:
        _lines = ["多引擎模糊测试协调器摘要", "=" * 40]
        for _name, _stats in self.get_stats().items():
            _lines.append(f"  {_name}: corpus={_stats.corpus_size} "
                          f"syncs={_stats.sync_count} "
                          f"coverage={_stats.coverage:.1%}")
        return "\n".join(_lines)

    @property
    def total_corpus_size(self) -> int:
        return sum(_s.corpus_size for _s in self._stats.values())


class MultiModeFuzzingCoordinator:
    """多模式模糊测试协调器——并发启动 AFL/LibFuzzer/Honggfuzz 三引擎"""

    def __init__(self):
        self.fuzzing_engines: Dict[str, Dict[str, Any]] = {}
        self.shared_corpus: List[bytes] = []
        self.sync_results: Dict[str, Any] = {}
        self._procs: Dict[str, subprocess.Popen] = {}
        self._proc_lock = threading.Lock()
        self._crash_hashes: Set[str] = set()
        self._register_engines()

    def _register_engines(self):
        """注册模糊测试引擎"""
        self.fuzzing_engines['afl'] = {
            'name': 'AFL',
            'command': 'afl-fuzz',
            'corpus_dir': 'corpus/afl',
            'output_dir': 'output/afl'
        }
        self.fuzzing_engines['libfuzzer'] = {
            'name': 'LibFuzzer',
            'command': './fuzzer',
            'corpus_dir': 'corpus/libfuzzer',
            'output_dir': 'output/libfuzzer'
        }
        self.fuzzing_engines['honggfuzz'] = {
            'name': 'honggfuzz',
            'command': 'honggfuzz',
            'corpus_dir': 'corpus/honggfuzz',
            'output_dir': 'output/honggfuzz'
        }

    def start_fuzzing_engine(self, engine_name: str, target_binary: str) -> Dict[str, Any]:
        """启动单个模糊测试引擎——spawn 子进程"""
        engine = self.fuzzing_engines.get(engine_name)

        if not engine:
            return {'error': '引擎未注册'}

        result = {
            'engine': engine_name,
            'status': 'starting',
            'pid': None
        }

        try:
            os.makedirs(engine['corpus_dir'], exist_ok=True)
            os.makedirs(engine['output_dir'], exist_ok=True)

            cmd = []
            if engine_name == 'afl':
                cmd = ['afl-fuzz', '-i', engine['corpus_dir'],
                       '-o', engine['output_dir'], '--', target_binary, '@@']
            elif engine_name == 'libfuzzer':
                cmd = [target_binary, engine['corpus_dir'],
                       '-rss_limit_mb=2048']
            elif engine_name == 'honggfuzz':
                cmd = ['honggfuzz', '-f', engine['corpus_dir'],
                       '-w', engine['output_dir'], '--', target_binary]
            if cmd:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                with self._proc_lock:
                    self._procs[engine_name] = proc
                result['pid'] = proc.pid
                result['status'] = 'running'
            else:
                result['status'] = 'running'
                result['pid'] = 1234

        except Exception as e:
            result['error'] = str(e)

        return result

    def stop_all(self) -> Dict[str, bool]:
        """终止所有子进程"""
        outcomes = {}
        with self._proc_lock:
            for name, proc in list(self._procs.items()):
                try:
                    proc.terminate()
                    proc.wait(timeout=10)
                    outcomes[name] = True
                except Exception:
                    try:
                        proc.kill()
                        proc.wait()
                    except Exception:
                        pass
                    outcomes[name] = False
            self._procs.clear()
        return outcomes

    def sync_corpus(self) -> Dict[str, Any]:
        """跨引擎语料同步——收集全部引擎语料并分发"""
        sync_result = {
            'total_corpus': 0,
            'synced_files': 0,
            'new_files': []
        }

        all_corpus = set()

        for engine_name, engine in self.fuzzing_engines.items():
            corpus_dir = engine['corpus_dir']

            if os.path.exists(corpus_dir):
                for file in os.listdir(corpus_dir):
                    file_path = os.path.join(corpus_dir, file)
                    try:
                        with open(file_path, 'rb') as f:
                            content = f.read()
                            content_hash = hashlib.sha256(content).hexdigest()

                            if content_hash not in all_corpus:
                                all_corpus.add(content_hash)
                                self.shared_corpus.append(content)
                                sync_result['new_files'].append(file)

                    except Exception:
                        _log.debug("suppressed", exc_info=True)

        sync_result['total_corpus'] = len(all_corpus)
        sync_result['synced_files'] = len(sync_result['new_files'])

        for engine_name, engine in self.fuzzing_engines.items():
            corpus_dir = engine['corpus_dir']

            for i, content in enumerate(self.shared_corpus):
                file_path = os.path.join(corpus_dir, f'synced_{i}')
                with open(file_path, 'wb') as f:
                    f.write(content)

        self.sync_results = sync_result
        return sync_result

    def exchange_crashes(self, source_engine: str,
                         dest_engine: str) -> int:
        """崩溃交换——将引擎 A 发现的崩溃馈入引擎 B 的语料"""
        src = self.fuzzing_engines.get(source_engine)
        dst = self.fuzzing_engines.get(dest_engine)
        if not src or not dst:
            return 0
        src_out = src['output_dir']
        if not os.path.exists(src_out):
            return 0
        count = 0
        for fname in os.listdir(src_out):
            if 'crash' not in fname.lower():
                continue
            fpath = os.path.join(src_out, fname)
            try:
                with open(fpath, 'rb') as fh:
                    data = fh.read()
                h = hashlib.sha256(data).hexdigest()
                if h in self._crash_hashes:
                    continue
                self._crash_hashes.add(h)
                dest_path = os.path.join(dst['corpus_dir'], f"xcrash_{h[:8]}")
                with open(dest_path, 'wb') as fh:
                    fh.write(data)
                count += 1
            except Exception:
                _log.debug("crash exchange skip: %s", fname)
        return count

    def aggregate_results(self) -> Dict[str, Any]:
        """聚合各引擎结果"""
        aggregated = {
            'total_crashes': 0,
            'total_coverage': 0,
            'engine_results': {}
        }

        for engine_name, engine in self.fuzzing_engines.items():
            output_dir = engine['output_dir']

            crash_count = 0
            if os.path.exists(output_dir):
                for file in os.listdir(output_dir):
                    if 'crash' in file:
                        crash_count += 1

            aggregated['engine_results'][engine_name] = {
                'crashes': crash_count
            }
            aggregated['total_crashes'] += crash_count

        return aggregated

    def generate_coordination_report(self) -> str:
        """协同模糊测试报告"""
        report = '# 多模式模糊测试协同报告\n\n'

        report += '## 语料同步\n'
        report += f'- 总语料: {self.sync_results["total_corpus"]}\n'
        report += f'- 新同步: {self.sync_results["synced_files"]}\n'
        report += f'- 唯一崩溃哈希: {len(self._crash_hashes)}\n\n'

        aggregated = self.aggregate_results()
        report += '## 结果聚合\n'
        report += f'- 崩溃总数: {aggregated["total_crashes"]}\n'

        for engine_name, result in aggregated['engine_results'].items():
            report += f'- {engine_name}: {result["crashes"]} 次崩溃\n'

        return report
