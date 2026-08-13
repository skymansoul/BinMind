"""Fuzz harness 生成 + 漏洞数据库——自动 harness + SQLite FTS5 搜索"""
import sqlite3
import os
import datetime
import subprocess
import threading
import logging
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


# Harness 生成

class HarnessGenerator:
    """目标二进制 fuzzing harness 生成——支持 stdin/file/socket 三种接口"""

    def generate_libfuzzer(self, target_name: str, params: str = "uint8_t *data, size_t size") -> str:
        """生成 libFuzzer C harness"""
        if target_name is None:
            target_name = ""
        return """#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size < 4) return 0;
    {target}(data, size);
    return 0;
}}
""".format(target=target_name or "test_target")

    def generate_afl(self, target_name: str) -> str:
        """生成 AFL stdin harness"""
        if target_name is None:
            target_name = ""
        return """#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {{
    unsigned char buf[65536];
    ssize_t len;
    while (__AFL_LOOP(1000)) {{
        len = read(0, buf, sizeof(buf));
        if (len <= 0) continue;
        {target}(buf, (size_t)len);
    }}
    return 0;
}}
""".format(target=target_name or "test_target")

    def generate_c_harness(self, target_func: str,
                           input_mode: str = "file",
                           lib_name: str = "libfuzzer") -> str:
        """按接口模式生成 C harness"""
        if input_mode == "file":
            return self._harness_libfuzzer(target_func)
        elif input_mode == "stdin":
            return self._harness_afl_stdin(target_func)
        elif input_mode == "socket":
            return self._harness_socket(target_func)
        return ""

    def _harness_libfuzzer(self, target: str) -> str:
        return """#include <stdint.h>
#include <stddef.h>
#include "{target}.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size < 4) return 0;
    {target}(data, size);
    return 0;
}}
""".format(target=target)

    def _harness_afl_stdin(self, target: str) -> str:
        return """#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "{target}.h"

int main(int argc, char **argv) {{
    unsigned char buf[65536];
    ssize_t len;
    while (__AFL_LOOP(1000)) {{
        len = read(0, buf, sizeof(buf));
        if (len <= 0) continue;
        {target}(buf, (size_t)len);
    }}
    return 0;
}}
""".format(target=target)

    def _harness_socket(self, target: str) -> str:
        return """#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "{target}.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size < 8) return 0;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    {target}(fd, data + 8, size - 8);
    return 0;
}}
""".format(target=target)

    def generate_python_harness(self, target_func: str,
                                input_mode: str = "file") -> str:
        """生成 Python fuzzing harness 骨架"""
        _tmpl = [
            "import sys",
            "import atheris",
            "",
            "def TestOneInput(data):",
            "    if len(data) < 4:",
            "        return",
            "    # call: {target_func}(data)",
            "    pass",
            "",
            "def main():",
            "    atheris.Setup(sys.argv, TestOneInput)",
            "    atheris.Fuzz()",
            "",
            "if __name__ == '__main__':",
            "    main()",
        ]
        return "\n".join(_tmpl).format(target_func=target_func)


class FuzzHarness:
    """轻量 harness 管理器——生成写入文件"""

    def __init__(self, target_binary: str = ""):
        self.target = target_binary or "test_target"
        self.gen = HarnessGenerator()
        self._mode = "file"

    def set_mode(self, mode: str):
        self._mode = mode

    def generate(self, target_name: str, engine: str = "libfuzzer",
                 lang: str = "c") -> str:
        """生成 harness 代码字符串"""
        if not target_name:
            target_name = self.target
        if lang != "c":
            return self.gen.generate_python_harness(target_name)
        if engine == "afl":
            return self.gen.generate_afl(target_name)
        return self.gen.generate_libfuzzer(target_name)


# 漏洞数据库

class VulnerabilityDB:
    """SQLite + FTS5 漏洞签名数据库——全文搜索"""

    DB_SCHEMA = """
    CREATE TABLE IF NOT EXISTS signatures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern_hash TEXT UNIQUE NOT NULL,
        vuln_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        description TEXT,
        cve TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    FTS_SCHEMA = """
    CREATE VIRTUAL TABLE IF NOT EXISTS fts_signatures
        USING fts5(vuln_type, description, content=signatures, content_rowid=id);
    """

    def __init__(self, db_path: str = ":memory:"):
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(self.DB_SCHEMA)
        try:
            self._conn.execute(self.FTS_SCHEMA)
        except sqlite3.OperationalError:
            pass  # FTS5 不可用
        self._conn.commit()

    def insert(self, vuln_type: str, severity: str = "medium",
               description: str = "", cve: str = "",
               pattern: bytes = b"", signature: str = None,
               cwe_id: str = None, **kwargs) -> int:
        """插入漏洞签名——同步 FTS 索引；signature/cwe_id 兼容旧接口"""
        if signature is not None:
            description = signature
        if cwe_id is not None:
            cve = cwe_id
        _hash = hashlib.sha256(pattern + vuln_type.encode()).hexdigest()[:16]
        _c = self._conn.execute(
            "INSERT OR IGNORE INTO signatures(pattern_hash, vuln_type, severity, description, cve) "
            "VALUES (?, ?, ?, ?, ?)",
            (_hash, vuln_type, severity, description, cve))
        self._conn.commit()
        _rowid = _c.lastrowid
        if _rowid:
            try:
                self._conn.execute(
                    "INSERT INTO fts_signatures(rowid, vuln_type, description) VALUES (?, ?, ?)",
                    (_rowid, vuln_type, description))
            except sqlite3.OperationalError:
                pass
        return _rowid or 0

    def search(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        """FTS5 全文搜索，降级为 LIKE 搜索"""
        try:
            _rows = self._conn.execute(
                "SELECT s.id, s.vuln_type, s.severity, s.description, s.cve "
                "FROM fts_signatures f JOIN signatures s ON f.rowid = s.id "
                "WHERE fts_signatures MATCH ? ORDER BY rank LIMIT ?",
                (query, limit)).fetchall()
        except sqlite3.OperationalError:
            _rows = self._conn.execute(
                "SELECT id, vuln_type, severity, description, cve FROM signatures "
                "WHERE vuln_type LIKE ? OR description LIKE ? LIMIT ?",
                (f"%{query}%", f"%{query}%", limit)).fetchall()

        _results = []
        for _r in _rows:
            _results.append({
                "id": _r[0], "vuln_type": _r[1], "severity": _r[2],
                "description": _r[3], "cve": _r[4],
            })
        return _results

    def count(self) -> int:
        _r = self._conn.execute("SELECT COUNT(*) FROM signatures").fetchone()
        return _r[0] if _r else 0

    def close(self):
        self._conn.close()


def search_vuln_db(query: str, db_path: str = None) -> List[Dict[str, Any]]:
    """快捷漏洞库搜索"""
    _db = VulnerabilityDB(db_path or ":memory:")
    _results = _db.search(query)
    _db.close()
    return _results

    if __import__("os").environ.get("BINMIND_DEBUG"):print(*a,**kw)


class FuzzerIntegration:
    """模糊测试集成层——harness 生成、会话管理、崩溃导入、Web API 控制"""

    def __init__(self, work_dir: str = "data/fuzzing"):
        self.work_dir = work_dir
        self.fuzz_sessions: Dict[str, Dict[str, Any]] = {}
        self.corpus_dir = os.path.join(work_dir, "corpus")
        self.crashes_dir = os.path.join(work_dir, "crashes")
        self._session_procs: Dict[str, subprocess.Popen] = {}
        self._session_lock = threading.Lock()
        os.makedirs(self.corpus_dir, exist_ok=True)
        os.makedirs(self.crashes_dir, exist_ok=True)

    def create_harness(self, target_binary: str, input_type: str) -> str:
        """从目标二进制和输入类型生成 harness"""
        if input_type == 'file':
            return self._generate_libfuzzer_harness(target_binary)
        elif input_type == 'network':
            return self._generate_afl_harness(target_binary)
        return ''

    def _generate_libfuzzer_harness(self, target: str) -> str:
        code = '''
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    return 0;
}}
'''
        return code

    def _generate_afl_harness(self, target: str) -> str:
        code = '''
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {{
    FILE *f;
    char buf[1024];

    if (argc < 2) {{
        fprintf(stderr, "Usage: %s <input_file>\\n", argv[0]);
        return 1;
    }}

    f = fopen(argv[1], "rb");
    if (!f) return 1;

    fread(buf, 1, sizeof(buf), f);
    fclose(f);

    return 0;
}}
'''
        return code

    def start_fuzzing_session(self, session_name: str, harness_path: str,
                              fuzzer_type: str = 'afl') -> Dict[str, Any]:
        """启动命名模糊测试会话——spawn 子进程并记录 PID"""
        session = {
            'name': session_name,
            'harness': harness_path,
            'fuzzer_type': fuzzer_type,
            'status': 'running',
            'corpus_count': 0,
            'crash_count': 0,
            'started_at': datetime.datetime.now().isoformat(),
            'pid': None,
        }

        self.fuzz_sessions[session_name] = session

        session_dir = os.path.join(self.work_dir, session_name)
        os.makedirs(session_dir, exist_ok=True)
        try:
            if fuzzer_type == 'afl':
                cmd = [
                    'afl-fuzz', '-i', self.corpus_dir,
                    '-o', session_dir, '--', harness_path, '@@'
                ]
            elif fuzzer_type == 'libfuzzer':
                cmd = [harness_path, '-jobs=1', f'-workers=1', session_dir]
            else:
                cmd = [harness_path, session_dir]
            proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with self._session_lock:
                self._session_procs[session_name] = proc
            session['pid'] = proc.pid
        except Exception as exc:
            session['status'] = 'error'
            session['error'] = str(exc)

        return session

    def stop_session(self, session_name: str) -> bool:
        """终止会话进程"""
        with self._session_lock:
            proc = self._session_procs.pop(session_name, None)
        if proc is None:
            return False
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        session = self.fuzz_sessions.get(session_name)
        if session:
            session['status'] = 'stopped'
        return True

    def import_crash(self, session_name: str, crash_path: str) -> Dict[str, Any]:
        """将崩溃样本导入分析管线"""
        crash_info = {
            'session': session_name,
            'crash_file': crash_path,
            'imported_at': datetime.datetime.now().isoformat(),
            'analysis_status': 'pending'
        }

        crash_dest = os.path.join(self.crashes_dir, f"{session_name}_{os.path.basename(crash_path)}")
        try:
            import shutil
            shutil.copy(crash_path, crash_dest)
            crash_info['stored_path'] = crash_dest
        except Exception as e:
            crash_info['error'] = str(e)

        return crash_info

    def get_session_status(self, session_name: str) -> Dict[str, Any]:
        """按名称查询会话状态"""
        return self.fuzz_sessions.get(session_name, {})

    def import_corpus_dir(self, dir_path: str) -> int:
        """扫描目录导入全部文件作为种子"""
        count = 0
        for entry in os.scandir(dir_path):
            if entry.is_file():
                dest = os.path.join(self.corpus_dir, entry.name)
                try:
                    import shutil
                    shutil.copy(entry.path, dest)
                    count += 1
                except Exception:
                    logger.debug("corpus import skip: %s", entry.name)
        return count
