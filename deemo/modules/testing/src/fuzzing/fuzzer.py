# 2026-07-22
# Fuzz harness generation + vulnerability database
# Harness 生成策略：分析目标二进制接口（stdin/file/socket），
# 自动生成 AFL/LibFuzzer harness 模板。
# Vuln DB: SQLite + FTS5 全文搜索漏洞签名。
import sqlite3
import os
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


# ================================================
# Harness generation
# ================================================

class HarnessGenerator:
    """为目标二进制生成 fuzzing harness。

    支持三种接口模式：
    - stdin: AFL persistent mode — 读 stdin, 调用 target, 循环
    - file: LibFuzzer-style — LLVMFuzzerTestOneInput(const uint8_t*, size_t)
    - socket: 网络 fuzzing — 发送变异的包到 localhost
    """

    def generate_c_harness(self, target_func: str,
                           input_mode: str = "file",
                           lib_name: str = "libfuzzer") -> str:
        """生成 C harness 代码。"""
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
    // 最小输入检查: 前 4 字节做参数传给 target
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
    // AFL persistent mode loop
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
    // socket harness: 将输入作为网络包传递给 target
    if (size < 8) return 0;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    {target}(fd, data + 8, size - 8);
    return 0;
}}
""".format(target=target)

    def generate_python_harness(self, target_func: str,
                                input_mode: str = "file") -> str:
        """生成 Python fuzzing harness。"""
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


# ================================================
# Fuzz harness wrapper
# ================================================

class FuzzHarness:
    """轻量 harness 管理器。"""

    def __init__(self, target_binary: str):
        self.target = target_binary
        self.gen = HarnessGenerator()
        self._mode = "file"

    def set_mode(self, mode: str):
        self._mode = mode

    def generate(self, output_path: str, lang: str = "c") -> str:
        """生成并写入 harness。"""
        _func = os.path.basename(self.target).replace("-", "_")
        if lang == "c":
            _code = self.gen.generate_c_harness(_func, self._mode)
        else:
            _code = self.gen.generate_python_harness(_func)
        with open(output_path, "w") as _f:
            _f.write(_code)
        return output_path


# ================================================
# Vulnerability Database
# ================================================

class VulnerabilityDB:
    """SQLite + FTS5 漏洞签名数据库。

    Schema:
    - signatures(id, pattern_hash, vuln_type, severity, description, cve)
    - fts_signatures: FTS5 virtual table over description + vuln_type
    """

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
            pass  # FTS5 not available
        self._conn.commit()

    def insert(self, vuln_type: str, severity: str,
               description: str, cve: str = "",
               pattern: bytes = b"") -> int:
        """插入漏洞签名。"""
        _hash = hashlib.sha256(pattern + vuln_type.encode()).hexdigest()[:16]
        _c = self._conn.execute(
            "INSERT OR IGNORE INTO signatures(pattern_hash, vuln_type, severity, description, cve) "
            "VALUES (?, ?, ?, ?, ?)",
            (_hash, vuln_type, severity, description, cve))
        self._conn.commit()
        # 同步 FTS
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
        """FTS5 全文搜索。"""
        try:
            _rows = self._conn.execute(
                "SELECT s.id, s.vuln_type, s.severity, s.description, s.cve "
                "FROM fts_signatures f JOIN signatures s ON f.rowid = s.id "
                "WHERE fts_signatures MATCH ? ORDER BY rank LIMIT ?",
                (query, limit)).fetchall()
        except sqlite3.OperationalError:
            # Fallback: like search
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
    """独立函数：在漏洞库中搜索。"""
    _db = VulnerabilityDB(db_path or ":memory:")
    _results = _db.search(query)
    _db.close()
    return _results
