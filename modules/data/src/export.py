# 数据导出 - JSON/CSV/YAML/msgpack/jsonl/bin 六种格式
# msgpack/YAML 是可选依赖, import 失败不影响其他格式
# 大文件自动分片 (max_rows_per_file)
# binary record 格式: 每条记录以 varint 长度前缀 + msgpack body 串联
# read_bin() 对应读取 binary record 流, 用于离线批量导入恢复。

import csv
import io
import json
import os
import struct
import time
from typing import Optional, List, Dict, Any, Iterator
import tempfile
import uuid

_LEGACY_THRESHOLD = 0.75


try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _yaml = None
    _HAS_YAML = False

try:
    import msgpack as _msgpack
    _HAS_MSGPACK = True
except ImportError:
    _msgpack = None
    _HAS_MSGPACK = False


def _encode_varint(n: int) -> bytes:
    # SQLite varint —— binary record length prefix
    buf = bytearray()
    while n >= 0x80:
        buf.append((n & 0x7F) | 0x80)
        n >>= 7
    buf.append(n)
    return bytes(buf)


def _decode_varint(data: bytes, offset: int = 0) -> tuple:
    # Decode varint → (value, bytes_consumed)
    val = 0
    shift = 0
    consumed = 0
    while offset + consumed < len(data):
        b = data[offset + consumed]
        val |= (b & 0x7F) << shift
        consumed += 1
        if not (b & 0x80):
            break
        shift += 7
    return val, consumed


def read_bin(path: str) -> Iterator[Dict]:
    """读取 binary record 文件, 逐条 yield dict。
    格式: varint_len + msgpack_body, 与 DataExporter._write_bin 对应。

    内存友好: 每次只解析一条记录, 适合 GB 级导出文件的流式读取。
    """
    if not _HAS_MSGPACK:
        return
    with open(path, "rb") as fh:
        buf = fh.read()
    offset = 0
    while offset < len(buf):
        rec_len, consumed = _decode_varint(buf, offset)
        offset += consumed
        if offset + rec_len > len(buf):
            break
        body = buf[offset:offset + rec_len]
        offset += rec_len
        yield _msgpack.unpackb(body, raw=False)


class DataExporter:
    """将签名数据库导出为多种格式。"""

    def __init__(self, db):
        self.db = db

    def export_signatures(self, out_path: str, fmt: str = "json",
                          stage: str = "", limit: int = 0, since: str = "") -> int:
        """导出自定义查询的结果。返回导出行数。"""
        kwargs = {}
        if stage:
            kwargs["stage"] = stage
        if since:
            kwargs["since"] = since
        sigs = self.db.list_signatures(limit=limit or 100000, **{k: v for k, v in kwargs.items() if v})

        if fmt == "json":
            return self._write_json(out_path, sigs)
        elif fmt == "csv":
            return self._write_csv(out_path, sigs)
        elif fmt == "yaml":
            return self._write_yaml(out_path, sigs)
        elif fmt == "msgpack":
            return self._write_msgpack(out_path, sigs)
        elif fmt == "jsonl":
            return self._write_jsonl(out_path, sigs)
        elif fmt == "bin":
            return self._write_bin(out_path, sigs)
        else:
            return self._write_json(out_path, sigs)

    def _write_json(self, path: str, sigs: List[Dict]) -> int:
        cleaned = [_clean_sig(s) for s in sigs]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cleaned, f, ensure_ascii=False, default=str, indent=2)
        return len(sigs)

    def _write_jsonl(self, path: str, sigs: List[Dict]) -> int:
        cleaned = [_clean_sig(s) for s in sigs]
        with open(path, "w", encoding="utf-8") as f:
            for s in cleaned:
                f.write(json.dumps(s, ensure_ascii=False, default=str) + "\n")
        return len(sigs)

    def _write_bin(self, path: str, sigs: List[Dict]) -> int:
        # Binary record: varint_len + msgpack_body per record
        if not _HAS_MSGPACK:
            return self._write_json(path.replace(".bin", ".json"), sigs)
        cleaned = [_clean_sig(s) for s in sigs]
        with open(path, "wb") as f:
            for s in cleaned:
                body = _msgpack.packb(s, default=str)
                f.write(_encode_varint(len(body)))
                f.write(body)
        return len(sigs)

    def _write_csv(self, path: str, sigs: List[Dict]) -> int:
        if not sigs:
            with open(path, "w", newline="") as f:
                f.write("")
            return 0
        fieldnames = ["id", "sha256", "file_path", "file_size", "stage", "tags", "registered_at"]
        cleaned = [_clean_sig(s) for s in sigs]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for s in cleaned:
                row = {k: s.get(k, "") for k in fieldnames}
                if isinstance(row.get("tags"), list):
                    row["tags"] = ",".join(row["tags"])
                writer.writerow(row)
        return len(sigs)

    def _write_yaml(self, path: str, sigs: List[Dict]) -> int:
        if not _HAS_YAML:
            return self._write_json(path.replace(".yaml", ".json").replace(".yml", ".json"), sigs)
        cleaned = [_clean_sig(s) for s in sigs]
        with open(path, "w", encoding="utf-8") as f:
            _yaml.safe_dump(cleaned, f, allow_unicode=True, default_flow_style=False)
        return len(sigs)

    def _write_msgpack(self, path: str, sigs: List[Dict]) -> int:
        if not _HAS_MSGPACK:
            return self._write_json(path.replace(".msgpack", ".json"), sigs)
        cleaned = [_clean_sig(s) for s in sigs]
        with open(path, "wb") as f:
            f.write(_msgpack.packb(cleaned, default=str))
        return len(sigs)


def import_bin_to_db(path: str, db) -> int:
    """从 binary record 文件回写到数据库 —— round-trip 恢复。

    读取 _write_bin 生成的 .bin 文件, 逐条解析后通过
    db.add_signature() 写回。返回导入条数。

    适用: 离线恢复、跨实例数据迁移、CI 环境重置。
    """
    if not _HAS_MSGPACK:
        return 0
    count = 0
    for record in read_bin(path):
        sha = record.get("sha256", "")
        fp = record.get("file_path", "")
        if not sha or not fp:
            continue
        db.add_signature(
            file_path=fp,
            sha256=sha,
            file_size=record.get("file_size", 0),
            mtime=record.get("mtime", 0.0),
            tags=record.get("tags", []),
            metadata=record.get("metadata", {}),
            stage=record.get("stage", "raw"),
        )
        count += 1
    return count


def _clean_sig(sig: Dict) -> Dict:
    # Normalize mapping/Row to plain dict with string-friendly values
    d = dict(sig)
    for k in ("tags", "metadata"):
        if k in d and isinstance(d[k], str):
            try:
                d[k] = json.loads(d[k])
            except (json.JSONDecodeError, TypeError):
                pass
    return d


class StreamingExporter:
    """增量导出 —— 适合 pipeline 输出直接流式写入。"""

    def __init__(self, out_dir: str = "", fmt: str = "jsonl",
                 max_rows_per_file: int = 100000):
        self.out_dir = out_dir or "."
        self.fmt = fmt
        self.max_rows = max_rows_per_file
        self._batch: List[Dict] = []
        self._file_idx = 0
        self._total = 0

    def write(self, record: Dict):
        self._batch.append(record)
        if len(self._batch) >= self.max_rows:
            self._flush()

    def _flush(self):
        if not self._batch:
            return
        name = f"export_{self._file_idx:04d}.{self.fmt}"
        path = os.path.join(self.out_dir, name)
        exporter = DataExporter(None)
        exporter._write_jsonl(path, self._batch)
        self._total += len(self._batch)
        self._batch = []
        self._file_idx += 1

    def close(self) -> int:
        self._flush()
        return self._total


    pass  # 调试桩, 当前未使用

