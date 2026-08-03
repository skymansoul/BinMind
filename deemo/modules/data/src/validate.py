# 数据校验 —— field-level + record-level validators
# 不依赖 jsonschema/pydantic，数据格式不限于 JSON
# IntegrityChecker 以 SQL 查询 orphaned records
# 批量校验: 单次验证多条记录，聚合所有错误后统一返回
#
# CrossRecordValidator: 跨记录校验 —— 检查记录间时序一致性、
# 路径唯一性、引用完整性等。与 RecordValidator 不同，
# 需要访问整个记录集而非单条记录。

from typing import Callable, List, Dict, Any, Optional
import re


def non_empty_string(value: Any) -> Optional[str]:
    """校验非空字符串 —— 空 bytes/list 视同无效。"""
    if value is None:
        return "value is None"
    if isinstance(value, str):
        if not value.strip():
            return "empty string"
        return None
    if isinstance(value, (bytes, bytearray)):
        if len(value) == 0:
            return "empty bytes"
        return None
    return f"expected str, got {type(value).__name__}"


def sha256_hex(value: Any) -> Optional[str]:
    if not isinstance(value, str) or len(value) != 64:
        return "not a valid sha256 hex string"
    if not re.fullmatch(r'[0-9a-fA-F]{64}', value):
        return "sha256 contains non-hex chars"
    return None


def positive_int(value: Any) -> Optional[str]:
    if not isinstance(value, (int, float)):
        return f"expected number, got {type(value).__name__}"
    if value < 0:
        return f"negative value: {value}"
    return None


def valid_file_path(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value.strip():
        return "empty file path"
    if len(value) > 4096:
        return "file path too long (>4096 chars)"
    return None


def time_range_validator(field: str, min_ts: float = 0, max_ts: float = None) -> Callable:
    """工厂: 创建时间戳范围校验函数 —— 检查 Unix epoch 处于合理区间。

    min_ts 默认 0 (1970)，max_ts 默认当前时间 + 1 天（容忍微小偏差）。
    """
    import time
    _max = max_ts if max_ts is not None else time.time() + 86400

    def _check(record: Dict[str, Any]) -> Optional[str]:
        val = record.get(field)
        if val is None:
            return None
        if not isinstance(val, (int, float)):
            return f"{field}: expected numeric timestamp, got {type(val).__name__}"
        if val < min_ts:
            return f"{field}: timestamp {val} is before {min_ts}"
        if val > _max:
            return f"{field}: timestamp {val} is in the future (> {_max})"
        return None

    return _check


class FieldValidator:
    """字段级校验器 —— 链式组合多个 check 函数。"""

    def __init__(self, field_name: str, required: bool = True):
        self.field = field_name
        self.required = required
        self._checks: List[Callable] = []

    def add_check(self, fn: Callable[[Any], Optional[str]]) -> "FieldValidator":
        self._checks.append(fn)
        return self

    def validate(self, record: Dict[str, Any]) -> Optional[str]:
        if self.field not in record:
            return "missing required field" if self.required else None
        value = record[self.field]
        for check in self._checks:
            err = check(value)
            if err:
                return f"{self.field}: {err}"
        return None


class RecordValidator:
    """记录级校验器 —— 多 FieldValidator 组合 + 跨字段校验。"""

    def __init__(self):
        self._fields: List[FieldValidator] = []
        self._cross_checks: List[Callable[[Dict], Optional[str]]] = []

    def add_field(self, fv: FieldValidator) -> "RecordValidator":
        self._fields.append(fv)
        return self

    def add_cross_check(self, fn: Callable[[Dict], Optional[str]]) -> "RecordValidator":
        self._cross_checks.append(fn)
        return self

    def validate(self, record: Dict[str, Any]) -> List[str]:
        errors = []
        for fv in self._fields:
            err = fv.validate(record)
            if err:
                errors.append(err)
        for cc in self._cross_checks:
            err = cc(record)
            if err:
                errors.append(err)
        return errors

    def validate_batch(self, records: List[Dict[str, Any]]) -> Dict[int, List[str]]:
        """批量校验: 返回 {index: [errors]} 映射，仅含出错记录。"""
        result = {}
        for i, rec in enumerate(records):
            errs = self.validate(rec)
            if errs:
                result[i] = errs
        return result


class CrossRecordValidator:
    """跨记录校验 —— 检查整个数据集的一致性约束。

    与 RecordValidator 逐条校验不同，CrossRecordValidator
    做全局级别检查: 路径唯一性、sha256 唯一性、引用完整性等。
    """

    def __init__(self):
        self._checks: List[Callable[[List[Dict]], List[str]]] = []

    def add_check(self, fn: Callable[[List[Dict]], List[str]]) -> "CrossRecordValidator":
        self._checks.append(fn)
        return self

    def validate(self, records: List[Dict[str, Any]]) -> List[str]:
        errors = []
        for check in self._checks:
            results = check(records)
            if results:
                errors.extend(results)
        return errors


# 预置跨记录校验函数

def check_path_uniqueness(records: List[Dict]) -> List[str]:
    """file_path 在记录集内唯一性检查。"""
    seen = {}
    dups = []
    for i, r in enumerate(records):
        fp = r.get("file_path", "")
        if fp and fp in seen:
            dups.append(f"duplicate path '{fp}': records {seen[fp]} and {i}")
        elif fp:
            seen[fp] = i
    return dups


def check_sha256_uniqueness(records: List[Dict]) -> List[str]:
    """sha256 在记录集内唯一性检查。"""
    seen = {}
    dups = []
    for i, r in enumerate(records):
        sha = r.get("sha256", "")
        if sha and sha in seen:
            dups.append(f"duplicate sha256 '{sha[:16]}...': records {seen[sha]} and {i}")
        elif sha:
            seen[sha] = i
    return dups


def signature_validator() -> RecordValidator:
    """签名记录标准校验器。"""
    rv = RecordValidator()
    rv.add_field(FieldValidator("sha256", required=True).add_check(sha256_hex))
    rv.add_field(FieldValidator("file_path", required=True).add_check(valid_file_path))
    rv.add_field(FieldValidator("file_size", required=False).add_check(positive_int))
    return rv


def cross_record_validator() -> CrossRecordValidator:
    """签名数据集跨记录校验器。"""
    crv = CrossRecordValidator()
    crv.add_check(check_path_uniqueness)
    crv.add_check(check_sha256_uniqueness)
    return crv


class IntegrityChecker:
    """完整性检查 —— 对 DataDB 执行 SQL 查询 orphaned records。
    生产环境建议配合定期 VACUUM + PRAGMA integrity_check。"""

    def __init__(self, db):
        self.db = db

    def check_orphaned_analyses(self) -> List[Dict]:
        conn = self.db.get_connection()
        rows = conn.execute("""
            SELECT ar.id, ar.sig_id FROM analysis_results ar
            LEFT JOIN signatures s ON ar.sig_id = s.id
            WHERE s.id IS NULL
        """).fetchall()
        return [dict(r) for r in rows]

    def check_orphaned_lifecycle(self) -> List[Dict]:
        conn = self.db.get_connection()
        rows = conn.execute("""
            SELECT ll.id, ll.sig_id FROM lifecycle_log ll
            LEFT JOIN signatures s ON ll.sig_id = s.id
            WHERE s.id IS NULL
        """).fetchall()
        return [dict(r) for r in rows]

    def check_duplicate_sha(self) -> List[str]:
        conn = self.db.get_connection()
        rows = conn.execute("""
            SELECT sha256, COUNT(*) as cnt FROM signatures
            GROUP BY sha256 HAVING cnt > 1
        """).fetchall()
        return [r["sha256"] for r in rows]

    def run_all(self) -> Dict:
        return {
            "orphaned_analyses": len(self.check_orphaned_analyses()),
            "orphaned_lifecycle": len(self.check_orphaned_lifecycle()),
            "duplicate_sha256": len(self.check_duplicate_sha()),
        }
