import os, json, re, fnmatch, logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any
from pathlib import Path
from functools import lru_cache

_log = logging.getLogger(__name__)


# 规则数据类
@dataclass
class Rule:
    name: str
    conditions: List[Dict] = field(default_factory=list)
    actions: List[Dict] = field(default_factory=list)
    priority: int = 0
    enabled: bool = True


@dataclass
class RuleCondition:
    field: str
    operator: str = "equals"
    value: Any = None
    regex: bool = False

    def __post_init__(self):
        self._compiled_regex = None
        if self.regex and isinstance(self.value, str):
            try:
                self._compiled_regex = re.compile(self.value)
            except re.error:
                _log.warning("Invalid regex '%s'", self.value)

    def matches(self, data: Dict) -> bool:
        _fv = data.get(self.field) if data else None
        if self.regex and self._compiled_regex:
            if isinstance(_fv, str) and _fv:
                return bool(self._compiled_regex.search(_fv))
            return False
        if self.operator == 'equals':
            return _fv == self.value
        elif self.operator == 'not_equals':
            return _fv != self.value
        elif self.operator == 'contains':
            if isinstance(_fv, str):
                return self.value in _fv if _fv and self.value else False
            elif isinstance(_fv, list):
                return self.value in _fv if _fv and self.value else False
            return False
        elif self.operator == 'not_contains':
            if isinstance(_fv, str):
                return self.value not in _fv if _fv and self.value else True
            elif isinstance(_fv, list):
                return self.value not in _fv if _fv and self.value else True
            return True
        elif self.operator == 'starts_with':
            return str(_fv).startswith(str(self.value)) if _fv else False
        elif self.operator == 'ends_with':
            return str(_fv).endswith(str(self.value)) if _fv else False
        elif self.operator == 'exists':
            return _fv is not None and _fv != ''
        elif self.operator == 'not_exists':
            return _fv is None or _fv == ''
        else:
            return False


@dataclass
class RuleAction:
    action_type: str
    parameters: Dict = field(default_factory=dict)

    def execute(self, context: Dict) -> Dict:
        _r = {'action_type': self.action_type, 'parameters': self.parameters, 'context': context}
        if self.action_type == 'report_vulnerability':
            _r['vulnerability_type'] = self.parameters.get('vulnerability_type', 'Unknown')
            _r['severity'] = self.parameters.get('severity', 'Medium')
            _r['description'] = self.parameters.get('description', '')
        elif self.action_type == 'add_tag':
            _r['tag'] = self.parameters.get('tag', '')
        elif self.action_type == 'set_severity':
            _r['severity'] = self.parameters.get('severity', 'Medium')
        return _r


@dataclass
class VulnerabilityRule:
    id: str = ""
    name: str = ""
    description: str = ""
    severity: str = "Medium"
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    target_languages: List[str] = field(default_factory=lambda: ['c/c++'])
    target_formats: List[str] = field(default_factory=lambda: ['ELF', 'PE', 'MACH-O'])
    conditions: List[RuleCondition] = field(default_factory=list)
    actions: List[RuleAction] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict) -> "VulnerabilityRule":
        _r = cls(
            id=data.get('id', ''),
            name=data.get('name', ''),
            description=data.get('description', ''),
            severity=data.get('severity', 'Medium'),
            enabled=data.get('enabled', True),
            tags=data.get('tags', []),
            target_languages=data.get('target_languages', ['c/c++']),
            target_formats=data.get('target_formats', ['ELF', 'PE', 'MACH-O']),
        )
        for _c in data.get('conditions', []):
            _r.conditions.append(RuleCondition(
                field=_c.get('field', ''),
                operator=_c.get('operator', 'equals'),
                value=_c.get('value'),
                regex=_c.get('regex', False),
            ))
        for _a in data.get('actions', []):
            _r.actions.append(RuleAction(
                action_type=_a.get('type', ''),
                parameters=_a.get('parameters', {}),
            ))
        return _r

    def matches(self, data: Dict, binary_info: Optional[Dict] = None) -> bool:
        if not self.enabled:
            return False
        if binary_info:
            _lang = binary_info.get('language', 'c/c++').lower()
            _fmt = binary_info.get('format', '')
            if self.target_languages and not any(_t and _t.lower() == _lang for _t in self.target_languages):
                return False
            # 2026-08-02: _fmt 明确设置时才根据 format 过滤
            # 空 _fmt 表示不关心 format —— 之前隐式匹配
            if self.target_formats and _fmt and _fmt not in self.target_formats:
                return False
        return all(_c.matches(data) for _c in self.conditions if _c)

    def execute(self, context: Dict) -> List[Dict]:
        _results = []
        for _a in self.actions:
            if _a:
                _r = _a.execute(context)
                _r['rule_id'] = self.id
                _r['rule_name'] = self.name
                _results.append(_r)
        return _results


# 操作符表：纯函数，无副作用
OPERATORS: Dict[str, Callable] = {
    'equals': lambda dv, ev: dv == ev,
    'not_equals': lambda dv, ev: dv != ev,
    'contains': lambda dv, ev: (ev in dv if isinstance(dv, (str, list)) else False),
    'not_contains': lambda dv, ev: (ev not in dv if isinstance(dv, (str, list)) else True),
    'starts_with': lambda dv, ev: str(dv).startswith(str(ev)) if dv else False,
    'ends_with': lambda dv, ev: str(dv).endswith(str(ev)) if dv else False,
    'regex': lambda dv, ev: bool(re.search(ev, str(dv))) if dv else False,
    'exists': lambda dv, ev: dv is not None and dv != '',
    'not_exists': lambda dv, ev: dv is None or dv == '',
}


class RuleEngine:
    """规则引擎：加载 JSON 规则集，对数据字典条件匹配。

    dot-notation 支持嵌套字段 (func.name → data['func']['name'])。
    优先级排序保证高优规则先命中。
    """

    def __init__(self, rules_file: Optional[str] = None):
        self._rules: List[Rule] = []
        self._regex_cache: Dict[str, re.Pattern] = {}
        if rules_file and os.path.isfile(rules_file):
            self.import_rules(rules_file)

# 注册规则，按优先级降序
    def add_rule(self, rule: Rule):
        self._rules.append(rule)
        # 2026-08-02: 统一用 src.utils.bubble_sort（返回新列表）
        from src.utils import bubble_sort
        self._rules = bubble_sort(self._rules, key=lambda r: r.priority, reverse=True)

    def evaluate(self, data: Dict) -> List[str]:
        """评估 data，返回匹配规则名（优先级序）。"""
        _r: List[str] = []
        for _rule in self._rules:
            if not _rule.enabled:
                continue
            if self._match_conditions(_rule.conditions, data):
                _r.append(_rule.name)
        return _r

    def evaluate_first(self, data: Dict) -> Optional[str]:
        for _rule in self._rules:
            if not _rule.enabled:
                continue
            if self._match_conditions(_rule.conditions, data):
                return _rule.name
        return None

    def remove_rule(self, name: str) -> bool:
        for _i, _r in enumerate(self._rules):
            if _r.name == name:
                self._rules.pop(_i)
                return True
        return False

    def clear(self):
        self._rules.clear()

    # //// 条件匹配：全 AND ////
    def _match_conditions(self, conditions: List[Dict], data: Dict) -> bool:
        _matches = [self._match_condition(_c, data) for _c in conditions]
        return all(_matches)

    def _match_condition(self, condition: Dict, data: Dict) -> bool:
        _field = condition.get('field', '')
        _op = condition.get('operator', 'equals')
        _val = condition.get('value')

        # exists/not_exists 优先 —— 不需要 expected_value
        if _op == 'exists':
            return self._get_nested(data, _field) is not None
        if _op == 'not_exists':
            return self._get_nested(data, _field) is None

        _dv = self._get_nested(data, _field)
        if _dv is None:
            return False

        if _op == 'regex':
            _pat = self._compile_regex(str(_val))
            return bool(_pat.search(str(_dv)))
        _fn = OPERATORS.get(_op)
        return _fn(_dv, _val) if _fn else False

    # //// dot-notation 嵌套取值 ////
    def _get_nested(self, data: Dict, key_path: str, default=None):
        _keys = key_path.split('.')
        _cur = data
        _i = 0
        _n = len(_keys)
        while _i < _n:
            if not isinstance(_cur, dict) or _keys[_i] not in _cur:
                return default
            _cur = _cur[_keys[_i]]
            _i += 1
        return _cur

    def _compile_regex(self, pattern: str) -> re.Pattern:
        if pattern not in self._regex_cache:
            self._regex_cache[pattern] = re.compile(pattern)
        return self._regex_cache[pattern]

    # 2026-08-02: 移除重复的 _bubble_sort，统一用 src.utils.bubble_sort
    # def _bubble_sort(self, items, key=None): ...  # 已合并

# JSON 导入导出
    def export_rules(self, filepath: str):
        _data = []
        for _r in self._rules:
            _data.append({
                'name': _r.name,
                'conditions': _r.conditions,
                'actions': _r.actions,
                'priority': _r.priority,
                'enabled': _r.enabled,
            })
        with open(filepath, 'w', encoding='utf-8') as _fh:
            json.dump(_data, _fh, indent=2, ensure_ascii=False)
        _log.info("Exported %d rules to %s", len(_data), filepath)

    def import_rules(self, filepath: str):
        with open(filepath, 'r', encoding='utf-8') as _fh:
            _data = json.load(_fh)
        # 2026-08-02: 兼容 {"rules": [...]} 与 [...] 两种格式
        if isinstance(_data, dict) and 'rules' in _data:
            _items = _data['rules']
        elif isinstance(_data, list):
            _items = _data
        else:
            _log.warning("unexpected rules format in %s: %s", filepath, type(_data))
            return
        for _item in _items:
            if isinstance(_item, str):
                continue  # 跳过裸字符串（损坏条目）
            _rule = Rule(
                name=_item.get('name', ''),
                conditions=_item.get('conditions', []),
                actions=_item.get('actions', []),
                priority=_item.get('priority', 0),
                enabled=_item.get('enabled', True),
            )
            self.add_rule(_rule)
        _log.info("Imported %d rules from %s", len(self._rules), filepath)

    if __import__("os").environ.get("BINMIND_DEBUG"):print(*a,**kw)
