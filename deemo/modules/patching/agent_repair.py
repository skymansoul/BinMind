"""
多轮修复闭环引擎

将补丁修复建模为 agent 循环，每轮：
  路由 -> 候选生成 -> 安全验证 -> 排序 -> 回溯。
失败轮次的验证反馈并入约束，驱动下一轮生成，直至通过或触顶。

参考：
  - Agentic Program Repair from Test Failures at Scale [arXiv:2507.18755]
  - SynthFix: Adaptive Code Vulnerability Repair [arXiv:2604.17184]
  - Autonomous Issue Resolver [arXiv:2512.08492]

区别于 patch_suggestion 单轮生成：本引擎引入多轮闭环、
类型自适应路由、候选排序与轨迹留痕。

安全边界：候选由 SafeRepairValidator 静态校验，不执行目标程序。
"""
import difflib
import logging
import re
import uuid
from dataclasses import dataclass, field

try:
    from .patch_type_router import PatchTypeRouter, RepairFamily, RepairRoute
    from .safe_repair_validator import SafeRepairValidator, ValidationStatus
    from .candidate_patch_ranker import CandidatePatchRanker
except ImportError:
    from patch_type_router import PatchTypeRouter, RepairFamily, RepairRoute
    from safe_repair_validator import SafeRepairValidator, ValidationStatus
    from candidate_patch_ranker import CandidatePatchRanker

logger = logging.getLogger(__name__)

# 验证状态 → 优劣序，跨轮选优用
_STATUS_ORDER = {
    'pass': 0,
    'warning': 1,
    'fail': 2,
    'skipped': 3,
}


def _now_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


@dataclass
class RepairCandidate:
    """单轮候选补丁 —— 携带 diff 与完整替换代码。"""
    candidate_id: str
    patch_diff: str
    new_code: str
    description: str
    route: str = ""
    family: str = ""

    def to_dict(self):
        return {
            'candidate_id': self.candidate_id,
            'route': self.route,
            'family': self.family,
            'description': self.description,
            'patch_diff': self.patch_diff,
            'new_code': self.new_code,
        }


@dataclass
class RepairRound:
    """一轮修复记录 —— 候选 + 验证结果 + 决策。"""
    index: int = 0
    candidate: RepairCandidate = None
    validation: object = None
    rank_score: float = 0.0
    decision: str = "retry"   # accepted / retry / rejected
    feedback: str = ""

    def to_dict(self):
        return {
            'round': self.index,
            'decision': self.decision,
            'rank_score': round(self.rank_score, 4),
            'candidate': self.candidate.to_dict() if self.candidate else None,
            'validation': self.validation.to_dict() if self.validation else None,
            'feedback': self.feedback,
        }


class RepairTrajectory:
    """修复轨迹 — 逐轮候选、反馈、决策，可审计。

    对应 Autonomous Issue Resolver [arXiv:2512.08492] 的
    zero-touch 修复过程留痕：任一轮均可回溯。
    """

    def __init__(self, target_function="", vuln_type="", root_cause="", cwe_id=""):
        self.target_function = target_function
        self.vuln_type = vuln_type
        self.root_cause = root_cause
        self.cwe_id = cwe_id
        self.rounds = []
        self.created_at = _now_iso()

    def add_round(self, rnd):
        self.rounds.append(rnd)

    @property
    def accepted_round(self):
        for r in self.rounds:
            if r.decision == 'accepted':
                return r
        return None

    def to_dict(self):
        return {
            'target_function': self.target_function,
            'vuln_type': self.vuln_type,
            'root_cause': self.root_cause,
            'cwe_id': self.cwe_id,
            'created_at': self.created_at,
            'round_count': len(self.rounds),
            'rounds': [r.to_dict() for r in self.rounds],
        }

    def to_markdown(self):
        """Markdown 审计报告 —— 供 patch_report_composer 引用。"""
        lines = [
            "# AgentRepair 修复轨迹报告", "",
            "| 字段 | 值 |",
            "|---|---|",
            "| 目标函数 | {} |".format(self.target_function or 'N/A'),
            "| 漏洞类型 | {} |".format(self.vuln_type or 'N/A'),
            "| 根因 | {} |".format((self.root_cause or 'N/A')[:80]),
            "| CWE | {} |".format(self.cwe_id or 'N/A'),
            "| 生成时间 | {} |".format(self.created_at),
            "| 轮次数 | {} |".format(len(self.rounds)),
            "",
        ]
        for r in self.rounds:
            lines.append("## 第 {} 轮 — {}".format(r.index, r.decision))
            if r.candidate:
                lines.append("- 路径: {} / {}".format(r.candidate.route, r.candidate.family))
                lines.append("- 描述: {}".format(r.candidate.description))
            if r.validation:
                lines.append("- 验证: {}".format(r.validation.status.value))
                lines.append("- 反馈: {}".format(r.validation.feedback or '无'))
            if r.candidate and r.candidate.patch_diff:
                lines.append("```diff")
                lines.append(r.candidate.patch_diff)
                lines.append("```")
            lines.append("")
        return '\n'.join(lines)


class RepairOutcome:
    """修复结果 — 成功带最终补丁，失败带最优候选。"""

    def __init__(self, success, final_patch, final_description,
                 trajectory, confidence=0.0):
        self.success = success
        self.final_patch = final_patch
        self.final_description = final_description
        self.trajectory = trajectory
        self.confidence = confidence

    def to_dict(self):
        return {
            'success': self.success,
            'confidence': round(self.confidence, 4),
            'final_patch': self.final_patch,
            'final_description': self.final_description,
            'trajectory': self.trajectory.to_dict(),
        }


class AgentRepairEngine:
    """多轮修复引擎 — 编排路由/生成/验证/排序/回溯。"""

    def __init__(self, max_rounds=3, allow_exec=False,
                 router=None, validator=None, ranker=None):
        self._max_rounds = max(1, max_rounds)
        self._router = router or PatchTypeRouter()
        self._validator = validator or SafeRepairValidator(allow_exec=allow_exec)
        self._ranker = ranker or CandidatePatchRanker()

    # -- public ---------------------------------------------------------

    def repair(self, vulnerable_code, vuln_type="unknown", function_name="",
               root_cause="", cwe_id=None, constraints=None, language="c"):
        """执行多轮修复，返回 RepairOutcome。

        constraints: 初始约束 dict，含 'refinements' 预设细化集。
        每轮失败后约束被 _backtrack 扩展并回写。
        """
        trajectory = RepairTrajectory(function_name, vuln_type, root_cause, cwe_id or "")
        if not vulnerable_code or not vulnerable_code.strip():
            return RepairOutcome(False, "", "empty vulnerable code", trajectory)

        route = self._router.route(vuln_type, cwe_id, vulnerable_code)
        constraints = dict(constraints) if constraints else {}
        required = self._required_positives(vuln_type, route.family)
        feedback = ""
        best_round = None

        for rnd in range(1, self._max_rounds + 1):
            candidates = self._generate_candidates(
                vulnerable_code, vuln_type, route, rnd, constraints, feedback)
            if not candidates:
                break
            validations = {}
            for cand in candidates:
                validations[cand.candidate_id] = self._validator.validate(
                    patch_diff=cand.patch_diff, code=cand.new_code,
                    lang=language, required_positive=required)
            ranked = self._ranker.rank(candidates, validations)
            top = ranked[0]
            top_cand = self._find_candidate(candidates, top.candidate_id)
            top_val = validations[top_cand.candidate_id]
            decision = self._decide(top_val.status)
            round_rec = RepairRound(index=rnd, candidate=top_cand,
                                    validation=top_val, rank_score=top.rank_score,
                                    decision=decision, feedback=top_val.feedback)
            trajectory.add_round(round_rec)

            # 保留跨轮最优（按验证状态优劣序+排序分）
            if (best_round is None
                    or _STATUS_ORDER[top_val.status.value]
                    < _STATUS_ORDER[best_round.validation.status.value]
                    or (_STATUS_ORDER[top_val.status.value]
                        == _STATUS_ORDER[best_round.validation.status.value]
                        and top.rank_score > best_round.rank_score)):
                best_round = round_rec

            if decision == 'accepted':
                return RepairOutcome(True, top_cand.patch_diff,
                                     top_cand.description, trajectory,
                                     top.rank_score)
            # 回溯：验证反馈入约束，推进下轮
            feedback = top_val.feedback
            constraints = self._backtrack(feedback, rnd, constraints)

        # 轮次耗尽——返回验证状态最优候选
        if best_round is not None and best_round.candidate:
            return RepairOutcome(False, best_round.candidate.patch_diff,
                                 best_round.candidate.description, trajectory,
                                 best_round.rank_score)
        return RepairOutcome(False, "", "no acceptable candidate produced", trajectory)

    # -- 候选生成 --------------------------------------------------------

    def _generate_candidates(self, code, vuln_type, route, rnd, constraints, feedback):
        """按路由族与反馈生成候选集。

        首轮：单项候选（符号守卫或模板替换）。
        第2轮起：若反馈指缺失项，额外合成综合候选。
        """
        candidates = []
        fam = route.family
        refinements = set(constraints.get('refinements', []))
        if feedback:
            refinements |= self._parse_feedback(feedback)

        path = route.route
        if path in (RepairRoute.SYMBOLIC, RepairRoute.HYBRID):
            candidates.extend(self._symbolic_candidates(code, vuln_type, fam, refinements))
        if path in (RepairRoute.TEMPLATE, RepairRoute.HYBRID):
            candidates.extend(self._template_candidates(code, vuln_type, fam, refinements))
        if rnd >= 2 or refinements:
            combined = self._combined_candidate(code, vuln_type, fam)
            if combined is not None:
                candidates.append(combined)
        candidates = self._dedup(candidates)
        if not candidates:
            candidates.append(self._noop_candidate(code, vuln_type))
        return candidates

    def _symbolic_candidates(self, code, vuln_type, fam, refinements):
        """符号约束路径 — 依操作数合成守卫。"""
        out = []
        vt = str(vuln_type).lower()
        if fam == RepairFamily.LOGIC_DEFECT or 'integer' in vt or 'overflow' in vt:
            for a, b in self._find_arith(code):
                guard = 'if (%s > INT_MAX - %s) { return -1; }' % (a, b)
                new_code = self._insert_guard(code, [guard])
                out.append(RepairCandidate(
                    candidate_id=self._new_id(),
                    patch_diff=self._build_diff(code, new_code),
                    new_code=new_code,
                    description='符号守卫: %s 溢出范围检查' % a,
                    route='symbolic', family=fam.value))
                break
        for dst, src in self._find_copy(code):
            guard = 'if (strlen(%s) >= sizeof(%s)) { return -1; }' % (src, dst)
            new_code = self._insert_guard(code, [guard])
            out.append(RepairCandidate(
                candidate_id=self._new_id(),
                patch_diff=self._build_diff(code, new_code),
                new_code=new_code,
                description='符号守卫: %s 长度边界检查' % dst,
                route='symbolic', family=fam.value))
            break
        if fam == RepairFamily.LOGIC_DEFECT or 'null' in vt or 'deref' in vt:
            for p in self._find_ptrs(code):
                guard = 'if (%s == NULL) { return -1; }' % p
                new_code = self._insert_guard(code, [guard])
                out.append(RepairCandidate(
                    candidate_id=self._new_id(),
                    patch_diff=self._build_diff(code, new_code),
                    new_code=new_code,
                    description='符号守卫: %s 空指针检查' % p,
                    route='symbolic', family=fam.value))
                break
        return out

    def _template_candidates(self, code, vuln_type, fam, refinements):
        """模板路径 — 危险模式直接替换为安全写法。"""
        out = []
        new_code = self._replace_safe_copy(code)
        if new_code != code:
            out.append(RepairCandidate(
                candidate_id=self._new_id(),
                patch_diff=self._build_diff(code, new_code),
                new_code=new_code,
                description='模板: strcpy/strcat → 安全函数',
                route='template', family=fam.value))
        new_code = self._replace_format(code)
        if new_code != code:
            out.append(RepairCandidate(
                candidate_id=self._new_id(),
                patch_diff=self._build_diff(code, new_code),
                new_code=new_code,
                description='模板: 格式化串改为字面量',
                route='template', family=fam.value))
        new_code = self._replace_free_null(code)
        if new_code != code:
            out.append(RepairCandidate(
                candidate_id=self._new_id(),
                patch_diff=self._build_diff(code, new_code),
                new_code=new_code,
                description='模板: free 后置空指针',
                route='template', family=fam.value))
        new_code = self._replace_malloc_check(code)
        if new_code != code:
            out.append(RepairCandidate(
                candidate_id=self._new_id(),
                patch_diff=self._build_diff(code, new_code),
                new_code=new_code,
                description='模板: malloc 返回值校验',
                route='template', family=fam.value))
        return out

    def _combined_candidate(self, code, vuln_type, fam):
        """综合候选 — 符号守卫 + 安全模板同时应用。

        第2轮起由反馈驱动，目标命中全部必需正向模式。
        """
        copies = self._find_copy(code)
        ariths = self._find_arith(code)
        ptrs = self._find_ptrs(code)
        new_code = code
        new_code = self._replace_safe_copy(new_code)
        new_code = self._replace_format(new_code)
        new_code = self._replace_free_null(new_code)
        new_code = self._replace_malloc_check(new_code)
        guards = []
        for dst, src in copies:
            g = 'if (strlen(%s) >= sizeof(%s)) { return -1; }' % (src, dst)
            if g not in guards:
                guards.append(g)
        for a, b in ariths:
            g = 'if (%s > INT_MAX - %s) { return -1; }' % (a, b)
            if g not in guards:
                guards.append(g)
        for p in ptrs:
            g = 'if (%s == NULL) { return -1; }' % p
            if g not in guards:
                guards.append(g)
        if guards:
            new_code = self._insert_guard(new_code, guards)
        if new_code == code:
            return None
        return RepairCandidate(
            candidate_id=self._new_id(),
            patch_diff=self._build_diff(code, new_code),
            new_code=new_code,
            description='综合修复: 符号守卫 + 安全模板（反馈细化）',
            route='hybrid', family=fam.value)

    def _noop_candidate(self, code, vuln_type):
        """占位候选 — 保证循环总有输出，验证器标 WARNING。"""
        return RepairCandidate(
            candidate_id=self._new_id(),
            patch_diff=self._build_diff(code, code),
            new_code=code,
            description='占位候选 — 无实质修改',
            route='template', family='unknown')

    # -- 代码变换 --------------------------------------------------------

    def _insert_guard(self, code, guards):
        """守卫语句插入函数体入口（第一个 { 之后）。"""
        if not guards:
            return code
        lines = code.splitlines()
        for i, ln in enumerate(lines):
            if '{' in ln:
                indent = ln[:len(ln) - len(ln.lstrip())] + '    '
                out = lines[:i + 1]
                for g in guards:
                    out.append(indent + g)
                out.extend(lines[i + 1:])
                return '\n'.join(out)
        # 无函数体 → 前插
        return '\n'.join(['    ' + g for g in guards] + lines)

    def _replace_safe_copy(self, code):
        """strcpy/strcat → strncpy/strncat，目标容量减1。"""
        new = re.sub(r'\bstrcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)',
                     r'strncpy(\1, \2, sizeof(\1) - 1)', code)
        new = re.sub(r'\bstrcat\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)',
                     r'strncat(\1, \2, sizeof(\1) - strlen(\1) - 1)', new)
        return new

    def _replace_format(self, code):
        """printf(变量) → printf("%s", 变量)。"""
        return re.sub(r'\bprintf\s*\(\s*([a-zA-Z_]\w*)\s*\)',
                      r'printf("%s", \1)', code)

    def _replace_free_null(self, code):
        """free(p) 后追加 p = NULL。"""
        lines = code.splitlines()
        out = []
        for ln in lines:
            out.append(ln)
            m = re.search(r'\bfree\s*\(\s*(\w+)\s*\)\s*;', ln)
            if m:
                out.append('    %s = NULL;' % m.group(1))
        return '\n'.join(out)

    def _replace_malloc_check(self, code):
        """malloc 赋值后追加 NULL 检查。"""
        lines = code.splitlines()
        out = []
        for ln in lines:
            out.append(ln)
            m = re.search(r'\b(\w+)\s*=\s*malloc\s*\(', ln)
            if m:
                out.append('    if (%s == NULL) { return -1; }' % m.group(1))
        return '\n'.join(out)

    def _find_arith(self, code):
        """提取算术操作数对 (a, b)。

        仅匹配加减。排除 *（可能是指针声明或乘法，乘法溢出
        判定公式不同）与 /，避免生成错误守卫。
        """
        out = []
        for m in re.finditer(r'\b([a-zA-Z_]\w*)\s*[+\-]\s*([a-zA-Z_]\w*)\b', code):
            pair = (m.group(1), m.group(2))
            if pair not in out:
                out.append(pair)
        return out

    def _find_copy(self, code):
        """提取 strcpy/strcat 的 (dst, src) 对。"""
        out = []
        for m in re.finditer(r'\b(strcpy|strcat)\s*\(\s*([a-zA-Z_]\w*)\s*,\s*([a-zA-Z_]\w*)\s*\)',
                             code):
            pair = (m.group(2), m.group(3))
            if pair not in out:
                out.append(pair)
        return out

    def _find_ptrs(self, code):
        """启发式提取指针候选（-> 解引用 / 指针声明变量名）。

        指针声明 `char *dst, char *src` 仅捕获 * 后的变量名，
        避免把类型名误当指针。
        """
        out = []
        for m in re.finditer(r'\b([a-zA-Z_]\w*)\s*->', code):
            if m.group(1) not in out:
                out.append(m.group(1))
        for m in re.finditer(
                r'\b(?:const\s+)?[a-zA-Z_]\w*\s*\*\s*([a-zA-Z_]\w*)\s*[,)]',
                code):
            if m.group(1) not in out:
                out.append(m.group(1))
        return out

    @staticmethod
    def _build_diff(orig, new):
        """生成 unified diff，供验证器与报告使用。"""
        diff = difflib.unified_diff(
            orig.splitlines(), new.splitlines(),
            fromfile='a/source.c', tofile='b/source.c', lineterm='')
        return '\n'.join(diff)

    @staticmethod
    def _dedup(candidates):
        """按 new_code 去重，保留首现。"""
        seen = set()
        out = []
        for c in candidates:
            if c.new_code in seen:
                continue
            seen.add(c.new_code)
            out.append(c)
        return out

    @staticmethod
    def _find_candidate(candidates, cid):
        for c in candidates:
            if c.candidate_id == cid:
                return c
        return candidates[0]

    @staticmethod
    def _parse_feedback(feedback):
        """解析 [tag] 标签 → 细化集合。"""
        refs = set()
        for m in re.finditer(r'\[([a-zA-Z0-9_:]+)\]', feedback or ''):
            refs.add(m.group(1))
        return refs

    def _backtrack(self, feedback, rnd, constraints):
        """反馈标签并入 refinements，记录轮次。"""
        refs = self._parse_feedback(feedback)
        merged = set(constraints.get('refinements', []))
        merged |= refs
        out = dict(constraints)
        out['refinements'] = sorted(merged)
        out['round'] = rnd
        return out

    # -- 杂项 ------------------------------------------------------------

    @staticmethod
    def _decide(status):
        """验证状态 → 轮次决策。"""
        if status == ValidationStatus.PASS:
            return 'accepted'
        if status == ValidationStatus.WARNING:
            return 'retry'
        return 'rejected'

    @staticmethod
    def _required_positives(vuln_type, fam):
        """按漏洞类型推导必需正向安全模式。

        边界：integer_overflow 虽含 overflow 但属算术溢出，
        不应要求 bounds_guard/safe_copy；仅内存拷贝语义
        （buffer/stack/heap/copy/strcpy/memcpy）时才要求。
        """
        vt = str(vuln_type).lower()
        req = []
        is_memcpy = any(k in vt for k in ('buffer', 'stack', 'heap', 'copy',
                                         'strcpy', 'memcpy'))
        if is_memcpy:
            req += ['bounds_guard', 'safe_copy']
        if any(k in vt for k in ('format', 'injection', 'command')):
            req.append('format_literal')
        if any(k in vt for k in ('null', 'deref')):
            req.append('null_guard')
        if 'integer' in vt or ('overflow' in vt and not is_memcpy):
            req.append('overflow_guard')
        if any(k in vt for k in ('free', 'leak', 'resource')):
            req.append('resource_release')
        if fam == RepairFamily.INPUT_VALIDATION:
            req.append('bounds_guard')
        # 去重保序
        seen = set()
        return [x for x in req if not (x in seen or seen.add(x))]

    @staticmethod
    def _new_id():
        return 'rc_' + uuid.uuid4().hex[:8]


def agent_repair(vulnerable_code, vuln_type="unknown", function_name="",
                 root_cause="", cwe_id=None, constraints=None,
                 language="c", max_rounds=3):
    """便捷入口 —— 单次调用完成多轮修复。"""
    engine = AgentRepairEngine(max_rounds=max_rounds)
    return engine.repair(vulnerable_code, vuln_type, function_name,
                         root_cause, cwe_id, constraints, language)


def repair_to_dict(outcome):
    """修复结果转 dict（含轨迹），供报告合成器消费。"""
    return outcome.to_dict() if hasattr(outcome, 'to_dict') else {'success': False}
