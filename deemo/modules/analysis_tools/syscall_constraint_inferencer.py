import logging
from dataclasses import dataclass, field
import typing

logger = logging.getLogger(__name__)



class ParamConstraint:
    __slots__ = ('param_index', 'param_name', 'param_type', 'min_value', 'max_value', 'not_null', 'alignment', 'must_be_valid_fd', 'must_be_writable', 'description',)

    def __init__(self, param_index, param_name, param_type, min_value=None, max_value=None, not_null=False, alignment=0, must_be_valid_fd=False, must_be_writable=False, description=""):
        self.param_index = param_index
        self.param_name = param_name
        self.param_type = param_type
        self.min_value = min_value
        self.max_value = max_value
        self.not_null = not_null
        self.alignment = alignment
        self.must_be_valid_fd = must_be_valid_fd
        self.must_be_writable = must_be_writable
        self.description = description

    def to_dict(self) -> Dict[str, Any]:
        return {
            'param_index': self.param_index,
            'param_name': self.param_name,
            'type': self.param_type,
            'range': f'[{self.min_value}, {self.max_value}]'
                    if self.min_value is not None else 'unconstrained',
            'not_null': self.not_null,
            'alignment': self.alignment
        }


class SyscallConstraintInferencer:
    SYSCALL_CONSTRAINTS: Dict[str, List[ParamConstraint]] = {
        'sys_read': [
            ParamConstraint(0, 'fd', 'unsigned int', 0, 1024, True,
                           must_be_valid_fd=True, description='File descriptor'),
            ParamConstraint(1, 'buf', 'char *', not_null=True,
                           must_be_writable=True, description='Buffer cannot be NULL'),
            ParamConstraint(2, 'count', 'size_t', 1, 0x7fffffff,
                           description='Read count must be positive'),
        ],
        'sys_write': [
            ParamConstraint(0, 'fd', 'unsigned int', 0, 1024, True,
                           must_be_valid_fd=True),
            ParamConstraint(1, 'buf', 'const char *', not_null=True),
            ParamConstraint(2, 'count', 'size_t', 1, 0x7fffffff),
        ],
        'sys_open': [
            ParamConstraint(0, 'filename', 'const char *', not_null=True),
            ParamConstraint(1, 'flags', 'int', 0, 0xFFFF),
            ParamConstraint(2, 'mode', 'umode_t', 0, 0x1FF),
        ],
        'sys_execve': [
            ParamConstraint(0, 'filename', 'const char *', not_null=True),
            ParamConstraint(1, 'argv', 'char *const *'),
            ParamConstraint(2, 'envp', 'char *const *'),
        ],
        'sys_mmap': [
            ParamConstraint(0, 'addr', 'unsigned long'),
            ParamConstraint(1, 'len', 'unsigned long', 1, 0x7fffffff),
            ParamConstraint(2, 'prot', 'unsigned long', 0, 7),
            ParamConstraint(3, 'flags', 'unsigned long', 1, 0xFFFFFFFF),
            ParamConstraint(4, 'fd', 'unsigned long'),
            ParamConstraint(5, 'offset', 'unsigned long', 0, None,
                           alignment=4096),
        ],
        'sys_ptrace': [
            ParamConstraint(0, 'request', 'long', 0, 0x20),
            ParamConstraint(1, 'pid', 'pid_t', 1, 0x7fffffff),
            ParamConstraint(2, 'addr', 'void *'),
            ParamConstraint(3, 'data', 'void *'),
        ],
    }

    def __init__(self):
        self._constraints: Dict[str, List[ParamConstraint]] = dict(self.SYSCALL_CONSTRAINTS)

    def get_constraints(self, syscall_name: str) -> List[ParamConstraint]:
        for name in [syscall_name, f'sys_{syscall_name}',
                     syscall_name.replace('sys_', '')]:
            if name in self._constraints:
                return self._constraints[name]
        return []

    def infer_from_usage(self, syscall_name: str,
                         observed_values: List[List[int]]) -> List[ParamConstraint]:
        base = self.get_constraints(syscall_name)
        if not observed_values:
            return base

        num_params = len(observed_values[0]) if observed_values else 0
        constraints = list(base)

        for i in range(min(num_params, len(constraints))):
            vals = [obs[i] for obs in observed_values if i < len(obs)]
            if vals:
                c = constraints[i]
                if c.min_value is None or min(vals) < c.min_value:
                    c.min_value = min(vals)
                if c.max_value is None or max(vals) > c.max_value:
                    c.max_value = max(vals)

        return constraints

    def check_violation(self, syscall_name: str,
                        args: List[int]) -> List[Dict[str, Any]]:
        violations = []
        constraints = self.get_constraints(syscall_name)

        for c in constraints:
            if c.param_index >= len(args):
                continue
            value = args[c.param_index]

            if c.not_null and value == 0:
                violations.append({
                    'param': c.param_name,
                    'constraint': 'not_null',
                    'actual_value': value,
                    'severity': 'critical'})
            if c.min_value is not None and value < c.min_value:
                violations.append({
                    'param': c.param_name,
                    'constraint': f'min={c.min_value}',
                    'actual_value': value,
                    'severity': 'high'})
            if c.max_value is not None and value > c.max_value:
                violations.append({
                    'param': c.param_name,
                    'constraint': f'max={c.max_value}',
                    'actual_value': value,
                    'severity': 'high'})
            if c.alignment and value % c.alignment != 0:
                violations.append({
                    'param': c.param_name,
                    'constraint': f'alignment={c.alignment}',
                    'actual_value': value,
                    'severity': 'medium'})

        return violations

    def analyze(self, syscall_name: Optional[str] = None,
                observed_args: Optional[List[int]] = None,
                **kwargs) -> Dict[str, Any]:
        result = {
            'success': True,
            'total_syscalls_in_db': len(self._constraints),
            'known_syscalls': list(self._constraints.keys())[:30]
        }

        if syscall_name:
            constraints = self.get_constraints(syscall_name)
            result['syscall'] = syscall_name
            result['constraints'] = [c.to_dict() for c in constraints]

        if observed_args and syscall_name:
            violations = self.check_violation(syscall_name, observed_args)
            result['violations'] = violations
            result['has_violations'] = len(violations) > 0
            result['risk_level'] = 'critical' if any(
                v['severity'] == 'critical' for v in violations) else \
                'high' if violations else 'low'

        return result

def infer_syscall_constraints(syscall_name: str,
                              observed_args: Optional[List[int]] = None,
                              **kwargs) -> Dict[str, Any]:
    inferencer = SyscallConstraintInferencer()
    return inferencer.analyze(syscall_name=syscall_name,
                             observed_args=observed_args)


__all__ = ["SyscallConstraintInferencer", "ParamConstraint",
           "infer_syscall_constraints"]
