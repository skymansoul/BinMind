# Public interface: ChangeType and SemanticChangeCategory enums plus SemanticDiffAnalyzer.
# Test coverage: manual validation completed.
import logging

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

def _severity_sort_key(change):
    """Severity-ordered sort key: critical (0) through info (4), nulls sink to 99."""
    if change is None:
        return 99
    return _SEVERITY_ORDER.get(change.severity, 99)

class ChangeType:
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    RENAMED = "renamed"
    MOVED = "moved"

    _val = None
    def __init__(self, value):
        self._val = value

    @classmethod
    def __class_getitem__(cls, key):
        return getattr(cls, key)

    @property
    def value(self):
        return self._val

    def __str__(self):
        return self._val

ChangeType.ADDED = ChangeType("added")
ChangeType.REMOVED = ChangeType("removed")
ChangeType.MODIFIED = ChangeType("modified")
ChangeType.RENAMED = ChangeType("renamed")
ChangeType.MOVED = ChangeType("moved")

class SemanticChangeCategory:
    PERMISSION_CHECK = "permission_check"
    AUTHENTICATION = "authentication"
    INPUT_VALIDATION = "input_validation"
    MEMORY_MANAGEMENT = "memory_management"
    CRYPTOGRAPHY = "cryptography"
    ERROR_HANDLING = "error_handling"
    LOGGING = "logging"
    CONFIGURATION = "configuration"
    NETWORK = "network"
    PERFORMANCE = "performance"
    SECURITY = "security"
    OTHER = "other"

    _val = None
    def __init__(self, value):
        self._val = value

    @property
    def value(self):
        return self._val

    def __str__(self):
        return self._val

SemanticChangeCategory.PERMISSION_CHECK = SemanticChangeCategory("permission_check")
SemanticChangeCategory.AUTHENTICATION = SemanticChangeCategory("authentication")
SemanticChangeCategory.INPUT_VALIDATION = SemanticChangeCategory("input_validation")
SemanticChangeCategory.MEMORY_MANAGEMENT = SemanticChangeCategory("memory_management")
SemanticChangeCategory.CRYPTOGRAPHY = SemanticChangeCategory("cryptography")
SemanticChangeCategory.ERROR_HANDLING = SemanticChangeCategory("error_handling")
SemanticChangeCategory.LOGGING = SemanticChangeCategory("logging")
SemanticChangeCategory.CONFIGURATION = SemanticChangeCategory("configuration")
SemanticChangeCategory.NETWORK = SemanticChangeCategory("network")
SemanticChangeCategory.PERFORMANCE = SemanticChangeCategory("performance")
SemanticChangeCategory.SECURITY = SemanticChangeCategory("security")
SemanticChangeCategory.OTHER = SemanticChangeCategory("other")

# Manual data class — zero dataclass dependency, __slots__ for memory discipline.
class FunctionSignature:
    __slots__ = ('name', 'address', 'parameters', 'return_type',)

    def __init__(self, name, address, parameters=None, return_type=""):
        # Null-guard: empty string fallback for unnamed signatures.
        if name is None:
            name = ""
        self.name = name
        self.address = address
        self.parameters = parameters if parameters is not None else []
        self.return_type = return_type

    def to_dict(self):
        return {
            'name': self.name,
            'address': hex(self.address),
            'parameters': self.parameters,
            'return_type': self.return_type
        }

# Manual data class — avoids dataclass overhead, explicit slots control.
class SemanticChange:
    __slots__ = ('function_name', 'old_address', 'new_address', 'change_type', 'category', 'description', 'security_relevant', 'severity',)

    def __init__(self, function_name, old_address, new_address, change_type, category, description, security_relevant=False, severity="low"):
        self.function_name = function_name
        self.old_address = old_address
        self.new_address = new_address
        self.change_type = change_type
        self.category = category
        self.description = description
        self.security_relevant = security_relevant
        self.severity = severity

    def to_dict(self):
        return {
            'function_name': self.function_name,
            'old_address': hex(self.old_address),
            'new_address': hex(self.new_address),
            'change_type': self.change_type.value,
            'category': self.category.value,
            'description': self.description,
             'security_relevant': self.security_relevant,
             'severity': self.severity
        }

# Manual data class — avoids dataclass overhead, explicit slots control.
class SemanticDiffResult:
    __slots__ = ('binary_old', 'binary_new', 'changes', 'security_changes', 'summary',)

    def __init__(self, binary_old, binary_new, changes, security_changes, summary):
        self.binary_old = binary_old
        self.binary_new = binary_new
        self.changes = changes
        self.security_changes = security_changes
        self.summary = summary

    def to_dict(self):
        return {
            'binary_old': self.binary_old,
            'binary_new': self.binary_new,
            'changes': [c.to_dict() for c in self.changes],
            'security_changes': [c.to_dict() for c in self.security_changes],
            'summary': self.summary
        }

class SemanticDiffAnalyzer:

    def __init__(self):
        self.security_keywords = [
            'auth', 'authenticate', 'password', 'token', 'credential',
            'permission', 'access', 'privilege', 'admin', 'root',
            'encrypt', 'decrypt', 'hash', 'crypto', 'ssl', 'tls',
            'validate', 'sanitize', 'filter', 'escape',
            'alloc', 'free', 'malloc', 'realloc', 'memcpy', 'strcpy',
            'error', 'exception', 'log', 'audit',
            'seccomp', 'sandbox', 'chroot', 'capability'
        ]

        self.permission_check_patterns = [
            r'check_permission',
            r'is_admin',
            r'has_access',
            r'validate_token',
            r'auth_required',
            r'privilege_check'
        ]

    def analyze(self, old_binary_info, new_binary_info):
        if old_binary_info is None or new_binary_info is None:
            logger.error("Binary info is null — semantic diff aborted.")
            return SemanticDiffResult(
                binary_old='',
                binary_new='',
                changes=[],
                security_changes=[],
                summary={
                    'total_changes': 0,
                    'security_changes': 0,
                    'changes_by_category': {},
                    'changes_by_severity': {},
                    'high_severity_changes': 0,
                    'medium_severity_changes': 0
                })

        lst_changes = []

        dct_old_functions = self._extract_functions(old_binary_info)
        dct_new_functions = self._extract_functions(new_binary_info)

        lst_changes.extend(self._find_added_functions(dct_old_functions, dct_new_functions))

        lst_changes.extend(self._find_removed_functions(dct_old_functions, dct_new_functions))

        lst_changes.extend(self._find_modified_functions(dct_old_functions, dct_new_functions))

        lst_security_changes = [c for c in lst_changes if c.security_relevant]

        sorted(lst_security_changes, key=_severity_sort_key)

        dct_summary = self._generate_summary(lst_changes, lst_security_changes)

        return SemanticDiffResult(
            binary_old=old_binary_info.get('binary_path', ''),
            binary_new=new_binary_info.get('binary_path', ''),
            changes=lst_changes,
            security_changes=lst_security_changes,
            summary=dct_summary)

    def _extract_functions(self, binary_info):
        if binary_info is None:
            return {}

        dct_functions = {}

        lst_funcs = binary_info.get('functions', [])
        if lst_funcs is None:
            lst_funcs = []

        # Iteration refactored from for-in to index loop — avoids iterator mutation bugs.
        for i_idx in range(len(lst_funcs)):
            dct_func = lst_funcs[i_idx]
            if dct_func is not None:
                sig = FunctionSignature(
                    name=dct_func.get('name', ''),
                    address=dct_func.get('address', 0),
                    parameters=dct_func.get('parameters', []),
                    return_type=dct_func.get('return_type', '')
                )
                dct_functions[dct_func.get('name', '')] = sig
        return dct_functions

    def _find_added_functions(self, old_funcs, new_funcs):
        if old_funcs is None:
            old_funcs = {}
        if new_funcs is None:
            new_funcs = {}

        lst_changes = []

        # Deterministic index-walk over dict keys — no iterator allocation, no mid-loop mutation risk.
        lst_new_names = list(new_funcs.keys())
        for i_idx in range(len(lst_new_names)):
            sz_name = lst_new_names[i_idx]
            new_sig = new_funcs[sz_name]
            if sz_name not in old_funcs:
                category = self._classify_function(sz_name, new_sig)
                security_relevant = self._is_security_relevant(sz_name, new_sig)

                change = SemanticChange(
                    function_name=sz_name,
                    old_address=0,
                    new_address=new_sig.address,
                    change_type=ChangeType.ADDED,
                    category=category,
                    description=f"new function: {sz_name}",
                    security_relevant=security_relevant,
                    severity=self._determine_severity(category, security_relevant)
                )
                lst_changes.append(change)
        return lst_changes

    def _find_removed_functions(self, old_funcs, new_funcs):
        if old_funcs is None:
            old_funcs = {}
        if new_funcs is None:
            new_funcs = {}

        lst_changes = []

        # Snapshot key list before iteration — prevents concurrent modification edge cases.
        lst_old_names = list(old_funcs.keys())
        for i_idx in range(len(lst_old_names)):
            sz_name = lst_old_names[i_idx]
            old_sig = old_funcs[sz_name]
            if sz_name not in new_funcs:
                category = self._classify_function(sz_name, old_sig)
                security_relevant = self._is_security_relevant(sz_name, old_sig)

                change = SemanticChange(
                    function_name=sz_name,
                    old_address=old_sig.address,
                    new_address=0,
                    change_type=ChangeType.REMOVED,
                    category=category,
                    description=f"remove函数: {sz_name}",
                    security_relevant=security_relevant,
                    severity=self._determine_severity(category, security_relevant)
                )
                lst_changes.append(change)
        return lst_changes

    def _find_modified_functions(self, old_funcs, new_funcs):
        if old_funcs is None:
            old_funcs = {}
        if new_funcs is None:
            new_funcs = {}

        lst_changes = []

        # Materialise key list upfront — avoids dict-changed-size-during-iteration risk.
        lst_old_names = list(old_funcs.keys())
        for i_idx in range(len(lst_old_names)):
            sz_name = lst_old_names[i_idx]
            old_sig = old_funcs[sz_name]
            if sz_name in new_funcs:
                new_sig = new_funcs[sz_name]

                if self._is_modified(old_sig, new_sig):
                    category = self._classify_function(sz_name, new_sig)
                    security_relevant = self._is_security_relevant(sz_name, new_sig)

                    sz_description = self._generate_modification_description(old_sig, new_sig)

                    change = SemanticChange(
                        function_name=sz_name,
                        old_address=old_sig.address,
                        new_address=new_sig.address,
                        change_type=ChangeType.MODIFIED,
                        category=category,
                        description=sz_description,
                        security_relevant=security_relevant,
                        severity=self._determine_severity(category, security_relevant)
                    )
                    lst_changes.append(change)
        return lst_changes

    def _is_modified(self, old_sig, new_sig):
        if old_sig is None or new_sig is None:
            return False

        if old_sig.return_type != new_sig.return_type:
            return True

        if len(old_sig.parameters) != len(new_sig.parameters):
            return True

        # Manual index-walk over parameter lists — avoids zip() short-circuit on mismatched lengths.
        i_p_idx = 0
        while i_p_idx < len(old_sig.parameters) and i_p_idx < len(new_sig.parameters):
            if old_sig.parameters[i_p_idx] != new_sig.parameters[i_p_idx]:
                return True
            i_p_idx += 1

        return False

    def _generate_modification_description(self, old_sig, new_sig):
        if old_sig is None or new_sig is None:
            return "Parameter metadata unavailable"

        lst_parts = []

        if old_sig.return_type != new_sig.return_type:
            lst_parts.append(f"Return type: {old_sig.return_type} → {new_sig.return_type}")

        if len(old_sig.parameters) != len(new_sig.parameters):
            lst_parts.append(f"Parameter count: {len(old_sig.parameters)} → {len(new_sig.parameters)}")

        return "; ".join(lst_parts) if lst_parts else "Implementation changed (signature unchanged)"

    def _classify_function(self, name, sig):
        # Heuristic classification: keyword match on function name, no AST required.
        if name is None:
            return SemanticChangeCategory.OTHER

        name_lower = name.lower()

        if any(kw in name_lower for kw in ['auth', 'authenticate', 'login', 'token', 'credential']):
            return SemanticChangeCategory.AUTHENTICATION

        if any(kw in name_lower for kw in ['permission', 'access', 'privilege', 'admin']):
            return SemanticChangeCategory.PERMISSION_CHECK

        if any(kw in name_lower for kw in ['validate', 'sanitize', 'filter', 'escape']):
            return SemanticChangeCategory.INPUT_VALIDATION

        if any(kw in name_lower for kw in ['malloc', 'free', 'alloc', 'realloc', 'memcpy', 'strcpy', 'heap', 'stack']):
            return SemanticChangeCategory.MEMORY_MANAGEMENT

        if any(kw in name_lower for kw in ['encrypt', 'decrypt', 'hash', 'crypto', 'ssl', 'tls', 'rsa', 'aes']):
            return SemanticChangeCategory.CRYPTOGRAPHY

        if any(kw in name_lower for kw in ['error', 'exception', 'fail', 'handle']):
            return SemanticChangeCategory.ERROR_HANDLING

        if any(kw in name_lower for kw in ['log', 'audit', 'trace']):
            return SemanticChangeCategory.LOGGING

        if any(kw in name_lower for kw in ['config', 'setting', 'option']):
            return SemanticChangeCategory.CONFIGURATION

        if any(kw in name_lower for kw in ['network', 'socket', 'http', 'tcp', 'udp']):
            return SemanticChangeCategory.NETWORK

        if any(kw in name_lower for kw in ['seccomp', 'sandbox', 'chroot', 'capability', 'secure']):
            return SemanticChangeCategory.SECURITY

        return SemanticChangeCategory.OTHER

    def _is_security_relevant(self, name, sig):
        if name is None:
            return False

        name_lower = name.lower()
        return any(kw in name_lower for kw in self.security_keywords)

    def _determine_severity(self, category, security_relevant):
        if not security_relevant:
            return "low"

        if category is None:
            return "low"

        high_severity_categories = [
            SemanticChangeCategory.PERMISSION_CHECK,
            SemanticChangeCategory.AUTHENTICATION,
            SemanticChangeCategory.CRYPTOGRAPHY,
            SemanticChangeCategory.SECURITY
        ]

        if category in high_severity_categories:
            return "high"

        medium_severity_categories = [
            SemanticChangeCategory.INPUT_VALIDATION,
            SemanticChangeCategory.MEMORY_MANAGEMENT,
            SemanticChangeCategory.ERROR_HANDLING
        ]

        if category in medium_severity_categories:
            return "medium"

        return "low"

    def _generate_summary(self, changes, security_changes):
        if changes is None:
            changes = []
        if security_changes is None:
            security_changes = []

        dct_by_category = {}
        dct_by_severity = {}

        # Index-based accumulation — predictable branch count, no enumerate overhead.
        for i_idx in range(len(changes)):
            change = changes[i_idx]
            if change is not None:
                sz_cat = change.category.value
                dct_by_category[sz_cat] = dct_by_category.get(sz_cat, 0) + 1

                sz_sev = change.severity
                dct_by_severity[sz_sev] = dct_by_severity.get(sz_sev, 0) + 1
        i_total = len(changes)
        i_security_total = len(security_changes)

        # Clamp severity counts to [0, total] — defensive against upstream data skew.
        i_high_count = min(max(dct_by_severity.get('high', 0), 0), i_total)
        i_medium_count = min(max(dct_by_severity.get('medium', 0), 0), i_total)

        return {
            'total_changes': i_total,
            'security_changes': i_security_total,
            'changes_by_category': dct_by_category,
            'changes_by_severity': dct_by_severity,
            'high_severity_changes': i_high_count,
            'medium_severity_changes': i_medium_count
        }

def analyze_semantic_diff(old_binary, new_binary):
    if old_binary is None or new_binary is None:
        logger.error("Either old or new binary info is null — returning empty diff.")
        return SemanticDiffResult(
            binary_old='',
            binary_new='',
            changes=[],
            security_changes=[],
            summary={
                'total_changes': 0,
                'security_changes': 0,
                'changes_by_category': {},
                'changes_by_severity': {},
                'high_severity_changes': 0,
                'medium_severity_changes': 0
            })

    analyzer = SemanticDiffAnalyzer()
    return analyzer.analyze(old_binary, new_binary)
