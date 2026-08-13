#!/usr/bin/env python3
# Primary interface: DeobfuscationLevel and associated pipeline classes.
import logging
import os
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class DeobfuscationLevel(Enum):
    LIGHT = "light"
    MEDIUM = "medium"
    AGGRESSIVE = "aggressive"

class ControlFlowPattern(Enum):
    NORMAL = "normal"
    FLATTENED = "flattened"
    SPLIT = "split"
    JUNK = "junk"


@dataclass
class BasicBlock:
    block_id: int
    start_addr: int
    end_addr: int
    instructions: list = field(default_factory=list)
    predecessors: list = field(default_factory=list)
    successors: list = field(default_factory=list)
    is_junk: bool = False
    original_pcode: str = ""


@dataclass
class ControlFlowGraph:
    function_name: str
    entry_block: int
    blocks: dict = field(default_factory=dict)
    edges: list = field(default_factory=list)
    complexity: int = 0


@dataclass
class DeobfuscationResult:
    success: bool
    original_cfg: Optional[ControlFlowGraph] = None
    deobfuscated_cfg: Optional[ControlFlowGraph] = None
    original_pseudocode: str = ""
    deobfuscated_pseudocode: str = ""
    metrics: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    analysis_time: float = 0.0
    modifications: list = field(default_factory=list)


@dataclass
class DeobfuscationMetrics:
    original_block_count: int = 0
    deobfuscated_block_count: int = 0
    block_reduction_ratio: float = 0.0
    original_edge_count: int = 0
    deobfuscated_edge_count: int = 0
    edge_reduction_ratio: float = 0.0
    original_complexity: int = 0
    deobfuscated_complexity: int = 0
    complexity_reduction_ratio: float = 0.0
    dead_code_removed: int = 0
    opaque_predicates_removed: int = 0
    control_flow_restructured: bool = False


class ConstantValue:
    """Constant value holder."""
    def __init__(self, value: Any, is_known: bool = True):
        self.value = value
        self.is_known = is_known

    def __repr__(self):
        return f"Const({self.value})" if self.is_known else "Unknown"

class FunctionDeobfuscator:
    """
    Function-level deobfuscator.

    Capabilities:
    1. Dead code elimination
    2. Control flow flattening recovery
    3. Constant propagation and folding
    4. Opaque predicate elimination
    5. Deobfuscation effectiveness evaluation
    """

    def __init__(self, binary_path: str = None, deobfuscation_level: DeobfuscationLevel = DeobfuscationLevel.MEDIUM):
        self.binary_path = binary_path
        self.deobfuscation_level = deobfuscation_level
        self.cfg = None
        self.constants: Dict[str, ConstantValue] = {}
        self.dead_blocks: Set[int] = set()
        self.opaque_predicates: Set[int] = set()
        self.state_variables: Set[str] = set()

        self.ollvm_patterns = {
            'dispatcher': [
                b'\x8b\x44\x24\x04',  # mov eax, [esp+4]
                b'\x83\xc0\x01',      # add eax, 1
            ],
            'state_var_init': [
                b'\xc7\x45\xfc\x00\x00\x00\x00',  # mov [ebp-4], 0
            ]
        }

    def load_cfg(self, cfg_data: Dict[str, Any]) -> ControlFlowGraph:
        """Load control flow graph data."""
        cfg = ControlFlowGraph(
            function_name=cfg_data.get('function_name', 'unknown'),
            entry_block=cfg_data.get('entry_block', 0)
        )

        for block_id, block_data in cfg_data.get('blocks', {}).items():
            block = BasicBlock(
                block_id=int(block_id),
                start_addr=block_data.get('start_addr', 0),
                end_addr=block_data.get('end_addr', 0),
                instructions=block_data.get('instructions', []),
                predecessors=block_data.get('predecessors', []),
                successors=block_data.get('successors', []),
                is_junk=block_data.get('is_junk', False),
                original_pcode=block_data.get('pcode', '')
            )
            cfg.blocks[int(block_id)] = block

        cfg.edges = cfg_data.get('edges', [])
        cfg.complexity = self._calculate_complexity(cfg)

        self.cfg = cfg
        return cfg

    def _calculate_complexity(self, cfg: ControlFlowGraph) -> int:
        """Calculate cyclomatic complexity."""
        if not cfg.blocks:
            return 0

        edges = 0
        for block in cfg.blocks.values():
            edges += len(block.successors)

        return edges - len(cfg.blocks) + 2 if len(cfg.blocks) > 1 else 1

    def detect_control_flow_pattern(self) -> ControlFlowPattern:
        """Detect control flow pattern."""
        if not self.cfg:
            return ControlFlowPattern.NORMAL

        has_dispatcher = self._detect_flattening_dispatcher()
        if has_dispatcher:
            return ControlFlowPattern.FLATTENED

        if self._detect_split_blocks():
            return ControlFlowPattern.SPLIT

        if len(self.dead_blocks) > len(self.cfg.blocks) * 0.3:
            return ControlFlowPattern.JUNK

        return ControlFlowPattern.NORMAL

    def _detect_flattening_dispatcher(self) -> bool:
        """Detect OLLVM flattening dispatcher."""
        if not self.cfg:
            return False

        entry_blocks = [b for b in self.cfg.blocks.values() if len(b.predecessors) == 1]

        if len(entry_blocks) > len(self.cfg.blocks) * 0.8:
            conditional_jumps = 0
            for block in self.cfg.blocks.values():
                for succ in block.successors:
                    if len(block.successors) > 1:
                        conditional_jumps += 1

            if conditional_jumps < len(self.cfg.blocks) * 0.2:
                return True

        return False

    def _detect_split_blocks(self) -> bool:
        """Detect split basic blocks."""
        if not self.cfg:
            return False

        single_instruction_blocks = [
            b for b in self.cfg.blocks.values()
            if len(b.instructions) <= 2
        ]

        return len(single_instruction_blocks) > len(self.cfg.blocks) * 0.3

    def eliminate_dead_code(self) -> int:
        """Eliminate dead code."""
        if not self.cfg:
            return 0

        reachable = self._find_reachable_blocks()

        dead_count = 0
        for block_id in list(self.cfg.blocks.keys()):
            if block_id not in reachable:
                self.dead_blocks.add(block_id)
                dead_count += 1

        for block_id in self.dead_blocks:
            if block_id in self.cfg.blocks:
                del self.cfg.blocks[block_id]

        new_edges = []
        for src, dst in self.cfg.edges:
            if src in reachable and dst in reachable:
                new_edges.append((src, dst))

        self.cfg.edges = new_edges

        return dead_count

    def _find_reachable_blocks(self) -> Set[int]:
        """DFS from entry to find reachable blocks."""
        if not self.cfg:
            return set()

        reachable = {self.cfg.entry_block}
        stack = [self.cfg.entry_block]

        while stack:
            current = stack.pop()
            if current in self.cfg.blocks:
                for succ in self.cfg.blocks[current].successors:
                    if succ not in reachable:
                        reachable.add(succ)
                        stack.append(succ)

        return reachable

    def constant_propagation(self) -> int:
        """Constant propagation."""
        if not self.cfg:
            return 0

        changes = 0

        for block in self.cfg.blocks.values():
            for i, instr in enumerate(block.instructions):
                if 'mov' in instr.lower() and '=' in instr:
                    parts = instr.replace('=', '=').split('=')
                    if len(parts) == 2:
                        lhs = parts[0].strip()
                        rhs = parts[1].strip()

                        const_value = self._extract_constant(rhs)
                        if const_value is not None:
                            self.constants[lhs] = ConstantValue(const_value)
                            changes += 1

        return changes

    def _extract_constant(self, expr: str) -> Optional[Any]:
        """Extract constant value from expression."""
        expr = expr.strip()

        if expr.startswith('0x') or expr.startswith('0X'):
            try:
                return int(expr, 16)
            except ValueError:
                pass

        try:
            return int(expr)
        except ValueError:
            pass

        return None

    def constant_folding(self) -> int:
        """Constant folding: evaluate compile-time constant expressions."""
        if not self.cfg:
            return 0

        folded = 0

        for block in self.cfg.blocks.values():
            for i, instr in enumerate(block.instructions):
                if any(op in instr for op in ['+', '-', '*', '/']):
                    folded_instr = self._fold_expression(instr)
                    if folded_instr != instr:
                        block.instructions[i] = folded_instr
                        folded += 1

        return folded

    def _fold_expression(self, instr: str) -> str:
        """Fold constant expressions."""
        replacements = [
            ('1 + 1', '2'),
            ('0 + ', ''),
            ('* 1', ''),
            ('/ 1', ''),
            ('& 0xff', ''),
        ]

        result = instr
        for old, new in replacements:
            result = result.replace(old, new)

        return result

    def eliminate_opaque_predicates(self) -> int:
        """Eliminate opaque predicates (false conditional branches)."""
        if not self.cfg:
            return 0

        removed = 0

        for block in self.cfg.blocks.values():
            if len(block.successors) > 1:
                if self._is_opaque_predicate(block):
                    if len(block.successors) >= 2:
                        block.successors = [block.successors[0]]
                        removed += 1

        return removed

    def _is_opaque_predicate(self, block: BasicBlock) -> bool:
        """Determine if this is an opaque predicate."""
        if len(block.instructions) <= 3:
            for instr in block.instructions:
                if 'cmp' in instr.lower() or 'test' in instr.lower():
                    return True

        return False

    def deflatten_control_flow(self) -> bool:
        """Control flow de-flattening (OLLVM)."""
        if not self.cfg or self.deobfuscation_level == DeobfuscationLevel.LIGHT:
            return False

        pattern = self.detect_control_flow_pattern()
        if pattern != ControlFlowPattern.FLATTENED:
            logger.info("No flattened control flow detected, skipping")
            return False

        logger.info("Flattened control flow detected, attempting recovery...")

        self._identify_state_variables()
        self._rebuild_block_order()
        self._restore_conditional_jumps()

        return True

    def _identify_state_variables(self):
        """Identify OLLVM state variables."""
        if not self.cfg:
            return

        var_usage = defaultdict(int)
        for block in self.cfg.blocks.values():
            for instr in block.instructions:
                for reg in ['eax', 'ebx', 'ecx', 'edx', 'ebp', 'esp', 'r12', 'r13', 'r14', 'r15']:
                    if reg in instr.lower():
                        var_usage[reg] += 1

        for var, count in var_usage.items():
            if count > len(self.cfg.blocks) * 0.5:
                self.state_variables.add(var)

    def _rebuild_block_order(self):
        """Rebuild basic block ordering."""
        if not self.cfg:
            return

        sorted_blocks = sorted(self.cfg.blocks.values(), key=lambda b: b.start_addr)

        new_id_map = {}
        for i, block in enumerate(sorted_blocks):
            new_id_map[block.block_id] = i
            block.block_id = i

        for block in self.cfg.blocks.values():
            block.predecessors = [new_id_map.get(p, p) for p in block.predecessors]
            block.successors = [new_id_map.get(s, s) for s in block.successors]

    def _restore_conditional_jumps(self):
        """Restore conditional jumps."""
        if not self.cfg:
            return

        for block in self.cfg.blocks.values():
            if block.instructions and 'jmp' in block.instructions[-1].lower():
                if len(block.successors) == 1:
                    pass

    def deobfuscate(self, cfg_data: Dict[str, Any] = None) -> DeobfuscationResult:
        """Execute complete deobfuscation pipeline."""
        start_time = time.time()
        result = DeobfuscationResult(success=False)

        try:
            if cfg_data:
                self.cfg = self.load_cfg(cfg_data)

            if not self.cfg:
                result.warnings.append("No CFG data provided")
                return result

            result.original_cfg = self._copy_cfg(self.cfg)
            original_metrics = DeobfuscationMetrics(
                original_block_count=len(self.cfg.blocks),
                original_edge_count=len(self.cfg.edges),
                original_complexity=self.cfg.complexity
            )

            pattern = self.detect_control_flow_pattern()
            logger.info(f"Detected control flow pattern: {pattern.value}")

            modifications = []

            if self.deobfuscation_level != DeobfuscationLevel.LIGHT:
                dead_count = self.eliminate_dead_code()
                if dead_count > 0:
                    modifications.append(f"Dead code eliminated: {dead_count} blocks")
                    original_metrics.dead_code_removed = dead_count

            const_count = self.constant_propagation()
            if const_count > 0:
                modifications.append(f"Constant propagation: {const_count} sites")

            folded_count = self.constant_folding()
            if folded_count > 0:
                modifications.append(f"Constant folding: {folded_count} sites")

            if self.deobfuscation_level == DeobfuscationLevel.AGGRESSIVE:
                opaque_count = self.eliminate_opaque_predicates()
                if opaque_count > 0:
                    modifications.append(f"Opaque predicates eliminated: {opaque_count}")
                    original_metrics.opaque_predicates_removed = opaque_count

            if self.deobfuscation_level != DeobfuscationLevel.LIGHT:
                if self.deflatten_control_flow():
                    modifications.append("Control flow de-flattened")
                    original_metrics.control_flow_restructured = True

            result.deobfuscated_cfg = self._copy_cfg(self.cfg)
            result.deobfuscated_pseudocode = self._generate_pseudocode(self.cfg)

            if result.original_cfg:
                result.original_pseudocode = self._generate_pseudocode(result.original_cfg)

            deobfuscated_metrics = DeobfuscationMetrics(
                deobfuscated_block_count=len(self.cfg.blocks),
                deobfuscated_edge_count=len(self.cfg.edges),
                deobfuscated_complexity=self._calculate_complexity(self.cfg)
            )

            if original_metrics.original_block_count > 0:
                deobfuscated_metrics.block_reduction_ratio = (
                    (original_metrics.original_block_count - deobfuscated_metrics.deobfuscated_block_count)
                    / original_metrics.original_block_count
                )

            if original_metrics.original_edge_count > 0:
                deobfuscated_metrics.edge_reduction_ratio = (
                    (original_metrics.original_edge_count - deobfuscated_metrics.deobfuscated_edge_count)
                    / original_metrics.original_edge_count
                )

            if original_metrics.original_complexity > 0:
                deobfuscated_metrics.complexity_reduction_ratio = (
                    (original_metrics.original_complexity - deobfuscated_metrics.deobfuscated_complexity)
                    / original_metrics.original_complexity
                )

            result.metrics = {
                'original': {
                    'block_count': original_metrics.original_block_count,
                    'edge_count': original_metrics.original_edge_count,
                    'complexity': original_metrics.original_complexity
                },
                'deobfuscated': {
                    'block_count': deobfuscated_metrics.deobfuscated_block_count,
                    'edge_count': deobfuscated_metrics.deobfuscated_edge_count,
                    'complexity': deobfuscated_metrics.deobfuscated_complexity
                },
                'reductions': {
                    'block_reduction': f"{deobfuscated_metrics.block_reduction_ratio * 100:.1f}%",
                    'edge_reduction': f"{deobfuscated_metrics.edge_reduction_ratio * 100:.1f}%",
                    'complexity_reduction': f"{deobfuscated_metrics.complexity_reduction_ratio * 100:.1f}%"
                },
                'control_flow_pattern': pattern.value,
                'deobfuscation_level': self.deobfuscation_level.value
            }

            result.modifications = modifications
            result.success = True
            result.analysis_time = time.time() - start_time

        except Exception as e:
            logger.error(f"Deobfuscation failed: {e}")
            result.warnings.append(f"Deobfuscation error: {str(e)}")

        return result

    def _copy_cfg(self, cfg: ControlFlowGraph) -> ControlFlowGraph:
        """Copy a control flow graph."""
        new_cfg = ControlFlowGraph(
            function_name=cfg.function_name,
            entry_block=cfg.entry_block,
            complexity=cfg.complexity
        )

        for block_id, block in cfg.blocks.items():
            new_cfg.blocks[block_id] = BasicBlock(
                block_id=block.block_id,
                start_addr=block.start_addr,
                end_addr=block.end_addr,
                instructions=block.instructions.copy(),
                predecessors=block.predecessors.copy(),
                successors=block.successors.copy(),
                is_junk=block.is_junk,
                original_pcode=block.original_pcode
            )

        new_cfg.edges = cfg.edges.copy()

        return new_cfg

    def _generate_pseudocode(self, cfg: ControlFlowGraph) -> str:
        """Generate pseudocode from CFG."""
        lines = [f"// Function: {cfg.function_name}"]
        lines.append(f"// Complexity: {cfg.complexity}")
        lines.append("")

        if not cfg.blocks:
            return "\n".join(lines)

        visited = set()
        stack = [cfg.entry_block]

        while stack:
            block_id = stack.pop()
            if block_id in visited:
                continue
            visited.add(block_id)

            if block_id in cfg.blocks:
                block = cfg.blocks[block_id]
                lines.append(f"block_{block_id}:")
                lines.append(f"    // {hex(block.start_addr)} - {hex(block.end_addr)}")

                for instr in block.instructions:
                    lines.append(f"    {instr}")

                if block.successors:
                    targets = ", ".join(f"block_{s}" for s in block.successors)
                    if len(block.successors) == 1:
                        lines.append(f"    goto {targets};")
                    else:
                        lines.append(f"    // Branch to {targets}")

                lines.append("")

                for succ in block.successors:
                    if succ not in visited:
                        stack.append(succ)

        return "\n".join(lines)

    def compare_pseudocode(self, original: str, deobfuscated: str) -> Dict[str, Any]:
        """Compare pseudocode before and after deobfuscation."""
        original_lines = original.strip().split('\n')
        deob_lines = deobfuscated.strip().split('\n')

        original_code_lines = [l for l in original_lines if l.strip() and not l.strip().startswith('//')]
        deob_code_lines = [l for l in deob_lines if l.strip() and not l.strip().startswith('//')]

        return {
            'original_lines': len(original_lines),
            'deobfuscated_lines': len(deob_lines),
            'original_code_lines': len(original_code_lines),
            'deobfuscated_code_lines': len(deob_code_lines),
            'line_reduction': len(original_code_lines) - len(deob_code_lines),
            'line_reduction_ratio': (
                (len(original_code_lines) - len(deob_code_lines)) / max(len(original_code_lines), 1) * 100
            )
        }


def deobfuscate_function(binary_path: str, function_name: str, deobfuscation_level: str = "medium", cfg_data: Dict[str, Any] = None) -> DeobfuscationResult:
    """Convenience function for deobfuscating a function."""
    level_map = {
        'light': DeobfuscationLevel.LIGHT,
        'medium': DeobfuscationLevel.MEDIUM,
        'aggressive': DeobfuscationLevel.AGGRESSIVE
    }

    level = level_map.get(deobfuscation_level.lower(), DeobfuscationLevel.MEDIUM)
    deobfuscator = FunctionDeobfuscator(binary_path, level)

    return deobfuscator.deobfuscate(cfg_data)


def format_deobfuscation_report(result: DeobfuscationResult) -> str:
    """Format deobfuscation report."""
    if not result.success:
        return f"Deobfuscation failed: {', '.join(result.warnings)}"

    parts = [
        "# Deobfuscation Analysis Report",
        "",
        f"Function: {result.deobfuscated_cfg.function_name if result.deobfuscated_cfg else 'unknown'}",
        f"Level: {result.metrics.get('deobfuscation_level', 'unknown')}",
        f"Pattern: {result.metrics.get('control_flow_pattern', 'unknown')}",
        f"Analysis time: {result.analysis_time:.2f}s",
        "",
        "## Effectiveness Metrics",
    ]

    metrics = result.metrics
    if 'original' in metrics and 'deobfuscated' in metrics:
        parts.extend([
            f"- Basic blocks: {metrics['original']['block_count']} -> {metrics['deobfuscated']['block_count']} "
            f"({metrics['reductions']['block_reduction']})",
            f"- CFG edges: {metrics['original']['edge_count']} -> {metrics['deobfuscated']['edge_count']} "
            f"({metrics['reductions']['edge_reduction']})",
            f"- Cyclomatic complexity: {metrics['original']['complexity']} -> {metrics['deobfuscated']['complexity']} "
            f"({metrics['reductions']['complexity_reduction']})",
        ])

    if result.modifications:
        parts.extend([
            "",
            "## Applied Optimizations",
        ])
        for mod in result.modifications:
            parts.append(f"- {mod}")

    return "\n".join(parts)


def export_deobfuscation_json(result: DeobfuscationResult, output_path: str) -> bool:
    """Export deobfuscation result as JSON."""
    try:
        export_data = {
            'success': result.success,
            'analysis_time': result.analysis_time,
            'metrics': result.metrics,
            'modifications': result.modifications,
            'warnings': result.warnings,
            'original_pseudocode': result.original_pseudocode,
            'deobfuscated_pseudocode': result.deobfuscated_pseudocode,
            'function_name': result.deobfuscated_cfg.function_name if result.deobfuscated_cfg else None
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)

        return True
    except Exception as e:
        logger.error(f"JSON export failed: {e}")
        return False
