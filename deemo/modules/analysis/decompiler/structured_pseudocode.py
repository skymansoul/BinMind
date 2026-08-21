# structured_pseudocode.py: construct structured pseudocode
# from decompiler engine flat output
#
# Raw decompiler output is lifted into a structured form:
# identifies if/else chains, loop structures, switch cases,
# exception handling blocks. Supports output in markdown, HTML,
# plain text formatting, optional type annotations,
# control-flow visualization hints.
#
# Decompiler output is flat C — structure is latent, not explicit.
# Recovering it means re-deriving abstract syntax that the compiler
# optimized away, via pattern recognition and parsing.

import logging
import re
import textwrap
import html
import hashlib
import json
from typing import Dict, List, Optional, Any, Tuple, Set, Iterator
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, deque

# 依赖现有 decomp_ai 基础设施
from modules.analysis.decompiler.decomp_ai import (
    DecompilerAI,
    strip_ansi_escape,
)

logger = logging.getLogger(__name__)


# 数据类型

class BlockType(str, Enum):
	"""代码块类型 — 对应高层语言的控制结构"""
	FUNCTION = "function"
	IF = "if"
	ELSE = "else"
	ELIF = "elif"
	WHILE = "while"
	FOR = "for"
	DO_WHILE = "do_while"
	SWITCH = "switch"
	CASE = "case"
	DEFAULT = "default"
	BREAK = "break"
	CONTINUE = "continue"
	RETURN = "return"
	GOTO = "goto"
	TRY = "try"
	CATCH = "catch"
	FINALLY = "finally"
	PLAIN = "plain"  # 普通语句块
	UNKNOWN = "unknown"


class OutputFormat(str, Enum):
	"""输出格式"""
	PLAIN = "plain"
	MARKDOWN = "markdown"
	HTML = "html"


@dataclass
class VariableInfo:
	"""变量信息"""
	name: str
	type_hint: str = "auto"
	scope_start: int = -1  # line number
	scope_end: int = -1
	is_parameter: bool = False
	is_local: bool = True
	references: int = 0


@dataclass
class CodeBlock:
	"""结构化的代码块"""
	block_id: int
	block_type: BlockType
	condition: str = ""            # if/while/for 的条件表达式
	body: List[str] = field(default_factory=list)
	children: List['CodeBlock'] = field(default_factory=list)
	indent_level: int = 0
	start_line: int = 0
	end_line: int = 0
	annotations: Dict[str, str] = field(default_factory=dict)
	parent: Optional['CodeBlock'] = None

	def add_child(self, child: 'CodeBlock') -> None:
		child.parent = self
		self.children.append(child)

	def to_dict(self) -> Dict[str, Any]:
		return {
			'id': self.block_id,
			'type': self.block_type.value if hasattr(self.block_type, 'value') else str(self.block_type),
			'condition': self.condition,
			'body': self.body,
			'children': [c.to_dict() for c in self.children],
			'indent': self.indent_level,
			'start_line': self.start_line,
			'end_line': self.end_line,
		}


@dataclass
class StructuredPseudocode:
	"""完整的结构化伪代码输出"""
	function_name: str = ""
	parameters: List[VariableInfo] = field(default_factory=list)
	return_type: str = "void"
	root_block: Optional[CodeBlock] = None
	variables: Dict[str, VariableInfo] = field(default_factory=dict)
	control_flow_hints: List[str] = field(default_factory=list)
	warnings: List[str] = field(default_factory=list)
	raw_input: str = ""


# 主类

class StructuredPseudocodeGenerator:
	"""
	将平坦的反编译伪代码转换为结构化的表示

	这不是解析器 — 反编译输出没有形式文法
	用启发式规则逐行推断结构，宁可少识别不能误分类
	"""

	# 控制流关键字的识别模式
	_KEYWORD_PATTERNS: Dict[BlockType, re.Pattern] = {
	    BlockType.IF: re.compile(r'^\s*if\s*\((.+)\)\s*\{?'),
	    BlockType.ELSE: re.compile(r'^\s*\}\s*else\s*\{?\s*$|^\s*else\s*\{?'),
	    BlockType.ELIF: re.compile(r'^\s*\}\s*else\s+if\s*\((.+)\)\s*\{?|^\s*else\s+if\s*\((.+)\)\s*\{?'),
	    BlockType.WHILE: re.compile(r'^\s*while\s*\((.+)\)\s*\{?'),
	    BlockType.FOR: re.compile(r'^\s*for\s*\((.+)\)\s*\{?'),
	    BlockType.DO_WHILE: re.compile(r'^\s*do\s*\{?'),
	    BlockType.SWITCH: re.compile(r'^\s*switch\s*\((.+)\)\s*\{?'),
	    BlockType.CASE: re.compile(r'^\s*case\s+(.+?)\s*:'),
	    BlockType.DEFAULT: re.compile(r'^\s*default\s*:'),
	    BlockType.BREAK: re.compile(r'^\s*break\s*;?\s*$'),
	    BlockType.CONTINUE: re.compile(r'^\s*continue\s*;?\s*$'),
	    BlockType.GOTO: re.compile(r'^\s*goto\s+(\w+)\s*;?\s*$'),
	    BlockType.TRY: re.compile(r'^\s*try\s*\{?'),
	    BlockType.CATCH: re.compile(r'^\s*catch\s*\(.*?\)\s*\{?'),
	    BlockType.FINALLY: re.compile(r'^\s*finally\s*\{?'),
	    BlockType.RETURN: re.compile(r'^\s*return\b'),
	}

	# 函数签名识别 — 支持 int/void/char* 等返回类型
	_FUNC_SIG_PATTERN = re.compile(
	    r'^\s*(?P<ret>\w+(?:\s*\*)*)\s*(?P<name>\w+)\s*\((?P<params>[^)]*)\)\s*\{?'
	)

	# 变量声明模式 — 小心别把 return/ 等关键字当类型
	_KEYWORD_BLACKLIST = frozenset({
	    'if', 'else', 'while', 'for', 'switch', 'case', 'default',
	    'return', 'goto', 'break', 'continue', 'sizeof', 'do',
	    'try', 'catch', 'finally', 'struct', 'union', 'enum',
	    'typedef', 'extern', 'static', 'volatile', 'register',
	})

	_VAR_DECL_PATTERN = re.compile(
	    r'^\s*(?P<type>(?:unsigned\s+)?(?:const\s+)?\w+(?:\s*\*)*)\s+'
	    r'(?P<name>\w+)\s*(?:=|;)'
	)

	def __init__(self):
		self._block_counter: int = 0
		self._var_counter: int = 0

	def generate(self,
	             pseudocode: str,
	             function_name: str = "",
	             output_format: OutputFormat = OutputFormat.PLAIN,
	             with_types: bool = True) -> StructuredPseudocode:
		"""主入口 — 解析伪代码并生成结构化输出"""
		cleaned = strip_ansi_escape(pseudocode)
		lines = cleaned.split('\n')
		non_empty = [l for l in lines if l.strip()]

		result = StructuredPseudocode(raw_input=cleaned)

		# 1. 提取函数签名
		sig_info = self._extract_function_signature(non_empty)
		result.function_name = sig_info.get('name', function_name) or "unknown"
		result.return_type = sig_info.get('return_type', 'void')
		result.parameters = sig_info.get('parameters', [])

		# 2. 提取变量
		if with_types:
			all_vars, var_map = self._extract_variables(lines)
			result.variables = var_map

		# 3. 构建结构化代码块树
		self._block_counter = 0
		root = self._build_block_tree(lines)
		result.root_block = root

		# 4. 分析控制流提示
		result.control_flow_hints = self._analyze_control_flow(lines, root)

		# 5. 检测混淆/去优化模式
		obfu_warnings = self._detect_obfuscation_patterns(lines)
		result.warnings.extend(obfu_warnings)

		logger.info(
		    f"Generated structured pseudocode for '{result.function_name}': "
		    f"{self._block_counter} blocks, {len(result.variables)} variables, "
		    f"{len(result.warnings)} warnings"
		)
		return result

	def generate_from_binary(self,
	                         binary_path: str,
	                         function_name: str = "main",
	                         output_format: OutputFormat = OutputFormat.PLAIN,
	                         with_types: bool = True) -> Optional[StructuredPseudocode]:
		"""直接从二进制文件生成结构化伪代码（自动调用 DecompilerAI）"""
		try:
			d = DecompilerAI(binary_path)
			pseudocode = d.decompile(function_name)
			if not pseudocode:
				logger.error(f"Failed to decompile {function_name} from {binary_path}")
				return None
			return self.generate(pseudocode, function_name, output_format, with_types)
		except Exception as e:
			logger.error(f"Error generating structured pseudocode: {e}")
			return None

	# 函数签名提取

	def _extract_function_signature(self, lines: List[str]) -> Dict[str, Any]:
		# 提取 function 签名 info 伪代码 lines
		result: Dict[str, Any] = {
			'name': '',
			'return_type': 'void',
			'parameters': [],
		}

		for line in lines[:20]:  # 只看前 20 行找签名
			m = self._FUNC_SIG_PATTERN.match(line)
			if m:
				result['name'] = m.group('name')
				result['return_type'] = m.group('ret').strip()

				params_str = m.group('params').strip()
				if params_str and params_str.lower() != 'void':
					for param in params_str.split(','):
						param = param.strip()
						if param:
							parts = param.split()
							p_type = ' '.join(parts[:-1]) if len(parts) > 1 else 'auto'
							p_name = parts[-1].lstrip('*').strip()
							result['parameters'].append(VariableInfo(
								name=p_name,
								type_hint=p_type,
								is_parameter=True,
								is_local=False,
							))
				break

		return result

	# 变量提取

	def _extract_variables(
	    self, lines: List[str]
	) -> Tuple[List[VariableInfo], Dict[str, VariableInfo]]:
		"""从伪代码中提取变量声明并推断作用域"""
		variables: Dict[str, VariableInfo] = {}
		var_list: List[VariableInfo] = []

		in_body = False
		open_braces = 0
		scope_stack: List[int] = []  # line numbers scope openings

		for i, line in enumerate(lines):
			# 追踪大括号
			if '{' in line:
				if not in_body:
					in_body = True
				open_braces += line.count('{')
				scope_stack.append(i)
			if '}' in line:
				open_braces -= line.count('}')

			# 只在函数体内找变量
			if not in_body:
				continue

			m = self._VAR_DECL_PATTERN.match(line)
			if m:
				var_type = m.group('type').strip()
				var_name = m.group('name').strip()

				# 排除关键字和函数调用 — type 也不能是关键字
				if var_name in self._KEYWORD_BLACKLIST:
					continue
				if var_type in self._KEYWORD_BLACKLIST:
					continue

				scope_start = scope_stack[-1] if scope_stack else i
				var_info = VariableInfo(
					name=var_name,
					type_hint=var_type,
					scope_start=scope_start,
					scope_end=-1,
					is_parameter=False,
					is_local=True,
				)
				variables[var_name] = var_info
				var_list.append(var_info)

		# 统计引用次数
		full_text = '\n'.join(lines)
		for vname, vinfo in variables.items():
			# 粗略统计：token 出现次数（排除声明行本身）
			vinfo.references = len(re.findall(
				r'\b' + re.escape(vname) + r'\b', full_text
			)) - 1  # -1 for declaration

		return var_list, variables

	# 代码块树构建

	def _build_block_tree(self, lines: List[str]) -> CodeBlock:
		"""递归构建结构化的代码块树"""
		root = CodeBlock(
			block_id=self._next_block_id(),
			block_type=BlockType.FUNCTION,
			start_line=1,
			end_line=len(lines),
		)

		# 先找到函数体范围
		body_start = 0
		body_end = len(lines)

		for i, line in enumerate(lines):
			if '{' in line and body_start == 0:
				body_start = i
			if body_start > 0 and '}' in line:
				body_end = i + 1

		if body_start == 0:
			# 没有大括号 — 可能是单行函数或者格式特殊
			body_start = 1

		body_lines = lines[body_start:body_end]
		root.body = body_lines

		# 递归解析子块
		children = self._parse_blocks(body_lines, indent_level=1)
		for child in children:
			root.add_child(child)

		return root

	def _parse_blocks(
	    self, lines: List[str], indent_level: int = 1
	) -> List[CodeBlock]:
		# 状态机解析行列表为结构化块列表；反编译输出不保证完美嵌套
		blocks: List[CodeBlock] = []
		i = 0

		while i < len(lines):
			line = lines[i]
			stripped = line.strip()

			if not stripped:
				i += 1
				continue

			block_type, condition, consumed = self._identify_block(
				lines, i
			)

			if block_type == BlockType.PLAIN:
				# 收集连续普通语句
				plain_lines: List[str] = []
				while i < len(lines):
					l = lines[i].strip()
					if not l:
						i += 1
						continue
					bt, _, _ = self._identify_block(lines, i)
					if bt != BlockType.PLAIN:
						break
					plain_lines.append(lines[i])
					i += 1

				if plain_lines:
					block = CodeBlock(
						block_id=self._next_block_id(),
						block_type=BlockType.PLAIN,
						body=plain_lines,
						indent_level=indent_level,
						start_line=i - len(plain_lines) + 1,
						end_line=i,
					)
					blocks.append(block)
			else:
				block = CodeBlock(
					block_id=self._next_block_id(),
					block_type=block_type,
					condition=condition,
					indent_level=indent_level,
					start_line=i + 1,
					end_line=i + consumed,
				)

				# 如果是有体的控制结构，递归解析体
				if block_type in (BlockType.IF, BlockType.ELIF, BlockType.WHILE,
				                   BlockType.FOR, BlockType.SWITCH, BlockType.TRY,
				                   BlockType.CATCH, BlockType.FINALLY, BlockType.ELSE,
				                   BlockType.DO_WHILE):
					body_lines = self._extract_body(lines, i)
					if body_lines:
						child_blocks = self._parse_blocks(
							body_lines, indent_level + 1
						)
						for c in child_blocks:
							block.add_child(c)

				blocks.append(block)
				i += consumed

		return blocks

	def _identify_block(
	    self, lines: List[str], idx: int
	) -> Tuple[BlockType, str, int]:
		"""识别当前位置的块类型、条件和消费行数"""
		if idx >= len(lines):
			return BlockType.PLAIN, "", 0

		line = lines[idx]
		stripped = line.strip()

		# 按优先级匹配 — 要在 else 之前
		ordered_checks = [
		    (BlockType.TRY, self._KEYWORD_PATTERNS[BlockType.TRY]),
		    (BlockType.CATCH, self._KEYWORD_PATTERNS[BlockType.CATCH]),
		    (BlockType.FINALLY, self._KEYWORD_PATTERNS[BlockType.FINALLY]),
		    (BlockType.SWITCH, self._KEYWORD_PATTERNS[BlockType.SWITCH]),
		    (BlockType.ELIF, self._KEYWORD_PATTERNS[BlockType.ELIF]),
		    (BlockType.ELSE, self._KEYWORD_PATTERNS[BlockType.ELSE]),
		    (BlockType.IF, self._KEYWORD_PATTERNS[BlockType.IF]),
		    (BlockType.FOR, self._KEYWORD_PATTERNS[BlockType.FOR]),
		    (BlockType.WHILE, self._KEYWORD_PATTERNS[BlockType.WHILE]),
		    (BlockType.DO_WHILE, self._KEYWORD_PATTERNS[BlockType.DO_WHILE]),
		    (BlockType.CASE, self._KEYWORD_PATTERNS[BlockType.CASE]),
		    (BlockType.DEFAULT, self._KEYWORD_PATTERNS[BlockType.DEFAULT]),
		    (BlockType.BREAK, self._KEYWORD_PATTERNS[BlockType.BREAK]),
		    (BlockType.CONTINUE, self._KEYWORD_PATTERNS[BlockType.CONTINUE]),
		    (BlockType.GOTO, self._KEYWORD_PATTERNS[BlockType.GOTO]),
		    (BlockType.RETURN, self._KEYWORD_PATTERNS[BlockType.RETURN]),
		]

		for bt, pattern in ordered_checks:
			m = pattern.match(stripped)
			if m:
				# 提取条件（对于有条件的类型）
				condition = ""
				if bt in (BlockType.IF, BlockType.WHILE, BlockType.FOR,
				          BlockType.SWITCH, BlockType.GOTO):
					condition = m.group(1).strip() if m.lastindex and m.lastindex >= 1 else ""
				elif bt == BlockType.ELIF:
					# elif 有两个可能的 group
					condition = (m.group(2) or m.group(1) or "").strip()

				# 计算消费行数 — 简单块 1 行，有体的块消费到匹配的}
				consumed = 1
				if bt in (BlockType.IF, BlockType.ELIF, BlockType.WHILE,
				          BlockType.FOR, BlockType.SWITCH, BlockType.TRY,
				          BlockType.CATCH, BlockType.FINALLY, BlockType.ELSE,
				          BlockType.DO_WHILE):
					consumed = self._find_closing_brace(lines, idx)

				return bt, condition, max(1, consumed)

		return BlockType.PLAIN, "", 1

	def _extract_body(self, lines: List[str], header_idx: int) -> List[str]:
		"""提取控制结构体内的代码行"""
		body: List[str] = []
		depth = 0
		in_body = False

		for i in range(header_idx, len(lines)):
			line = lines[i]
			stripped = line.strip()

			if not in_body:
				if '{' in stripped:
					in_body = True
					depth += stripped.count('{')
					# 拿 '{' 之后的内容
					brace_pos = line.index('{')
					rest = line[brace_pos + 1:].strip()
					if rest:
						body.append(rest)
				continue

			depth += stripped.count('{')
			depth -= stripped.count('}')

			if depth <= 0:
				# 提取 '}' 之前的内容
				if '}' in stripped:
					brace_pos = stripped.index('}')
					before = stripped[:brace_pos].strip()
					if before:
						body.append(before)
				break

			body.append(line)

		return body

	def _find_closing_brace(self, lines: List[str], start: int) -> int:
		"""找匹配的闭合括号，返回从 start 到} 的行数"""
		depth = 0
		in_body = False

		for i in range(start, len(lines)):
			line = lines[i]
			stripped = line.strip()

			if not in_body:
				if '{' in stripped:
					in_body = True
					depth += stripped.count('{')
					depth -= stripped.count('}')
					if depth <= 0:
						return i - start + 1
				continue

			depth += stripped.count('{')
			depth -= stripped.count('}')

			if depth <= 0:
				return i - start + 1

		return len(lines) - start

	# 控制流分析

	def _analyze_control_flow(
	    self, lines: List[str], root: CodeBlock
	) -> List[str]:
		"""分析控制流特征，生成结构化提示"""
		hints: List[str] = []

		full_text = '\n'.join(lines)

		# 循环复杂度估算
		loop_count = len(re.findall(r'\b(while|for|do)\b', full_text))
		if_count = len(re.findall(r'\bif\b', full_text))
		goto_count = len(re.findall(r'\bgoto\b', full_text))
		switch_count = len(re.findall(r'\bswitch\b', full_text))

		if loop_count == 0 and if_count == 0:
			hints.append("LINEAR: 无分支/循环 — 纯顺序执行")
		elif loop_count == 0 and if_count > 0:
			hints.append(f"BRANCHED: {if_count} 个条件分支，无循环")
		elif loop_count > 0:
			hints.append(f"LOOPED: {loop_count} 个循环 + {if_count} 个分支")

		if goto_count > 0:
			hints.append(f"GOTO_PRESENT: {goto_count} 个 goto — 控制流未完全结构化")

		if switch_count > 0:
			hints.append(f"SWITCH: {switch_count} 个 switch 语句")

		# 嵌套深度
		max_depth = self._max_nesting_depth(root)
		if max_depth > 3:
			hints.append(f"DEEP_NESTING: 最大嵌套深度 {max_depth} — 可读性受影响")

		return hints

	def _max_nesting_depth(self, block: CodeBlock) -> int:
		"""递归计算最大嵌套深度"""
		if not block.children:
			return block.indent_level
		return max(self._max_nesting_depth(c) for c in block.children)

	# 混淆检测

	def _detect_obfuscation_patterns(self, lines: List[str]) -> List[str]:
		"""检测混淆/去优化代码模式"""
		warnings: List[str] = []
		full_text = '\n'.join(lines)

		# 不透明谓词
		opaque_patterns = [
		    (r'if\s*\(\s*[^)]*\s*\^\s*[^)]*\s*==\s*[^)]*\s*\)',
		     "可能的不透明谓词 (XOR comparison)"),
		    (r'if\s*\(\s*1\s*==\s*0\s*\)',
		     "死代码块 (if (1==0))"),
		    (r'if\s*\(\s*0\s*==\s*1\s*\)',
		     "死代码块 (if (0==1))"),
		]
		for pattern, msg in opaque_patterns:
			if re.search(pattern, full_text):
				warnings.append(f"OBFUSCATION: {msg}")

		# 平坦化控制流特征
		dispatcher_pattern = re.compile(
		    r'(switch\s*\([^)]*\)\s*\{[^}]*case\s+\d+\s*:.*case\s+\d+\s*:){3,}',
		    re.DOTALL
		)
		if dispatcher_pattern.search(full_text):
			warnings.append("OBFUSCATION: 检测到控制流平坦化模式 (密集 switch-case)")

		# 栈字符串
		stack_str_pattern = re.compile(
		    r'(mov\s+(?:byte|word|dword|qword)\s+ptr\s+\[.*?\]\s*,\s*0x[0-9a-fA-F]+\s*;?\s*){4,}',
		    re.IGNORECASE
		)
		if stack_str_pattern.search(full_text):
			warnings.append("OBFUSCATION: 栈上字符串构造 — 常见于混淆代码")

		# 垃圾指令
		junk_patterns = [
		    (r'\b(jmp\s+\$|jmp\s+next\d*)\b', "垃圾跳转 (jmp $/jmp next)"),
		    (r'\b(push\s+rax\s*\n\s*pop\s+rax)\b', "NOP 等价序列"),
		]
		for pattern, msg in junk_patterns:
			if re.search(pattern, full_text, re.IGNORECASE):
				warnings.append(f"OBFUSCATION: {msg}")

		return warnings

	# 格式化输出

	def format_output(self,
	                  structured: StructuredPseudocode,
	                  fmt: OutputFormat = OutputFormat.PLAIN,
	                  with_types: bool = True) -> str:
		"""将结构化表示转换为指定格式的文本输出"""
		if fmt == OutputFormat.MARKDOWN:
			return self._format_markdown(structured, with_types)
		elif fmt == OutputFormat.HTML:
			return self._format_html(structured, with_types)
		else:
			return self._format_plain(structured, with_types)

	def _format_plain(self, sp: StructuredPseudocode, with_types: bool) -> str:
		"""纯文本格式 — 带类型标注的缩进伪代码"""
		lines: List[str] = []

		# 函数头
		params_str = ', '.join(
			f"{p.type_hint} {p.name}" if with_types and p.type_hint != 'auto' else p.name
			for p in sp.parameters
		)
		lines.append(f"{sp.return_type} {sp.function_name}({params_str}) {{")

		# 变量声明块
		if with_types and sp.variables:
			local_vars = [v for v in sp.variables.values()
			               if v.is_local and not v.is_parameter]
			if local_vars:
				for v in local_vars:
					lines.append(f"    {v.type_hint} {v.name};  // refs: {v.references}")
				lines.append("")

		# 代码块递归打印
		if sp.root_block:
			for child in sp.root_block.children:
				lines.extend(self._format_block_plain(child, 4, with_types))

		lines.append("}")

		# 控制流提示
		if sp.control_flow_hints:
			lines.append("")
			lines.append("// Control Flow Hints:")
			for hint in sp.control_flow_hints:
				lines.append(f"//   {hint}")

		# 警告
		if sp.warnings:
			lines.append("")
			lines.append("// Warnings:")
			for w in sp.warnings:
				lines.append(f"//   :warning: {w}")

		return '\n'.join(lines)

	def _format_block_plain(self, block: CodeBlock,
	                         indent: int, with_types: bool) -> List[str]:
		"""递归格式化代码块 — plain text"""
		lines: List[str] = []
		indent_str = " " * indent

		bt = block.block_type

		if bt == BlockType.PLAIN:
			for line in block.body:
				lines.append(f"{indent_str}{line}")
			return lines

		if bt == BlockType.IF:
			lines.append(f"{indent_str}if ({block.condition}) {{")
			for child in block.children:
				lines.extend(self._format_block_plain(child, indent + 4, with_types))
			lines.append(f"{indent_str}}}")

		elif bt == BlockType.ELIF:
			lines.append(f"{indent_str}}} else if ({block.condition}) {{")
			for child in block.children:
				lines.extend(self._format_block_plain(child, indent + 4, with_types))

		elif bt == BlockType.ELSE:
			lines.append(f"{indent_str}}} else {{")
			for child in block.children:
				lines.extend(self._format_block_plain(child, indent + 4, with_types))
			lines.append(f"{indent_str}}}")

		elif bt == BlockType.WHILE:
			lines.append(f"{indent_str}while ({block.condition}) {{")
			for child in block.children:
				lines.extend(self._format_block_plain(child, indent + 4, with_types))
			lines.append(f"{indent_str}}}")

		elif bt == BlockType.FOR:
			lines.append(f"{indent_str}for ({block.condition}) {{")
			for child in block.children:
				lines.extend(self._format_block_plain(child, indent + 4, with_types))
			lines.append(f"{indent_str}}}")

		elif bt == BlockType.SWITCH:
			lines.append(f"{indent_str}switch ({block.condition}) {{")
			for child in block.children:
				lines.extend(self._format_block_plain(child, indent + 4, with_types))
			lines.append(f"{indent_str}}}")

		elif bt == BlockType.CASE:
			lines.append(f"{indent_str}case {block.condition}:")
			for child in block.children:
				lines.extend(self._format_block_plain(child, indent + 4, with_types))

		elif bt == BlockType.DEFAULT:
			lines.append(f"{indent_str}default:")
			for child in block.children:
				lines.extend(self._format_block_plain(child, indent + 4, with_types))

		elif bt == BlockType.RETURN:
			lines.append(f"{indent_str}return;  // {block.body[0] if block.body else ''}")

		elif bt == BlockType.GOTO:
			lines.append(f"{indent_str}goto {block.condition};")

		elif bt == BlockType.BREAK:
			lines.append(f"{indent_str}break;")

		elif bt == BlockType.CONTINUE:
			lines.append(f"{indent_str}continue;")

		elif bt == BlockType.TRY:
			lines.append(f"{indent_str}try {{")
			for child in block.children:
				lines.extend(self._format_block_plain(child, indent + 4, with_types))
			lines.append(f"{indent_str}}}")

		elif bt == BlockType.CATCH:
			lines.append(f"{indent_str}catch ({block.condition}) {{")
			for child in block.children:
				lines.extend(self._format_block_plain(child, indent + 4, with_types))
			lines.append(f"{indent_str}}}")

		return lines

	def _format_markdown(self, sp: StructuredPseudocode, with_types: bool) -> str:
		"""Markdown 格式输出"""
		lines = [
			f"# Structured Pseudocode: `{sp.function_name}`",
			"",
			f"```c",
			self._format_plain(sp, with_types),
			"```",
			"",
		]

		if sp.control_flow_hints:
			lines.append("## Control Flow Hints")
			lines.append("")
			for hint in sp.control_flow_hints:
				lines.append(f"- {hint}")
			lines.append("")

		if sp.variables:
			lines.append("## Variable Table")
			lines.append("")
			lines.append("| Name | Type | Scope | References |")
			lines.append("|------|------|-------|------------|")
			for v in sorted(sp.variables.values(), key=lambda x: x.name):
				scope = f"L{v.scope_start}-L{v.scope_end}" if v.scope_end > 0 else f"L{v.scope_start}+"
				lines.append(f"| `{v.name}` | `{v.type_hint}` | {scope} | {v.references} |")
			lines.append("")

		if sp.warnings:
			lines.append("## Warnings")
			lines.append("")
			for w in sp.warnings:
				lines.append(f"- :warning: {w}")

		return '\n'.join(lines)

	def _format_html(self, sp: StructuredPseudocode, with_types: bool) -> str:
		"""HTML 格式输出 — 带语法高亮 CSS class"""
		escaped = html.escape(self._format_plain(sp, with_types))

		# 简单关键字高亮
		keywords = ['if', 'else', 'while', 'for', 'switch', 'case', 'default',
		            'return', 'goto', 'break', 'continue', 'try', 'catch', 'finally',
		            'void', 'int', 'long', 'char', 'float', 'double', 'unsigned']
		for kw in keywords:
			escaped = re.sub(
				r'\b(' + re.escape(kw) + r')\b',
				r'<span class="kw">\1</span>',
				escaped
			)

		# 注释高亮
		escaped = re.sub(
			r'(//[^\n]*)',
			r'<span class="comment">\1</span>',
			escaped
		)

		return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Structured Pseudocode: {html.escape(sp.function_name)}</title>
<style>
body {{ font-family: 'Consolas', 'Monaco', monospace; background: #1e1e1e;
       color: #d4d4d4; padding: 20px;}}
.kw {{ color: #569cd6; font-weight: bold;}}
.comment {{ color: #6a9955; font-style: italic;}}
pre {{ background: #2d2d2d; padding: 15px; border-radius: 5px;
      overflow-x: auto; }}
.warning {{ color: #cca700;}}
h1 {{ color: #569cd6;}}
</style>
</head>
<body>
<h1>Structured Pseudocode: <code>{html.escape(sp.function_name)}</code></h1>
<pre>{escaped}</pre>
'''
		if sp.control_flow_hints:
			lines = ["<ul>"]
			for hint in sp.control_flow_hints:
				lines.append(f'<li class="warning">{html.escape(hint)}</li>')
			lines.append("</ul>")
			return f'{escaped}\n' + '\n'.join(lines) + '</body></html>'

		return f'{escaped}</body></html>'

	# 工具

	def _next_block_id(self) -> int:
		self._block_counter += 1
		return self._block_counter

	def to_json(self, sp: StructuredPseudocode) -> str:
		"""将 Structured伪代码 序列化为 JSON"""
		data = {
			'function_name': sp.function_name,
			'return_type': sp.return_type,
			'parameters': [
				{'name': p.name, 'type_hint': p.type_hint,
				 'scope_start': p.scope_start, 'references': p.references}
				for p in sp.parameters
			],
			'variables': {
				name: {
					'type_hint': v.type_hint,
					'scope_start': v.scope_start,
					'scope_end': v.scope_end,
					'references': v.references,
					'is_parameter': v.is_parameter,
				}
				for name, v in sp.variables.items()
			},
			'root_block': sp.root_block.to_dict() if sp.root_block else None,
			'control_flow_hints': sp.control_flow_hints,
			'warnings': sp.warnings,
		}
		return json.dumps(data, indent=2, ensure_ascii=False)


# 便捷入口

def generate_structured_pseudocode(
    pseudocode: str,
    function_name: str = "",
    output_format: str = "plain",
    with_types: bool = True,
) -> StructuredPseudocode:
    """一站式：把反编译输出文本变成结构化伪代码"""
    fmt = OutputFormat.PLAIN
    if output_format.lower() == 'markdown':
        fmt = OutputFormat.MARKDOWN
    elif output_format.lower() == 'html':
        fmt = OutputFormat.HTML

    gen = StructuredPseudocodeGenerator()
    return gen.generate(pseudocode, function_name, fmt, with_types)


def format_structured_output(
    structured: StructuredPseudocode,
    fmt: str = "plain",
    with_types: bool = True,
) -> str:
    """将结构化结果格式化为文本"""
    out_fmt = OutputFormat.PLAIN
    if fmt.lower() == 'markdown':
        out_fmt = OutputFormat.MARKDOWN
    elif fmt.lower() == 'html':
        out_fmt = OutputFormat.HTML

    gen = StructuredPseudocodeGenerator()
    return gen.format_output(structured, out_fmt, with_types)
