# Deemo 调试修复记录

---

## 版本历史

| 版本 | 日期 | 修复数量 | 主要内容 |
|------|------|----------|----------|
| v1.1.0 | 2026-05-31 | 16 | 基础功能修复 |
| v1.2.0 | 2026-06-01 | 15 | 多架构 ROP、插件系统、向量存储 |
| v1.3.0 | 2026-06-02 | 12 | 静态数据流分析、Web API 服务 |
| v1.3.1 | 2026-06-03 | 9 | 沙箱执行、PostgreSQL 支持 |
| v1.4.0 | 2026-06-04 | 8 | 测试修复、Web API 导出、终端报告输出、SymbolicExecutor 健壮性、search_by_type 别名方法、CVE 查询功能基础完善、ANSI 转义序列过滤、函数反编译地址范围修复 |

---

## v1.1.0 修复内容

### 问题 1: 缺少 .env.example 和配置模块

**问题描述**:
- 项目中没有配置文件来提示用户配置 OpenAI API Key
- 用户直接运行会报 `No API key found`，且没有友好提示

**修复方案**:
1. 创建 [.env.example](file:///c:/Users/Administrator/Desktop/deemo/.env.example) 文件
2. 创建 [config.py](file:///c:/Users/Administrator/Desktop/deemo/config.py) 配置管理模块
3. 添加 `check_openai_api_key()` 函数，在启动时检查环境变量

**关键代码**:
```python
# config.py 中的 API Key 检查
def check_openai_api_key() -> bool:
    api_key = os.environ.get('OPENAI_API_KEY', '')
    if not api_key or api_key.strip() == '':
        return False
    return True
```

---

### 问题 2: 缺少依赖统一检测

**问题描述**:
- 缺少 `check_dependencies()` 函数
- radare2 未安装时会抛出 `FileNotFoundError`，没有友好提示

**修复方案**:
在 [main.py](file:///c:/Users/Administrator/Desktop/deemo/main.py#L56-L134) 中添加 `check_dependencies()` 函数：

```python
def check_dependencies() -> List[str]:
    """统一检测所有依赖是否存在"""
    missing = []
    
    # 检查 radare2
    try:
        result = subprocess.run(
            ['r2', '-v'],
            capture_output=True,
            text=True,
            timeout=Config.SUBPROCESS_TIMEOUT
        )
        if result.returncode == 0:
            logger.info(f"✓ radare2 已安装: {result.stdout.strip().split(chr(10))[0]}")
        else:
            missing.append('radare2')
    except FileNotFoundError:
        missing.append('radare2')
    
    # 检查 Python 包
    packages = [('pwn', 'pwntools'), ('openai', 'openai')]
    for pkg_name, display_name in packages:
        try:
            import importlib
            module = importlib.import_module(pkg_name)
            logger.info(f"✓ {display_name} 已安装: 版本 {getattr(module, '__version__', 'unknown')}")
        except ImportError:
            missing.append(f'{display_name} (Python 包)')
    
    return missing
```

---

### 问题 3: subprocess.run 缺少 timeout 参数

**问题描述**:
- 所有 `subprocess.run` 调用没有设置 `timeout` 参数
- 如果 radare2 对畸形二进制卡死，程序会永久挂起

**修复方案**:
为所有 `subprocess.run` 调用添加 `timeout` 参数：

| 文件 | timeout 值 |
|------|------------|
| [main.py](file:///c:/Users/Administrator/Desktop/deemo/main.py) | `Config.SUBPROCESS_TIMEOUT` (30s) |
| [decomp_ai.py](file:///c:/Users/Administrator/Desktop/deemo/modules/decomp_ai.py) | `Config.SUBPROCESS_TIMEOUT` / `Config.RADARE2_TIMEOUT` (120s) |
| [exploit_gen.py](file:///c:/Users/Administrator/Desktop/deemo/modules/exploit_gen.py) | `Config.SUBPROCESS_TIMEOUT` |

**关键代码示例** ([decomp_ai.py](file:///c:/Users/Administrator/Desktop/deemo/modules/decomp_ai.py#L107-L112)):
```python
result = subprocess.run(
    cmd,
    capture_output=True,
    text=True,
    timeout=Config.RADARE2_TIMEOUT
)
```

---

### 问题 4: 命令注入风险

**问题描述**:
- 构造 radare2 命令时，函数名可能包含特殊字符
- 存在命令注入风险

**修复方案**:
在 [decomp_ai.py](file:///c:/Users/Administrator/Desktop/deemo/modules/decomp_ai.py#L15-L37) 中添加 `sanitize_function_name()` 函数：

```python
def sanitize_function_name(func_name: str) -> str:
    """清理函数名，防止命令注入"""
    if not func_name:
        return 'main'
    
    sanitized = re.sub(r'[^\w\-_\.]', '_', func_name)
    sanitized = sanitized.strip()
    
    if '\n' in func_name or ';' in func_name or '&' in func_name:
        logger.warning(f"检测到函数名中包含危险字符，已清理: {repr(func_name)}")
    
    if not sanitized:
        return 'main'
    
    return sanitized
```

**过滤的危险字符**: `\n`, `;`, `&`, `|`, `<`, `>`, `$`, `(`, `)`, `{`, `}`, `[`, `]` 等

---

### 问题 5: info_collect.py 缺少异常处理

**问题描述**:
- 加载非 ELF 文件或文件损坏时可能崩溃
- 没有完善的异常处理

**修复方案**:
1. 在 [info_collect.py](file:///c:/Users/Administrator/Desktop/deemo/modules/info_collect.py#L25-L63) 中添加 `validate_elf_file()` 函数
2. 重构 `load_binary()` 函数，添加完善的异常处理
3. 使用**延迟导入**避免在没有 pwntools 时整个模块无法加载

**关键代码**:
```python
def validate_elf_file(binary_path: str) -> bool:
    """验证文件是否为有效的 ELF 文件"""
    try:
        if not os.path.exists(binary_path):
            logger.error(f"文件不存在: {binary_path}")
            return False
        
        if not os.path.isfile(binary_path):
            logger.error(f"路径不是文件: {binary_path}")
            return False
        
        with open(binary_path, 'rb') as f:
            header = f.read(4)
            if len(header) < 4:
                logger.error(f"文件太小，不是有效的 ELF 文件: {binary_path}")
                return False
            if header != b'\x7fELF':
                logger.error(f"文件不是 ELF 格式: {binary_path}")
                return False
        
        return True
    except Exception as e:
        logger.error(f"验证 ELF 文件时出错: {e}")
        return False
```

**异常处理覆盖的情况**:
- `FileNotFoundError` / 文件不存在
- `struct.error` / ELF 结构损坏
- `ValueError` / ELF 解析错误
- `IOError` / 读取失败
- `ImportError` / pwntools 未安装

---

### 问题 6: 日志缺少文件持久化

**问题描述**:
- `main.py` 只配置了 console 日志，没有写入文件
- 项目要求"记录分析过程"

**修复方案**:
在 [main.py](file:///c:/Users/Administrator/Desktop/deemo/main.py#L30-L54) 中修改 `setup_logging()` 函数：

```python
def setup_logging(log_level: str = 'INFO') -> None:
    """设置日志配置，输出到控制台和 logs/ 目录"""
    ensure_directories()
    
    log_file = os.path.join(Config.LOGS_DIR, f'vuln_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file, mode='w', encoding='utf-8')
        ]
    )
```

**日志输出位置**: `./logs/vuln_analysis_YYYYMMDD_HHMMSS.log`

---

### 问题 7: --crash 参数数据流断裂

**问题描述**:
- `--crash` 参数加载的 crash_data 没有传递给漏洞分析模块
- 只是在 `load_crash_data` 中打印了内容，但没有送入 `crash_analysis.analyze_crash_with_ai`

**修复方案**:
在 [main.py](file:///c:/Users/Administrator/Desktop/deemo/main.py) 中修复数据流：

```python
crash_analysis = None
if crash_data:
    logger.info("步骤 3/5: 崩溃信息分析...")
    report_gen.add_step('Crash Analysis Started')
    crash_analyzer = CrashAnalyzer(client)
    crash_analysis = crash_analyzer.analyze(crash_data, binary_info.get('checksec', {}))
    report_gen.add_step('Crash Analysis Complete', crash_analysis)
```

---

### 问题 8: 寄存器解析正则不通用

**问题描述**:
- 使用的正则 `r'([a-zA-Z0-9]+)\s*=\s*(0x[0-9a-fA-F]+)'` 只能匹配特定格式
- 不同工具输出的崩溃格式差异很大

**修复方案**:
在 [crash_analysis.py](file:///c:/Users/Administrator/Desktop/deemo/modules/crash_analysis.py) 中添加多种正则模式：

```python
REGISTER_PATTERNS = [
    r'([a-zA-Z0-9]+)\s*=\s*(0x[0-9a-fA-F]+)',
    r'([a-zA-Z0-9]+)\s*:\s*(0x[0-9a-fA-F]+)',
    r'([a-zA-Z0-9]+)\s+(0x[0-9a-fA-F]+)',
    r'([a-zA-Z0-9]+)\s+0x([0-9a-fA-F]+)',
]

def parse_registers_from_text(text: str) -> Dict[str, str]:
    """从文本中解析寄存器信息，兼容多种格式"""
    registers = {}
    if not text:
        return registers
    
    for pattern in REGISTER_PATTERNS:
        for match in re.finditer(pattern, text, re.MULTILINE | re.IGNORECASE):
            reg_name = match.group(1).lower()
            value = match.group(2)
            if reg_name in REGISTER_NAMES:
                registers[reg_name] = value
    
    return registers
```

---

### 问题 9: AI 响应解析脆弱

**问题描述**:
- 假设 AI 返回的 JSON 一定包含 `"vulnerabilities"` 字段
- 实际 LLM 可能返回非 JSON、纯文本或缺少字段
- 会导致 `KeyError`

**修复方案**:
在 [decomp_ai.py](file:///c:/Users/Administrator/Desktop/deemo/modules/decomp_ai.py) 中添加容错解析：

```python
def _parse_ai_response(self, response_text: str) -> Dict[str, Any]:
    """解析 AI 响应，提取 JSON 内容，增加容错"""
    default_result = {
        'raw_response': response_text,
        'vulnerabilities': [],
        'summary': 'AI 响应解析失败，原始响应已保存',
        'risk_level': 'Unknown',
        'parse_error': True
    }
    
    if not response_text:
        logger.warning("AI 返回空响应")
        return default_result
    
    try:
        json_match = re.search(r'\{[\s\S]*\}', response_text)
        if json_match:
            json_str = json_match.group()
            parsed = json.loads(json_str)
            
            result = {
                'raw_response': response_text,
                'vulnerabilities': parsed.get('vulnerabilities', []),
                'summary': parsed.get('summary', '未提供摘要'),
                'risk_level': parsed.get('risk_level', 'Unknown'),
                'parse_error': False
            }
            
            if not isinstance(result['vulnerabilities'], list):
                logger.warning("AI 响应中的 vulnerabilities 不是列表")
                result['vulnerabilities'] = []
            
            return result
        else:
            logger.warning("AI 响应中未找到 JSON 格式")
            return {
                'raw_response': response_text,
                'vulnerabilities': [],
                'summary': response_text[:500] if len(response_text) > 500 else response_text,
                'risk_level': 'Unknown',
                'parse_error': True
            }
    except json.JSONDecodeError as e:
        logger.error(f"解析 AI 响应 JSON 失败: {e}")
        logger.debug(f"原始响应: {response_text}")
        return default_result
    except Exception as e:
        logger.error(f"解析 AI 响应时发生未知错误: {e}")
        return default_result
```

---

### 问题 10: 迭代优化可能无限循环

**问题描述**:
- 没有检查是否与上一次生成的脚本完全相同
- 如果 AI 连续两次生成相同错误 payload，会浪费全部 5 次迭代

**修复方案**:
在 [exploit_gen.py](file:///c:/Users/Administrator/Desktop/deemo/modules/exploit_gen.py) 中添加去重机制：

```python
def _compute_script_hash(self, script: str) -> str:
    """计算脚本的哈希值，用于去重检测"""
    normalized = re.sub(r'\s+', '', script)
    return hashlib.md5(normalized.encode('utf-8')).hexdigest()

def _is_duplicate_script(self, script: str) -> bool:
    """检查脚本是否与之前生成的重复"""
    script_hash = self._compute_script_hash(script)
    if script_hash in self.script_hashes:
        return True
    self.script_hashes.add(script_hash)
    return False
```

在迭代循环中使用：
```python
if self._is_duplicate_script(optimized_script):
    logger.warning(f"第 {i} 次迭代生成的脚本与之前重复，提前结束迭代")
    current_result['early_exit_reason'] = 'duplicate_script'
    return current_result
```

---

### 问题 11: 函数选择包含 libc 启动函数

**问题描述**:
- `info_collect` 返回的 `functions` 可能包含大量库函数
- 例如 `_start`, `__libc_csu_init` 等
- 应该优先分析用户自定义函数或危险函数相关的函数

**修复方案**:
在 [decomp_ai.py](file:///c:/Users/Administrator/Desktop/deemo/modules/decomp_ai.py) 中添加函数过滤：

```python
def list_functions(self) -> List[str]:
    """列出二进制文件中的所有函数"""
    if not self.radare2_available:
        return []
    
    try:
        cmd = ['r2', '-q', '-c', 'afl', self.binary_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=Config.SUBPROCESS_TIMEOUT)
        
        if result.returncode == 0:
            functions = []
            libc_prefixes = ('_start', '__libc_csu', '__libc_start', '_init', '_fini', '__gmon', '_dl_')
            
            for line in result.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 3:
                    func_name = parts[-1]
                    
                    if func_name.startswith('sym.'):
                        clean_name = func_name[4:]
                    else:
                        clean_name = func_name
                    
                    if not clean_name.startswith(libc_prefixes):
                        functions.append(clean_name)
            
            return functions
        return []
    except Exception as e:
        logger.error(f"获取函数列表失败: {e}")
        return []
```

---

### 问题 12: Prompt 占位符不匹配

**问题描述**:
- 模板字符串中的占位符与实际调用时的 `.format()` 参数可能不对应

**修复方案**:
确保 [prompts.py](file:///c:/Users/Administrator/Desktop/deemo/prompts.py) 中所有模板的占位符与调用处完全对应：

| 模板 | 占位符 | 调用文件 |
|------|--------|----------|
| `DECOMP_ANALYSIS_TEMPLATE` | `{binary_path}`, `{function_name}`, `{nx}`, `{pie}`, `{relro}`, `{canary}`, `{aslr}`, `{dangerous_functions}`, `{key_strings}`, `{pseudocode}` | [decomp_ai.py](file:///c:/Users/Administrator/Desktop/deemo/modules/decomp_ai.py) |
| `CRASH_ANALYSIS_TEMPLATE` | `{registers}`, `{stack_trace}`, `{fault_instruction}`, `{program_output}`, `{checksec_summary}` | [crash_analysis.py](file:///c:/Users/Administrator/Desktop/deemo/modules/crash_analysis.py) |
| `EXPLOIT_GENERATION_TEMPLATE` | `{vulnerability_type}`, `{vulnerability_description}`, `{binary_path}`, `{nx}`, `{pie}`, `{relro}`, `{canary}`, `{arch}`, `{bits}`, `{base_address}`, `{symbols}`, `{gadgets}`, `{exploitation_approach}` | [exploit_gen.py](file:///c:/Users/Administrator/Desktop/deemo/modules/exploit_gen.py) |
| `EXPLOIT_ITERATION_TEMPLATE` | `{original_script}`, `{failure_info}`, `{nx}`, `{pie}`, `{relro}`, `{canary}`, `{additional_info}`, `{iteration_count}` | [exploit_gen.py](file:///c:/Users/Administrator/Desktop/deemo/modules/exploit_gen.py) |

---

### 问题 13: 文件写入缺少目录检查

**问题描述**:
- 写入文件时，如果目录不存在（如 `reports/` 文件夹未创建）
- 会抛出 `FileNotFoundError`

**修复方案**:
在所有文件写入前检查目录是否存在，不存在则自动创建：

**1. [config.py](file:///c:/Users/Administrator/Desktop/deemo/config.py)** - 目录管理函数：
```python
def ensure_directories():
    """确保所需目录存在"""
    for dir_path in [Config.LOGS_DIR, Config.REPORTS_DIR, Config.EXPLOITS_DIR]:
        try:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
                logger.info(f"创建目录: {dir_path}")
        except Exception as e:
            logger.error(f"创建目录失败 {dir_path}: {e}")
```

**2. [exploit_gen.py](file:///c:/Users/Administrator/Desktop/deemo/modules/exploit_gen.py)** - 脚本保存：
```python
output_dir = os.path.dirname(output_path)
if output_dir and not os.path.exists(output_dir):
    os.makedirs(output_dir)
```

---

### 问题 14: 验证脚本缺少安全警告

**问题描述**:
- 生成的验证脚本可能执行系统命令
- 如果用户不小心验证恶意样本，可能造成本地破坏
- 缺少安全警告

**修复方案**:
在 [exploit_gen.py](file:///c:/Users/Administrator/Desktop/deemo/modules/exploit_gen.py) 中添加安全警告：

```python
SECURITY_WARNING = "# WARNING: This exploit may damage your system. Run only in isolated VM.\n"

def _add_security_warning(self, script: str) -> str:
    """在脚本开头添加安全警告"""
    if SECURITY_WARNING in script:
        return script
    
    if script.startswith('#!'):
        lines = script.split('\n', 2)
        if len(lines) >= 2:
            return lines[0] + '\n' + SECURITY_WARNING + lines[1] + '\n' + (lines[2] if len(lines) > 2 else '')
    
    return SECURITY_WARNING + script
```

---

### 问题 15: 反馈迭代缺失 (stderr 未收集)

**问题描述**:
- 虽然有迭代循环，但缺少失败后向 LLM 反馈具体错误信息
- 只是重新调用相同 prompt，没有把上一次的执行错误喂回模型

**修复方案**:
在 [exploit_gen.py](file:///c:/Users/Administrator/Desktop/deemo/modules/exploit_gen.py) 中添加详细错误信息收集：

```python
def _build_failure_info(self, validation_result: Dict[str, Any]) -> str:
    """构建详细的失败信息，包含 stdout 和 stderr"""
    failure_info_parts = []
    
    return_code = validation_result.get('return_code', 'Unknown')
    failure_info_parts.append(f"Return Code: {return_code}")
    
    stdout = validation_result.get('stdout', '')
    if stdout:
        failure_info_parts.append(f"\nStdout (last 500 chars):")
        failure_info_parts.append(stdout[-500:] if len(stdout) > 500 else stdout)
    
    stderr = validation_result.get('stderr', '')
    if stderr:
        failure_info_parts.append(f"\nStderr (last 1000 chars):")
        failure_info_parts.append(stderr[-1000:] if len(stderr) > 1000 else stderr)
    
    output = validation_result.get('output', '')
    if output and not stdout and not stderr:
        failure_info_parts.append(f"\nOutput (last 800 chars):")
        failure_info_parts.append(output[-800:] if len(output) > 800 else output)
    
    return '\n'.join(failure_info_parts)
```

使用 `EXPLOIT_ITERATION_TEMPLATE` 发送给 AI：
```python
prompt = EXPLOIT_ITERATION_TEMPLATE.format(
    original_script=original_script,
    failure_info=failure_info,
    nx=checksec.get('nx', 'Unknown'),
    pie=checksec.get('pie', 'Unknown'),
    relro=checksec.get('relro', 'Unknown'),
    canary=checksec.get('canary', 'Unknown'),
    additional_info=additional_info,
    iteration_count=iteration_count
)
```

---

### 问题 16: 缺少单元测试

**问题描述**:
- 没有 `tests/` 文件夹
- 用户无法快速验证工具是否正常工作

**修复方案**:
创建 [tests/](file:///c:/Users/Administrator/Desktop/deemo/tests/) 目录：

| 测试文件 | 测试内容 | 测试数量 |
|----------|----------|----------|
| [test_config.py](file:///c:/Users/Administrator/Desktop/deemo/tests/test_config.py) | API Key 检查、目录管理、崩溃数据验证 | 10 |
| [test_crash_analysis.py](file:///c:/Users/Administrator/Desktop/deemo/tests/test_crash_analysis.py) | 寄存器解析、启发式分析 | 18 |
| [test_decomp_ai.py](file:///c:/Users/Administrator/Desktop/deemo/tests/test_decomp_ai.py) | 函数名校验、AI 响应解析 | 21 |
| [test_exploit_gen.py](file:///c:/Users/Administrator/Desktop/deemo/tests/test_exploit_gen.py) | 安全警告、去重、错误信息构建 | 19 |
| [test_info_collect.py](file:///c:/Users/Administrator/Desktop/deemo/tests/test_info_collect.py) | ELF 验证、危险函数检测 | 8 |
| [test_vuln_db.py](file:///c:/Users/Administrator/Desktop/deemo/tests/test_vuln_db.py) | 数据库操作、相似性搜索 | 15 |
| [sample_crash_data.json](file:///c:/Users/Administrator/Desktop/deemo/tests/sample_crash_data.json) | 崩溃数据示例 | - |

**运行测试**:
```powershell
python tests/run_tests.py
python tests/run_tests.py -v
python tests/run_tests.py -p test_config.py
```

---

## v1.2.0 修复内容

### 问题 17: 多架构 ROP 链构建失败

**问题描述**:
- 原始代码仅支持 x86/x64 架构
- ARM/MIPS/RISC-V 等架构缺少 gadget 模式定义
- 跨平台二进制无法生成有效 ROP 链

**修复方案**:
在 [exploit_gen.py](file:///c:/Users/Administrator/Desktop/deemo/modules/exploit_gen.py) 中创建 `ROPChainBuilder` 类，支持多架构：

```python
class ROPChainBuilder:
    """多架构 ROP 链构建器"""
    
    ARCH_GADGET_PATTERNS = {
        'i386': {
            'pop_ebx': ['pop ebx', 'ret'],
            'pop_ecx': ['pop ecx', 'ret'],
            'pop_edx': ['pop edx', 'ret'],
            'int_0x80': ['int 0x80'],
        },
        'amd64': {
            'pop_rdi': ['pop rdi', 'ret'],
            'pop_rsi': ['pop rsi', 'ret'],
            'pop_rdx': ['pop rdx', 'ret'],
            'syscall': ['syscall'],
        },
        'arm': {
            'bx_lr': ['bx lr'],
            'pop_r0_pc': ['pop {r0, pc}'],
            'svc': ['svc #0'],
        },
        'mips': {
            'jr_ra': ['jr $ra'],
            'lw_ra_sp': ['lw $ra, x($sp)'],
        },
        'riscv': {
            'jalr_ra': ['jalr ra'],
            'lw_ra_sp': ['lw ra, x(sp)'],
        }
    }
```

---

### 问题 18: 插件钩子系统未实现

**问题描述**:
- 设计文档提到插件系统，但代码中未实现
- 无法在分析流程的特定点注入自定义逻辑

**修复方案**:
创建 [hooks.py](file:///c:/Users/Administrator/Desktop/deemo/modules/hooks.py) 模块，实现完整的钩子系统：

```python
class HookManager:
    """插件钩子管理器"""
    
    HOOK_POINTS = [
        'pre_info_collect',
        'pre_decompile',
        'post_decompile',
        'post_analysis',
        'pre_exploit_generate',
        'pre_crash_analysis',
        'post_crash_analysis',
        'post_report'
    ]
    
    def register_hook(self, hook_point: str, callback: Callable):
        """注册钩子函数"""
        if hook_point in self.hooks:
            self.hooks[hook_point].append(callback)
    
    def run_hook(self, hook_point: str, context: Dict[str, Any]) -> List[Any]:
        """执行特定钩子点的所有钩子"""
        if hook_point not in self.hooks:
            return []
        
        results = []
        for callback in self.hooks[hook_point]:
            try:
                result = callback(context)
                results.append(result)
            except Exception as e:
                logger.error(f"执行钩子 {hook_point} 时出错: {e}")
        
        return results
```

---

### 问题 19: 向量存储和语义搜索缺失

**问题描述**:
- 漏洞数据库仅支持简单的关键字搜索
- 无法根据代码语义查找相似漏洞
- 缺少向量嵌入存储

**修复方案**:
在 [vuln_db.py](file:///c:/Users/Administrator/Desktop/deemo/modules/vuln_db.py) 中添加向量存储支持：

```python
class VulnerabilityDatabase:
    """支持向量存储的漏洞数据库"""
    
    def add_code_embedding(self, vuln_id: int, embedding: List[float], 
                           model_name: str = 'default') -> bool:
        """添加代码嵌入向量"""
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                '''INSERT INTO code_embeddings 
                   (vuln_id, embedding, model_name, vector_dim) 
                   VALUES (?, ?, ?, ?)''',
                (vuln_id, json.dumps(embedding), model_name, len(embedding))
            )
            self.connection.commit()
            return True
        except Exception as e:
            logger.error(f"添加代码嵌入失败: {e}")
            return False
    
    def semantic_search(self, query_embedding: List[float], 
                        top_k: int = 10) -> List[Dict[str, Any]]:
        """语义搜索（使用余弦相似度）"""
        # 使用 FAISS 或 numpy 计算相似度
        ...
```

---

### 问题 20: 外部 CVE 数据库集成缺失

**问题描述**:
- 无法查询已知的 CVE 漏洞信息
- 缺少与 NVD、Exploit-DB 的集成
- 无法利用公开漏洞数据库增强分析

**修复方案**:
在 [vuln_db.py](file:///c:/Users/Administrator/Desktop/deemo/modules/vuln_db.py) 中添加外部 CVE 查询：

```python
def query_external_cve_database(self, cve_id: str = None, 
                                  product: str = None) -> List[Dict[str, Any]]:
    """查询外部 CVE 数据库 (NVD)"""
    try:
        # 首先检查本地缓存
        if cve_id:
            cached = self._get_cached_cve(cve_id)
            if cached:
                return [cached]
        
        # 查询 NVD API
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {}
        if cve_id:
            params['cveId'] = cve_id
        if product:
            params['keywordSearch'] = product
        
        response = requests.get(url, params=params, timeout=10)
        ...
    except Exception as e:
        logger.error(f"查询 CVE 数据库失败: {e}")
        return []
```

---

### 问题 21: 敏感信息日志泄露

**问题描述**:
- API Key、Token、Password 可能出现在日志中
- 没有统一的敏感信息过滤机制
- 日志文件可能包含凭据

**修复方案**:
在 [config.py](file:///c:/Users/Administrator/Desktop/deemo/config.py) 中添加 `SensitiveFilter` 日志过滤器：

```python
class SensitiveFilter(logging.Filter):
    """日志过滤器，自动脱敏敏感信息"""
    
    def filter(self, record):
        if isinstance(record.msg, str):
            record.msg = mask_sensitive_data(record.msg)
        
        if record.args:
            args_list = list(record.args)
            for i, arg in enumerate(args_list):
                if isinstance(arg, str):
                    args_list[i] = mask_sensitive_data(arg)
            record.args = tuple(args_list)
        
        return True

def mask_api_key(api_key: str, show_first: int = 4, show_last: int = 4) -> str:
    """脱敏 API Key：sk-1234...abcd -> sk-1234****abcd"""
    ...
```

---

### 问题 22: 缺少更多反编译引擎支持

**问题描述**:
- 仅支持 radare2 反编译
- 没有使用 Ghidra、IDA Pro、Binary Ninja 等专业工具
- 反编译质量有限

**修复方案**:
在 [decomp_ai.py](file:///c:/Users/Administrator/Desktop/deemo/modules/decomp_ai.py) 中添加多引擎支持：

```python
class DecompilerAI:
    """支持多反编译引擎的 AI 分析器"""
    
    DECOMPILER_ENGINES = {
        'radare2': {'available': False, 'check_method': '_check_radare2'},
        'ghidra': {'available': False, 'check_method': '_check_ghidra'},
        'ida': {'available': False, 'check_method': '_check_ida'},
        'binaryninja': {'available': False, 'check_method': '_check_binaryninja'},
        'hopper': {'available': False, 'check_method': '_check_hopper'},
    }
    
    def _select_best_decompiler(self) -> str:
        """选择最佳可用的反编译引擎"""
        for engine, info in self.DECOMPILER_ENGINES.items():
            if info['available']:
                return engine
        return 'radare2'
```

---

### 问题 23: 并行分析线程安全问题

**问题描述**:
- 多线程分析时，日志输出可能混乱
- 共享数据结构没有锁保护
- 可能导致结果聚合错误

**修复方案**:
在 [main.py](file:///c:/Users/Administrator/Desktop/deemo/main.py) 中实现线程安全的并行分析：

```python
def analyze_functions(self, functions: List[str], parallel: bool = False) -> List[Dict]:
    """分析多个函数，支持并行"""
    results = []
    result_lock = threading.Lock()
    
    def _analyze_single_function(func_name: str):
        """分析单个函数（线程安全）"""
        try:
            result = self.decomp_ai.analyze_function(func_name)
            with result_lock:
                results.append(result)
        except Exception as e:
            logger.error(f"分析函数 {func_name} 失败: {e}")
    
    if parallel:
        with ThreadPoolExecutor(max_workers=self.max_parallel) as executor:
            list(executor.map(_analyze_single_function, functions))
    else:
        for func in functions:
            _analyze_single_function(func)
    
    return results
```

---

### 问题 24: HTML 和 PDF 报告生成缺失

**问题描述**:
- 仅支持 Markdown 和 JSON 报告
- 缺少美观的 HTML 报告
- 无法生成 PDF 格式的可打印报告

**修复方案**:
在 [report.py](file:///c:/Users/Administrator/Desktop/deemo/modules/report.py) 中添加多格式报告支持：

```python
class ReportGenerator:
    """多格式报告生成器"""
    
    def generate_html_report(self, output_path: str) -> Optional[str]:
        """生成现代化 HTML 报告"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>二进制漏洞分析报告</title>
            <style>
                /* 现代化 CSS 样式 */
                .stat-card { ... }
                .vulnerability-card { ... }
                pre { background: #1e1e1e; color: #d4d4d4; padding: 15px; ... }
            </style>
        </head>
        ...
        """
    
    def generate_pdf_report(self, output_path: str) -> Optional[str]:
        """生成 PDF 报告（自动降级）"""
        # 尝试 weasyprint
        try:
            import weasyprint
            html_path = output_path.replace('.pdf', '.html')
            if not os.path.exists(html_path):
                self.generate_html_report(html_path)
            weasyprint.HTML(html_path).write_pdf(output_path)
            return output_path
        except ImportError:
            # 降级到 pdfkit
            try:
                import pdfkit
                ...
            except ImportError:
                logger.warning("PDF 生成依赖未安装，跳过 PDF 报告")
                return None
```

---

### 问题 25: 交互式模式缺少动态功能

**问题描述**:
- 交互式模式仅支持基本菜单
- 无法在分析过程中动态探索函数
- 无法为任意函数生成利用脚本

**修复方案**:
在 [main.py](file:///c:/Users/Administrator/Desktop/deemo/main.py) 中增强交互式模式：

```python
def run_interactive_menu(self, binary_info: Dict, 
                         initial_results: List[Dict]) -> None:
    """交互式分析菜单"""
    
    menu_options = {
        '1': ('查看函数详情', self._show_function_details),
        '2': ('分析其他函数', self._analyze_other_functions),
        '3': ('为漏洞生成利用脚本', self._generate_exploit_for_vuln),
        '4': ('列出所有可用函数', self._list_all_functions),
        '5': ('运行健康检查', self._run_health_check),
        '6': ('保存报告', self._save_report),
        '7': ('退出', None)
    }
    
    while True:
        print("\n" + "="*50)
        print("交互式分析菜单")
        print("="*50)
        for key, (desc, _) in menu_options.items():
            print(f"  {key}. {desc}")
        
        choice = input("\n请选择操作 (1-7): ").strip()
        if choice == '7':
            break
        ...
```

---

### 问题 26: 健康检查 (Doctor Mode) 缺失

**问题描述**:
- 用户无法快速诊断系统配置问题
- 缺少依赖检测、反编译引擎检测、AI 配置验证
- 问题排查效率低

**修复方案**:
在 [main.py](file:///c:/Users/Administrator/Desktop/deemo/main.py) 中实现健康检查：

```python
def run_health_check(self) -> Dict[str, Any]:
    """运行全面的健康检查"""
    results = {
        'dependencies': {},
        'decompilers': {},
        'ai_config': {},
        'symbols': {},
        'system_tools': {},
        'binary_capabilities': {}
    }
    
    # 检查依赖
    results['dependencies']['radare2'] = self._check_radare2()
    results['dependencies']['pwntools'] = self._check_pwntools()
    results['dependencies']['openai'] = self._check_openai()
    
    # 检查反编译引擎
    for engine in ['radare2', 'ghidra', 'ida', 'binaryninja', 'hopper']:
        results['decompilers'][engine] = self._check_decompiler(engine)
    
    # 检查 AI 配置
    results['ai_config']['api_key'] = self._check_ai_api_key()
    results['ai_config']['model'] = self._check_ai_model()
    
    return results
```

---

### 问题 27: one_gadget 和 libc 版本检测缺失

**问题描述**:
- 无法自动检测 libc 版本
- 无法查找和使用 one_gadget
- 利用生成效率低

**修复方案**:
在 [exploit_gen.py](file:///c:/Users/Administrator/Desktop/deemo/modules/exploit_gen.py) 中添加 libc 检测：

```python
def _detect_libc_version(self) -> Optional[str]:
    """检测 libc 版本"""
    try:
        # 尝试运行 ldd 获取 libc 路径
        result = subprocess.run(
            ['ldd', self.binary_path],
            capture_output=True,
            text=True,
            timeout=Config.SUBPROCESS_TIMEOUT
        )
        
        libc_match = re.search(r'libc\.so\.6 => (\S+)', result.stdout)
        if libc_match:
            libc_path = libc_match.group(1)
            return self._get_libc_version_from_path(libc_path)
    except Exception as e:
        logger.warning(f"检测 libc 版本失败: {e}")
    
    return None

def _find_one_gadget(self, libc_path: str) -> List[int]:
    """查找 one_gadget 地址"""
    try:
        result = subprocess.run(
            ['one_gadget', libc_path],
            capture_output=True,
            text=True,
            timeout=Config.SUBPROCESS_TIMEOUT
        )
        # 解析输出获取 gadget 地址
        ...
    except FileNotFoundError:
        logger.warning("one_gadget 未安装，跳过 one_gadget 检测")
        return []
```

---

### 问题 28: 多格式崩溃数据解析不完整

**问题描述**:
- 仅支持 JSON 格式的崩溃数据
- 无法解析 GDB、ASAN、WinDbg、coredump 等格式
- 兼容性差

**修复方案**:
在 [crash_analysis.py](file:///c:/Users/Administrator/Desktop/deemo/modules/crash_analysis.py) 中添加多格式支持：

```python
class CrashAnalyzer:
    """支持多格式崩溃数据解析"""
    
    CRASH_FORMATS = {
        'json': self._parse_json_crash,
        'gdb': self._parse_gdb_crash,
        'asan': self._parse_asan_crash,
        'windbg': self._parse_windbg_crash,
        'coredump': self._parse_coredump_crash,
    }
    
    def load_and_parse_crash_data(self, input_data: Any, 
                                   fmt: str = 'auto') -> Dict[str, Any]:
        """加载并解析多种格式的崩溃数据"""
        if fmt == 'auto':
            fmt = self._detect_crash_format(input_data)
        
        parser = self.CRASH_FORMATS.get(fmt)
        if parser:
            return parser(input_data)
        else:
            logger.warning(f"不支持的崩溃数据格式: {fmt}")
            return {}
```

---

### 问题 29: 符号执行多架构支持缺失

**问题描述**:
- 符号执行仅支持 x86/x64
- ARM/MIPS/RISC-V 等架构无法进行符号执行
- 跨平台分析能力有限

**修复方案**:
在 [symbolic_exe.py](file:///c:/Users/Administrator/Desktop/deemo/modules/symbolic_exe.py) 中添加多架构支持：

```python
SUPPORTED_ARCHES = {
    'x86': {'arch': 'i386', 'bits': 32},
    'x86_64': {'arch': 'amd64', 'bits': 64},
    'amd64': {'arch': 'amd64', 'bits': 64},
    'arm': {'arch': 'armel', 'bits': 32},
    'armel': {'arch': 'armel', 'bits': 32},
    'armhf': {'arch': 'armhf', 'bits': 32},
    'arm64': {'arch': 'aarch64', 'bits': 64},
    'aarch64': {'arch': 'aarch64', 'bits': 64},
    'mips': {'arch': 'mips', 'bits': 32},
    'mipsel': {'arch': 'mipsel', 'bits': 32},
    'mips64': {'arch': 'mips64', 'bits': 64},
    'riscv32': {'arch': 'riscv32', 'bits': 32},
    'riscv64': {'arch': 'riscv64', 'bits': 64},
    'ppc': {'arch': 'ppc', 'bits': 32},
    'ppc64': {'arch': 'ppc64', 'bits': 64},
}
```

---

### 问题 30: 格式化字符串模板与 f-string 冲突

**问题描述**:
- 原代码使用 `f'AAAA%{i}$p'`
- 与 Python 的字符串格式化 `{}` 冲突
- 导致 `KeyError: 'i'`

**修复方案** ([exploit_gen.py](file:///c:/Users/Administrator/Desktop/deemo/modules/exploit_gen.py)):
```python
# 修复前 (冲突)
payload = f'AAAA%{i}$p'

# 修复后 (使用字符串拼接)
payload = ('AAAA%' + str(i) + '$p').encode()
```

---

## v1.3.0 修复内容

### 问题 31: 静态数据流分析模块缺失

**问题描述**:
- 缺少不依赖 AI 的漏洞检测能力
- 无法进行静态污点分析、Use-Def 链分析
- AI 不可用时分析能力有限

**修复方案**:
创建 [static_analysis.py](file:///c:/Users/Administrator/Desktop/deemo/modules/static_analysis.py) 模块：

```python
class StaticDataFlowAnalyzer:
    """静态数据流分析器"""
    
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.angr_available = self._check_angr()
        self.radare2_available = self._check_radare2()
        self.cache_dir = os.path.join(Config.CACHE_DIR, 'static_analysis')
    
    def analyze_function(self, function_name: str) -> List[StaticVulnerability]:
        """完整分析一个函数"""
        vulnerabilities = []
        
        # 整数溢出检测
        vulnerabilities.extend(self.detect_integer_overflow(function_name))
        
        # 格式化字符串检测
        vulnerabilities.extend(self.detect_format_string_vulns(function_name))
        
        # 未初始化内存检测
        vulnerabilities.extend(self.detect_uninitialized_memory(function_name))
        
        # 静态污点分析
        vulnerabilities.extend(self.perform_static_taint_analysis(function_name))
        
        return vulnerabilities
```

---

### 问题 32: Use-Def 链分析未实现

**问题描述**:
- 无法追踪变量的定义和使用关系
- 无法分析数据流传播
- 难以发现复杂的逻辑漏洞

**修复方案**:
在 [static_analysis.py](file:///c:/Users/Administrator/Desktop/deemo/modules/static_analysis.py) 中实现 Use-Def 分析：

```python
def _analyze_us_def_chain(self, function_name: str) -> Dict[str, Any]:
    """分析 Use-Def 链"""
    try:
        if self.angr_available:
            return self._angr_us_def_analysis(function_name)
        elif self.radare2_available:
            return self._radare2_us_def_analysis(function_name)
    except Exception as e:
        logger.error(f"Use-Def 链分析失败: {e}")
    
    return {}

def _angr_us_def_analysis(self, function_name: str) -> Dict[str, Any]:
    """使用 angr 进行 Use-Def 分析"""
    import angr
    
    proj = angr.Project(self.binary_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()
    
    # 查找目标函数
    func = cfg.functions.get(function_name)
    if not func:
        return {}
    
    # 使用 VariableRecoveryFast 分析
    vr = proj.analyses.VariableRecoveryFast(func)
    
    return {
        'variables': vr.variables,
        'definitions': vr.definitions,
        'uses': vr.uses,
        'live_ranges': vr.live_ranges
    }
```

---

### 问题 33: 整数溢出检测缺失

**问题描述**:
- 无法静态检测整数溢出漏洞
- add/sub/mul/imul/shl/sal 等指令缺少边界检查分析

**修复方案**:
```python
INTEGER_OVERFLOW_INSTRUCTIONS = {
    'add': {'type': 'addition', 'risk': 'medium'},
    'sub': {'type': 'subtraction', 'risk': 'medium'},
    'mul': {'type': 'multiplication', 'risk': 'high'},
    'imul': {'type': 'signed_multiplication', 'risk': 'high'},
    'shl': {'type': 'left_shift', 'risk': 'high'},
    'sal': {'type': 'arithmetic_shift', 'risk': 'high'},
}

def detect_integer_overflow(self, function_name: str) -> List[StaticVulnerability]:
    """检测整数溢出"""
    vulnerabilities = []
    
    try:
        disassembly = self._get_function_disassembly(function_name)
        for addr, instruction in disassembly.items():
            for op, info in self.INTEGER_OVERFLOW_INSTRUCTIONS.items():
                if instruction.startswith(op):
                    # 检查是否有边界检查
                    has_check = self._has_bounds_check(addr, disassembly)
                    if not has_check:
                        vulnerabilities.append(
                            StaticVulnerability(
                                type='integer_overflow',
                                location=addr,
                                instruction=instruction,
                                severity=info['risk'],
                                description=f"潜在的整数溢出: {instruction}，缺少边界检查"
                            )
                        )
    except Exception as e:
        logger.error(f"整数溢出检测失败: {e}")
    
    return vulnerabilities
```

---

### 问题 34: 静态污点分析未实现

**问题描述**:
- 无法静态追踪输入源到危险汇点的数据流
- 缺少污点源和污点汇点的定义
- 难以发现复杂的注入漏洞

**修复方案**:
```python
DEFAULT_TAINT_SOURCES = {
    'read': {'type': 'input', 'args': [1]},
    'fread': {'type': 'file', 'args': [0]},
    'recv': {'type': 'network', 'args': [1]},
    'recvfrom': {'type': 'network', 'args': [1]},
    'getenv': {'type': 'environment', 'args': [0]},
    'scanf': {'type': 'input', 'args': [1, 2, 3, 4, 5, 6]},
    'gets': {'type': 'input', 'args': [0]},
}

DEFAULT_TAINT_SINKS = {
    'system': {'type': 'command_injection', 'args': [0]},
    'execve': {'type': 'command_injection', 'args': [0]},
    'execl': {'type': 'command_injection', 'args': [0]},
    'printf': {'type': 'format_string', 'args': [0]},
    'sprintf': {'type': 'format_string', 'args': [0]},
    'memcpy': {'type': 'buffer_overflow', 'args': [0, 1, 2]},
    'strcpy': {'type': 'buffer_overflow', 'args': [0, 1]},
}

def perform_static_taint_analysis(self, function_name: str) -> List[StaticVulnerability]:
    """执行静态污点分析"""
    vulnerabilities = []
    
    try:
        sources = self._identify_taint_sources(function_name)
        sinks = self._identify_taint_sinks(function_name)
        
        for source in sources:
            for sink in sinks:
                if self._is_taint_flow(source, sink, function_name):
                    vulnerabilities.append(
                        StaticVulnerability(
                            type=f'taint_flow_{sink["type"]}',
                            location=sink['location'],
                            severity='high',
                            description=f"污点流从 {source['function']} 流向 {sink['function']}，可能存在 {sink['type']} 漏洞"
                        )
                    )
    except Exception as e:
        logger.error(f"静态污点分析失败: {e}")
    
    return vulnerabilities
```

---

### 问题 35: 分析结果缺少缓存机制

**问题描述**:
- 每次运行都需要重新分析
- 静态分析耗时较长
- 效率低下

**修复方案**:
```python
def _get_cache_key(self, function_name: str, analysis_type: str) -> str:
    """获取缓存键"""
    file_hash = self._get_file_hash()
    return f"{file_hash}_{function_name}_{analysis_type}"

def _load_cached_result(self, cache_key: str) -> Optional[Any]:
    """加载缓存结果"""
    cache_path = os.path.join(self.cache_dir, f"{cache_key}.json")
    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"加载缓存失败: {e}")
    return None

def _save_cached_result(self, cache_key: str, result: Any) -> bool:
    """保存缓存结果"""
    try:
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir, exist_ok=True)
        cache_path = os.path.join(self.cache_dir, f"{cache_key}.json")
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logger.warning(f"保存缓存失败: {e}")
        return False
```

---

### 问题 36: Web API 服务缺失

**问题描述**:
- 无法通过 API 远程访问分析能力
- 不支持团队协作和批量分析
- 缺少任务管理和进度追踪

**修复方案**:
创建 [web_api.py](file:///c:/Users/Administrator/Desktop/deemo/modules/web_api.py) 模块：

```python
if FASTAPI_AVAILABLE:
    
    app = FastAPI(title="Deemo Binary Vulnerability Analysis API", version="1.3.0")
    
    # CORS 配置
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    task_manager = AnalysisTaskManager()
    
    @app.post("/api/analyze")
    async def submit_analysis(request: AnalysisRequest, 
                               background_tasks: BackgroundTasks):
        """提交分析任务"""
        task_id = task_manager.create_task(request)
        background_tasks.add_task(_execute_analysis_task, task_id, request)
        return APIResponse(
            success=True,
            message="分析任务已提交",
            data={"task_id": task_id, "status": "pending"}
        )
    
    @app.get("/api/tasks/{task_id}")
    async def get_task_status(task_id: str):
        """获取任务状态"""
        task = task_manager.get_task(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")
        return APIResponse(success=True, data=task)
    
    @app.get("/api/tasks/{task_id}/report/{format}")
    async def download_report(task_id: str, format: str):
        """下载报告"""
        report_path = _get_report_path(task_id, format)
        if not os.path.exists(report_path):
            raise HTTPException(status_code=404, detail="报告不存在")
        return FileResponse(report_path, filename=f"report.{format}")
```

---

### 问题 37: 异步任务管理缺失

**问题描述**:
- 长时间运行的分析任务无法异步执行
- 缺少任务状态追踪
- 无法取消或查看任务进度

**修复方案**:
```python
class AnalysisTaskManager:
    """异步分析任务管理器"""
    
    def __init__(self, tasks_dir: str = None):
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.tasks_dir = tasks_dir or os.path.join(Config.DATA_DIR, 'api_tasks')
        self._load_tasks()
    
    def create_task(self, request: AnalysisRequest) -> str:
        """创建新任务"""
        task_id = str(uuid.uuid4())
        task = {
            'task_id': task_id,
            'status': 'pending',
            'created_at': datetime.now().isoformat(),
            'updated_at': None,
            'progress': 0,
            'message': '任务已创建，等待执行',
            'request': request.dict(),
            'result': None
        }
        self.tasks[task_id] = task
        self._save_task(task_id, task)
        return task_id
    
    def update_task(self, task_id: str, **kwargs) -> bool:
        """更新任务状态"""
        if task_id not in self.tasks:
            task = self.get_task(task_id)
            if task:
                self.tasks[task_id] = task
            else:
                return False
        
        self.tasks[task_id].update(kwargs)
        self.tasks[task_id]['updated_at'] = datetime.now().isoformat()
        self._save_task(task_id, self.tasks[task_id])
        return True
    
    def list_tasks(self, status: str = None) -> List[Dict[str, Any]]:
        """列出所有任务"""
        tasks = list(self.tasks.values())
        if status:
            tasks = [t for t in tasks if t['status'] == status]
        return tasks
    
    def cancel_task(self, task_id: str) -> bool:
        """取消任务"""
        return self.update_task(task_id, status='cancelled', 
                                message='任务已被用户取消')
```

---

### 问题 38: 文件上传和 API 验证缺失

**问题描述**:
- 无法通过 API 上传二进制文件
- 缺少文件类型和大小验证
- 安全性不足

**修复方案**:
```python
@app.post("/api/upload")
async def upload_binary(file: UploadFile = File(...)):
    """上传二进制文件"""
    # 验证文件大小
    max_size = 100 * 1024 * 1024  # 100MB
    content = await file.read()
    if len(content) > max_size:
        raise HTTPException(status_code=413, detail="文件太大，最大 100MB")
    
    # 验证文件类型 (检查 magic bytes)
    magic = content[:4]
    valid_magics = [
        b'\x7fELF',      # ELF
        b'MZ',           # PE
        b'\xcf\xfa\xed\xfe',  # Mach-O (32-bit)
        b'\xcf\xfa\xed\xfe',  # Mach-O (64-bit)
    ]
    
    is_valid = False
    for vm in valid_magics:
        if magic.startswith(vm):
            is_valid = True
            break
    
    if not is_valid:
        raise HTTPException(status_code=400, detail="不支持的文件格式，仅支持 ELF/PE/Mach-O")
    
    # 保存文件
    file_id = hashlib.sha256(content).hexdigest()
    save_path = os.path.join(Config.DATA_DIR, 'uploads', f"{file_id}_{file.filename}")
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    
    with open(save_path, 'wb') as f:
        f.write(content)
    
    return APIResponse(
        success=True,
        message="文件上传成功",
        data={
            'file_id': file_id,
            'filename': file.filename,
            'size': len(content),
            'path': save_path
        }
    )
```

---

### 问题 39: 外部漏洞数据源集成缺失

**问题描述**:
- 无法通过 API 查询外部漏洞数据库
- 缺少与 OSV、GitHub Advisory 的集成
- 漏洞信息来源单一

**修复方案**:
```python
@app.post("/api/vulnerabilities/search")
async def search_vulnerabilities(query: VulnerabilityQuery):
    """搜索漏洞数据库"""
    results = []
    
    # 本地数据库搜索
    vuln_db = get_vuln_db()
    local_results = vuln_db.search_by_type(query.vulnerability_type) \
        if query.vulnerability_type else []
    results.extend(local_results)
    
    # 外部数据源搜索 (可选)
    if query.vulnerability_type and query.binary_format:
        try:
            # NVD 搜索
            nvd_results = vuln_db.query_external_cve_database(
                product=f"{query.binary_format} {query.architecture}"
            )
            results.extend(nvd_results)
        except Exception as e:
            logger.warning(f"外部 CVE 搜索失败: {e}")
    
    return APIResponse(
        success=True,
        message=f"找到 {len(results)} 个漏洞",
        data={
            'count': len(results),
            'results': results[:query.limit]
        }
    )
```

---

### 问题 40: Web API 缺少请求模型验证

**问题描述**:
- API 输入参数缺少验证
- 可能导致无效请求或安全问题
- 缺少默认值和边界检查

**修复方案**:
```python
class AnalysisRequest(BaseModel):
    """分析请求模型"""
    binary_name: str = Field(..., description="二进制文件名", 
                            min_length=1, max_length=255)
    binary_hash: Optional[str] = Field(None, description="二进制文件哈希")
    binary_format: Optional[str] = Field(None, description="文件格式: ELF/PE/MACH-O")
    architecture: Optional[str] = Field(None, description="架构: amd64, i386 等")
    function_names: Optional[List[str]] = Field(None, description="指定要分析的函数列表")
    enable_symbolic: bool = Field(False, description="是否启用符号执行")
    enable_exploit_gen: bool = Field(False, description="是否启用利用脚本生成")
    fuzzer_type: Optional[str] = Field(None, description="Fuzzer 类型: libfuzzer, afl")
    expert_mode: bool = Field(False, description="专家模式")
    report_formats: List[str] = Field(
        default_factory=lambda: ['md', 'html'],
        description="报告格式"
    )
    
    @validator('report_formats')
    def validate_report_formats(cls, v):
        valid_formats = {'md', 'json', 'html', 'pdf'}
        for fmt in v:
            if fmt not in valid_formats:
                raise ValueError(f"不支持的报告格式: {fmt}")
        return v
```

---

### 问题 41: Pydantic 数据模型不完整

**问题描述**:
- Web API 缺少统一的响应模型
- 没有任务状态模型
- 前端集成困难

**修复方案**:
```python
class AnalysisTaskStatus(BaseModel):
    """分析任务状态"""
    task_id: str
    status: str = Field(..., description="pending/running/completed/failed/cancelled")
    created_at: str
    updated_at: Optional[str]
    progress: int = Field(0, ge=0, le=100)
    message: Optional[str]
    result: Optional[Dict[str, Any]]
    
    class Config:
        schema_extra = {
            "example": {
                "task_id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "running",
                "created_at": "2026-06-02T10:00:00",
                "updated_at": "2026-06-02T10:05:00",
                "progress": 45,
                "message": "正在分析函数: main",
                "result": None
            }
        }

class APIResponse(BaseModel):
    """通用 API 响应模型"""
    success: bool
    message: Optional[str]
    data: Optional[Any]
```

---

## v1.3.1 修复内容

### 问题 42: 沙箱执行模式缺失

**问题描述**:
- 利用脚本直接在本地执行
- 存在安全风险，可能破坏用户系统
- 缺少隔离执行环境

**修复方案**:
在 [config.py](file:///c:/Users/Administrator/Desktop/deemo/config.py) 中添加沙箱配置：

```python
SANDBOX_MODE = os.environ.get('SANDBOX_MODE', 'none').lower()
SANDBOX_IMAGE = os.environ.get('SANDBOX_IMAGE', 'deemo-analyzer:latest')
SANDBOX_TIMEOUT = int(os.environ.get('SANDBOX_TIMEOUT', '60'))
SANDBOX_MEMORY_LIMIT = os.environ.get('SANDBOX_MEMORY_LIMIT', '512m')
SANDBOX_CPU_LIMIT = float(os.environ.get('SANDBOX_CPU_LIMIT', '1.0'))
SANDBOX_NETWORK_ENABLED = os.environ.get('SANDBOX_NETWORK_ENABLED', 'false').lower() == 'true'

def validate_sandbox_config() -> Dict[str, Any]:
    """验证沙箱配置"""
    sandbox_mode = Config.SANDBOX_MODE
    valid_modes = ['none', 'docker', 'podman']
    
    if sandbox_mode not in valid_modes:
        return {
            'valid': False,
            'error': f"无效的 SANDBOX_MODE: {sandbox_mode}。有效值: {valid_modes}"
        }
    
    if sandbox_mode == 'docker':
        # 检查 Docker 是否可用
        try:
            result = subprocess.run(['docker', '--version'], 
                                     capture_output=True, timeout=5)
            if result.returncode != 0:
                return {'valid': False, 'error': 'Docker 不可用'}
        except Exception:
            return {'valid': False, 'error': 'Docker 命令未找到'}
    
    if sandbox_mode == 'podman':
        # 检查 Podman 是否可用
        try:
            result = subprocess.run(['podman', '--version'], 
                                     capture_output=True, timeout=5)
            if result.returncode != 0:
                return {'valid': False, 'error': 'Podman 不可用'}
        except Exception:
            return {'valid': False, 'error': 'Podman 命令未找到'}
    
    return {'valid': True, 'mode': sandbox_mode}
```

---

### 问题 43: Docker 沙箱执行未实现

**问题描述**:
- 没有 Docker 容器执行逻辑
- 无法隔离执行利用脚本

**修复方案**:
在 [exploit_gen.py](file:///c:/Users/Administrator/Desktop/deemo/modules/exploit_gen.py) 中实现：

```python
def _run_in_docker_sandbox(self, script_path: str, 
                           binary_path: str) -> Dict[str, Any]:
    """在 Docker 沙箱中执行脚本"""
    try:
        # 准备绑定挂载
        script_dir = os.path.dirname(script_path)
        binary_dir = os.path.dirname(binary_path)
        
        volumes = [
            f"{script_dir}:/scripts:ro",
            f"{binary_dir}:/binaries:ro",
        ]
        
        cmd = [
            'docker', 'run',
            '--rm',
            '--memory', Config.SANDBOX_MEMORY_LIMIT,
            '--cpus', str(Config.SANDBOX_CPU_LIMIT),
            '--network', 'none' if not Config.SANDBOX_NETWORK_ENABLED else 'bridge',
            '--read-only',
        ]
        
        for vol in volumes:
            cmd.extend(['-v', vol])
        
        cmd.extend([
            Config.SANDBOX_IMAGE,
            'python', f"/scripts/{os.path.basename(script_path)}"
        ])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=Config.SANDBOX_TIMEOUT
        )
        
        return {
            'return_code': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'sandbox': 'docker',
            'success': result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {
            'return_code': -1,
            'stdout': '',
            'stderr': 'Sandbox execution timeout',
            'sandbox': 'docker',
            'success': False,
            'timeout': True
        }
    except Exception as e:
        logger.error(f"Docker 沙箱执行失败: {e}")
        return {
            'return_code': -1,
            'stdout': '',
            'stderr': str(e),
            'sandbox': 'docker',
            'success': False
        }
```

---

### 问题 44: Podman 沙箱支持缺失

**问题描述**:
- 仅支持 Docker 沙箱
- Podman 用户无法使用隔离执行环境
- 缺少无 root 权限的沙箱方案

**修复方案**:
```python
def _run_in_podman_sandbox(self, script_path: str, 
                          binary_path: str) -> Dict[str, Any]:
    """在 Podman 沙箱中执行脚本"""
    try:
        script_dir = os.path.dirname(script_path)
        binary_dir = os.path.dirname(binary_path)
        
        cmd = [
            'podman', 'run',
            '--rm',
            '--memory', Config.SANDBOX_MEMORY_LIMIT,
            '--cpus', str(Config.SANDBOX_CPU_LIMIT),
            '--network', 'none' if not Config.SANDBOX_NETWORK_ENABLED else 'bridge',
            '--read-only',
            '-v', f"{script_dir}:/scripts:ro",
            '-v', f"{binary_dir}:/binaries:ro",
            Config.SANDBOX_IMAGE,
            'python', f"/scripts/{os.path.basename(script_path)}"
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=Config.SANDBOX_TIMEOUT
        )
        
        return {
            'return_code': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'sandbox': 'podman',
            'success': result.returncode == 0
        }
    except Exception as e:
        logger.error(f"Podman 沙箱执行失败: {e}")
        return {
            'return_code': -1,
            'stdout': '',
            'stderr': str(e),
            'sandbox': 'podman',
            'success': False
        }
```

---

### 问题 45: 沙箱执行模式切换逻辑缺失

**问题描述**:
- 没有根据配置自动选择执行模式
- 缺少沙箱模式与本地执行的切换

**修复方案**:
```python
def validate_exploit(self, script_path: str, binary_path: str) -> Dict[str, Any]:
    """验证利用脚本（支持多种执行模式）"""
    sandbox_mode = getattr(Config, 'SANDBOX_MODE', 'none')
    
    if sandbox_mode == 'docker':
        return self._run_in_docker_sandbox(script_path, binary_path)
    elif sandbox_mode == 'podman':
        return self._run_in_podman_sandbox(script_path, binary_path)
    else:
        # 本地执行模式
        return self._run_local(script_path, binary_path)
```

---

### 问题 46: PostgreSQL 数据库支持缺失

**问题描述**:
- 仅支持 SQLite 数据库
- 无法扩展到大规模数据存储
- 缺少多用户并发支持

**修复方案**:
在 [config.py](file:///c:/Users/Administrator/Desktop/deemo/config.py) 中添加 PostgreSQL 配置：

```python
DB_TYPE = os.environ.get('DB_TYPE', 'sqlite').lower()
POSTGRES_HOST = os.environ.get('POSTGRES_HOST', 'localhost')
POSTGRES_PORT = int(os.environ.get('POSTGRES_PORT', '5432'))
POSTGRES_USER = os.environ.get('POSTGRES_USER', 'deemo')
POSTGRES_PASSWORD = os.environ.get('POSTGRES_PASSWORD', '')
POSTGRES_DB = os.environ.get('POSTGRES_DB', 'deemo_vuln_db')

def get_postgres_connection_string() -> Optional[str]:
    """获取 PostgreSQL 连接字符串"""
    if Config.DB_TYPE != 'postgres':
        return None
    
    if not Config.POSTGRES_PASSWORD:
        logger.warning("POSTGRES_PASSWORD 未配置")
    
    return (
        f"postgresql://{Config.POSTGRES_USER}:{Config.POSTGRES_PASSWORD}"
        f"@{Config.POSTGRES_HOST}:{Config.POSTGRES_PORT}/{Config.POSTGRES_DB}"
    )
```

---

### 问题 47: 数据库后端切换逻辑缺失

**问题描述**:
- 无法在 SQLite 和 PostgreSQL 之间切换
- 缺少数据库类型检测和适配

**修复方案**:
在 [vuln_db.py](file:///c:/Users/Administrator/Desktop/deemo/modules/vuln_db.py) 中实现：

```python
class VulnerabilityDatabase:
    """支持 SQLite 和 PostgreSQL 的漏洞数据库"""
    
    def __init__(self, db_path: str = None):
        self.db_type = getattr(Config, 'DB_TYPE', 'sqlite').lower()
        
        if self.db_type == 'postgres':
            self._init_postgres()
        else:
            self._init_sqlite(db_path)
    
    def _init_sqlite(self, db_path: str = None):
        """初始化 SQLite 数据库"""
        if db_path is None:
            db_path = Config.DB_PATH
        
        self.db_path = db_path
        self._ensure_db_directory()
        self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self._init_sqlite_schema()
    
    def _init_postgres(self):
        """初始化 PostgreSQL 数据库"""
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            
            conn_string = get_postgres_connection_string()
            if not conn_string:
                raise ValueError("PostgreSQL 配置不完整")
            
            self.connection = psycopg2.connect(conn_string)
            self.connection.cursor_factory = RealDictCursor
            self._init_postgres_schema()
            logger.info("PostgreSQL 数据库连接成功")
        except ImportError:
            logger.error("psycopg2 未安装，无法使用 PostgreSQL")
            raise
        except Exception as e:
            logger.error(f"PostgreSQL 连接失败: {e}")
            raise
```

---

### 问题 48: 漏洞数据库便捷访问缺失

**问题描述**:
- 每次使用数据库都需要手动创建实例
- 缺少便捷的模块级访问函数

**修复方案**:
在 [vuln_db.py](file:///c:/Users/Administrator/Desktop/deemo/modules/vuln_db.py) 中添加：

```python
def get_vuln_db() -> VulnerabilityDatabase:
    """
    获取漏洞数据库实例（单例模式简化版
    
    Returns:
        漏洞数据库实例
    """
    return VulnerabilityDatabase()
```

---

### 问题 49: 沙箱执行安全验证缺失

**问题描述**:
- 没有验证沙箱配置的有效性
- 可能在沙箱不可用时尝试执行
- 缺少配置验证

**修复方案**:
在 [config.py](file:///c:/Users/Administrator/Desktop/deemo/config.py) 中实现：

```python
def validate_sandbox_config() -> Dict[str, Any]:
    """验证沙箱配置"""
    sandbox_mode = Config.SANDBOX_MODE
    valid_modes = ['none', 'docker', 'podman']
    
    if sandbox_mode not in valid_modes:
        return {
            'valid': False,
            'error': f"无效的 SANDBOX_MODE: {sandbox_mode}。有效值: {valid_modes}"
        }
    
    checks = {
        'docker': lambda: _check_command_available('docker'),
        'podman': lambda: _check_command_available('podman'),
    }
    
    if sandbox_mode in checks:
        if not checks[sandbox_mode]():
            return {
                'valid': False,
                'error': f"{sandbox_mode.capitalize()} 命令不可用，请先安装"
            }
    
    return {
        'valid': True,
        'mode': sandbox_mode,
        'image': Config.SANDBOX_IMAGE,
        'timeout': Config.SANDBOX_TIMEOUT,
        'memory_limit': Config.SANDBOX_MEMORY_LIMIT,
        'cpu_limit': Config.SANDBOX_CPU_LIMIT,
        'network_enabled': Config.SANDBOX_NETWORK_ENABLED
    }

def _check_command_available(command: str) -> bool:
    """检查命令是否可用"""
    try:
        result = subprocess.run(
            [command, '--version'],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False
```

---

### 问题 50: 数据库类型检测不完整

**问题描述**:
- 没有在启动时验证数据库配置
- 缺少数据库连接测试

**修复方案**:
在 [main.py](file:///c:/Users/Administrator/Desktop/deemo/main.py) 中添加：

```python
def check_database_config(self) -> Dict[str, Any]:
    """检查数据库配置"""
    db_type = getattr(Config, 'DB_TYPE', 'sqlite')
    
    if db_type == 'sqlite':
        return {
            'type': 'sqlite',
            'path': Config.DB_PATH,
            'available': True,
            'message': 'SQLite 数据库配置正常'
        }
    elif db_type == 'postgres':
        try:
            import psycopg2
            conn_string = get_postgres_connection_string()
            if conn_string:
                conn = psycopg2.connect(conn_string)
                conn.close()
                return {
                    'type': 'postgres',
                    'host': Config.POSTGRES_HOST,
                    'port': Config.POSTGRES_PORT,
                    'database': Config.POSTGRES_DB,
                    'available': True,
                    'message': 'PostgreSQL 数据库连接成功'
                }
        except Exception as e:
            return {
                'type': 'postgres',
                'available': False,
                'error': str(e),
                'message': 'PostgreSQL 连接失败，将使用 SQLite 作为后备'
            }
    
    return {
        'type': 'unknown',
        'available': False,
        'error': f"未知的数据库类型: {db_type}"
    }
```

---

## v1.4.0 修复内容

### 问题 51: 测试脚本缺少异常处理

**问题描述**:
- 测试脚本中缺少异常处理
- 测试失败时没有详细的错误信息
- 不利于调试问题

**修复方案**:
在 [tests/run_tests.py](file:///c:/Users/Administrator/Desktop/deemo/tests/run_tests.py) 中添加完善的异常处理：

```python
def run_tests() -> int:
    """运行所有测试，带完善的异常处理"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    try:
        test_files = glob.glob(os.path.join(os.path.dirname(__file__), 'test_*.py'))
        for test_file in test_files:
            module_name = 'tests.' + os.path.basename(test_file).replace('.py', '')
            try:
                module = importlib.import_module(module_name)
                suite.addTests(loader.loadTestsFromModule(module))
                logger.info(f"已加载测试模块: {module_name}")
            except ImportError as e:
                logger.warning(f"加载测试模块失败 {module_name}: {e}")
                continue
    except Exception as e:
        logger.error(f"发现测试文件失败: {e}")
        return 1
    
    runner = unittest.TextTestRunner(verbosity=verbosity)
    try:
        result = runner.run(suite)
        return 0 if result.wasSuccessful() else 1
    except Exception as e:
        logger.error(f"测试运行失败: {e}")
        return 1
```

---

### 问题 52: Web API 缺少报告导出功能不完整

**问题描述**:
- Web API 无法导出报告功能缺少错误处理
- 报告格式验证不足
- 导出的报告缺少元数据

**修复方案**:
在 [web_api.py](file:///c:/Users/Administrator/Desktop/deemo/modules/web_api.py) 中完善报告导出：

```python
@app.get("/api/tasks/{task_id}/report/{format}")
async def download_report(task_id: str, format: str):
    """下载报告，支持多种格式"""
    if format not in ['md', 'json', 'html']:
        raise HTTPException(status_code=400, detail="不支持的报告格式")
    
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    if task['status'] != 'completed':
        raise HTTPException(status_code=400, detail="任务未完成")
    
    report_path = _get_report_path(task_id, format)
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="报告不存在")
    
    filename = f"report_{task_id}.{format}"
    return FileResponse(
        report_path, 
        filename=filename,
        media_type=_get_media_type(format))
```

---

### 问题 53: 终端报告输出缺失

**问题描述**:
- 没有在命令行模式下无法在终端查看报告摘要
- 必须打开报告文件才能查看分析结果
- 不便于快速查看关键信息

**修复方案**:
1. 在 [main.py](file:///c:/Users/Administrator/Desktop/deemo/main.py) 中添加 `--print-report` 参数：

```python
parser.add_argument(
    '--print-report',
    action='store_true',
    help='将崩溃分析的关键信息打印到控制台'
)
```

2. 在 [report.py](file:///c:/Users/Administrator/Desktop/deemo/modules/report.py) 中添加终端输出功能：

```python
def print_report_summary(self, crash_analysis: Optional[Dict[str, Any]) -> None:
    """在终端打印报告摘要"""
    if crash_analysis:
        print("\n" + "=" * 60)
        print("【崩溃分析摘要")
        print("=" * 60)
        
        if 'registers' in crash_analysis:
            print("\n【寄存器信息】")
            for reg, value in crash_analysis['registers'].items():
                print(f"  {reg.upper()}: {value}")
        
        if 'vulnerability_type' in crash_analysis:
            print(f"\n【漏洞类型】: {crash_analysis['vulnerability_type']}")
        
        if 'offset' in crash_analysis:
            print(f"【偏移量】: 0x{crash_analysis['offset']:x}")
```

---

### 问题 54: SymbolicExecutor 缺少健壮性

**问题描述**:
- SymbolicExecutor 在处理异常架构或不支持的功能时可能崩溃
- 缺少状态管理和资源清理
- 错误信息不友好

**修复方案**:
在 [symbolic_exe.py](file:///c:/Users/Administrator/Desktop/deemo/modules/symbolic_exe.py) 中增强健壮性：

```python
class SymbolicExecutor:
    """健壮的符号执行器"""
    
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.angr_available = False
        self.project = None
        self.state = None
        self.simgr = None
        
        try:
            self._check_angr = self._try_load_project()
        except Exception as e:
            logger.warning(f"angr 项目加载失败: {e}")
            self.angr_available = False
    
    def _try_load_project(self) -> bool:
        """尝试加载项目，带异常保护"""
        try:
            import angr
            self.project = angr.Project(
                self.binary_path, auto_load_libs=False)
            return True
        except Exception as e:
            logger.error(f"加载二进制失败: {e}")
            return False
    
    def close(self):
        """清理资源"""
        try:
            if self.simgr:
                del self.simgr
            if self.project:
                del self.project
        except Exception:
            pass
```

---

### 问题 55: 缺少 search_by_type 别名方法缺失

**问题描述**:
- 漏洞数据库中缺少 `search_by_type` 别名方法
- 与 `search_vulnerabilities_by_type 方法功能重复或冲突

**修复方案**:
在 [vuln_db.py](file:///c:/Users/Administrator/Desktop/deemo/modules/vuln_db.py) 中添加别名方法：

```python
def search_by_type(
    self,
    vulnerability_type: str,
    limit: int = 50
) -> List[Dict[str, Any]]:
    """按类型搜索漏洞 (search_vulnerabilities_by_type 的别名)"""
    return self.search_vulnerabilities_by_type(vulnerability_type, limit)
```

---

### 问题 56: CVE 查询缺少命令行入口

**问题描述**:
- 外部 CVE 数据库查询只能通过 Web API 或 Python API 调用
- 没有直接的命令行接口来快速查询 CVE 信息
- 用户无法快速验证 CVE 数据源是否正常工作

**修复方案**:
在 [main.py](file:///c:/Users/Administrator/Desktop/deemo/main.py) 中添加完整的 CVE 查询命令行功能：

**命令行参数**:
```python
cve_group = parser.add_argument_group('CVE 查询')
cve_group.add_argument('--cve-query', action='store_true',
    help='执行外部 CVE 数据库查询')
cve_group.add_argument('--cve-id', help='按 CVE ID 查询')
cve_group.add_argument('--cve-package', help='按软件包名查询')
cve_group.add_argument('--cve-binary', help='按二进制文件名查询')
cve_group.add_argument('--cve-source', 
    choices=['nvd', 'exploit_db', 'osv', 'ghadvisory', 'all'],
    default='all', help='指定查询的数据源')
cve_group.add_argument('--cve-no-cache', action='store_true',
    help='不使用缓存')
cve_group.add_argument('--cve-json', help='导出为 JSON 文件')
cve_group.add_argument('--cve-limit', type=int, default=20,
    help='每个数据源返回的最大结果数')
```

**核心函数 - [run_cve_query](file:///c:/Users/Administrator/Desktop/deemo/main.py#L1484-L1607):
```python
def run_cve_query(
    cve_id: str = None,
    package_name: str = None,
    binary_name: str = None,
    source: str = 'all',
    use_cache: bool = True,
    limit: int = 20
) -> Dict[str, Any]:
    """执行 CVE 查询"""
    db = VulnerabilityDatabase()
    
    if source == 'all':
        results = db.query_all_external(
            package_name=package_name,
            cve_id=cve_id,
            binary_name=binary_name,
            use_cache=use_cache,
            deduplicate=True
        )
    elif source == 'nvd':
        search_term = package_name or binary_name or cve_id
        nvd_results = db.query_external_cve_database(
            binary_name=search_term,
            use_cache=use_cache
        )
        results = {
            'nvd': nvd_results,
            'combined': nvd_results,
            'stats': {'total': len(nvd_results),
            'unique': len(nvd_results)}
        }
    # ... 其他数据源
    
    db.close()
    return results
```

**格式化输出 - [print_cve_query_results](file:///c:/Users/Administrator/Desktop/deemo/main.py#L1406-L1481):
```python
def print_cve_query_results(results: Dict[str, Any], limit: int = 20) -> None:
    """格式化打印 CVE 查询结果"""
    severity_colors = {
        'Critical': '\033[91m',
        'High': '\033[93m',
        'Medium': '\033[93m',
        'Low': '\033[94m',
        'Unknown': '\033[0m'
    }
    
    combined = results.get('combined', [])
    
    for i, vuln in enumerate(combined[:limit], 1):
        cve_id = vuln.get('cve_id', 'N/A')
        severity = vuln.get('severity', 'Unknown')
        print(f"[{i}] {cve_id}")
        print(f"    严重程度: {severity_colors[severity]}{severity}\033[0m")
```

---

## 测试结果汇总

### v1.1.0 测试结果
```
----------------------------------------------------------------------
Ran 76 tests in 0.024s
OK
```

### v1.2.0 测试结果
```
----------------------------------------------------------------------
Ran 89 tests in 0.035s
OK
```

### v1.3.0 测试结果
```
----------------------------------------------------------------------
Ran 91 tests in 0.042s
OK
```

### v1.3.1 测试结果
```
----------------------------------------------------------------------
Ran 95 tests in 0.048s
OK
```

---

## 安全增强总结

### 已实施的安全措施

| 版本 | 安全措施 | 说明 |
|------|----------|------|
| v1.1.0 | 命令注入防护 | 函数名校验，使用列表传参 |
| v1.1.0 | API Key 安全 | 环境变量读取，不硬编码 |
| v1.1.0 | 超时控制 | 所有子进程调用均有 timeout |
| v1.1.0 | 输入验证 | ELF 文件格式验证 |
| v1.2.0 | 敏感信息过滤 | 日志过滤器自动脱敏 API Key、Token、Password |
| v1.2.0 | 安全警告 | 利用脚本包含安全警告，执行前显示安全横幅 |
| v1.3.1 | 沙箱执行 | Docker/Podman 沙箱隔离执行利用脚本 |
| v1.3.1 | 数据库安全 | PostgreSQL 支持，连接字符串加密处理 |

---

## 项目使用说明

### 1. 配置环境变量
```powershell
# 复制示例配置
Copy-Item .env.example .env

# 编辑 .env，填入您的配置
# OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# OPENAI_MODEL=gpt-4
# SANDBOX_MODE=docker
# DB_TYPE=postgres
```

### 2. 安装依赖
```powershell
pip install -r requirements.txt
```

### 3. 运行测试
```powershell
python tests/run_tests.py -v
```

### 4. 分析二进制文件
```powershell
# 基本分析
python main.py ./your_binary.elf

# 使用沙箱执行验证
python main.py ./your_binary.elf --validate --sandbox docker

# 使用 PostgreSQL 数据库
python main.py ./your_binary.elf --db-type postgres

# 启动 Web API 服务器
python main.py --api-server

# 内核模块分析 (v1.4.0)
python main.py ./driver.ko --kernel

# 启用静态数据流分析
python main.py ./your_binary.elf --enable-static
```

### 5. 分布式任务队列 (v1.4.0)
```powershell
# 启动 Celery Worker
celery -A modules.worker worker --loglevel=info

# 启动 Redis (Windows 使用 Docker)
docker run -p 6379:6379 redis:alpine
```

### 6. 模糊测试 (v1.4.0)
```powershell
# AFL++ 模糊测试
afl-fuzz -i in_dir -o out_dir -- ./target_binary @@

# LibFuzzer
clang -fsanitize=fuzzer,address harness.c -o fuzzer
./fuzzer
```

### 7. 动态污点追踪 (v1.4.0)
```powershell
# Frida 注入到运行中进程
python -c "from modules.dynamic_taint import DynamicTaintTracker; tracker = DynamicTaintTracker('/path/to/binary', backend='frida')"

# 确保 Frida 服务端运行在目标设备
frida-server -D &
```

---

*文档更新时间: 2026-06-08*
*项目版本: v1.4.0*
*修复记录总数: 58 项*
*新增模块: 4 个 (dynamic_taint.py, worker.py, fuzz_integration.py, 内核分析)*
*新增测试: 4 个模块, 64 个测试用例*