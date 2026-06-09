# Deemo - 大语言模型辅助的二进制漏洞分析工具

---

## 一、项目概述

### 1.1 项目简介

**Deemo** 是一个基于大语言模型的智能二进制漏洞分析工具，版本 v1.3.1。该工具旨在自动化二进制文件的漏洞分析流程，结合了传统的二进制分析技术和现代AI模型的能力，为安全研究人员提供高效、智能化的漏洞发现和利用辅助。

### 1.2 核心功能特性

| 功能模块 | 描述 | 版本引入 |
|----------|------|----------|
| **多平台支持** | 支持 ELF (Linux)、PE (Windows)、Mach-O (macOS) 三种主流二进制格式 | v1.1.0 |
| **多反编译引擎** | 自动检测并使用 radare2、Ghidra、IDA Pro、Binary Ninja、Hopper 进行反编译 | v1.2.0 |
| **多 AI 提供商** | 集成 OpenAI、Azure OpenAI、Ollama、llama.cpp、Custom API 等多种 AI 提供商 | v1.2.0 |
| **多架构 ROP** | 支持 x86/x64/ARM/ARM64/MIPS/RISC-V 的 ROP 链构建和利用生成 | v1.2.0 |
| **符号执行** | 基于 angr 的自动漏洞发现和利用分析，支持多架构 | v1.2.0 |
| **静态数据流分析** | Use-Def 链分析、整数溢出检测、格式化字符串检测、未初始化内存检测、污点分析 | v1.3.0 |
| **Web API 服务** | FastAPI REST API，支持异步任务管理、文件上传、报告下载 | v1.3.0 |
| **漏洞数据库** | 支持 SQLite 和 PostgreSQL 双后端，向量存储和语义搜索（FAISS 加速） | v1.2.0 / v1.3.1 |
| **沙箱执行** | 支持 Docker/Podman 沙箱隔离执行利用脚本，提高安全性 | v1.3.1 |
| **CVSS 评分** | 自动计算 CVSS 3.1 漏洞严重程度评分，生成向量字符串 | v1.4.0 |
| **Ghidra 集成** | 生成可在 Ghidra 中运行的标注脚本，自动标记漏洞位置 | v1.4.0 |
| **可视化图表** | vis.js 函数调用图和控制流图可视化 | v1.4.0 |
| **自动化利用** | 基于漏洞信息自动生成 pwntools 利用脚本，支持 one_gadget 和 libc 检测 | v1.2.0 |
| **多格式报告** | 生成 Markdown、JSON、HTML、PDF 格式的分析报告 | v1.2.0 |
| **插件系统** | 可扩展的钩子系统，支持自定义插件 | v1.2.0 |
| **并行分析** | 支持多线程并行函数分析 | v1.2.0 |
| **交互式模式** | 交互式分析菜单，支持动态探索 | v1.2.0 |
| **健康检查** | 系统依赖和配置的全面诊断 | v1.2.0 |
| **安全增强** | 敏感信息日志过滤，防止 API Key 泄露 | v1.2.0 |
| **外部 CVE 集成** | NVD (National Vulnerability Database)、Exploit-DB 查询 | v1.2.0 |

### 1.3 技术栈

| 技术/库 | 用途 | 版本要求 | 类型 |
|---------|------|----------|------|
| **Python 3** | 主开发语言 | 3.8+ | 必需 |
| **pwntools** | ELF 文件解析、漏洞利用辅助 | >= 4.10.0 | 必需 |
| **radare2** | 二进制反编译 | 任何版本 | 必需 |
| **openai** | 大语言模型 API 调用 | >= 1.0.0 | 必需 |
| **angr** | 符号执行引擎 | 任何版本 | 可选 |
| **fastapi** | Web API 框架 | 任何版本 | 可选 |
| **uvicorn** | ASGI 服务器 | 任何版本 | 可选 |
| **numpy** | 向量运算 | 任何版本 | 可选 |
| **faiss** | 向量相似度搜索加速 | 任何版本 | 可选 |
| **docker** | Docker 沙箱 | 任何版本 | 可选 |
| **podman** | Podman 沙箱 | 任何版本 | 可选 |
| **psycopg2** | PostgreSQL 驱动 | 任何版本 | 可选 |
| **pefile** | PE 文件解析 | 任何版本 | 可选 |
| **macholib** | Mach-O 文件解析 | 任何版本 | 可选 |
| **weasyprint / pdfkit** | PDF 报告生成 | 任何版本 | 可选 |

### 1.4 核心设计理念

1. **模块化架构**: 每个功能独立封装在单独的模块中，便于维护和扩展
2. **AI + 启发式双模式**: 支持 AI 智能分析和启发式规则分析两种模式，确保在无 AI 情况下也能工作
3. **闭环反馈机制**: 分析 → 生成 → 执行 → 失败 → 再分析 → 再生成的迭代优化流程
4. **安全优先**: 完善的异常处理、输入验证、命令注入防护、敏感信息脱敏
5. **可扩展性**: 插件钩子系统、多反编译引擎支持、多 AI 提供商支持
6. **跨平台**: 支持多种二进制格式和 CPU 架构

---

## 二、项目目录结构

```
deemo/
├── main.py                         # 主程序入口
├── config.py                       # 配置管理模块
├── prompts.py                      # AI Prompt 模板
├── requirements.txt                # Python 依赖列表
├── Dockerfile                      # Docker 容器化配置
├── PROJECT_OVERVIEW.md             # 项目概览 (本文档)
├── DEBUG_FIXES.md                  # 调试修复记录
├── 项目代码功能总结.md              # 详细代码功能文档
├── project_code.txt                # 代码参考文档
│
├── modules/                        # 核心功能模块
│   ├── __init__.py
│   ├── info_collect.py             # 二进制信息收集
│   ├── decomp_ai.py                # 反编译 + AI 分析
│   ├── crash_analysis.py           # 崩溃信息分析
│   ├── exploit_gen.py              # 利用脚本生成 (含多架构 ROP)
│   ├── symbolic_exe.py             # 符号执行 (angr)
│   ├── vuln_db.py                  # 漏洞数据库 (SQLite/PostgreSQL)
│   ├── report.py                   # 报告生成 (Markdown/JSON/HTML/PDF)
│   ├── hooks.py                    # 插件钩子系统
│   ├── static_analysis.py          # 静态数据流分析 (v1.3.0 新增)
│   └── web_api.py                  # Web API 服务 (v1.3.0 新增)
│
├── tests/                          # 单元测试
│   ├── __init__.py
│   ├── run_tests.py                # 测试运行器
│   ├── test_config.py              # 配置模块测试
│   ├── test_info_collect.py        # 信息收集模块测试
│   ├── test_decomp_ai.py           # 反编译分析模块测试
│   ├── test_crash_analysis.py      # 崩溃分析模块测试
│   ├── test_exploit_gen.py         # 利用生成模块测试
│   ├── test_vuln_db.py             # 数据库测试
│   └── sample_crash_data.json      # 崩溃数据示例
│
├── data/                           # 数据目录
│   ├── vulnerabilities.db          # SQLite 漏洞数据库
│   ├── cache/                      # 静态分析结果缓存
│   ├── corpus/                     # 语料库/样本数据
│   └── api_tasks/                  # Web API 任务存储
│
├── logs/                           # 日志目录
├── reports/                        # 报告输出目录
├── exploits/                       # 利用脚本输出目录
└── hooks/                          # 用户插件目录 (自动创建)
    └── example_hook.py             # 示例钩子脚本
```

---

## 三、核心模块详解

### 3.1 主程序入口 - [main.py](file:///c:/Users/Administrator/Desktop/deemo/main.py)

#### 3.1.1 功能描述

主程序负责：
- 命令行参数解析
- 日志配置（控制台 + 文件双重输出 + 敏感信息过滤）
- 依赖检查（radare2、pwntools、openai、angr、pefile、macholib）
- 分析流程编排（Pipeline）
- 并行函数分析（ThreadPoolExecutor）
- 插件钩子集成
- 交互式分析模式
- 健康检查（Doctor Mode）

#### 3.1.2 核心函数

| 函数名 | 功能 | 行号 |
|--------|------|------|
| `setup_logging()` | 配置日志系统，输出到控制台和 `logs/` 目录，启用敏感信息过滤 | [L30-L54](file:///c:/Users/Administrator/Desktop/deemo/main.py#L30-L54) |
| `check_dependencies()` | 检查所有依赖是否安装，提供友好提示 | [L56-L134](file:///c:/Users/Administrator/Desktop/deemo/main.py#L56-L134) |
| `get_function_symbols_from_radare2()` | 使用 radare2 获取函数符号信息 | [L137-L213](file:///c:/Users/Administrator/Desktop/deemo/main.py#L137-L213) |
| `is_library_function()` | 判断是否为库函数 | - |
| `filter_user_functions()` | 过滤用户函数，排除库函数 | - |
| `_analyze_single_function()` | 单个函数分析（用于并行） | - |
| `analyze_functions()` | 选择并分析目标函数，支持并行 | - |
| `find_highest_risk_vulnerability()` | 从分析结果中找到最高风险的漏洞 | - |
| `print_analysis_summary()` | 打印分析摘要 | - |
| `run_interactive_menu()` | 交互式分析菜单 | - |
| `run_health_check()` | 运行健康检查（Doctor Mode） | - |
| `run_pipeline()` | 运行完整的 6 步分析流水线 | - |

#### 3.1.3 完整分析流水线

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      分析流水线 (Analysis Pipeline)                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  步骤 0: 健康检查 (可选)                                                         │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  run_health_check()                                                    │   │
│  │  - 依赖检测 (radare2, pwntools, openai, angr)                          │   │
│  │  - AI 配置验证 (API Key, Base URL, Model)                              │   │
│  │  - 反编译引擎检测                                                       │   │
│  │  - 系统工具检测 (r2, docker, podman)                                    │   │
│  │  - 二进制分析能力检测 (ELF/PE/Mach-O)                                   │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                              ↓                                                  │
│  步骤 1: 信息收集                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  modules/info_collect.py: get_binary_info()                             │   │
│  │  - pre_info_collect 钩子 → 执行前                                         │   │
│  │  │                                                                       │   │
│  │  │  ELF 验证 (ELF magic check)                                           │   │
│  │  │  PE 验证 (PE header check)                                            │   │
│  │  │  Mach-O 验证 (Mach-O magic check)                                     │   │
│  │  │                                                                       │   │
│  │  │  checksec (NX/PIE/RELRO/Canary/ASLR)                                 │   │
│  │  │  危险函数识别 (gets, strcpy, system, execve, 等)                     │   │
│  │  │  关键字符串提取 (system, bin/sh, flag, password)                      │   │
│  │  │  符号表分析 (导入/导出符号)                                           │   │
│  │  │  架构/位数/字节序检测                                                 │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                              ↓                                                  │
│  步骤 2: 反编译 + AI 漏洞分析                                                   │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  modules/decomp_ai.py: DecompilerAI                                    │   │
│  │  - pre_decompile 钩子 → 执行前                                          │   │
│  │  │                                                                       │   │
│  │  │  函数列表获取 (过滤 libc 启动函数)                                     │   │
│  │  │  反编译引擎选择 (radare2/Ghidra/IDA/Binary Ninja/Hopper)              │   │
│  │  │  函数名校验 (命令注入防护)                                             │   │
│  │  │                                                                       │   │
│  │  │  AI 智能分析 或 启发式规则分析                                       │   │
│  │  │  │  AI 模式: 发送伪代码给 LLM 进行漏洞分析                             │   │
│  │  │  │  启发式模式: 危险函数检测、风险评估                                │   │
│  │  │                                                                       │   │
│  │  │  AI 响应容错解析 (JSON 提取、字段缺失处理)                            │   │
│  │  │  结果缓存 (避免重复分析)                                               │   │
│  │  │                                                                       │   │
│  │  │  - post_decompile 钩子 → 执行后                                       │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                              ↓                                                  │
│  步骤 3: 静态数据流分析 (可选)                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  modules/static_analysis.py: StaticDataFlowAnalyzer                     │   │
│  │  - Use-Def 链分析 (angr VariableRecoveryFast)                          │   │
│  │  - 整数溢出检测 (add/sub/mul/imul/shl/sal)                             │   │
│  │  - 格式化字符串漏洞检测                                                 │   │
│  │  - 未初始化内存使用检测                                                 │   │
│  │  - 静态污点分析 (输入源 → 危险汇点)                                     │   │
│  │  - 结果缓存 (MD5 哈希标识)                                              │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                              ↓                                                  │
│  步骤 4: 符号执行 (可选)                                                        │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  modules/symbolic_exe.py: SymbolicExecutor                              │   │
│  │  - 自动探索危险函数 (gets, strcpy, scanf, 等)                           │   │
│  │  - 多架构支持 (x86/x64/ARM/ARM64/MIPS/RISC-V/PPC)                      │   │
│  │  - 污点分析 (angr taint analysis)                                       │   │
│  │  - 可视化支持 (angr-explorer)                                           │   │
│  │  - 崩溃路径发现和利用辅助                                                │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                              ↓                                                  │
│  步骤 5: 崩溃信息分析 (可选)                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  modules/crash_analysis.py: CrashAnalyzer                               │   │
│  │  - pre_crash_analysis 钩子 → 执行前                                     │   │
│  │  │                                                                       │   │
│  │  │  寄存器解析 (兼容多种格式)                                            │   │
│  │  │  栈回溯分析                                                           │   │
│  │  │  信号类型分析 (SIGSEGV, SIGABRT, 等)                                  │   │
│  │  │                                                                       │   │
│  │  │  启发式漏洞类型判断                                                   │   │
│  │  │  │  RIP 控制检测 → 栈溢出                                             │   │
│  │  │  │  Canary 失败检测 → Canary 绕过                                    │   │
│  │  │  │  格式化字符串检测 → Format String                                 │   │
│  │  │  │  Double Free 检测 → Use-After-Free                               │   │
│  │  │                                                                       │   │
│  │  │  AI 辅助深度分析                                                     │   │
│  │  │                                                                       │   │
│  │  │  - post_crash_analysis 钩子 → 执行后                                 │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                              ↓                                                  │
│  步骤 6: 利用脚本生成与验证 (可选)                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  modules/exploit_gen.py: ExploitGenerator + ROPChainBuilder             │   │
│  │  - pre_exploit_generate 钩子 → 执行前                                   │   │
│  │  │                                                                       │   │
│  │  │  漏洞类型模板生成 (栈溢出/格式化字符串/堆/通用)                        │   │
│  │  │  ROP 链构建 (多架构支持)                                              │   │
│  │  │  │  x86/x64: pop_rdi, pop_rsi, syscall                               │   │
│  │  │  │  ARM: bx_lr, pop_r0_pc, svc                                      │   │
│  │  │  │  MIPS: jr_ra, lw_ra_sp                                            │   │
│  │  │  │  RISC-V: jalr_ra, lw_ra_sp                                        │   │
│  │  │                                                                       │   │
│  │  │  AI 智能生成                                                         │   │
│  │  │  迭代优化 (最多 5 次)                                                │   │
│  │  │  去重检测 (防止重复脚本浪费迭代)                                     │   │
│  │  │  one_gadget 支持                                                     │   │
│  │  │  libc 版本自动检测                                                   │   │
│  │  │                                                                       │   │
│  │  │  沙箱执行验证 (Docker/Podman)                                        │   │
│  │  │  stderr 收集 (用于反馈迭代)                                          │   │
│  │  │  安全警告添加                                                         │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                              ↓                                                  │
│  步骤 7: 漏洞数据库存储 (可选)                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  modules/vuln_db.py: VulnerabilityDatabase                              │   │
│  │  - 存储成功的漏洞分析结果和利用脚本                                      │   │
│  │  - 向量存储和语义搜索 (numpy + FAISS)                                   │   │
│  │  - 相似性搜索 (余弦相似度、Jaccard 相似度)                               │   │
│  │  - 危险函数组合评分                                                     │   │
│  │  - 外部 CVE 查询 (NVD, Exploit-DB)                                      │   │
│  │  - 导出/导入知识库                                                      │   │
│  │  - SQLite/PostgreSQL 双后端支持                                         │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                              ↓                                                  │
│  步骤 8: 报告生成                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  modules/report.py: ReportGenerator                                     │   │
│  │  - post_report 钩子 → 执行前                                            │   │
│  │  │                                                                       │   │
│  │  │  Markdown 报告 (人类可读)                                            │   │
│  │  │  JSON 报告 (机器可读)                                                 │   │
│  │  │  HTML 报告 (现代化 UI、统计卡片、代码高亮)                           │   │
│  │  │  PDF 报告 (weasyprint/pdfkit 双后端)                                 │   │
│  │  │                                                                       │   │
│  │  │  分析步骤记录 (时间戳、数据)                                          │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

#### 3.1.4 命令行参数

| 参数 | 类型 | 说明 |
|------|------|------|
| `binary` | 必填 | 要分析的二进制文件路径 |
| `-f, --functions` | 可选 | 指定要分析的函数名列表 |
| `--crash` | 可选 | 崩溃数据 JSON 文件路径 |
| `--crash-format` | 可选 | 崩溃数据格式 (auto/json/gdb/asan) |
| `--validate` | 开关 | 验证生成的利用脚本 |
| `--no-ai` | 开关 | 禁用 AI 分析，仅使用启发式方法 |
| `--no-exec` | 开关 | 仅生成脚本，不执行验证 |
| `-o, --output` | 可选 | 报告输出目录 (默认: ./reports) |
| `-l, --log-level` | 可选 | 日志级别 (DEBUG/INFO/WARNING/ERROR/CRITICAL) |
| `--skip-deps-check` | 开关 | 跳过依赖检查 |
| `--health` | 开关 | 仅运行健康检查 |
| `--interactive` | 开关 | 启用交互式分析模式 |
| `--parallel` | 开关 | 启用并行函数分析 |
| `--max-parallel` | 可选 | 最大并行数 (默认: 4) |
| `--include-lib` | 开关 | 分析时包含库函数 |
| `--decompiler` | 可选 | 指定反编译引擎 (auto/radare2/ghidra/ida/binaryninja/hopper) |
| `--enable-symbolic` | 开关 | 启用符号执行 |
| `--enable-static` | 开关 | 启用静态数据流分析 |
| `--plugin` | 可选 | 加载自定义插件脚本 |
| `--sandbox` | 可选 | 沙箱执行模式 (none/docker/podman) |
| `--db-type` | 可选 | 数据库类型 (sqlite/postgres) |
| `--api-server` | 开关 | 启动 Web API 服务器 |
| `--api-host` | 可选 | API 服务器主机 (默认: 0.0.0.0) |
| `--api-port` | 可选 | API 服务器端口 (默认: 8000) |

---

### 3.2 配置管理 - [config.py](file:///c:/Users/Administrator/Desktop/deemo/config.py)

#### 3.2.1 功能描述

集中管理项目配置，包括：
- 环境变量读取
- API Key 验证和脱敏
- 目录管理
- 崩溃数据格式验证
- 多 AI 提供商支持
- 沙箱配置
- 数据库配置
- API 配置
- Fuzzer 配置

#### 3.2.2 配置项

**AI 提供商配置:**

| 配置项 | 环境变量 | 默认值 | 说明 |
|--------|----------|--------|------|
| `AI_PROVIDER` | `AI_PROVIDER` | 'openai' | AI 提供商 (openai/azure/ollama/llamacpp/custom) |
| `OPENAI_API_KEY` | `OPENAI_API_KEY` | '' | OpenAI API 密钥 |
| `OPENAI_MODEL` | `OPENAI_MODEL` | 'gpt-4' | 使用的模型 |
| `OPENAI_BASE_URL` | `OPENAI_BASE_URL` | None | API 端点 URL |
| `AZURE_OPENAI_API_KEY` | `AZURE_OPENAI_API_KEY` | '' | Azure API 密钥 |
| `AZURE_OPENAI_ENDPOINT` | `AZURE_OPENAI_ENDPOINT` | '' | Azure 端点 |
| `OLLAMA_HOST` | `OLLAMA_HOST` | 'http://localhost:11434' | Ollama 主机 |
| `OLLAMA_MODEL` | `OLLAMA_MODEL` | 'llama2' | Ollama 模型 |
| `LLAMACPP_HOST` | `LLAMACPP_HOST` | 'http://localhost:8080' | llama.cpp 主机 |
| `CUSTOM_API_KEY` | `CUSTOM_API_KEY` | '' | 自定义 API 密钥 |
| `CUSTOM_BASE_URL` | `CUSTOM_BASE_URL` | '' | 自定义 API 端点 |

**目录配置:**

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `LOGS_DIR` | './logs' | 日志目录 |
| `REPORTS_DIR` | './reports' | 报告目录 |
| `EXPLOITS_DIR` | './exploits' | 利用脚本目录 |
| `DB_DIR` | './data' | 数据库目录 |
| `CACHE_DIR` | './data/cache' | 缓存目录 |
| `CORPUS_DIR` | './data/corpus' | 语料库目录 |

**超时配置:**

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `MAX_ITERATIONS` | 5 | 最大迭代优化次数 |
| `SUBPROCESS_TIMEOUT` | 30 | 子进程超时 (秒) |
| `RADARE2_TIMEOUT` | 120 | radare2 反编译超时 (秒) |
| `GHIDRA_TIMEOUT` | 300 | Ghidra 超时 (秒) |
| `IDA_TIMEOUT` | 300 | IDA 超时 (秒) |
| `ANGR_TIMEOUT` | 300 | angr 超时 (秒) |

**沙箱配置 (v1.3.1 新增):**

| 配置项 | 环境变量 | 默认值 | 说明 |
|--------|----------|--------|------|
| `SANDBOX_MODE` | `SANDBOX_MODE` | 'none' | 沙箱模式 (none/docker/podman) |
| `SANDBOX_IMAGE` | `SANDBOX_IMAGE` | 'deemo-analyzer:latest' | 沙箱镜像 |
| `SANDBOX_TIMEOUT` | `SANDBOX_TIMEOUT` | 60 | 沙箱超时 (秒) |
| `SANDBOX_MEMORY_LIMIT` | `SANDBOX_MEMORY_LIMIT` | '512m' | 内存限制 |
| `SANDBOX_CPU_LIMIT` | `SANDBOX_CPU_LIMIT` | 1.0 | CPU 限制 |
| `SANDBOX_NETWORK_ENABLED` | `SANDBOX_NETWORK_ENABLED` | false | 是否启用网络 |

**数据库配置 (v1.3.1 新增):**

| 配置项 | 环境变量 | 默认值 | 说明 |
|--------|----------|--------|------|
| `DB_TYPE` | `DB_TYPE` | 'sqlite' | 数据库类型 (sqlite/postgres) |
| `POSTGRES_HOST` | `POSTGRES_HOST` | 'localhost' | PostgreSQL 主机 |
| `POSTGRES_PORT` | `POSTGRES_PORT` | 5432 | PostgreSQL 端口 |
| `POSTGRES_USER` | `POSTGRES_USER` | 'deemo' | PostgreSQL 用户 |
| `POSTGRES_PASSWORD` | `POSTGRES_PASSWORD` | '' | PostgreSQL 密码 |
| `POSTGRES_DB` | `POSTGRES_DB` | 'deemo_vuln_db' | PostgreSQL 数据库名 |

**API 配置:**

| 配置项 | 环境变量 | 默认值 | 说明 |
|--------|----------|--------|------|
| `API_HOST` | `API_HOST` | '0.0.0.0' | API 服务器主机 |
| `API_PORT` | `API_PORT` | 8000 | API 服务器端口 |
| `API_RELOAD` | `API_RELOAD` | false | 热重载模式 |

#### 3.2.3 核心函数和类

| 名称 | 类型 | 功能 |
|------|------|------|
| `SensitiveFilter` | 类 | 日志过滤器，自动脱敏敏感信息 |
| `mask_api_key()` | 函数 | API Key 脱敏，显示前后部分 |
| `mask_sensitive_data()` | 函数 | 敏感数据脱敏，适用于日志输出 |
| `check_openai_api_key()` | 函数 | 检查 OpenAI API Key 是否已配置 |
| `get_openai_client()` | 函数 | 获取 AI 客户端实例，支持多种提供商 |
| `get_current_ai_model()` | 函数 | 获取当前配置的 AI 模型名称 |
| `ensure_directories()` | 函数 | 确保所需目录存在 |
| `validate_sandbox_config()` | 函数 | 验证沙箱配置 (v1.3.1 新增) |
| `get_postgres_connection_string()` | 函数 | 获取 PostgreSQL 连接字符串 (v1.3.1 新增) |
| `validate_crash_data()` | 函数 | 验证崩溃数据格式 |
| `get_crash_data_example()` | 函数 | 获取崩溃数据示例格式 |
| `call_ai_with_retry()` | 函数 | 统一的 AI API 调用函数，包含指数退避重试 |
| `test_api_connection()` | 函数 | 测试 AI API 连接是否正常 |

#### 3.2.4 安全特性

**敏感信息脱敏:**
- API Key 脱敏：`sk-1234...abcd` → `sk-1234****abcd`
- 日志过滤器自动过滤所有日志中的敏感信息
- 支持多种模式识别（Bearer Token、环境变量格式、直接 API Key）

**AI 提供商支持:**
```
┌─────────────────────────────────────────────────────────────────┐
│                    AI 提供商支持                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│  │  OpenAI     │    │ Azure       │    │ Ollama      │        │
│  │  (云端)      │    │ OpenAI      │    │ (本地)      │        │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘        │
│         │                  │                  │                │
│         └──────────────────┼──────────────────┘                │
│                            │                                   │
│  ┌─────────────┐    ┌─────────────┐                           │
│  │ llama.cpp   │    │ Custom API  │                           │
│  │ (本地)      │    │ (兼容OpenAI) │                           │
│  └─────────────┘    └─────────────┘                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

### 3.3 二进制信息收集 - [modules/info_collect.py](file:///c:/Users/Administrator/Desktop/deemo/modules/info_collect.py)

#### 3.3.1 功能描述

使用 pwntools 加载和分析二进制文件，支持 ELF、PE、Mach-O 三种格式，收集以下信息：
- 基本信息（架构、位数、字节序）
- 保护机制（checksec）
- 导入函数（特别关注危险函数）
- 关键字符串
- 符号表
- 函数列表

#### 3.3.2 危险函数列表

```python
DANGEROUS_FUNCTIONS = [
    'gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf',
    'scanf', 'sscanf', 'fscanf', 'vscanf',
    'system', 'execve', 'execl', 'execle', 'execlp', 'execv', 'execvp',
    'popen', 'unlink', 'remove',
    'malloc', 'free', 'realloc', 'calloc'
]
```

#### 3.3.3 关键字符串模式

```python
KEY_STRING_PATTERNS = [
    'system', 'bin/sh', 'cat', '/etc/passwd', 'flag',
    'password', 'secret', 'admin', 'root',
    'sudo', 'chmod', 'chown', 'setuid', 'setgid'
]
```

#### 3.3.4 核心函数

| 函数名 | 功能 |
|--------|------|
| `validate_binary_path()` | 验证二进制路径，确保安全 |
| `detect_binary_format()` | 检测二进制格式 (ELF/PE/MACH-O) |
| `detect_pe_arch()` | 检测 PE 架构 |
| `detect_pe_bits()` | 检测 PE 位数 |
| `validate_elf_file()` | 验证文件是否为有效的 ELF 文件 |
| `load_binary()` | 加载二进制文件（延迟导入 pwntools） |
| `get_checksec()` | 获取保护机制信息 |
| `get_imported_functions()` | 获取导入函数，识别危险函数 |
| `get_key_strings_generic()` | 提取关键字符串（通用方法） |
| `get_symbols()` | 获取符号表 |
| `get_functions()` | 获取函数列表 |
| `get_binary_info()` | 收集完整的二进制信息 |
| `format_info_for_report()` | 格式化信息为 Markdown |

#### 3.3.5 异常处理覆盖

| 异常类型 | 处理方式 |
|----------|----------|
| `FileNotFoundError` | 文件不存在提示 |
| `struct.error` | ELF 结构损坏 |
| `ValueError` | ELF 解析错误 |
| `IOError` | 读取失败 |
| `ImportError` | pwntools 未安装 |
| `PermissionError` | 权限不足 |
| `Exception` | 通用异常捕获 |

---

### 3.4 反编译与 AI 分析 - [modules/decomp_ai.py](file:///c:/Users/Administrator/Desktop/deemo/modules/decomp_ai.py)

#### 3.4.1 功能描述

- 使用多种反编译引擎对指定函数进行反编译
- 调用 AI API 进行智能漏洞分析
- 当 API 不可用时，使用启发式规则进行模拟分析
- 支持插件钩子系统
- 结果缓存机制

#### 3.4.2 支持的反编译引擎

| 引擎 | 类型 | 平台 | 说明 |
|------|------|------|------|
| radare2 | 开源 | 全平台 | 默认引擎，无需额外配置 |
| Ghidra | 开源 | 全平台 | NSA 开发，功能强大 |
| IDA Pro | 商业 | Windows/Linux/macOS | 行业标准 |
| Binary Ninja | 商业 | 全平台 | 现代化界面 |
| Hopper | 商业 | macOS/Linux | macOS 下流行 |

#### 3.4.3 核心类：`DecompilerAI`

**初始化参数:**
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `binary_path` | str | 是 | 二进制文件路径 |
| `openai_client` | OpenAI | 否 | OpenAI 客户端实例 |

**核心方法:**

| 方法名 | 功能 |
|--------|------|
| `_check_radare2()` | 检查 radare2 是否可用 |
| `_check_ghidra()` | 检查 Ghidra 是否可用 |
| `_check_ida()` | 检查 IDA 是否可用 |
| `_check_binaryninja()` | 检查 Binary Ninja 是否可用 |
| `_check_hopper()` | 检查 Hopper 是否可用 |
| `decompile_with_radare2()` | 使用 radare2 反编译 |
| `decompile_with_ghidra()` | 使用 Ghidra 反编译 |
| `decompile_with_ida()` | 使用 IDA 反编译 |
| `decompile_with_binaryninja()` | 使用 Binary Ninja 反编译 |
| `decompile_with_hopper()` | 使用 Hopper 反编译 |
| `list_functions()` | 列出函数（过滤 libc 启动函数） |
| `call_openai_analysis()` | 调用 AI 进行漏洞分析 |
| `_parse_ai_response()` | 解析 AI 响应（容错处理） |
| `_simulate_analysis()` | 启发式模拟分析 |
| `analyze_function()` | 完整分析流程 |

#### 3.4.4 安全特性

**函数名清洗 (`sanitize_function_name`):**
- 过滤危险字符：`\n`, `;`, `&`, `|`, `<`, `>`, `$`, `(`, `)`, `{`, `}`, `[`, `]`
- 允许的字符：字母、数字、下划线、连字符、点
- 空值或无效值默认返回 `'main'`

**libc 函数过滤 (`list_functions`):**
- 过滤前缀：`_start`, `__libc_csu`, `__libc_start`, `_init`, `_fini`, `__gmon`, `_dl_`

**AI 响应容错 (`_parse_ai_response`):**
- 支持从 markdown 代码块中提取 JSON
- 非 JSON 响应返回默认值
- 缺少字段时使用默认值
- 完整记录原始响应便于调试

---

### 3.5 崩溃信息分析 - [modules/crash_analysis.py](file:///c:/Users/Administrator/Desktop/deemo/modules/crash_analysis.py)

#### 3.5.1 功能描述

解析程序崩溃信息，分析漏洞类型：
- 寄存器状态解析（兼容多种格式）
- 栈回溯分析
- 信号类型分析
- 启发式漏洞类型判断
- AI 辅助深度分析
- 多格式崩溃数据加载（JSON/GDB/ASAN/WinDbg/coredump）

#### 3.5.2 寄存器解析正则

支持的格式示例：

| 格式 | 示例 |
|------|------|
| 等号分隔 | `rax = 0x4141414141414141` |
| 冒号分隔 | `RAX: 0x4141414141414141` |
| 空格分隔 | `rax 0x4141414141414141` |
| GDB 格式 | `rax  0x7ffff7a04d40  140737347882304` |

#### 3.5.3 核心类：`CrashAnalyzer`

**核心方法:**

| 方法名 | 功能 |
|--------|------|
| `parse_registers_from_text()` | 从文本中解析寄存器信息 |
| `parse_crash_info()` | 解析崩溃信息 |
| `heuristic_analysis()` | 启发式漏洞类型判断 |
| `call_openai_analysis()` | AI 深度分析 |
| `analyze()` | 完整分析流程 |
| `load_and_parse_crash_data()` | 加载并解析多种格式的崩溃数据 |

#### 3.5.4 启发式规则

| 规则 | 触发条件 | 漏洞类型 | 可利用性 |
|------|----------|----------|----------|
| RIP 控制 | RIP 包含 `0x41414141` 等可控值 | 栈溢出 | High/Critical |
| Canary 失败 | 信号 SIGABRT + `stack_chk_fail` | Canary 检测失败 | Medium |
| 格式化字符串 | 输出包含 `%x`, `%p` 等 | 格式化字符串 | High |
| Double Free | 输出包含 `double free` | Double Free | High |
| Use-After-Free | 输出包含 `use-after-free` | Use-After-Free | High |
| 整数溢出 | 寄存器值异常大 | 整数溢出 | Medium |

---

### 3.6 利用脚本生成 - [modules/exploit_gen.py](file:///c:/Users/Administrator/Desktop/deemo/modules/exploit_gen.py)

#### 3.6.1 功能描述

根据漏洞类型和保护机制，生成 pwntools 利用脚本：
- 基础模板生成
- AI 智能生成
- 迭代优化（最多 5 次）
- 去重检测（防止重复脚本）
- stderr 收集（用于反馈迭代）
- 多架构 ROP 链构建
- one_gadget 支持
- libc 版本自动检测
- 沙箱执行验证

#### 3.6.2 安全警告

所有生成的脚本首行包含：
```python
# WARNING: This exploit may damage your system. Run only in isolated VM.
```

执行前显示安全横幅：
```
╔════════════════════════════════════════════════════════════════╗
║                    ⚠️  安全警告  ⚠️                             ║
╠════════════════════════════════════════════════════════════════╣
║  即将在本地执行漏洞利用脚本！                                     ║
║  建议的隔离执行方式：Docker、虚拟机、沙箱环境                     ║
╚════════════════════════════════════════════════════════════════╝
```

#### 3.6.3 支持的架构

| 架构 | 常量名 | ROP 模式 |
|------|--------|----------|
| x86 (32位) | `i386` | int 0x80, pop eax/ebx/etc |
| x64 (64位) | `amd64` | syscall, pop rdi/rsi/rdx |
| ARM (32位) | `arm` | bx lr, pop r0/pc, svc |
| ARM64 | `aarch64` | ret, ldp x0_x30, svc |
| MIPS (32位) | `mips` | jr $ra, lw $ra/sp |
| MIPS64 | `mips64` | jr $ra, ld $ra/sp |
| RISC-V (32位) | `riscv` | jalr ra, lw ra/sp |
| RISC-V64 | `riscv64` | jalr ra, ld ra/sp |

#### 3.6.4 核心类

**`ROPChainBuilder` - ROP 链构建器:**
- 多架构 gadget 模式数据库
- 自动架构检测和标准化
- libc 检测和 one_gadget 支持

**`ExploitGenerator` - 利用脚本生成器:**

| 方法名 | 功能 |
|--------|------|
| `_add_security_warning()` | 添加安全警告注释 |
| `_compute_script_hash()` | 计算脚本哈希（去重用） |
| `_is_duplicate_script()` | 检测脚本是否重复 |
| `generate_basic_exploit()` | 生成基础模板脚本 |
| `call_openai_for_exploit()` | AI 智能生成脚本 |
| `iterate_with_ai()` | AI 迭代优化 |
| `_build_failure_info()` | 构建详细失败信息（含 stderr） |
| `iterate_until_success()` | 迭代优化直到成功 |
| `validate_exploit()` | 验证脚本执行 |
| `save_script()` | 保存脚本到文件 |

#### 3.6.5 漏洞类型模板

| 漏洞类型 | 模板函数 |
|----------|----------|
| 栈溢出 | `_stack_overflow_template()` |
| 格式化字符串 | `_format_string_template()` |
| 堆漏洞 | `_heap_template()` |
| 通用漏洞 | `_generic_template()` |

#### 3.6.6 迭代优化流程

```
┌─────────────────────────────────────────────────────────────┐
│                    迭代优化流程                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │ 生成脚本    │───▶│ 验证脚本     │───▶│ 成功?        │   │
│  │ (第1次)    │    │ (沙箱执行)   │    │              │   │
│  └─────────────┘    └──────────────┘    └──────┬───────┘   │
│                                                │ 否         │
│                                                ▼            │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │ 返回成功    │◀───│ 与上一次      │◀───│ 收集 stderr  │   │
│  │             │    │ 相同?        │    │ 和 stdout     │   │
│  └─────────────┘    └──────┬───────┘    └──────────────┘   │
│                            │ 是                            │
│                            ▼                               │
│  ┌─────────────┐    ┌──────────────┐                       │
│  │ 提前退出    │    │ 发送给 AI    │                       │
│  │ (重复脚本)  │    │ 进行优化     │                       │
│  └─────────────┘    └──────────────┘                       │
│                                                             │
│  最大迭代次数: 5 次                                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

### 3.7 符号执行 - [modules/symbolic_exe.py](file:///c:/Users/Administrator/Desktop/deemo/modules/symbolic_exe.py)

#### 3.7.1 功能描述

基于 angr 的符号执行引擎，提供：
- 自动探索危险函数
- 多架构支持
- 污点分析
- 可视化支持（angr-explorer）
- 崩溃路径发现

#### 3.7.2 支持的架构

```
x86, x86_64, amd64,
arm, armel, armhf, arm64, aarch64,
mips, mipsel, mips64,
riscv32, riscv64, ppc, ppc64
```

#### 3.7.3 核心类：`SymbolicExecutor`

**核心方法:**

| 方法名 | 功能 |
|--------|------|
| `_load_project()` | 加载 angr 项目 |
| `find_dangerous_functions()` | 查找危险函数 |
| `_find_functions_calling_dangerous()` | 查找调用危险函数的函数 |
| `auto_explore_dangerous_functions()` | 自动探索危险函数 |
| `_explore_function()` | 探索特定函数 |
| `perform_taint_analysis()` | 污点分析 |

#### 3.7.4 自动探索危险函数流程

1. 识别二进制中的危险函数 (gets, strcpy, scanf 等)
2. 查找调用这些危险函数的上层函数
3. 对每个目标函数进行符号执行探索
4. 检测是否能通过用户输入触发崩溃
5. 返回崩溃信息供后续分析

---

### 3.8 静态数据流分析 - [modules/static_analysis.py](file:///c:/Users/Administrator/Desktop/deemo/modules/static_analysis.py)

#### 3.8.1 功能描述

提供基于 angr 或 radare2 ESIL 的静态数据流分析功能，无需执行程序即可检测潜在漏洞：
- Use-Def 链分析
- 整数溢出检测
- 格式化字符串漏洞检测
- 未初始化内存使用检测
- 静态污点分析
- 结果缓存机制

#### 3.8.2 数据类

| 数据类 | 说明 |
|--------|------|
| `TaintSource` | 污点源定义 (input/network/file/environment) |
| `TaintSink` | 污点汇点定义 (system/execve/printf_family 等) |
| `TaintFlow` | 污点传播路径 |
| `StaticVulnerability` | 静态检测到的漏洞 |

#### 3.8.3 核心类：`StaticDataFlowAnalyzer`

**核心方法:**

| 方法名 | 功能 |
|--------|------|
| `_get_cache_key()` | 获取缓存键 |
| `_load_cached_result()` | 加载缓存结果 |
| `_save_cached_result()` | 保存缓存结果 |
| `analyze_function()` | 完整分析一个函数 |
| `perform_static_taint_analysis()` | 执行静态污点分析 |
| `_identify_taint_sources()` | 识别污点源 |
| `_identify_taint_sinks()` | 识别污点汇点 |
| `detect_uninitialized_memory()` | 检测未初始化内存使用 |
| `detect_integer_overflow()` | 检测整数溢出 |
| `_analyze_us_def_chain()` | 分析 Use-Def 链 |
| `detect_format_string_vulns()` | 检测格式化字符串漏洞 |

#### 3.8.4 默认污点源

| 函数 | 类型 | 说明 |
|------|------|------|
| `read` | input | 标准输入 |
| `fread` | file | 文件读取 |
| `recv` | network | 网络接收 |
| `recvfrom` | network | 网络接收（带地址） |
| `getenv` | environment | 环境变量 |
| `scanf` | input | 格式化输入 |
| `gets` | input | 危险输入函数 |

#### 3.8.5 默认污点汇点

| 函数 | 类型 | 风险参数位置 |
|------|------|-------------|
| `system` | system | 0 |
| `execve` | execve | 0 |
| `execl` | execve | 0 |
| `printf` | printf_family | 0 |
| `sprintf` | printf_family | 0 |
| `fprintf` | printf_family | 1 |
| `memcpy` | memcpy | 0, 1, 2 |
| `strcpy` | strcpy | 0, 1 |
| `strcat` | strcpy | 0, 1 |

---

### 3.9 漏洞数据库 - [modules/vuln_db.py](file:///c:/Users/Administrator/Desktop/deemo/modules/vuln_db.py)

#### 3.9.1 功能描述

本地漏洞数据库，用于存储和检索漏洞知识：
1. 存储成功的漏洞分析结果和利用脚本
2. 根据代码片段和危险函数进行相似性搜索
3. 导出/导入知识库
4. 向量存储和语义搜索（可选 FAISS 加速）
5. 外部漏洞数据库集成（CVE、Exploit-DB）
6. 支持 SQLite 和 PostgreSQL 双后端

#### 3.9.2 数据库表结构

**vulnerabilities 表:**
```sql
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_type TEXT NOT NULL,
    binary_name TEXT,
    binary_format TEXT,
    architecture TEXT,
    bits INTEGER,
    function_name TEXT,
    pseudocode_hash TEXT,
    pseudocode_snippet TEXT,
    exploit_script TEXT,
    dangerous_functions TEXT,
    checksec TEXT,
    symbols TEXT,
    severity TEXT,
    description TEXT,
    notes TEXT,
    call_graph_summary TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**code_embeddings 表 (向量存储):**
```sql
CREATE TABLE code_embeddings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id INTEGER,
    embedding TEXT,
    model_name TEXT,
    vector_dim INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
);
```

**external_cve_cache 表 (外部 CVE 缓存):**
```sql
CREATE TABLE external_cve_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT UNIQUE,
    binary_hash TEXT,
    binary_name TEXT,
    cve_data TEXT,
    source TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### 3.9.3 核心类：`VulnerabilityDatabase`

**核心方法:**

| 方法名 | 功能 |
|--------|------|
| `add_vulnerability()` | 添加漏洞记录 |
| `get_vulnerability()` | 获取单个漏洞记录 |
| `search_by_type()` | 按漏洞类型搜索 |
| `search_by_function()` | 按函数名搜索 |
| `search_similar()` | 相似性搜索 |
| `fuzzy_search_by_dangerous_functions()` | 危险函数模糊搜索 |
| `update_vulnerability()` | 更新漏洞记录 |
| `delete_vulnerability()` | 删除漏洞记录 |
| `get_all_vulnerabilities()` | 获取所有漏洞记录 |
| `get_statistics()` | 获取统计信息 |
| `export_database()` | 导出数据库 |
| `import_database()` | 导入数据库 |
| `add_code_embedding()` | 添加代码嵌入向量 |
| `semantic_search()` | 语义搜索 |
| `jaccard_similarity()` | Jaccard 相似度计算 |
| `cosine_similarity()` | 余弦相似度计算 |
| `calculate_dangerous_function_score()` | 危险函数组合评分 |
| `query_external_cve_database()` | 查询外部 CVE 数据库 (NVD) |
| `query_exploit_db()` | 查询 Exploit-DB |
| `enhanced_search_similar()` | 增强版相似搜索 |

#### 3.9.4 模块级函数 (v1.3.1 新增)

| 函数名 | 功能 |
|--------|------|
| `get_vuln_db()` | 获取漏洞数据库实例（单例模式简化版） |

#### 3.9.5 危险函数组合评分

部分危险函数组合及其评分：

| 组合 | 评分 | 说明 |
|------|------|------|
| `gets`, `strcpy` | 100 | 经典缓冲区溢出组合 |
| `scanf`, `%s` | 95 | scanf 无边界读取 |
| `read`, `strcpy` | 90 | read + strcpy 组合 |
| `system`, `gets` | 95 | 直接命令执行风险 |
| `free`, `malloc` | 50 | UAF 风险 |

---

### 3.10 报告生成 - [modules/report.py](file:///c:/Users/Administrator/Desktop/deemo/modules/report.py)

#### 3.10.1 功能描述

生成分析报告，支持多种格式：
- **Markdown**: 人类可读，便于查看和分享
- **JSON**: 机器可读，便于后续处理
- **HTML**: 现代化 UI、统计卡片、代码高亮
- **PDF**: weasyprint/pdfkit 双后端，自动降级

#### 3.10.2 核心类：`ReportGenerator`

**核心方法:**

| 方法名 | 功能 |
|--------|------|
| `add_step()` | 记录分析步骤 |
| `format_binary_info_section()` | 格式化二进制信息 |
| `format_decomp_analysis_section()` | 格式化反编译分析 |
| `format_crash_analysis_section()` | 格式化崩溃分析 |
| `format_exploit_section()` | 格式化利用脚本信息 |
| `format_static_analysis_section()` | 格式化静态分析 |
| `format_symbolic_analysis_section()` | 格式化符号执行分析 |
| `generate_report()` | 生成 Markdown 报告 |
| `generate_json_report()` | 生成 JSON 报告 |
| `generate_html_report()` | 生成 HTML 报告 |
| `generate_pdf_report()` | 生成 PDF 报告 |

#### 3.10.3 报告内容结构

**Markdown 报告:**
```
# 二进制漏洞分析报告
## 1. 分析概览
   - 分析时间
   - 二进制文件
   - 分析模式 (AI/启发式)
   
## 2. 二进制文件信息
   - 基本信息 (架构、位数)
   - 保护机制 (NX/PIE/RELRO/Canary)
   - 危险函数
   - 关键字符串
   - 重要符号

## 3. 函数分析 (每个函数一个章节)
   - 反编译代码
   - 发现的漏洞
   - 风险等级

## 4. 静态数据流分析 (如有)
   - Use-Def 链分析
   - 整数溢出检测
   - 格式化字符串检测
   - 未初始化内存检测
   - 污点分析结果

## 5. 符号执行分析 (如有)
   - 探索路径
   - 发现的崩溃
   - 污点分析结果

## 6. 崩溃信息分析 (如有)
   - 寄存器状态
   - 启发式分析
   - 漏洞类型评估

## 7. 利用脚本 (如有)
   - 脚本路径
   - 生成时间
   - 验证结果
   - 迭代记录

## 8. 分析步骤记录
   - 每步的时间戳和数据
```

---

### 3.11 插件钩子系统 - [modules/hooks.py](file:///c:/Users/Administrator/Desktop/deemo/modules/hooks.py)

#### 3.11.1 功能描述

提供可扩展的插件钩子系统，允许用户编写 Python 脚本在分析流程的特定点执行自定义逻辑。

#### 3.11.2 可用钩子点

| 钩子点 | 触发时机 | 上下文信息 |
|--------|----------|------------|
| `pre_info_collect` | 信息收集前 | binary_path |
| `pre_decompile` | 反编译前 | binary_path, function_name |
| `post_decompile` | 反编译后 | binary_path, functions_analyzed, decomp_results |
| `post_analysis` | AI 分析后 | vulnerabilities, function_name |
| `pre_exploit_generate` | 利用生成前 | vulnerability_type, binary_info |
| `pre_crash_analysis` | 崩溃分析前 | crash_data |
| `post_crash_analysis` | 崩溃分析后 | crash_analysis_result |
| `post_report` | 报告生成后 | reports (dict of format -> path) |

#### 3.11.3 核心类：`HookManager`

**核心方法:**

| 方法名 | 功能 |
|--------|------|
| `_load_hooks()` | 加载 hooks 目录下的所有 Python 脚本 |
| `register_hook()` | 注册钩子函数 |
| `run_hook()` | 执行特定钩子点的所有钩子 |
| `get_registered_hooks()` | 获取所有注册的钩子 |

#### 3.11.4 示例钩子脚本

```python
"""
示例钩子脚本

可用的钩子点:
- pre_info_collect(context): 信息收集前
- pre_decompile(context): 反编译前
- post_decompile(context): 反编译后
- post_analysis(context): AI 分析后
- pre_exploit_generate(context): 利用生成前
- post_report(context): 报告生成后
- pre_crash_analysis(context): 崩溃分析前
- post_crash_analysis(context): 崩溃分析后
"""

import logging

logger = logging.getLogger(__name__)

def pre_info_collect(context):
    """信息收集前钩子"""
    binary_path = context.get('binary_path', 'unknown')
    logger.debug(f"[Custom Hook] 开始分析: {binary_path}")

def post_decompile(context):
    """反编译后钩子"""
    func_count = context.get('functions_analyzed', 0)
    logger.info(f"[Custom Hook] 反编译完成，分析了 {func_count} 个函数")

def pre_exploit_generate(context):
    """利用生成前钩子"""
    vuln_type = context.get('vulnerability_type', 'unknown')
    logger.info(f"[Custom Hook] 开始生成 {vuln_type} 类型的利用脚本")

def post_report(context):
    """报告生成后钩子"""
    reports = context.get('reports', {})
    for fmt, path in reports.items():
        logger.info(f"[Custom Hook] 报告已生成: {fmt} -> {path}")
```

---

### 3.12 Web API 服务 - [modules/web_api.py](file:///c:/Users/Administrator/Desktop/deemo/modules/web_api.py)

#### 3.12.1 功能描述

基于 FastAPI 实现的 REST API 服务，支持：
- 异步分析任务管理
- 文件上传分析
- 多格式报告下载
- 漏洞数据库查询
- 外部漏洞数据源集成
- CORS 跨域支持
- 任务进度实时追踪

#### 3.12.2 Pydantic 数据模型

| 模型 | 说明 |
|------|------|
| `AnalysisRequest` | 分析请求模型 |
| `VulnerabilityQuery` | 漏洞查询模型 |
| `AnalysisTaskStatus` | 分析任务状态 |
| `APIResponse` | 通用 API 响应模型 |

#### 3.12.3 API 端点

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/` | API 信息 |
| GET | `/health` | 健康检查 |
| POST | `/api/analyze` | 提交分析任务 |
| GET | `/api/tasks` | 获取所有任务列表 |
| GET | `/api/tasks/{task_id}` | 获取任务状态 |
| POST | `/api/tasks/{task_id}/cancel` | 取消任务 |
| GET | `/api/tasks/{task_id}/report/{format}` | 下载报告 (md/json/html/pdf) |
| POST | `/api/upload` | 上传二进制文件 |
| POST | `/api/vulnerabilities` | 查询漏洞数据库 |
| GET | `/api/vulnerabilities/{vuln_id}` | 获取漏洞详情 |
| POST | `/api/vulnerabilities/search` | 搜索漏洞 |

#### 3.12.4 核心类：`AnalysisTaskManager`

管理异步分析任务的创建、执行和状态追踪。

**核心方法:**

| 方法名 | 功能 |
|--------|------|
| `create_task()` | 创建新的分析任务 |
| `get_task()` | 获取任务状态 |
| `update_task()` | 更新任务状态 |
| `list_tasks()` | 列出所有任务 |
| `cancel_task()` | 取消任务 |
| `delete_task()` | 删除任务 |
| `_load_tasks()` | 从磁盘加载任务 |
| `_save_task()` | 保存任务到磁盘 |

#### 3.12.5 任务状态

| 状态 | 说明 |
|------|------|
| `pending` | 等待执行 |
| `running` | 正在执行 |
| `completed` | 完成 |
| `failed` | 失败 |
| `cancelled` | 已取消 |

---

### 3.13 AI Prompt 模板 - [prompts.py](file:///c:/Users/Administrator/Desktop/deemo/prompts.py)

#### 3.13.1 模板列表

| 模板常量 | 用途 | 占位符数量 |
|----------|------|------------|
| `DECOMP_ANALYSIS_TEMPLATE` | 反编译代码漏洞分析 | 10 个 |
| `CRASH_ANALYSIS_TEMPLATE` | 崩溃信息分析 | 5 个 |
| `EXPLOIT_GENERATION_TEMPLATE` | 利用脚本生成 | 13 个 |
| `EXPLOIT_ITERATION_TEMPLATE` | 迭代优化提示 | 8 个 |
| `REPORT_SUMMARY_TEMPLATE` | 报告摘要生成 | 3 个 |

#### 3.13.2 模板占位符对齐

**DECOMP_ANALYSIS_TEMPLATE (反编译分析):**
```
{binary_path}, {function_name}, {nx}, {pie}, {relro}, 
{canary}, {aslr}, {dangerous_functions}, {key_strings}, {pseudocode}
```

**EXPLOIT_ITERATION_TEMPLATE (迭代优化):**
```
{original_script}, {failure_info}, {nx}, {pie}, {relro},
{canary}, {additional_info}, {iteration_count}
```

---

## 四、模块依赖关系

```
                    ┌─────────────────┐
                    │   main.py       │  (入口)
                    │  流程编排       │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
            ▼                ▼                ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │ config.py    │ │ prompts.py   │ │ requirements │
    │ 配置管理      │ │ Prompt模板   │ │ 依赖列表      │
    └──────┬───────┘ └──────────────┘ └──────────────┘
           │
           │ 被所有模块导入
           │
    ┌──────┼─────────────────────────────────┬─────────────────┐
    │      │                                 │                 │
    ▼      ▼                                 ▼                 ▼
┌─────────────────┐        ┌────────────────────────┐ ┌──────────────┐
│ info_collect.py │        │ modules/               │ │ tests/       │
│ 多格式文件收集   │        │  - decomp_ai.py       │ │ 单元测试      │
│ (pwntools)      │        │  - crash_analysis.py  │ └──────────────┘
└────────┬────────┘        │  - exploit_gen.py     │
         │                 │  - symbolic_exe.py    │
         │                 │  - static_analysis.py │
         │                 │  - report.py          │
         │                 │  - vuln_db.py         │
         │                 │  - hooks.py           │
         │                 │  - web_api.py         │
         │                 └──────────┬─────────────┘
         │                            │
         ▼                            ▼
    ┌─────────────────────────────────────────┐
    │            数据流                        │
    │  binary_info → decomp_analysis → report │
    │  crash_data → crash_analysis → report   │
    │  vulnerabilities → exploit_gen → report │
    │  static/symbolic → vuln_db → report     │
    └─────────────────────────────────────────┘
```

---

## 五、测试模块

### 5.1 测试覆盖

| 测试文件 | 测试数量 | 覆盖模块 |
|----------|----------|----------|
| [test_config.py](file:///c:/Users/Administrator/Desktop/deemo/tests/test_config.py) | ~10 | 配置管理 |
| [test_info_collect.py](file:///c:/Users/Administrator/Desktop/deemo/tests/test_info_collect.py) | ~8 | ELF 信息收集 |
| [test_decomp_ai.py](file:///c:/Users/Administrator/Desktop/deemo/tests/test_decomp_ai.py) | ~21 | 反编译分析 |
| [test_crash_analysis.py](file:///c:/Users/Administrator/Desktop/deemo/tests/test_crash_analysis.py) | ~18 | 崩溃分析 |
| [test_exploit_gen.py](file:///c:/Users/Administrator/Desktop/deemo/tests/test_exploit_gen.py) | ~19 | 利用生成 |
| [test_vuln_db.py](file:///c:/Users/Administrator/Desktop/deemo/tests/test_vuln_db.py) | ~15 | 漏洞数据库 |
| **总计** | **~91** | - |

### 5.2 运行测试

```powershell
# 运行所有测试
python tests/run_tests.py

# 详细输出
python tests/run_tests.py -v

# 运行特定测试文件
python tests/run_tests.py -p test_config.py

# 运行特定测试
python -m pytest tests/test_config.py::TestConfig::test_check_openai_api_key_set -v
```

---

## 六、安全措施

### 6.1 已实施的安全措施

| 措施 | 说明 | 实现位置 |
|------|------|----------|
| **命令注入防护** | 函数名校验，使用列表传参 | [decomp_ai.py](file:///c:/Users/Administrator/Desktop/deemo/modules/decomp_ai.py) |
| **API Key 安全** | 环境变量读取，不硬编码，日志脱敏 | [config.py](file:///c:/Users/Administrator/Desktop/deemo/config.py) |
| **超时控制** | 所有子进程调用均有 timeout | 所有模块 |
| **输入验证** | ELF/PE/Mach-O 格式验证，崩溃数据格式验证 | [info_collect.py](file:///c:/Users/Administrator/Desktop/deemo/modules/info_collect.py), [config.py](file:///c:/Users/Administrator/Desktop/deemo/config.py) |
| **异常处理** | 完善的 try-except 覆盖 | 所有模块 |
| **安全警告** | 利用脚本包含安全警告，执行前显示安全横幅 | [exploit_gen.py](file:///c:/Users/Administrator/Desktop/deemo/modules/exploit_gen.py) |
| **沙箱执行** | Docker/Podman 沙箱隔离执行利用脚本 | [config.py](file:///c:/Users/Administrator/Desktop/deemo/config.py), [exploit_gen.py](file:///c:/Users/Administrator/Desktop/deemo/modules/exploit_gen.py) |
| **目录隔离** | logs/, reports/, exploits/ 目录自动创建 | [config.py](file:///c:/Users/Administrator/Desktop/deemo/config.py) |
| **敏感信息过滤** | 日志过滤器自动脱敏 API Key、Token、Password | [config.py](file:///c:/Users/Administrator/Desktop/deemo/config.py) |

### 6.2 危险字符过滤

在 `sanitize_function_name()` 中过滤以下字符：
- 换行符: `\n`
- 分号: `;`
- 与号: `&`
- 管道: `|`
- 重定向: `<`, `>`
- 替换: `$`
- 括号: `()`, `{}`, `[]`

---

## 七、使用指南

### 7.1 环境配置

**1. 安装 Python 依赖**
```powershell
pip install -r requirements.txt
```

**2. 安装 radare2 (必需)**
```powershell
# Ubuntu/Debian
sudo apt install radare2

# macOS
brew install radare2

# Windows
# 从 https://github.com/radareorg/radare2/releases 下载
```

**3. 配置环境变量**
```powershell
# 复制示例配置
Copy-Item .env.example .env

# 编辑 .env
# OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# OPENAI_MODEL=gpt-4
# OPENAI_BASE_URL=https://api.openai.com/v1
```

### 7.2 基本使用

**分析二进制文件**
```powershell
python main.py ./your_binary.elf
```

**指定分析函数**
```powershell
python main.py ./your_binary.elf -f main vuln get_flag
```

**包含崩溃数据分析**
```powershell
python main.py ./your_binary.elf --crash crash_data.json
```

**验证生成的利用脚本**
```powershell
python main.py ./your_binary.elf --validate
```

**禁用 AI（仅启发式分析）**
```powershell
python main.py ./your_binary.elf --no-ai
```

**启用并行分析**
```powershell
python main.py ./your_binary.elf --parallel --max-parallel 8
```

**启用静态数据流分析**
```powershell
python main.py ./your_binary.elf --enable-static
```

**启用符号执行**
```powershell
python main.py ./your_binary.elf --enable-symbolic
```

**交互式分析模式**
```powershell
python main.py ./your_binary.elf --interactive
```

**运行健康检查**
```powershell
python main.py ./your_binary.elf --health-check
```

**使用沙箱执行**
```powershell
# Docker 沙箱
python main.py ./your_binary.elf --validate --sandbox docker

# Podman 沙箱
python main.py ./your_binary.elf --validate --sandbox podman
```

**启动 Web API 服务器**
```powershell
python main.py --api-server

# 自定义主机和端口
python main.py --api-server --api-host 127.0.0.1 --api-port 9000
```

### 7.3 崩溃数据格式

```json
{
  "registers": {
    "rax": "0x0000000000000000",
    "rbx": "0x0000000000000000",
    "rsp": "0x00007fffffffdbe8",
    "rip": "0x000055555555514a"
  },
  "stack_trace": [
    "#0  0x000055555555514a in main ()",
    "#1  0x00007ffff7c29d90 in __libc_start_call_main ()"
  ],
  "fault_instruction": "0x55555555514a <main+31>:    ret",
  "output": "Segmentation fault (core dumped)",
  "signal": "SIGSEGV"
}
```

### 7.4 Web API 使用

**启动服务器:**
```powershell
python main.py --api-server
```

**访问文档:**
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

**示例请求:**
```powershell
# 提交分析任务
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"binary_name": "vulnerable_app", "function_names": ["main"]}'

# 获取任务状态
curl http://localhost:8000/api/tasks/{task_id}

# 下载报告
curl http://localhost:8000/api/tasks/{task_id}/report/md --output report.md
```

---

## 八、版本历史

### v1.4.0 (2026-06-04)

**新增功能:**

1. **CVSS 3.1 评分系统**
   - 自动计算漏洞严重程度评分 (0.0-10.0)
   - 支持完整的 CVSS 3.1 指标 (AV/AC/PR/UI/S/C/I/A)
   - 基于漏洞类型和特征的启发式指标推断
   - 生成标准 CVSS 向量字符串
   - 详细的评分说明和解释

2. **Ghidra 集成脚本**
   - 生成可在 Ghidra 中运行的 Python 标注脚本
   - 为漏洞函数自动添加书签 (Bookmark)
   - 为高风险代码设置自定义背景颜色 (按严重程度)
   - 在函数入口添加前置注释说明漏洞详情
   - 一键下载和查看脚本

3. **vis.js 可视化图表**
   - 函数调用图 (Call Graph) 可视化
   - 控制流图 (Control Flow Graph) 可视化
   - 节点颜色表示漏洞风险等级
   - 节点大小表示重要性
   - 交互式拖拽和缩放

4. **HTML 报告增强**
   - CVSS 评分统计卡片 (最高/平均评分)
   - Ghidra 脚本下载按钮
   - 脚本内容查看/隐藏切换
   - vis.js 交互式图表集成

**新增方法:**
- `ReportGenerator.calculate_cvss()` - 计算 CVSS 3.1 评分
- `ReportGenerator._infer_cvss_metrics()` - 推断 CVSS 指标
- `ReportGenerator._compute_cvss_base_score()` - 计算基础评分
- `ReportGenerator._build_cvss_vector()` - 构建向量字符串
- `ReportGenerator._generate_vis_js_graphs()` - 生成可视化图表
- `ReportGenerator.generate_ghidra_script()` - 生成 Ghidra 脚本

---

### v1.3.1 (2026-06-03)

**新增功能:**

1. **沙箱执行模式**
   - 支持 Docker 沙箱执行
   - 支持 Podman 沙箱执行
   - `SANDBOX_MODE` 配置 (none/docker/podman)
   - 安全隔离的利用脚本执行环境
   - `validate_sandbox_config()` 配置验证函数

2. **PostgreSQL 数据库支持**
   - SQLite/PostgreSQL 双后端支持
   - `DB_TYPE` 配置 (sqlite/postgres)
   - `get_postgres_connection_string()` 连接字符串生成
   - 可扩展的数据库后端架构

3. **漏洞数据库便捷访问**
   - 新增 `get_vuln_db()` 模块级函数
   - 单例模式简化版访问

**改进:**
- 更灵活的数据库架构设计
- 增强的安全执行环境支持
- 代码质量优化

---

**新增功能:**

1. **沙箱执行模式**
   - 支持 Docker 沙箱执行
   - 支持 Podman 沙箱执行
   - `SANDBOX_MODE` 配置 (none/docker/podman)
   - 安全隔离的利用脚本执行环境
   - `validate_sandbox_config()` 配置验证函数

2. **PostgreSQL 数据库支持**
   - SQLite/PostgreSQL 双后端支持
   - `DB_TYPE` 配置 (sqlite/postgres)
   - `get_postgres_connection_string()` 连接字符串生成
   - 可扩展的数据库后端架构

3. **漏洞数据库便捷访问**
   - 新增 `get_vuln_db()` 模块级函数
   - 单例模式简化版访问

**改进:**
- 更灵活的数据库架构设计
- 增强的安全执行环境支持
- 代码质量优化

---

### v1.3.0 (2026-06-02)

**新增功能:**

1. **静态数据流分析模块** (`modules/static_analysis.py`)
   - Use-Def 链分析 (angr VariableRecoveryFast)
   - 整数溢出检测 (add/sub/mul/imul/shl/sal)
   - 格式化字符串漏洞检测
   - 未初始化内存检测
   - 静态污点分析 (追踪输入源到危险汇点)
   - 结果缓存机制 (MD5 哈希标识)

2. **Web API 服务模块** (`modules/web_api.py`)
   - FastAPI 框架，自动生成 Swagger/ReDoc 文档
   - 异步分析任务管理 (pending/running/completed/failed/cancelled)
   - 文件上传分析 (multipart/form-data)
   - 多格式报告下载 (md/json/html/pdf)
   - 漏洞数据库查询 API
   - 外部漏洞数据源集成 (NVD, OSV, GitHub Advisory)
   - CORS 跨域支持
   - 任务进度实时追踪

---

### v1.2.0 (2026-06-01)

**新增功能 (16 项):**

1. **插件钩子系统**
   - 新增 `modules/hooks.py` 模块
   - 8 个预定义钩子点
   - 支持自定义 Python 脚本插件
   - 自动创建示例钩子脚本

2. **多架构 ROP 支持**
   - 支持 x86/x64/ARM/ARM64/MIPS/RISC-V 架构
   - 架构特定的 gadget 模式数据库
   - 自动架构检测和标准化

3. **one_gadget 集成**
   - 自动检测和使用 one_gadget
   - libc 路径自动查找
   - 输出解析和候选列表

4. **libc 版本检测**
   - 自动检测 libc 版本
   - libc-database 集成
   - 精确利用辅助

5. **并行函数分析**
   - ThreadPoolExecutor 并行分析
   - 可配置的最大并发数
   - 线程安全的日志和结果聚合

6. **交互式分析模式**
   - 交互式菜单界面
   - 函数详情查看
   - 动态分析其他函数
   - 为漏洞生成利用脚本
   - 列出所有可用函数

7. **健康检查 (Doctor Mode)**
   - 依赖检查
   - 反编译引擎检测
   - AI 客户端配置检测
   - 符号执行引擎检测
   - 系统工具检测
   - 二进制分析能力检测

8. **多格式报告生成**
   - HTML 报告（现代化 UI、统计卡片、代码高亮）
   - PDF 报告（weasyprint/pdfkit 双后端）
   - 自动降级机制

9. **向量存储与语义搜索**
   - numpy/FAISS 支持
   - 代码嵌入向量存储
   - 余弦相似度搜索
   - Jaccard 相似度匹配
   - 危险函数组合评分

10. **外部 CVE 集成**
    - NVD (National Vulnerability Database) 查询
    - Exploit-DB 查询
    - 本地缓存机制

11. **安全增强**
    - `SensitiveFilter` 日志过滤器
    - API Key 脱敏
    - 敏感数据自动过滤
    - 安全警告横幅

12. **更多反编译引擎**
    - Binary Ninja 支持
    - Hopper Disassembler 支持

13. **多格式崩溃数据解析**
    - GDB 输出解析
    - ASAN 输出解析
    - WinDbg 输出解析
    - coredump 解析

14. **符号执行增强**
    - 多架构支持 (x86/x64/ARM/ARM64/MIPS/RISC-V/PPC)
    - 自动危险函数探索
    - 污点分析支持
    - angr-explorer 可视化支持

**测试结果:** 76+ 个测试全部通过

---

### v1.1.0 (2026-05-31)

- 初始版本
- 基本的二进制分析功能
- AI 辅助漏洞分析
- 利用脚本生成
- 基础的漏洞数据库

---

## 九、相关文档

| 文档 | 说明 |
|------|------|
| [DEBUG_FIXES.md](file:///c:/Users/Administrator/Desktop/deemo/DEBUG_FIXES.md) | 详细的调试修复记录 |
| [项目代码功能总结.md](file:///c:/Users/Administrator/Desktop/deemo/%E9%A1%B9%E7%9B%AE%E4%BB%A3%E7%A0%81%E5%8A%9F%E8%83%BD%E6%80%BB%E7%BB%93.md) | 详细代码功能文档 |
| [project_code.txt](file:///c:/Users/Administrator/Desktop/deemo/project_code.txt) | 代码参考文档 |
| [requirements.txt](file:///c:/Users/Administrator/Desktop/deemo/requirements.txt) | Python 依赖列表 |
| [Dockerfile](file:///c:/Users/Administrator/Desktop/deemo/Dockerfile) | Docker 容器化配置 |

---

## 十、项目统计

### 10.1 项目规模

| 指标 | 数值 |
|------|------|
| **总代码文件** | 23 个 (19 个 Python 源文件 + 4 个测试辅助文件) |
| **核心模块** | 13 个 (主入口 + 配置 + 提示 + 10 个功能模块) |
| **测试模块** | 7 个 (6 个测试文件 + 1 个运行器) |

### 10.2 代码行数估算

| 模块 | 行数 (估算) | 主要功能 |
|------|------------|----------|
| main.py | ~850 | 主流程控制 |
| config.py | ~600 | 配置管理 + 安全过滤 + 沙箱 + DB |
| prompts.py | ~200 | AI 提示模板 |
| modules/hooks.py | ~260 | 插件钩子系统 |
| modules/static_analysis.py | ~900 | 静态数据流分析 (v1.3.0) |
| modules/web_api.py | ~1200 | Web API 服务 (v1.3.0) |
| modules/symbolic_exe.py | ~750 | 符号执行 |
| modules/vuln_db.py | ~1050 | 漏洞数据库 + 向量搜索 + PostgreSQL |
| modules/report.py | ~800 | 报告生成 + HTML/PDF |
| modules/exploit_gen.py | ~1800 | 利用脚本生成 + 多架构 ROP |
| modules/crash_analysis.py | ~600 | 崩溃分析 |
| modules/decomp_ai.py | ~1200 | 反编译与 AI 分析 |
| modules/info_collect.py | ~1000 | 二进制信息收集 |
| 测试文件 | ~1500 | 单元测试 |
| **总计** | **~12,110** | |

### 10.3 新功能统计

#### v1.3.1
| 功能类别 | 新增数量 |
|----------|----------|
| 新增配置项 | 7 个 |
| 新增函数/方法 | 3 个 |
| 新增数据库后端 | 1 个 |
| 新增沙箱支持 | 2 种 |

#### v1.3.0
| 功能类别 | 新增数量 |
|----------|----------|
| 新增模块 | 2 个 |
| 新增函数/方法 | 60+ 个 |
| 新增命令行参数 | 15+ 个 |
| 新增 API 端点 | 10+ 个 |
| 新增分析技术 | 5 种 |

#### v1.2.0
| 功能类别 | 新增数量 |
|----------|----------|
| 新增模块 | 1 个 |
| 新增函数/方法 | 50+ 个 |
| 新增命令行参数 | 10+ 个 |
| 新增反编译引擎 | 2 个 |
| 新增架构支持 | 6 种 |
| 新增报告格式 | 2 种 |
| 新增钩子点 | 8 个 |

---

*文档生成时间: 2026-06-03*\
*项目版本: v1.3.1*\
*文档版本: 1.0*
