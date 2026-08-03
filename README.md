# BinMind — LLM 辅助的二进制漏洞挖掘与验证框架

面向真实二进制程序（ELF/PE/Mach-O）的安全分析工具链，将大语言模型
作为辅助组件与传统程序分析技术（反编译、模糊测试、符号执行、规则检测）
协同工作，降低漏洞研判门槛，提升分析效率。

## 核心能力

- **程序画像**: 一键获取 checksec (NX/PIE/Canary/RELRO)、PLT/GOT 地址、libc 版本、ROP gadget 统计
- **栈溢出自动分析**: angr 符号执行计算 padding，检测 canary，推荐利用策略
- **格式化字符串检测**: 三级检测链（静态→符号执行→LLM），自动定位偏移
- **验证闭环**: 生成 exploit → 沙箱执行 → 失败时 LLM 自动修正迭代
- **自适应调度**: MAB 算法根据样本特征动态选择最优分析方法组合
- **批量实验**: 一键批量分析目录，生成四维评估报告

## 快速开始

### 安装

```bash
pip install -e .
# 完整依赖 (angr, pwntools, capstone 等)
pip install -e ".[full]"
```

### 基本使用

```bash
# 单文件分析
binmind analyze ./vuln_binary --symbolic

# 批量分析
python scripts/batch_analyze.py ./samples/ctf/ -o ./results/

# 查看版本
binmind version
```

### Python API

```python
from core.binary_profile import build_binary_profile
from core.stack_overflow_analyzer import analyze_stack_overflow

profile = build_binary_profile('vuln_binary')
result = analyze_stack_overflow('vuln_binary', 'vuln', libc_info=profile['libc'])
print(f"Padding: {result['padding']}, Strategy: {result['strategy']}")
```

## 项目结构

```
BinMind/
├── deemo/
│   ├── core/           # 核心管线与分析模块
│   │   ├── pipeline.py           # 中央调度管线
│   │   ├── checksec.py           # 保护机制检测
│   │   ├── plt_scanner.py        # PLT/GOT 解析
│   │   ├── libc_identifier.py    # libc 版本识别
│   │   ├── binary_profile.py     # 程序综合画像
│   │   ├── stack_overflow_analyzer.py  # 栈溢出自动分析
│   │   ├── format_string_detector.py   # 格式化字符串检测
│   │   ├── exploit_executor.py   # 沙箱执行
│   │   ├── feedback_loop.py      # LLM 反馈迭代
│   │   ├── crash_analyzer_llm.py # LLM 崩溃分析
│   │   ├── adaptive_scheduler.py # 自适应调度
│   │   ├── cfg_extractor.py      # CFG 结构提取
│   │   ├── sample_manager.py     # 样本管理
│   │   └── experiment_tracker.py # 实验追踪
│   ├── modules/        # 24 个专业分析子模块
│   ├── plugins/        # 轻量插件 (ROP tools, fuzz harness, taint...)
│   ├── utils/          # ELF/PE/Mach-O 底层解析
│   └── tests/          # 180+ 测试文件
├── samples/            # 实验样本库 (ctf/teaching/cve)
├── docs/               # 文档与实验记录
└── pyproject.toml
```

## 文档

- [技术路线说明](docs/技术路线说明.md) — 对应申报书路线图
- [实验记录模板](docs/实验记录模板.md) — 标准化实验报告格式
- [样例分析: 栈溢出](docs/样例分析报告_栈溢出.md)
- [样例分析: 格式化字符串](docs/样例分析报告_格式化字符串.md)
- [实现说明](docs/实现说明.md) — 模块设计与集成

## 许可证

MIT
