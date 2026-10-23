# 仓库指南

## 项目结构与模块组织

BinMind 是 Python 3.8+ 二进制漏洞分析工具。核心代码在 `core/`，CLI 在 `cli/` 与 `binmind.py`，领域模块在 `modules/`；测试、样本、报告分别位于 `tests/`、`samples/`、`results/` 和 `reports/`。

## 构建、测试与开发命令

安装依赖：`pip install -r requirements-dev.txt`；可编辑安装：`pip install -e ".[dev]"`。全量测试：`python -m pytest`；单文件测试：`python -m pytest tests/test_report.py -v`；语法检查：`python -m py_compile main.py binmind.py cli/commands.py`；CLI 自检：`binmind --test`。

## 编码风格与命名约定

使用 4 空格缩进；函数、变量和模块用 `snake_case`，类用 `PascalCase`，常量用 `UPPER_SNAKE_CASE`。注释只说明意图、边界或兼容性，不复述代码。

## 测试指南

pytest 配置在 `pyproject.toml`，支持 `unit`、`integration`、`slow`、`security` 标记。测试文件使用 `test_*.py`，函数使用 `test_<行为>`；涉及样本或外部工具的改动应补回归测试。

## 提交与 Pull Request 指南

提交沿用 `feat:`、`fix:`、`perf:`、`chore:` 前缀，例如 `fix: handle missing ELF symbols`。PR 需说明问题、改动范围、测试结果，并为 CLI、报告或前端改动附输出或截图；不得提交密钥、配置、缓存、日志和生成物。
