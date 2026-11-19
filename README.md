# BinMind

BinMind 是一个面向 CTF、靶场与授权安全研究场景的二进制漏洞分析工具。它面向 ELF / PE / Mach-O 文件，集成基础二进制信息提取、反编译证据整理、规则检测、符号执行、漏洞报告、逆向报告、Exploit 草稿与 Web API 服务。

> 仅在你拥有授权的环境中使用本项目。不要将漏洞分析、利用生成或调试能力用于未授权目标。

## 功能概览

- 二进制基础画像：格式、架构、位数、保护机制、导入函数、字符串、ROP gadget 摘要。
- 漏洞分析：规则检测、函数级分析、危险函数识别、崩溃信息整合。
- 符号执行：可选启用 angr 进行路径与约束分析。
- 报告输出：Markdown / JSON 报告，支持中文/英文切换。
- 逆向工程报告：根据已有分析结果生成结构化逆向报告。
- Exploit 辅助：生成利用脚本草稿，并支持反馈迭代入口。
- Web API：通过 FastAPI 提供服务接口。

## 目录结构

当前仓库已经将原 `deemo/` 目录内容提升到项目根目录，常用文件如下：

```text
BinMind/
├── binmind                 # Linux/WSL 启动脚本，可直接 ./binmind ...
├── binmind.py              # Python CLI 主入口
├── main.py                 # 兼容入口，转发到 binmind.py
├── cli/                    # 命令行参数与子命令
├── core/                   # 分析流水线、报告、二进制信息等核心逻辑
├── modules/                # LLM、分析工具、辅助模块
├── tests/                  # 测试用例
├── samples/                # 示例样本
├── results/                # 默认分析输出目录
├── reports/                # 逆向报告默认输出目录，运行时生成
├── requirements-core.txt   # 核心依赖
├── requirements.txt        # 完整运行依赖
├── requirements-dev.txt    # 开发/测试依赖
├── pyproject.toml          # Python 项目配置
├── setup.py                # 兼容安装配置
└── install.sh              # Linux/WSL 安装脚本
```

## 环境要求

推荐环境：

- Python 3.8+
- Linux / WSL / macOS；Windows 可通过 WSL 使用
- pip、venv
- 可选系统工具：`file`、`binutils`、`gdb`、`radare2`

Ubuntu / WSL 推荐先安装系统依赖：

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv file binutils gdb build-essential libssl-dev libffi-dev git wget curl unzip
```

如果源中存在 `radare2`，可额外安装：

```bash
sudo apt install -y radare2
```

## 安装方式一：使用安装脚本（推荐 Linux/WSL）

在项目根目录执行：

```bash
cd ~/BinMind
chmod +x install.sh
./install.sh --user
```

常用参数：

```bash
./install.sh --user                 # 安装命令到 ~/.local/bin
./install.sh --system               # 安装命令到 /usr/local/bin，需要 sudo
./install.sh --user --dev           # 安装开发/测试依赖
./install.sh --user --force         # 重建虚拟环境后安装
./install.sh --user --no-system-deps # 跳过 apt 系统依赖安装
```

安装后如果提示找不到 `binmind`，把 `~/.local/bin` 加入 PATH：

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

验证：

```bash
binmind --help
binmind version
```

## 安装方式二：手动虚拟环境安装

适合不想运行安装脚本的情况：

```bash
cd ~/BinMind
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements-core.txt
pip install -e .
```

如果需要完整功能，包括 angr、FastAPI、frida、graphviz 等：

```bash
pip install -r requirements.txt
pip install -e .[full]
```

开发/测试环境：

```bash
pip install -r requirements-dev.txt
pip install -e .[dev]
```

验证：

```bash
binmind --help
binmind version
```

如果还没有把入口命令安装到 PATH，也可以在项目根目录直接运行：

```bash
./binmind --help
./binmind version
```

## 从 Windows 复制到 WSL 后安装

如果项目在 Windows：

```text
E:\win_c\Desktop\BinMind
```

在 WSL 中对应路径通常是：

```bash
/mnt/e/win_c/Desktop/BinMind
```

复制到 WSL 家目录：

```bash
cp -r "/mnt/e/win_c/Desktop/BinMind" ~/BinMind
cd ~/BinMind
./install.sh --user
```

如果你已经在 `~/BinMind` 中，只需要同步当前 Windows 项目内容，可以使用：

```bash
rsync -a --delete "/mnt/e/win_c/Desktop/BinMind/" "$HOME/BinMind/"
```

## 语言设置

BinMind 支持中文/英文输出，默认跟随环境变量 `BINMIND_LANGUAGE`。

中文：

```bash
export BINMIND_LANGUAGE=zh
```

英文：

```bash
export BINMIND_LANGUAGE=en
```

持久化中文输出：

```bash
echo 'export BINMIND_LANGUAGE=zh' >> ~/.bashrc
source ~/.bashrc
```

## LLM 配置

未配置 LLM 时，部分报告会以模板/模拟模式生成，并标注 `simulation=true`。如需启用 LLM 分析，请配置 OpenAI 兼容接口环境变量：

```bash
export AI_MODEL="gpt-4o-mini"
export AI_PROVIDER="openai"
export API_KEY="你的 API Key"
export BASE_URL="https://api.openai.com/v1"
```

如果使用本地或第三方 OpenAI 兼容服务，将 `BASE_URL`、`AI_MODEL` 和 `AI_PROVIDER` 改为对应值即可。

不要把 API Key 写入仓库或提交到 Git。

## 基本使用

### 查看帮助

```bash
binmind --help
```

如果还没有安装入口命令，也可以在项目根目录直接运行：

```bash
./binmind --help
```

### 分析单个二进制

```bash
binmind analyze ./samples/example.bin -o ./results
```

输出 Markdown 报告：

```bash
binmind analyze ./samples/example.bin -o ./results -f markdown
```

输出 JSON 报告：

```bash
binmind analyze ./samples/example.bin -o ./results -f json
```

限制最大分析函数数量：

```bash
binmind analyze ./samples/example.bin --max-funcs 50 -o ./results
```

只分析指定函数：

```bash
binmind analyze ./samples/example.bin --functions main vuln_func -o ./results
```

包含库函数：

```bash
binmind analyze ./samples/example.bin --include-lib -o ./results
```

启用并行分析：

```bash
binmind analyze ./samples/example.bin --parallel -o ./results
```

禁用 AI 辅助：

```bash
binmind analyze ./samples/example.bin --no-ai -o ./results
```

显式启用 AI 辅助：

```bash
binmind analyze ./samples/example.bin --ai-analysis -o ./results
```

### 搭配崩溃日志分析

```bash
binmind analyze ./samples/example.bin --crash ./crash.log -o ./results
```

### 启用符号执行

需要已安装 angr：

```bash
binmind analyze ./samples/example.bin --symbolic -o ./results
```

如果未安装 angr，先执行：

```bash
pip install angr==9.2.223
```

### 批量分析目录

```bash
binmind batch ./samples -o ./results
```

指定报告格式：

```bash
binmind batch ./samples -o ./results -f json
```

## 逆向工程报告

先运行分析：

```bash
binmind analyze ./samples/example.bin -o ./results
```

再生成逆向报告：

```bash
binmind --reverse-report --binary ./samples/example.bin
```

报告默认保存到：

```text
./reports/
```

中文报告：

```bash
BINMIND_LANGUAGE=zh binmind --reverse-report --binary ./samples/example.bin
```

英文报告：

```bash
BINMIND_LANGUAGE=en binmind --reverse-report --binary ./samples/example.bin
```

## 调试工具入口

查看二进制保护机制：

```bash
binmind debug checksec ./samples/example.bin
```

查看 PLT 信息：

```bash
binmind debug plt ./samples/example.bin
```

提取关键字符串：

```bash
binmind debug strings ./samples/example.bin
```

查看 ROP gadgets：

```bash
binmind debug gadgets ./samples/example.bin
```

libc 泄露辅助：

```bash
binmind debug libc ./samples/example.bin --leak puts=0x7ffff7a5e5f0
```

符号执行调试：

```bash
binmind debug symexec ./samples/example.bin
```

## Exploit 反馈迭代

使用生成或已有脚本进行反馈闭环：

```bash
binmind feedback ./samples/example.bin --script ./exploits/poc.py --iterations 3 --timeout 30
```

如果没有初始脚本：

```bash
binmind feedback ./samples/example.bin --iterations 3
```

## 人工复核队列

列出待复核发现：

```bash
binmind review -o ./results --list
```

标记某条记录为确认漏洞：

```bash
binmind review -o ./results --index 0 --verdict confirmed
```

标记误报：

```bash
binmind review -o ./results --index 0 --verdict false_positive
```

恢复待定：

```bash
binmind review -o ./results --index 0 --verdict pending
```

## 导出与重放

导出某个二进制的分析报告：

```bash
binmind export ./samples/example.bin -o ./exported_reports
```

查看数据库中的分析状态：

```bash
binmind status
```

重放历史分析：

```bash
binmind replay 1
```

其中 `1` 是历史运行 ID。


## Fuzz 入口

BinMind 提供 fuzz 子命令，并将后续参数转发给 fuzzing CLI：

```bash
binmind fuzz --help
```

示例：

```bash
binmind fuzz --target ./samples/example.bin --output ./results/fuzz
```

具体参数以 `binmind fuzz --help` 输出为准。

## 测试

安装测试依赖：

```bash
pip install -r requirements-dev.txt
```

运行全部测试：

```bash
python -m pytest
```

或使用内置入口：

```bash
binmind --test
```

运行指定测试文件：

```bash
python -m pytest tests/test_report.py -v
```

快速语法检查：

```bash
python -m py_compile main.py binmind.py cli/commands.py core/report.py core/i18n.py modules/analysis_tools/reverse_report.py
```

## 常见问题

### 1. `binmind: command not found`

确认安装脚本是否执行成功，并检查 PATH：

```bash
export PATH="$HOME/.local/bin:$PATH"
binmind --help
```

如果未安装命令入口，也可以直接运行：

```bash
./binmind --help
```

### 2. `ModuleNotFoundError`

通常是依赖未安装或虚拟环境未激活：

```bash
cd ~/BinMind
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### 3. angr 安装慢或失败

angr 依赖较重，建议在 Linux/WSL 中安装，并使用固定版本：

```bash
pip install angr==9.2.223
```

如网络较慢，可指定镜像源：

```bash
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple angr==9.2.223
```

### 4. 报告显示 `simulation=true`

说明当前没有可用 LLM 配置，或 LLM 客户端不可用。配置 `API_KEY`、`BASE_URL`、`AI_MODEL`、`AI_PROVIDER` 后重新运行。

### 5. 中文路径问题

WSL 访问 Windows 路径时，盘符会挂载到 `/mnt/<盘符小写>/`。例如：

```text
E:\win_c\Desktop\项目\BinMind
```

对应：

```bash
/mnt/e/win_c/Desktop/项目/BinMind
```

路径中有中文或空格时，务必加引号：

```bash
cd "/mnt/e/win_c/Desktop/项目/BinMind"
```

## 授权与合规

本项目用于 CTF、靶场、教学、企业内部授权安全测试与研究。使用者需要自行确保目标、样本与网络环境均已获得授权。
