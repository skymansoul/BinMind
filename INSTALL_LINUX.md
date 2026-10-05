# Linux 安装说明

本项目支持在 Ubuntu 和 Kali 中安装 `binmind` 命令。安装完成后，可以直接在终端中使用：

```bash
binmind --help
```

## 一键安装

在项目根目录执行：

```bash
chmod +x install.sh binmind
./install.sh --system
binmind --help
```

`install.sh` 会自动完成以下工作：

- 使用 `apt-get` 安装 Ubuntu/Kali 所需的系统依赖。
- 创建项目内 Python 虚拟环境 `.venv`。
- 使用 `.venv` 安装 `requirements.txt` 中的 Python 依赖。
- 将 `binmind` 注册为系统命令。
- 需要管理员权限时，会自动调用 `sudo`。

## 配置 AI 服务

AI 服务支持通过环境变量配置（读取逻辑见 `deemo/core/ai_backends.py` 与 `deemo/config.py`），环境变量优先于 `config.py`；也可直接编辑项目根目录下 `config.py` 中的默认值。常用环境变量：

- `AI_PROVIDER`：模型服务商（`openai`/`anthropic`/`ollama`/`deepseek`，缺省回退 `config.AI_PROVIDER`）
- `API_KEY` / `BASE_URL`：OpenAI 兼容服务的密钥与接口地址
- `ANTHROPIC_API_KEY`：Anthropic 服务密钥
- `OLLAMA_BASE_URL`：Ollama 服务地址
- `AI_MODEL`：默认模型名

OpenAI 示例：

```bash
export AI_PROVIDER=openai
export AI_MODEL=gpt-4
export API_KEY=sk-xxxx
export BASE_URL=https://api.openai.com/v1
```

Ollama 示例：

```python
AI_PROVIDER = AI_PROVIDER_OLLAMA
OLLAMA_HOST = 'http://localhost:11434'
OLLAMA_MODEL = 'llama2'
```

## 用户目录安装

如果不想安装到 `/usr/local/bin`，可以安装到当前用户目录：

```bash
chmod +x install.sh binmind
./install.sh --user
binmind -help
```

如果提示 `binmind` 找不到，说明 `~/.local/bin` 不在 `PATH` 中。把下面这一行加入 `~/.bashrc` 或 `~/.zshrc`：

```bash
export PATH="$HOME/.local/bin:$PATH"
```

然后重新打开终端，或执行：

```bash
source ~/.bashrc
```

## 只安装命令

如果依赖已经装好，只想注册 `binmind` 命令：

```bash
./install.sh --system --no-deps
```

用户目录安装同理：

```bash
./install.sh --user --no-deps
```

## 自定义命令名

默认命令名是 `binmind`。如需改名：

```bash
COMMAND_NAME=mybin ./install.sh --system
mybin -help
```

## 自定义虚拟环境目录

默认虚拟环境路径是项目根目录下的 `.venv`。如需指定其他目录：

```bash
VENV_DIR="$HOME/.venvs/binmind" ./install.sh --system
binmind -help
```

## 常见问题

如果 `apt-get` 不存在，脚本会跳过系统依赖安装。这种情况下需要手动安装 `python3`、`python3-pip`、`python3-venv`、`radare2` 等依赖。

如果 Python 依赖安装失败，通常是网络或编译依赖问题。可以重新执行：

```bash
./install.sh --system
```
