"""前后验证 — API 密钥预检、生成文件语法检查、脚本自检。"""
from parallel_deep_dev.config import CONFIG


def validate_api_key() -> bool:
    """预检 API 密钥是否有效。返回 True 表示密钥可用。"""
    if not CONFIG.API_KEY:
        return False
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=CONFIG.API_KEY)
        response = client.messages.create(
            model=CONFIG.API_MODEL,
            max_tokens=1,
            messages=[{"role": "user", "content": "."}],
        )
        return bool(response)
    except anthropic.AuthenticationError:
        print("[验证] API 密钥无效或已过期")
        return False
    except anthropic.RateLimitError:
        print("[验证] API 配额已用完或频率受限")
        return False
    except Exception as e:
        print(f"[验证] API 连接失败: {e}")
        return False


def validate_generated_files(files: list[str]) -> dict[str, list[str]]:
    """对 AI 生成的文件做 Python 语法检查。返回 {status: [filenames]}。"""
    import py_compile
    ok_files: list[str] = []
    err_files: list[str] = []
    skipped: list[str] = []

    for fpath in files:
        if not fpath.endswith(".py"):
            skipped.append(fpath)
            continue
        try:
            py_compile.compile(fpath, doraise=True)
            ok_files.append(fpath)
        except py_compile.PyCompileError as e:
            print(f"  [语法错误] {fpath}: {e}")
            err_files.append(fpath)
        except Exception as e:
            print(f"  [检查失败] {fpath}: {e}")
            err_files.append(fpath)

    return {"ok": ok_files, "error": err_files, "skipped": skipped}


def self_check(script_path: str) -> bool:
    """使用 py_compile 检查脚本语法。"""
    import py_compile
    try:
        py_compile.compile(script_path, doraise=True)
        print("[自检] 语法检查通过 [OK]")
        return True
    except py_compile.PyCompileError as e:
        print(f"[自检] 语法错误: {e}")
        return False
