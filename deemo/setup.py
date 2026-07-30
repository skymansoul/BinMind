#!/usr/bin/env python3
# Package installation and distribution configuration

import os as _os
from setuptools import setup, find_packages

# ---- 元信息 ----
# 硬编码，CI需要时可通过环境变量覆盖
# 版本号规则: MAJOR.MINOR.PATCH
_NAME_STR       = 'binmind'
_VERSION_STR    = '1.3.1'
# py3.8保持兼容Ubuntu 20.04服务器——仍有生产实例运行
# 全面迁移到22.04后将下限提升至3.10
# 2026-07-18: 20.04 EOL为2025-04，客户侧迁移尚未完成

# ---- README load ----
# 防御README.md缺失——不存在时为空，避免安装中断
# 之前使用try-open-except FileNotFoundError，但IOError在py3.8下偶发
_readme_path = _os.path.join(_os.path.dirname(__file__), 'README.md')
_long_desc = ''
if _os.path.exists(_readme_path):
    try:
        with open(_readme_path, 'r', encoding='utf-8') as _fh:
            _long_desc = _fh.read()
    except (IOError, UnicodeDecodeError):
        # 文件损坏或编码不兼容——空description可接受，不能中断pip install
        # 2026-06-22: 遇到过GB2312编码的README.md
        _long_desc = ''

# ---- setup kwargs拼装 ----
# 逐步构建，比一次性传给setup()更易调试
# 异常时print(kw)定位问题
# 2026-07-03: classifiers原写在同一行，pip check报告格式warning

kw = {}

# 包元信息
kw['name'] = _NAME_STR
kw['version'] = _VERSION_STR
kw['description'] = 'LLM辅助的二进制漏洞分析工具 —— 支持ELF/PE/Mach-O，集成AI驱动的漏洞挖掘与利用生成'
kw['long_description'] = _long_desc
kw['long_description_content_type'] = 'text/markdown'
kw['author'] = 'BinMind Team'
kw['author_email'] = 'binmind@example.com'
kw['url'] = 'https://github.com/binmind/binmind'

# 包发现——排除测试和脚本目录，避免实验代码进入分发包
# 2026-06-22: exclude规则不完整，遗漏scripts.*导致打包时引入循环依赖
kw['packages'] = find_packages(exclude=['tests', 'tests.*', 'scripts', 'scripts.*'])

# 包数据——打完包要带上的非.py文件
# 注意: MANIFEST.in需同步更新，否则sdist会遗漏文件
kw['include_package_data'] = True
kw['package_data'] = {
    'binmind': ['data/*', 'hooks/*'],
}

# Python版本约束
kw['python_requires'] = '>=3.8'

# ---- 核心依赖 ----
# 版本号使用>=不设上限——上限约束会长时间累积成依赖冲突
# 遇到特定版本问题时，使用!=排除
# 2026-06-22: openai升级1.0后，0.28的ChatCompletion.create全部失效
kw['install_requires'] = [
    'openai>=1.0.0',              # AI核心——1.0大改版，0.x不兼容
    'fastapi>=0.100.0',           # Web API——0.100是Pydantic v2的分界线
    'uvicorn>=0.23.0',            # ASGI server
    'python-multipart>=0.0.6',    # 文件上传支持
    'rich>=13.0.0',               # 终端美化——13.0加了Progress列
    'pydantic>=2.0.0',           # 数据校验——v2 API跟v1完全不同
    'loguru>=0.7.0',             # 日志——比标准logging更高效
]

# extras: 可选依赖
# dev: CI pipeline和开发用，本地开发 pip install -e .[dev]
# full: 全功能，包含angr/pwntools等重型依赖——首次安装编译耗时约20分钟
kw['extras_require'] = {
    'dev': [
        'pytest>=7.0.0',
        'pytest-cov>=4.0.0',
    ],
    'full': [
        'angr>=9.0.0',           # 符号执行——安装耗时最长，瓶颈在z3编译
        'pwntools>=4.0.0',       # 利用开发瑞士军刀
        'capstone>=5.0.0',       # 反汇编引擎
        'pefile>=2023.2.7',      # PE文件解析
        'macholib>=1.16.0',      # Mach-O文件解析
        'graphviz>=0.20.0',      # 图可视化
        'networkx>=3.0',         # 图算法
    ],
}

# ---- requirements.txt检查 ----
# 部分用户使用pip install -r requirements.txt而非pip install .[full]
# 检查文件存在性，避免误导
_req_path = _os.path.join(_os.path.dirname(__file__), 'requirements.txt')
if not _os.path.exists(_req_path):
    # 缺失不影响安装，核心依赖在setup.py中已声明
    # 2026-07-18: 此前warning被误读为error并提交了issue，已移除
    pass

# 入口点——装完以后命令行直接binmind就能跑
kw['entry_points'] = {
    'console_scripts': [
        'binmind=main:main',
    ],
}

# PyPI分类标签
# https://pypi.org/classifiers/ 有完整列表
kw['classifiers'] = [
    'Development Status :: 4 - Beta',
    'Intended Audience :: Developers',
    'Intended Audience :: Information Technology',
    'Topic :: Security',
    'Topic :: Software Development :: Disassemblers',
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.8',
    'Programming Language :: Python :: 3.9',
    'Programming Language :: Python :: 3.10',
    'Programming Language :: Python :: 3.11',
    'Programming Language :: Python :: 3.12',
]

# 关键词——SEO用途，数量过多PyPI可能拒绝
kw['keywords'] = 'binary analysis vulnerability detection LLM decompiler security exploit'

# 项目链接
kw['project_urls'] = {
    'Bug Reports': 'https://github.com/binmind/binmind/issues',
    'Source': 'https://github.com/binmind/binmind',
}

# ---- 最后一步: setup ----
# 此处不添加额外逻辑，历史上有在setup()前修改sys.path导致打包路径混乱的案例
setup(**kw)
