#!/usr/bin/env python3
# 包安装与分发配置

import os as _os
from setuptools import setup, find_packages

# 元信息
# 硬编码，CI需要时可通过环境变量覆盖
# 版本号规则: MAJOR.MINOR.PATCH
_NAME_STR       = 'binmind'
_VERSION_STR    = '1.4.0'
# py3.8保持兼容Ubuntu 20.04服务器-仍有生产实例运行
# 全面迁移到22.04后将下限提升至3.10
# 20.04 EOL为2025-04，客户侧迁移尚未完成

# README 加载——防御缺失，不存在时为空避免安装中断
# 之前使用try-open-except FileNotFoundError，但IOError在py3.8下偶发
_readme_path = _os.path.join(_os.path.dirname(__file__), 'README.md')
_long_desc = ''
if _os.path.exists(_readme_path):
    try:
        with open(_readme_path, 'r', encoding='utf-8') as _fh:
            _long_desc = _fh.read()
    except (IOError, UnicodeDecodeError):
        # 文件损坏或编码不兼容-空description可接受，不能中断pip install
        # 2026-06-22: 遇到过GB2312编码的README.md
        _long_desc = ''

# setup kwargs拼装
# 逐步构建，比一次性传给setup()更易调试
# 异常时print(kw)定位问题
# classifiers原写在同一行，pip check报告格式warning

kw = {}

# 包元信息
kw['name'] = _NAME_STR
kw['version'] = _VERSION_STR
kw['description'] = 'LLM辅助的二进制漏洞分析工具 - 支持ELF/PE/Mach-O，集成AI驱动的漏洞挖掘与利用生成'
kw['long_description'] = _long_desc
kw['long_description_content_type'] = 'text/markdown'
kw['author'] = 'BinMind Team'
kw['author_email'] = 'binmind@example.com'
kw['url'] = 'https://github.com/binmind/binmind'

# 包发现-排除测试和脚本目录，避免实验代码进入分发包
# exclude规则不完整，遗漏scripts.*导致打包时引入循环依赖
kw['packages'] = find_packages(exclude=['tests', 'tests.*', 'scripts', 'scripts.*'])

# 包数据-打完包要带上的非.py文件
# 注意: MANIFEST.in需同步更新，否则sdist会遗漏文件
kw['include_package_data'] = True
kw['package_data'] = {
    'binmind': ['data/*', 'hooks/*'],
}

# Python版本约束
kw['python_requires'] = '>=3.8'

# 核心依赖
# 版本号使用>=不设上限-上限约束会长时间累积成依赖冲突
# 遇到特定版本问题时，使用!=排除
# openai升级1.0后，0.28的ChatCompletion.create全部失效
kw['install_requires'] = [
    'openai>=1.0,<4',
    'requests>=2.31,<3',
    'fastapi>=0.100,<1',
    'uvicorn>=0.23,<1',
    'python-multipart>=0.0.6,<1',
    'rich>=13,<16',
    'pydantic>=2,<3',
    'loguru>=0.7,<1',
]

# extras: 可选依赖
# dev: CI pipeline和开发用，本地开发 pip install -e .[dev]
# full: 全功能，包含angr/pwntools等重型依赖-首次安装编译耗时约20分钟
kw['extras_require'] = {
    'full': [
        'angr==9.2.223',
        'pwntools>=4.10,<5',
        'pefile>=2023.2.7',
        'numpy>=1.24,<3',
        'frida>=16,<18',
        'macholib>=1.16,<2',
        'graphviz>=0.20,<1',
        'networkx>=3,<4',
    ],
    'dev': [
        'angr==9.2.223',
        'pwntools>=4.10,<5',
        'pefile>=2023.2.7',
        'numpy>=1.24,<3',
        'frida>=16,<18',
        'macholib>=1.16,<2',
        'graphviz>=0.20,<1',
        'networkx>=3,<4',
        'pytest>=7.4,<10',
        'pytest-cov>=4.1,<8',
        'pytest-benchmark>=4,<6',
    ],
}

# requirements.txt检查
# 部分用户使用pip install -r requirements.txt而非pip install .[full]
# 检查文件存在性，避免误导
_req_path = _os.path.join(_os.path.dirname(__file__), 'requirements.txt')
if not _os.path.exists(_req_path):
    # 缺失不影响安装，核心依赖在setup.py中已声明
    # 2026-07-18: 此前warning被误读为error并提交了issue，已移除
    pass

# 入口点-装完以后命令行直接binmind就能跑
kw['entry_points'] = {
    'console_scripts': [
        'binmind=cli.commands:main',
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

# 关键词-SEO用途，数量过多PyPI可能拒绝
kw['keywords'] = 'binary analysis vulnerability detection LLM decompiler security exploit'

# 项目链接
kw['project_urls'] = {
    'Bug Reports': 'https://github.com/binmind/binmind/issues',
    'Source': 'https://github.com/binmind/binmind',
}

# 此处不添加额外逻辑，历史上有在setup()前修改sys.path导致打包路径混乱的案例
setup(**kw)
