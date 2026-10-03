#!/usr/bin/env python3
"""
=============================================================================
  BinMind 深度创新并行开发脚本 — parallel_deep_dev v4.0
=============================================================================

用法:
  1. 设置环境变量:
     export ANTHROPIC_API_KEY="sk-ant-..."
     (Windows: set ANTHROPIC_API_KEY=sk-ant-...)
     可选: ANTHROPIC_BASE_URL / ANTHROPIC_MODEL 覆盖 API 端点与模型。

  2. 安装依赖:
     pip install anthropic

  3. 运行:
     python parallel_deep_dev.py                   # 完整执行
     python parallel_deep_dev.py --dry-run         # 仅生成 prompt，不调用 API
     python parallel_deep_dev.py --workers 3       # 并行数 (上限 5)
     python parallel_deep_dev.py --validate-only   # 仅校验 API 密钥
     python parallel_deep_dev.py --module ai_ml    # 指定单个子模块

时间戳策略:
  本脚本不执行任何文件时间戳伪造或回溯修改。子 agent 新增/修改的文件
  一律保留真实 mtime（写入时刻）。如需统一调整时间戳，请在脚本之外
  使用标准工具（touch / os.utime）另行处理。

各子模块创新点与支撑论文:
  ai_ml        强化学习驱动的变异算子组合选择 + 语义引导输入生成
               (R1-Fuzz, SAFuzz,
                DeepGo, LLAMAFUZZ)
  crypto       依赖引导的 LLM 增强密码学误用检测（消除静态规则假阳性）
               (CRYPTBARA ASE 2025,,,
)
  exploit      堆布局约束合成 + 上下文堆操作序列引导
               (IEEE 2025 Heap Layout Constraints, CtxFuzz JSS 2025,
                PBAEG Cybersecurity 2024)
  fuzzing      RL 后训练变异调度 + LLM 初始种子语料增强
               (R1-Fuzz, LLAMAFUZZ,
                ISC4DGF, DeepGo)
  multimodal   冗余性感知 + 模态缺失鲁棒对比融合
               (Robult, FedMAC,
)
  network      多视图异构图加密流量分类 + 环境偏移鲁棒流图
               (MH-Net, FG-SAT,
)
  patching     神经符号 + 静态分析/测试反馈的智能体修复
               (Agentic Repair, SynthFix,
)
  vuln         CPG 引导 LLM 漏洞检测 + 反事实增强鲁棒性
               (LLMxCPG, VISION,
                CodeSAGE JISA 2025, NatGVD)
  cve          语义嵌入跨源去重 + 不一致性发现
               (VuldiffFinder Comput&Sec 2025, IntelEX,
                SEvenLLM)
  data         自适应学习布隆过滤器 + 数据温度加权删除
               (Adversary-Resilient LBF,
                Learned LSM-trees, Ensemble LBF ICML 2025,
                DWLBF JKSU-CI 2025)
  distributed  图强化学习任务调度 + 动态图划分

  testing      LLM 差分测试预言机 + 优化回归检测
               (DiffSpec,,
,)
  project      GNN+DRL 的 DAG 任务调度

  core         DAG 感知的钩子/依赖加载顺序优化

  output       事件溯源可审计证据链报告
               (ESAA-Security, DEER,
                ReportLogic)
  analysis     可解释特征二进制相似性 + 神经反编译等价校验
               (Beyond Embeddings,
                Neural Decompiler Equivalence,
                Recover Function Signature CCS 2025)
  platform     事件基故障定位 + 大规模库重用识别的固件分析增强
               (FirmRCA, AutoFirm,
, Swarm-Net)
  stubs        stub 健康监控 + 神经符号渐进实现

  utils        数据温度感知缓存分层 + 冷热分离

  info         LLM 攻击级威胁情报提取 + TTP 结构化映射
               (, IntelEX,
                SEvenLLM, SecureBERT 2.0)
  info_collection  LLM 意图推断驱动的信息采集路由

预期执行总时长: 15-50 分钟（取决于并行数与 API 延迟）
API 调用次数:   约 21-26 次（每子模块一次，含失败最多重试 2 次）

=============================================================================
"""

import os
import re
import sys
import time
import argparse
import hashlib
import subprocess
import traceback
import random as _random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any




# Windows 控制台默认 GBK，重配置 UTF-8 输出防止中文乱码
if sys.stdout and getattr(sys.stdout, "encoding", "").lower() not in ("utf-8", "utf8"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and getattr(sys.stderr, "encoding", "").lower() not in ("utf-8", "utf8"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# 全局配置

class Config:
    """全局配置 — 命令行参数或环境变量均可覆盖。"""

# API 参数
    API_KEY: str = os.environ.get("ANTHROPIC_API_KEY", "")
    API_BASE_URL: str = os.environ.get("ANTHROPIC_BASE_URL", "")
    API_MODEL: str = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-20251001")
    API_MAX_TOKENS: int = 16000
    API_TEMPERATURE: float = 0.3
    API_TIMEOUT: int = 600

# 路径
    ROOT_DIR: str = os.path.dirname(os.path.abspath(__file__))

# 执行控制
    MAX_WORKERS: int = min(5, (os.cpu_count() or 4))
    MAX_RETRIES: int = 2
    DRY_RUN: bool = False

# 排除模式
    EXCLUDE_PATTERNS: list = [
        "__pycache__", ".git", ".claude", ".mypy_cache",
        ".pytest_cache", "*.pyc", "parallel_deep_dev",
        "apply_timestamps_global.py", "LOG.md",
    ]

CONFIG = Config()

# 模块定义 — 各子模块的创新点、论文依据、核心文件

MODULE_DEFINITIONS: Dict[str, dict] = {
    "ai_ml": {
        "description": (
            "AI/ML 驱动的二进制分析引擎。包含基于多臂老虎机的变异算子选择、"
            "熵引导字节位置变异、Markov 链字节转换、MinHash 种子去重、"
            "GNN 图编码器、RL 漏洞利用智能体、语义差异分析、自适应 AI 模型、"
            "集成投票、置信度校准、路径优先级排序等子系统。"
        ),
        "core_files": [
            "ai_mutator.py", "adaptive_ai_model.py", "rl_exploit_agent.py",
            "gat_graph_encoder.py", "semantic_diff.py", "ai_ensemble_voting.py",
            "ai_confidence_calibrator.py", "ai_path_prioritizer.py",
            "vector_search_accelerator.py", "ml_features.py",
        ],
        "innovation": {
            "title": "强化学习驱动的变异算子组合选择 + 语义引导输入生成 (RL-Mutate)",
            "summary": (
                "现有 MAB 调度器按 UCB 权重独立选择单个变异算子，未建模算子之间的"
                "时序依赖。借鉴 R1-Fuzz 的 GRPO 后训练思想，将变异算子选择建模为"
                "序列决策问题：(1) 组合式老虎机——以覆盖率为奖励，对 (算子, 上下文特征)"
                "二元组做注意力加权选择，借鉴 LLAMAFUZZ 的语料感知；(2) 语义预言机——"
                "借鉴 SAFuzz 对 LLM 生成代码的语义缺陷模式（幻觉资源释放、不一致错误处理）"
                "建立检测规则，指导结构感知变异；(3) DeepGo 的预测性路径奖励用于定向变异。"
                "差异点：现有 UCB 无状态、单步选择；新增方案引入序列依赖与语义反馈。"
            ),
            "papers": [
                "R1-Fuzz: Specializing Language Models for Textual Fuzzing via Reinforcement Learning — (2025). GRPO 后训练，覆盖率提升 75%。",
                "SAFuzz: Semantic-Guided Adaptive Fuzzing for LLM-Generated Code — (2026). 语义预言机 + LLM 引导自适应变异。",
                "DeepGo: Predictive Directed Greybox Fuzzing — (2025). 虚拟集成环境 + RL 路径规划。",
                "LLAMAFUZZ: Large Language Model Enhanced Greybox Fuzzing — (2024). LLM 语料感知的输入生成。",
            ],
        },
        "keywords": ["fuzzing", "reinforcement learning", "mutation", "semantic oracle"],
    },

    "crypto": {
        "description": (
            "密码学检测模块。包含加密算法检测（魔数/结构/API 字符串匹配）、"
            "密码学误用检测（ECB 模式、静态 IV、弱密钥、硬编码盐值、可预测 RNG）、"
            "污点传播、固件加密分析、区块链密码学、CBOM 生成、FPE 检测、"
            "后量子算法检测、加密流量解密等。"
        ),
        "core_files": [
            "src/crypto_detector.py", "src/crypto_misuse.py", "src/crypto_taint.py",
            "src/firmware_crypto.py", "src/blockchain_crypto.py", "src/cbom_generator.py",
            "src/fpe_detector.py", "src/crypto_traffic_decrypt.py",
            "src/entropy_analyzer.py", "src/cert_analysis.py",
            "src/hardware_hash.py", "src/pqc_ml_detector.py",
        ],
        "innovation": {
            "title": "依赖引导的 LLM 增强密码学误用检测 (DepLLM-Crypto)",
            "summary": (
                "现有模式匹配存在高假阳性。借鉴 CRYPTBARA 的依赖上下文方法："
                "(1) 数据流敏感的污点传播路径构建（密钥生成点 → 加密调用点）；"
                "(2) LLM 语义验证层——对模式命中的候选误用提取上下游依赖上下文，"
                "提交 LLM 二次确认，消除静态规则假阳性；"
                "(3) 跨文件常量折叠传播——跟踪硬编码密钥/IV 是否跨编译单元传递；"
                "(4) 借鉴 的 secrets 检测经验做密钥分类。"
                "LLM 仅在模式匹配命中时调用且结果缓存，控制开销。"
            ),
            "papers": [
                "CRYPTBARA: Dependency-Guided Detection of Python Cryptographic API Misuses — ASE 2025. 依赖上下文 + LLM 推理，F1=95.43%。",
                "Beyond Static Pattern Matching? Rethinking Automatic Cryptographic API Misuse Detection in the Era of LLMs — .",
                "Automatic Generation of a Cryptography Misuse Taxonomy Using Large Language Models — (2025). 279 种误用类别。",
                "Evaluating Large Language Models in Detecting Secrets in Android Apps — (2025).",
            ],
        },
        "keywords": ["crypto misuse", "taint analysis", "LLM validation", "dependency graph"],
    },

    "exploit": {
        "description": (
            "漏洞利用生成模块。包含自动利用生成、利用策略规划、shellcode 编码、"
            "Nuclei 模板生成、利用代码转译、利用验证器、动态适配器、模板引擎等。"
        ),
        "core_files": [
            "exploit_gen.py", "exploit_strategy.py", "shellcode_encoder.py",
            "nuclei_generator.py", "exploit_transpiler.py", "exploit_verifier.py",
            "exploit_adaptor_dynamic.py", "exploit_template_engine.py",
        ],
        "innovation": {
            "title": "堆布局约束合成 + 上下文堆操作序列引导 (HLS-Fuzz)",
            "summary": (
                "现有 exploit_gen 对堆利用场景缺少对分配/释放顺序的精确控制。"
                "借鉴基于堆布局约束的自动堆利用生成："
                "(1) 将堆状态建模为约束系统，求解可达的相邻块布局；"
                "(2) 借鉴 CtxFuzz 的上下文堆操作序列抽象，对危险函数之前的"
                "分配/释放序列做加权引导，优先生成能命中布局约束的输入；"
                "(3) 利用验证器增加布局可达性检查，避免盲目迭代。"
                "差异点：现有方法以路径覆盖为目标，新增方法以堆布局约束满足为目标。"
            ),
            "papers": [
                "Toward Automatic Heap Exploit Generation by Using Heap Layout Constraints on Binary Programs — IEEE (2025). 堆布局约束求解。",
                "CtxFuzz: Discovering heap-based memory vulnerabilities through context heap operation sequence guided fuzzing — Journal of Systems and Software (2025).",
                "PBAEG: combine-vulnerabilities AEG to defeat protection mechanisms — Cybersecurity (Springer, 2024).",
                "Nothing is unreachable — USENIX Security 2025. 可达性驱动利用生成。",
            ],
        },
        "keywords": ["heap layout", "exploit generation", "constraint solving", "AEG"],
    },

    "fuzzing": {
        "description": (
            "覆盖率引导模糊测试框架：64KB 共享内存覆盖率位图、边覆盖率元组哈希、"
            "种子调度（能量分配+队列剔除）、多臂老虎机变异策略选择、"
            "崩溃聚类去重、结构感知变异、输入最小化、差分测试、符号执行桥接、"
            "污点引导变异、语法推断、语料库优化、定向模糊测试。"
        ),
        "core_files": [
            "fuzz_integration.py", "fuzz_dictionary_generator.py",
            "fuzz_harness_optimizer.py", "fuzz_seed_evolution.py",
            "fuzz_cluster_autoscaler.py", "fuzz_suspicious_point.py",
            "fuzz_crash_triage.py", "fuzz_bandit_scheduler.py",
            "fuzz_structure_mutator.py", "fuzz_directed.py",
        ],
        "innovation": {
            "title": "RL 后训练变异调度 + LLM 初始种子语料增强 (RL-SeedFuzz)",
            "summary": (
                "现有种子调度与变异选择为启发式规则。借鉴 R1-Fuzz 的 GRPO 后训练："
                "(1) 将变异序列选择建模为策略梯度问题，以覆盖率增益为奖励；"
                "(2) 借鉴 ISC4DGF，对定向目标使用 LLM 生成初始种子语料，"
                "提升冷启动阶段的命中概率；"
                "(3) 借鉴 LLAMAFUZZ 的 LLM 语料感知，为字典与结构感知变异"
                "提供语义先验。差异点：现有调度为无状态启发式，新增方案引入"
                "策略梯度与语义先验，可学习长期依赖。"
            ),
            "papers": [
                "R1-Fuzz: Specializing Language Models for Textual Fuzzing via Reinforcement Learning — (2025). GRPO 后训练，29 个新漏洞。",
                "LLAMAFUZZ: Large Language Model Enhanced Greybox Fuzzing — (2024). LLM 语料感知输入生成。",
                "ISC4DGF: Enhancing Directed Grey-box Fuzzing with LLM-Driven Initial Seed Corpus Generation — (2024).",
                "DeepGo: Predictive Directed Greybox Fuzzing — (2025).",
            ],
        },
        "keywords": ["coverage-guided fuzzing", "reinforcement learning", "seed scheduling"],
    },

    "multimodal": {
        "description": (
            "多模态分析模块：多模态注意力、跨模态对齐、置信度评估、多阶段编排器、"
            "多目标利用适配、多核并行分析、多维统计 API。融合静态/动态/行为信号。"
        ),
        "core_files": [
            "multi_modal_attention.py", "multi_modal_alignment.py",
            "multi_modal_confidence.py", "multi_stage_orchestrator.py",
            "multi_target_exploit_adapter.py", "multicore_parallel_analyzer.py",
            "multi_dimension_stats_api.py",
        ],
        "innovation": {
            "title": "冗余性感知 + 模态缺失鲁棒对比融合 (RedunFuse)",
            "summary": (
                "现有对齐/融合在某一模态缺失或含噪时置信度骤降。借鉴 Robult 的"
                "冗余-特异分解：将各模态特征拆分为冗余部分与模态特异部分，"
                "融合时按冗余度加权；借鉴 FedMAC 的跨模态对比正则化增强缺失模态"
                "下的表征一致性；借鉴不完整模态识别工作补充缺失模态掩码生成。"
                "差异点：现有融合为静态加权，新增方案按冗余度动态分配权重，"
                "并显式建模缺失模态。"
            ),
            "papers": [
                "Robult: Leveraging Redundancy and Modality-Specific Features for Robust Multimodal Learning — (2025).",
                "FedMAC: Tackling Partial-Modality Missing in Federated Learning with Cross-Modal Aggregation and Contrastive Regularization — (2024).",
                "Towards Robust and Reliable Multimodal Misinformation Recognition with Incomplete Modality — (2025).",
            ],
        },
        "keywords": ["multimodal fusion", "missing modality", "contrastive learning", "redundancy"],
    },

    "network": {
        "description": (
            "网络分析模块：TLS 分析、pcap 处理、网络入侵检测、拓扑映射、"
            "serverless 分析、SDR 二进制分析、BLE 射频分析、mmap IO。"
        ),
        "core_files": [
            "tls_analyzer.py", "pcap_processor.py", "network_ids.py",
            "topology_mapper.py", "serverless_analyzer.py", "sdr_binary_analyzer.py",
            "ble_radio_analyzer.py", "mmap_io.py",
        ],
        "innovation": {
            "title": "多视图异构图加密流量分类 + 环境偏移鲁棒流图 (MH-Flow)",
            "summary": (
                "现有网络特征多为手工统计。借鉴 MH-Net 的多视图异构图建模："
                "以会话为节点、以 TLS 指纹/报文大小序列/时序为多视图特征构造"
                "异构图并做图分类；借鉴 FG-SAT 的流图表示，增强对网络环境偏移"
                "（重传、分片、代理）的鲁棒性；借鉴两阶段明文+密文分类方法，"
                "对可读明文段做预筛。差异点：现有方法为单一统计视图，新增方案"
                "引入多视图异构图与分布偏移鲁棒表示。"
            ),
            "papers": [
                "Revolutionizing Encrypted Traffic Classification with MH-Net: A Multi-View Heterogeneous Graph Model — .",
                "FG-SAT: Efficient Flow Graph for Encrypted Traffic Classification under Environment Shifts — (2024).",
                "Efficiently and Effectively: A Two-stage Approach to Balance Plaintext and Encrypted Text for Traffic Classification — (2024).",
            ],
        },
        "keywords": ["encrypted traffic", "graph classification", "TLS fingerprinting"],
    },

    "patching": {
        "description": (
            "自动补丁模块：补丁差异定位、补丁建议生成、自动补丁规范、自动打补丁、"
            "自动根因分析、重编译检查、CVE 知识库、补丁报告生成。"
        ),
        "core_files": [
            "auto_patcher.py", "patch_diff_locator.py", "patch_suggestion.py",
            "auto_patch_spec.py", "auto_root_cause.py", "recompiler_check.py",
            "cve_knowledge_base.py", "patch_report_composer.py",
        ],
        "innovation": {
            "title": "神经符号 + 静态分析/测试反馈的智能体修复 (AgentRepair)",
            "summary": (
                "现有补丁建议依赖规则模板，缺乏执行反馈闭环。借鉴 Agentic Program Repair"
                "的神经符号框架：将修复建模为多轮 agent 循环，每轮由静态分析提供"
                "候选位置与约束、由测试执行反馈验证修复有效性，失败则回溯重试；"
                "借鉴 SynthFix 的自适应神经符号修复，对漏洞类型做分类并选择"
                "符号约束或 LLM 生成路径。差异点：现有方案单轮模板生成，新增方案"
                "引入多轮验证-回溯闭环。"
            ),
            "papers": [
                "Agentic Program Repair from Test Failures at Scale: A Neuro-symbolic approach with static analysis and test execution feedback — (2025).",
                "SynthFix: Adaptive Neuro-Symbolic Code Vulnerability Repair — (2026).",
                "Autonomous Issue Resolver: Towards Zero-Touch Code Maintenance — (2025).",
            ],
        },
        "keywords": ["program repair", "neuro-symbolic", "test feedback", "static analysis"],
    },

    "vuln": {
        "description": (
            "漏洞检测模块：漏洞数据库、漏洞管理、LLM 漏洞检测器、利用生成流水线、"
            "模糊测试编排、YARA 管理、供应链检测、漏洞去重。"
        ),
        "core_files": [
            "vuln_db.py", "detection/vuln_management.py",
            "detection/llm_vuln_detector.py", "detection/exploit_generation_pipeline.py",
            "detection/fuzzing_orchestrator.py", "detection/yara_manager.py",
            "detection/supply_chain.py",
        ],
        "innovation": {
            "title": "CPG 引导 LLM 漏洞检测 + 反事实增强鲁棒性 (CPG-LLM-Vuln)",
            "summary": (
                "现有 LLM 漏洞检测器以源码文本为输入，缺失结构信息。借鉴 LLMxCPG："
                "构建代码属性图（CPG）并将关键路径序列化为 LLM 上下文，提升跨函数"
                "数据流理解；借鉴 VISION 的反事实增强，对训练样本做最小扰动生成"
                "对抗样本，提升检测器对攻击性扰动的鲁棒性；借鉴 CodeSAGE 的多特征"
                "融合注意力。差异点：现有输入为纯文本，新增方案引入 CPG 结构与"
                "反事实正则。"
            ),
            "papers": [
                "LLMxCPG: Context-Aware Vulnerability Detection Through Code Property Graph-Guided Large Language Models — (2025).",
                "VISION: Robust and Interpretable Code Vulnerability Detection Leveraging Counterfactual Augmentation — (2025).",
                "CodeSAGE: A multi-feature fusion vulnerability detection approach using code attribute graphs and attention mechanisms — Journal of Information Security and Applications (2025).",
                "NatGVD: Natural Adversarial Example Attack towards Graph-based Vulnerability Detection — (2025).",
            ],
        },
        "keywords": ["vulnerability detection", "code property graph", "LLM", "counterfactual"],
    },

    "cve": {
        "description": (
            "CVE 分析模块：CVE 匹配、SBOM 匹配、图神经网络漏洞图、因果对比学习、"
            "GHSA/ExploitDB 聚合、知识库、PURL/CPE 解析。"
        ),
        "core_files": [
            "src/cve_matcher.py", "src/cve_sbom_matcher.py", "src/cve_graph_gnn.py",
            "src/cve_causal_contrastive.py", "src/cve_ghsa.py",
            "src/cve_exploitdb.py", "src/cve_kb.py", "src/cve_purl_cpe.py",
        ],
        "innovation": {
            "title": "语义嵌入跨源去重 + 非结构化信息不一致性发现 (SemDedup)",
            "summary": (
                "多源 CVE 记录存在重复与冲突。借鉴 VuldiffFinder 的不一致性发现："
                "对同一 CVE 在不同源（NVD/GHSA/ExploitDB）的描述做语义嵌入相似度"
                "计算与字段级对齐，标记 CVSS 分值、受影响版本等冲突；"
                "借鉴 IntelEX 的结构化抽取将非结构化描述映射到统一模式；"
                "对去重后的实体利用因果对比学习增强版本区间嵌入。"
            ),
            "papers": [
                "VuldiffFinder: Discovering inconsistencies in unstructured vulnerability information — Computers & Security (2025).",
                "IntelEX: A LLM-driven Attack-level Threat Intelligence Extraction Framework — (2024).",
                "SEvenLLM: Benchmarking, Eliciting, and Enhancing Abilities of Large Language Models in Cyber Threat Intelligence — (2024).",
            ],
        },
        "keywords": ["CVE deduplication", "semantic embedding", "inconsistency detection"],
    },

    "data": {
        "description": (
            "数据层模块：去重、数据库访问、缓存、数据集构建、指标、GNN 评分、"
            "来源追踪。支撑上层模块的数据存取与特征存储。"
        ),
        "core_files": [
            "src/dedup.py", "src/db.py", "src/cache.py", "src/dataset_builder.py",
            "src/metrics.py", "src/gnn_scorer.py", "src/provenance.py", "main.py",
        ],
        "innovation": {
            "title": "自适应学习布隆过滤器 + 数据温度加权删除 (AdaThermoLBF)",
            "summary": (
                "现有去重/缓存使用固定布隆过滤器。借鉴 Learned LSM-trees 的学习式"
                "过滤器：为每个桶维护误判率感知的模型，热点键用更紧凑表示；"
                "借鉴 DWLBF 的数据温度加权，对冷数据支持可删除且降低误判惩罚；"
                "借鉴 Adversary-Resilient LBF 引入对抗扰动下的误判率上界保证。"
                "差异点：现有过滤器参数静态，新增方案按访问频率自适应调整"
                "每个桶的容量与模型复杂度。"
            ),
            "papers": [
                "Learned LSM-trees: Two Approaches Using Learned Bloom Filters — (2025).",
                "DWLBF: a deletable weighted learned Bloom Filter based on data temperature — Journal of King Saud University (2025).",
                "Adversary Resilient Learned Bloom Filters — (2024).",
                "Ensemble Learned Bloom Filters: Two Oracles are Better than One — ICML 2025.",
            ],
        },
        "keywords": ["learned bloom filter", "deduplication", "data temperature", "cache"],
    },

    "distributed": {
        "description": (
            "分布式执行模块：worker、节点注册、任务调度、流水线、自适应断路器、"
            "指标收集、CLI。负责多节点任务的分配与容错。"
        ),
        "core_files": [
            "worker.py", "src/node_registry.py", "src/scheduler.py",
            "src/pipeline.py", "src/adaptive_breaker.py", "src/metrics.py", "src/cli.py",
        ],
        "innovation": {
            "title": "图强化学习任务调度 + 动态图划分 (GRL-Sched)",
            "summary": (
                "现有调度为静态优先级。借鉴 GraphEdge 的动态图划分：将任务依赖图"
                "切分为可并行的子图，依据节点负载与通信代价做 GNN 编码，"
                "以完成时间为奖励做强化学习调度；对拓扑变化实时重划分。"
                "差异点：现有调度不考虑任务间通信依赖图，新增方案显式建模"
                "依赖图并在线重划分。"
            ),
            "papers": [
                "GraphEdge: Dynamic Graph Partition and Task Scheduling for GNNs Computing in Edge Network — (2025).",
            ],
        },
        "keywords": ["task scheduling", "graph neural network", "reinforcement learning"],
    },

    "testing": {
        "description": (
            "测试模块：覆盖引导的测试模糊化、差分测试、测试生成、引擎差分测试、"
            "测试编排器、符号执行桥接、类型感知模糊、三分类报告。"
        ),
        "core_files": [
            "testing_fuzzing.py", "differential_tester.py", "test_generator.py",
            "engine_differential_test.py", "test_orchestrator.py",
            "src/concolic_bridge.py", "src/type_aware_fuzz.py", "src/triage_reporter.py",
        ],
        "innovation": {
            "title": "LLM 差分测试预言机 + 优化回归检测 (DiffOracle)",
            "summary": (
                "现有差分测试依赖多实现间的行为差异，缺少语义级预言机。"
                "借鉴 DiffSpec 用自然语言规范 + 代码工件生成差分预言；"
                "借鉴 Finding Missed Code Size Optimizations 用 LLM 识别"
                "编译器/反编译器可改进处；借鉴 LLM-Powered Test Case Generation"
                "针对 tricky bug 生成针对性用例。差异点：现有预言机为纯差分，"
                "新增方案引入规范级语义约束，覆盖差分无法触发的等值行为缺陷。"
            ),
            "papers": [
                "DiffSpec: Differential Testing with LLMs using Natural Language Specifications and Code Artifacts — (2024).",
                "Finding Missed Code Size Optimizations in Compilers using LLMs — (2025).",
                "LLM-Powered Test Case Generation for Detecting Tricky Bugs — (2024).",
                "Evolutionary Generative Fuzzing for Differential Testing of the Kotlin Compiler — (2024).",
            ],
        },
        "keywords": ["differential testing", "test oracle", "LLM", "compiler testing"],
    },

    "project": {
        "description": (
            "项目管理模块：web API、漏洞知识图谱、二进制差分引擎、合规映射、"
            "数据血缘、自适应调度器、发现增强、指标异常检测。"
        ),
        "core_files": [
            "web_api.py", "vuln_knowledge_graph.py", "binary_diff_engine.py",
            "compliance_mapper.py", "data_lineage.py", "adaptive_scheduler.py",
            "finding_enricher.py", "metrics_anomaly.py",
        ],
        "innovation": {
            "title": "GNN+DRL 的 DAG 任务调度与动态重排 (DAG-DRL)",
            "summary": (
                "现有自适应调度器基于规则。借鉴 GraphEdge 的图 RL 调度：将分析任务"
                "建模为 DAG，用 GNN 编码任务依赖与资源占用，以端到端时延为奖励"
                "训练调度策略；对新增/撤销任务在线增量重排。差异点：现有规则调度"
                "缺乏对依赖图的感知，新增方案显式建模 DAG 并在线优化。"
            ),
            "papers": [
                "GraphEdge: Dynamic Graph Partition and Task Scheduling for GNNs Computing in Edge Network — (2025).",
            ],
        },
        "keywords": ["DAG scheduling", "graph neural network", "DRL"],
    },

    "core": {
        "description": (
            "核心基础设施：扁平命名空间懒加载器（_FlatFinder/sys.meta_path）、"
            "compat 兼容代理、二进制格式加载、IDS 规则生成、密码参数提取、"
            "攻击面分析、CI 集成、攻击映射、精确虚表恢复。"
        ),
        "core_files": [
            "compat/binary_format_loader.py", "compat/ids_rule_generator.py",
            "compat/crypto_param_extractor.py", "compat/attack_surface.py",
            "compat/ci_integration.py", "compat/attack_mapper.py",
            "compat/precise_vtable_recovery.py",
        ],
        "innovation": {
            "title": "DAG 感知的钩子执行与依赖加载顺序优化 (HookDAG)",
            "summary": (
                "懒加载器按元数据优先解析模块位置，但钩子之间的执行顺序与依赖"
                "关系未显式建模。借鉴图调度的依赖感知思想：为钩子注册构建依赖"
                "DAG，按拓扑序执行并支持旁路失效路径；对同一模块的多个钩子"
                "按数据依赖折叠，减少重复加载。差异点：现有钩子按注册顺序线性"
                "执行，新增方案引入依赖图与拓扑排序。"
            ),
            "papers": [
                "GraphEdge: Dynamic Graph Partition and Task Scheduling for GNNs Computing in Edge Network — (2025).",
            ],
        },
        "keywords": ["lazy loading", "hook", "DAG ordering", "dependency"],
    },

    "output": {
        "description": (
            "输出模块：报告生成、web API、证据链报告。将分析结论汇总为结构化"
            "报告与证据链。"
        ),
        "core_files": [
            "report.py", "web_api.py", "evidence_chain_report.py",
        ],
        "innovation": {
            "title": "事件溯源可审计证据链报告 (EventSourcedEvidence)",
            "summary": (
                "现有证据链报告为静态快照，无法追溯推导过程。借鉴 ESAA-Security"
                "的事件溯源架构：将每次分析动作（输入、中间结论、来源引用）记录为"
                "事件序列，报告生成时按事件回放重建证据链；借鉴 DEER 的报告结构"
                "基准评估报告的信息完整性；引入逻辑一致性检查避免结论跳步。"
                "差异点：现有报告只含结论，新增方案记录推导事件并支持回放审计。"
            ),
            "papers": [
                "ESAA-Security: An Event-Sourced, Verifiable Architecture for Agent-Assisted Security Audits of AI-Generated Code — (2026).",
                "DEER: A Benchmark for Evaluating Deep Research Agents on Expert Report Generation — (2025).",
                "ReportLogic: Evaluating Logical Quality in Deep Research Reports — (2026).",
            ],
        },
        "keywords": ["evidence chain", "event sourcing", "audit", "report generation"],
    },

    "analysis": {
        "description": (
            "静态/动态分析模块：AI 反编译、路径多样性、符号执行优化器、"
            "混合符号执行、按需符号执行、符号执行调度器、分布式符号执行。"
        ),
        "core_files": [
            "decompiler/decomp_ai.py", "symbolic/path_diversity.py",
            "symbolic/symexec_optimizer.py", "symbolic/concolic_execution.py",
            "symbolic/on_demand_symbolic.py", "symbolic/symbolic_scheduler.py",
            "symbolic/symbolic_exe.py", "symbolic/distributed_symbex.py",
        ],
        "innovation": {
            "title": "可解释特征二进制相似性 + 神经反编译等价校验 (InterpBCS)",
            "summary": (
                "现有反编译/相似性依赖嵌入向量，缺乏可解释性。借鉴 Beyond Embeddings"
                "的可解释特征提取，在函数嵌入之外输出结构化语义特征（调用模式、"
                "常量统计、CFG 形态）用于相似性判定；借鉴神经反编译等价性校验，"
                "对反编译结果与真实源码做细粒度等价检查；借鉴 CCS 2025 的函数签名"
                "恢复，提升跨架构识别。差异点：现有方法端到端黑盒，新增方案"
                "叠加可解释特征与等价性验证。"
            ),
            "papers": [
                "Beyond Embeddings: Interpretable Feature Extraction for Binary Code Similarity — (2025).",
                "Fast, Fine-Grained Equivalence Checking for Neural Decompilers — (2025).",
                "Recover Function Signature from Combined Constraints — ACM CCS 2025.",
                "Binary2vec: Cross-architecture binary embeddings with global attention-enhanced graph neural networks — Array (2025).",
            ],
        },
        "keywords": ["decompilation", "binary similarity", "symbolic execution", "interpretability"],
    },

    "platform": {
        "description": (
            "平台级分析模块：智能合约分析、逻辑炸弹检测、EDR 绕过检测、"
            "内核利用生成、固件 UEFI 分析。"
        ),
        "core_files": [
            "smart_contract/smart_contract_analyzer.py", "malware/logic_bomb_detector.py",
            "malware/edr_bypass_detector.py", "kernel/kernel_exploit_gen.py",
            "firmware/src/analyzers/uefi_analyzer.py",
        ],
        "innovation": {
            "title": "事件基故障定位 + 大规模库重用识别的固件分析增强 (FirmEvent)",
            "summary": (
                "现有固件/内核分析以静态扫描为主。借鉴 FirmRCA 的事件基故障定位："
                "在模糊测试后对崩溃样本按事件序列定位根因调用点；借鉴 AutoFirm 的"
                "大规模库重用识别，对固件内嵌库做哈希/结构匹配以复用已知 CVE；"
                "借鉴 Swarm-Net 的图网络固件验证思想增强相似性判定。差异点："
                "现有分析无执行反馈，新增方案引入事件基定位与库指纹。"
            ),
            "papers": [
                "FirmRCA: Towards Post-Fuzzing Analysis on ARM Embedded Firmware with Efficient Event-based Fault Localization — (2024).",
                "AutoFirm: Automatically Identifying Reused Libraries inside IoT Firmware at Large-Scale — (2024).",
                "Securing LLM-Generated Embedded Firmware through AI Agent-Driven Validation and Patching — (2025).",
                "Swarm-Net: Firmware Attestation in IoT Swarms using Graph Neural Networks and Volatile Memory — (2024).",
            ],
        },
        "keywords": ["firmware", "fault localization", "library reuse", "UEFI"],
    },

    "stubs": {
        "description": (
            "占位实现模块：stub 注册表、stub 健康监控、以及尚未实现的各分析器"
            "占位（固件分析、污点追踪、内核漏洞分析、字符串去混淆、补丁差异分析）。"
        ),
        "core_files": [
            "stub_registry.py", "stub_health_monitor.py", "firmware_analyzer.py",
            "taint_tracker.py", "kernel_vuln_analyzer.py", "string_unobfuscator.py",
            "patch_diff_analyzer.py",
        ],
        "innovation": {
            "title": "Stub 健康监控 + 神经符号渐进实现 (StubGradual)",
            "summary": (
                "stub 目录存放大量未实现占位。借鉴 Agentic Repair 的神经符号流程："
                "为每个 stub 生成接口契约（签名+输入输出约束+错误语义），"
                "依据健康监控得分与调用频率排序实现优先级；实现过程中以测试执行"
                "反馈验证语义正确性，未通过则回退并记录。差异点：现有 stub 为纯"
                "占位，新增方案引入契约驱动的渐进实现与验证闭环。"
            ),
            "papers": [
                "Agentic Program Repair from Test Failures at Scale: A Neuro-symbolic approach — (2025).",
                "SynthFix: Adaptive Neuro-Symbolic Code Vulnerability Repair — (2026).",
            ],
        },
        "keywords": ["stub", "interface contract", "incremental implementation"],
    },

    "utils": {
        "description": (
            "通用工具模块：LRU 缓存、定时器、二进制 IO、模式扫描、并发工具、"
            "哈希工具、字符串工具、线段树。"
        ),
        "core_files": [
            "lru.py", "timer_utils.py", "binary_io.py", "pattern_scan.py",
            "concurrent_utils.py", "hash_utils.py", "string_utils.py", "segment_tree.py",
        ],
        "innovation": {
            "title": "数据温度感知缓存分层 + 冷热分离 (ThermoLRU)",
            "summary": (
                "现有 LRU 缓存与线段树独立工作。借鉴 DWLBF 的数据温度概念："
                "以访问频率估计数据温度，将缓存分为热/温/冷三层，热层用精确索引、"
                "冷层用紧凑近似结构；借鉴对抗鲁棒布隆过滤器为冷层误判率提供"
                "上界。差异点：现有 LRU 仅按访问时间排序，新增方案显式引入"
                "温度分层与近似结构。"
            ),
            "papers": [
                "DWLBF: a deletable weighted learned Bloom Filter based on data temperature — Journal of King Saud University (2025).",
                "Adversary Resilient Learned Bloom Filters — (2024).",
            ],
        },
        "keywords": ["cache", "LRU", "data temperature", "approximate membership"],
    },

    "info": {
        "description": (
            "信息采集与情报模块：信息收集、交互式 shell、信息泄露分析、二进制信息、"
            "PII 扫描、进程伪装检测。"
        ),
        "core_files": [
            "info_collect.py", "info_collection/info_collect.py",
            "info_collection/interactive_shell.py", "info_collection/info_leak_analyzer.py",
            "info_collection/pii_scanner.py", "info_collection/process_spoofing_detector.py",
        ],
        "innovation": {
            "title": "LLM 攻击级威胁情报提取 + TTP 结构化映射 (CTI-TTP)",
            "summary": (
                "现有信息采集以关键词匹配为主。借鉴 的攻击技术识别："
                "用 LLM 从采集文本中识别并映射到 ATT&CK TTP；借鉴 IntelEX 的"
                "攻击级抽取，将多步攻击组织为攻击剧本；借鉴 SEvenLLM 的基准"
                "评估校准抽取质量。差异点：现有为关键词/正则，新增方案引入"
                "LLM 语义抽取与 TTP 结构化。"
            ),
            "papers": [
                "Towards Effective Identification of Attack Techniques in Cyber Threat Intelligence Reports using Large Language Models — (2025).",
                "IntelEX: A LLM-driven Attack-level Threat Intelligence Extraction Framework — (2024).",
                "SEvenLLM: Benchmarking, Eliciting, and Enhancing Abilities of Large Language Models in Cyber Threat Intelligence — (2024).",
                "SecureBERT 2.0: Advanced Language Model for Cybersecurity Intelligence — (2025).",
            ],
        },
        "keywords": ["OSINT", "threat intelligence", "TTP mapping", "LLM extraction"],
    },

    "info_collection": {
        "description": (
            "信息采集子模块：LLM 意图推断，负责将用户请求路由到具体采集动作。"
        ),
        "core_files": [
            "src/llm_intent_infer.py",
        ],
        "innovation": {
            "title": "LLM 意图推断驱动的信息采集路由 (IntentRoute)",
            "summary": (
                "现有意图推断为规则/小模型。借鉴 SEvenLLM 的 LLM 能力增强与"
                "IntelEX 的结构化抽取：对用户请求做意图分类（静态采集/动态交互/"
                "情报关联）并输出结构化动作参数，路由到对应采集器；对歧义请求"
                "生成澄清问题。差异点：现有路由为固定映射，新增方案引入"
                "LLM 语义分类与参数化动作。"
            ),
            "papers": [
                "SEvenLLM: Benchmarking, Eliciting, and Enhancing Abilities of Large Language Models in Cyber Threat Intelligence — (2024).",
                "IntelEX: A LLM-driven Attack-level Threat Intelligence Extraction Framework — (2024).",
            ],
        },
        "keywords": ["intent inference", "task routing", "LLM"],
    },
}

# 代码收集

def get_file_summary(filepath: str, max_lines: int = 80) -> str:
    """读取文件前 max_lines 行作为摘要快照。"""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = []
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                lines.append(line.rstrip("\n"))
        content = "\n".join(lines)
        size = os.path.getsize(filepath)
        return f"# === {os.path.relpath(filepath, CONFIG.ROOT_DIR)} ({size} 字节) ===\n{content}"
    except Exception:
        return f"# === {os.path.relpath(filepath, CONFIG.ROOT_DIR)} (读取失败) ==="

def collect_module_code(module_name: str) -> str:
    """收集指定模块关键文件的内容摘要。"""
    mod_def = MODULE_DEFINITIONS.get(module_name, {})
    core_files = mod_def.get("core_files", [])
    module_dir = os.path.join(CONFIG.ROOT_DIR, module_name)

    parts = []
    for rel in core_files:
        fpath = os.path.join(module_dir, rel)
        if os.path.isfile(fpath):
            parts.append(get_file_summary(fpath))
        else:
            # 递归查找同名文件
            hits = []
            for dirpath, dirnames, filenames in os.walk(module_dir):
                dirnames[:] = [d for d in dirnames if d != "__pycache__"]
                if os.path.basename(rel) in filenames:
                    hits.append(os.path.join(dirpath, os.path.basename(rel)))
            if hits:
                parts.append(get_file_summary(sorted(hits)[0]))
            else:
                parts.append(f"# === {module_name}/{rel} (文件不存在) ===")

    code = "\n\n".join(parts)

    # 硬截断：防止超出 API 上下文窗口
    max_code_chars = 60000
    if len(code) > max_code_chars:
        code = code[:max_code_chars] + "\n\n[... 代码已截断，总大小超出限制 ...]"
    return code

# Prompt 构建

def build_sub_prompt(module_name: str) -> str:
    """为单个子模块拼接完整开发 prompt。"""
    mod_def = MODULE_DEFINITIONS.get(module_name, {})
    if not mod_def:
        return f"# 模块 {module_name}\n\n请分析此模块并建议改进。"

    desc = mod_def.get("description", "无描述")
    innovation = mod_def.get("innovation", {})
    papers = innovation.get("papers", [])
    title = innovation.get("title", "功能增强")
    summary = innovation.get("summary", "优化和改进现有功能。")

    papers_text = "\n".join(f"  [{i+1}] {p}" for i, p in enumerate(papers)) if papers else "  (无特定论文)"

    code_context = collect_module_code(module_name)

    prompt = f"""# 深度创新开发任务 — 模块: {module_name}

# 当前模块描述
{desc}

# 设计的深度创新点: {title}

# 创新动机与理论依据
{summary}

# 支撑论文
{papers_text}

# 当前模块代码 (关键文件摘要)
```python
{code_context}
```

# 开发要求 (必须严格遵守)

# 1. 保留所有原有功能与注释
- 绝不删除或修改任何已有函数、类、枚举、变量。
- 绝不删除或修改任何已有注释（包括中文和英文注释）。
- 新增代码只能追加在文件末尾或作为新的独立文件添加。

# 2. 新增注释规范
- 使用中文理性风格注释：仅陈述设计意图、算法依据、边界条件、与参考论文的对应关系。
- 禁止情绪化表达与无关事实陈述。
- 示例格式：
  ```python
  # 设计依据: R1-Fuzz GRPO 奖励建模，
  # 以覆盖率增益为唯一奖励源，避免稀疏奖励导致的训练发散。
  # 边界: 当状态维度超过 100 时降级为上下文老虎机，防止组合爆炸。
  def _grpo_mutation_reward(state_vector, coverage_gain):
      ...
  ```

# 3. 代码风格要求
- 编写自然、一致、可维护的代码：错误处理方式应贴合函数实际场景（不同函数使用
  不同粒度的异常处理，不必统一模板），命名风格与所在文件既有风格保持一致。
- 避免机械重复：核心算法给出详细注释，简单辅助函数仅一行注释，注释疏密自然。
- 绝不为了风格统一而破坏代码正确性，所有功能必须可运行。

# 4. 文件时间戳
- 不要修改任何文件的时间戳。时间戳由主控脚本处理。

# 输出格式要求

你必须返回所有需要新增或修改的文件的完整内容。对每个文件使用以下分隔符格式：

```
===FILE_START: {module_name}/新文件名.py ===
# 完整文件内容
===FILE_END: {module_name}/新文件名.py ===
```

对于需要修改的现有文件（追加内容），也提供完整文件内容。

请确保：
1. 每个新增文件至少包含 100 行有意义的代码（非注释非空行）。
2. 文件直接写在 {module_name}/ 目录下（flat structure，子目录可用 src/）。
3. 所有 import 语句使用相对导入（如 from .xxx import yyy）或标准库。
4. 代码可以直接运行，不需要额外安装依赖（除非已有可选依赖检测模式）。

现在，请为模块 `{module_name}` 实现上述创新点。"""
    return prompt

SYSTEM_PROMPT = """你是一个深度技术专家，负责为现有 Python 代码库实现创新性功能增强。

核心原则：
1. 保留所有现有代码和注释，绝不删除或修改。
2. 新增代码以独立文件或文件末尾追加的形式提供。
3. 注释使用中文理性风格：仅陈述设计意图、算法依据、边界条件。
4. 编写自然、一致、可维护的代码；错误处理贴合场景，避免机械重复。
5. 返回完整文件内容，用 ===FILE_START: path === / ===FILE_END: path === 分隔。"""

# API 调用

def call_anthropic_api(system_prompt: str, user_prompt: str, module_name: str) -> Optional[str]:
    """调用 Anthropic Claude API，返回响应文本。"""
    if CONFIG.DRY_RUN:
        print(f"  [DRY-RUN] {module_name}: 跳过 API 调用")
        return f"[DRY-RUN] 模块 {module_name} 的模拟响应"

    if not CONFIG.API_KEY:
        print(f"  [跳过] {module_name}: ANTHROPIC_API_KEY 未设置")
        return None

    try:
        from anthropic import Anthropic
    except ImportError:
        print(f"  [错误] {module_name}: anthropic 库未安装，请执行 pip install anthropic")
        return None

    client_kwargs = {"api_key": CONFIG.API_KEY, "timeout": CONFIG.API_TIMEOUT}
    if CONFIG.API_BASE_URL:
        client_kwargs["base_url"] = CONFIG.API_BASE_URL
    client = Anthropic(**client_kwargs)

    for attempt in range(CONFIG.MAX_RETRIES + 1):
        try:
            if attempt > 0:
                wait = 2 ** attempt
                print(f"  [重试 {attempt}/{CONFIG.MAX_RETRIES}] {module_name}: 等待 {wait}s...")
                time.sleep(wait)

            print(f"  [API] {module_name}: 发送请求 (模型={CONFIG.API_MODEL}, tokens={CONFIG.API_MAX_TOKENS})...")
            t0 = time.time()

            response = client.messages.create(
                model=CONFIG.API_MODEL,
                max_tokens=CONFIG.API_MAX_TOKENS,
                temperature=CONFIG.API_TEMPERATURE,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )

            elapsed = time.time() - t0
            text = response.content[0].text if hasattr(response.content[0], 'text') else str(response.content[0])
            print(f"  [OK] {module_name}: 响应长度={len(text)} 字符, 耗时={elapsed:.1f}s")
            return text

        except Exception as e:
            print(f"  [错误] {module_name} (尝试 {attempt+1}/{CONFIG.MAX_RETRIES+1}): {e}")
            if attempt >= CONFIG.MAX_RETRIES:
                print(f"  [失败] {module_name}: 超过最大重试次数")
                return None

    return None

# 响应解析与文件写入

def parse_and_write_files(module_name: str, response_text: str) -> List[str]:
    """解析响应文本，提取文件内容写入磁盘。返回已写入的文件路径列表。"""
    written_files = []
    module_dir = os.path.join(CONFIG.ROOT_DIR, module_name)
    os.makedirs(module_dir, exist_ok=True)

    # 匹配 ===FILE_START: path === ... ===FILE_END: path ===
    pattern = r'===FILE_START:\s*(\S+)\s*===\n(.*?)===FILE_END:\s*\1\s*==='
    matches = list(re.finditer(pattern, response_text, re.DOTALL))

    if not matches:
        # 宽松回退
        pattern2 = r'===FILE_START:\s*(\S+)\s*===\s*(.*?)\s*===FILE_END:'
        matches = list(re.finditer(pattern2, response_text, re.DOTALL))

    if not matches:
        # 代码块 fallback
        code_block_pattern = r'```python\n# File:\s*(\S+)\n(.*?)```'
        matches = list(re.finditer(code_block_pattern, response_text, re.DOTALL))

    for match in matches:
        try:
            rel_path = match.group(1).strip()
            content = match.group(2)

            # 路径规范化：剥离可能的前缀
            if rel_path.startswith(f"{module_name}/"):
                rel_path = rel_path[len(module_name) + 1:]
            elif rel_path.startswith(f"modules/{module_name}/"):
                rel_path = rel_path[len(f"modules/{module_name}/") + 1:]

            # 确保落在模块目录内
            full_path = os.path.join(module_dir, rel_path)
            full_path = os.path.normpath(full_path)

            # 安全边界：禁止写回模块目录外
            if not full_path.startswith(os.path.normpath(module_dir)):
                print(f"  [安全] 拒绝写入模块外路径: {rel_path}")
                continue

            # 按需创建子目录
            os.makedirs(os.path.dirname(full_path), exist_ok=True)

            # 判断是否覆盖已有文件
            is_update = os.path.exists(full_path)

            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)

            written_files.append(full_path)
            tag = "[更新]" if is_update else "[新建]"
            print(f"  {tag} {rel_path} ({len(content)} 字符)")

        except Exception as e:
            print(f"  [写入错误] {match.group(1)}: {e}")

    # 无匹配时保存原始响应到 fallback 文件
    if not written_files:
        fallback_path = os.path.join(module_dir, f"_ai_response_{module_name}.txt")
        with open(fallback_path, "w", encoding="utf-8") as f:
            f.write(response_text)
        print(f"  [fallback] 未解析到文件，原始响应保存至 _ai_response_{module_name}.txt")

    return written_files

# 文件哈希快照

def snapshot_tree_hashes(root_dir: str) -> Dict[str, str]:
    """生成目录树下所有 .py 文件的 SHA256 快照。"""
    hashes = {}
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d != "__pycache__" and d != ".git"]
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "rb") as f:
                    hashes[fpath] = hashlib.sha256(f.read()).hexdigest()
            except Exception:
                pass
    return hashes

# 代码质量抽查审计

def audit_module_output(module_name: str, files_written: List[str]):
    """抽查审计：检测新增代码中是否存在机械重复模式。"""
    patterns_to_check = [
        (r"def \w+\(self, \w+: \w+\) -> \w+:", "统一的类型注解模式"),
        (r"logger\.(info|debug|warning)\(f\"", "f-string 日志模式"),
        (r"except Exception as e:\s*\n\s*logger\.error", "相同的异常处理模式"),
    ]

    for fpath in files_written[:3]:  # 仅抽查前 3 个文件
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            continue

        issues = []
        for pattern, desc in patterns_to_check:
            matches = re.findall(pattern, content, re.MULTILINE)
            if len(matches) > 5:
                issues.append(f"{desc}: 出现 {len(matches)} 次")

        if issues:
            print(f"  [审计] {module_name}/{os.path.basename(fpath)}: 发现潜在机械重复模式")
            for issue in issues:
                print(f"    - {issue}")
        else:
            print(f"  [审计] {module_name}/{os.path.basename(fpath)}: 无明显机械重复模式")

# 主执行逻辑

def process_module(module_name: str) -> Dict[str, Any]:

    """处理单个模块：构建 prompt、调 API、写文件。"""
    result = {
        "module": module_name,
        "success": False,
        "files_written": [],
        "error": None,
        "response_len": 0,
    }

    try:
        mod_def = MODULE_DEFINITIONS.get(module_name)
        if not mod_def:
            result["error"] = f"模块 {module_name} 未在 MODULE_DEFINITIONS 中定义"
            return result

        print(f"\n{'=' * 50}")
        print(f"  处理模块: {module_name}")
        print(f"  创新点: {mod_def['innovation']['title']}")
        print(f"{'=' * 50}")

        # 构建 prompt
        print(f"  [准备] 收集代码摘要...")
        sub_prompt = build_sub_prompt(module_name)
        print(f"  [准备] prompt 长度: {len(sub_prompt)} 字符")

        response = call_anthropic_api(SYSTEM_PROMPT, sub_prompt, module_name)

        if response is None:
            result["error"] = "API 调用失败 (无响应)"
            return result

        result["response_len"] = len(response)

        # 解析并写入文件
        files_written = parse_and_write_files(module_name, response)
        result["files_written"] = files_written
        result["success"] = len(files_written) > 0

        if not files_written:
            result["error"] = "响应中未解析到文件内容"

        # 随机触发抽查审计（15% 概率）
        if files_written and _random.random() < 0.15:
            audit_module_output(module_name, files_written)

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        result["traceback"] = traceback.format_exc()
        print(f"  [异常] {module_name}: {e}")

    return result

def validate_api_key() -> bool:
    """校验 API 密钥是否可用。"""
    if not CONFIG.API_KEY:
        print("[验证] ANTHROPIC_API_KEY 未设置")
        return False
    try:
        from anthropic import Anthropic
        client_kwargs = {"api_key": CONFIG.API_KEY, "timeout": 30}
        if CONFIG.API_BASE_URL:
            client_kwargs["base_url"] = CONFIG.API_BASE_URL
        client = Anthropic(**client_kwargs)
        response = client.messages.create(
            model=CONFIG.API_MODEL,
            max_tokens=10,
            messages=[{"role": "user", "content": "OK"}],
        )
        print(f"[验证] API 密钥有效 (模型: {CONFIG.API_MODEL})")
        return True
    except Exception as e:
        print(f"[验证] API 密钥验证失败: {e}")
        return False

def self_check(script_path: str) -> bool:
    """语法自检：编译自身检查语法错误。"""
    try:
        subprocess.run(
            [sys.executable, "-m", "py_compile", script_path],
            check=True, capture_output=True, text=True
        )
        print(f"[自检] {os.path.basename(script_path)} 语法检查通过")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[自检错误] {os.path.basename(script_path)}:\n{e.stderr}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="BinMind 深度创新并行开发脚本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--dry-run", action="store_true", help="仅生成 prompt 文件，不调用 API")
    parser.add_argument("--workers", type=int, default=CONFIG.MAX_WORKERS, help="并行线程数 (上限 5)")
    parser.add_argument("--validate-only", action="store_true", help="仅验证 API 密钥")
    parser.add_argument("--module", type=str, help="仅处理指定模块")
    parser.add_argument("--skip-audit", action="store_true", help="跳过抽查审计")
    args = parser.parse_args()

    # 同步配置
    CONFIG.DRY_RUN = args.dry_run
    CONFIG.MAX_WORKERS = min(args.workers, 5)

    print("=" * 60)
    print("  BinMind 深度创新并行开发脚本 v4.0")
    print("=" * 60)
    print(f"  目标目录: {os.path.basename(CONFIG.ROOT_DIR)}")
    print(f"  定义模块: {len(MODULE_DEFINITIONS)} 个")
    print(f"  并行线程: {CONFIG.MAX_WORKERS}")
    print(f"  API 模型:  {CONFIG.API_MODEL}")
    mode = "DRY-RUN" if CONFIG.DRY_RUN else "LIVE"
    if args.validate_only:
        mode = "VALIDATE-ONLY"
    print(f"  模式:      {mode}")
    print(f"  API 密钥:  {'已设置' if CONFIG.API_KEY else '未设置'}")
    print("=" * 60)

    # 自检
    script_path = os.path.abspath(__file__)
    if not self_check(script_path):
        return 1

    # 仅验证模式
    if args.validate_only:
        if validate_api_key():
            return 0
        return 1

    # 选择范围
    if args.module:
        if args.module in MODULE_DEFINITIONS:
            target_modules = {args.module: MODULE_DEFINITIONS[args.module]}
        else:
            print(f"[错误] 未知模块: {args.module}")
            print(f"  可用模块: {', '.join(sorted(MODULE_DEFINITIONS.keys()))}")
            return 1
    else:
        target_modules = MODULE_DEFINITIONS

    print(f"\n[计划] 将处理 {len(target_modules)} 个模块:")
    for name, defn in target_modules.items():
        print(f"  - {name}: {defn['innovation']['title']}")

    if CONFIG.DRY_RUN:
        print("\n[DRY-RUN 模式] 仅生成 prompt 文件，不调用 API")
        prompt_dir = os.path.join(CONFIG.ROOT_DIR, "_dry_run_prompts")
        os.makedirs(prompt_dir, exist_ok=True)
        for module_name in target_modules:
            prompt = build_sub_prompt(module_name)
            fpath = os.path.join(prompt_dir, f"{module_name}_prompt.txt")
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(prompt)
            print(f"  [已保存] {fpath} ({len(prompt)} 字符)")
        print(f"\n所有 prompt 已保存到 {prompt_dir}/")
        return 0

    if not CONFIG.API_KEY:
        print("\n[错误] ANTHROPIC_API_KEY 未设置。请设置环境变量后重试:")
        print("  export ANTHROPIC_API_KEY='sk-ant-...'")
        print("  或使用 --dry-run 模式仅生成 prompt 文件。")
        return 1

    # 记录变更前哈希
    print("\n[快照] 记录变更前文件哈希...")
    hashes_before = snapshot_tree_hashes(CONFIG.ROOT_DIR)

# 并行执行
    print(f"\n[执行] 开始并行处理 (workers={CONFIG.MAX_WORKERS})...")
    t_start = time.time()

    results = {}
    with ThreadPoolExecutor(max_workers=CONFIG.MAX_WORKERS) as executor:
        future_to_module = {
            executor.submit(process_module, name): name
            for name in target_modules
        }

        for future in as_completed(future_to_module):
            module_name = future_to_module[future]
            try:
                result = future.result()
                results[module_name] = result
            except Exception as e:
                results[module_name] = {
                    "module": module_name,
                    "success": False,
                    "error": f"Future 异常: {e}",
                    "files_written": [],
                }

    t_elapsed = time.time() - t_start

# 结果汇总
    print(f"\n{'=' * 60}")
    print(f"  执行完成 — 总耗时 {t_elapsed:.0f}s")
    print(f"{'=' * 60}")

    success_count = sum(1 for r in results.values() if r["success"])
    fail_count = len(results) - success_count
    total_files = sum(len(r["files_written"]) for r in results.values())

    print(f"  成功: {success_count}/{len(results)}")
    print(f"  失败: {fail_count}/{len(results)}")
    print(f"  文件: {total_files} 个")

    if fail_count > 0:
        print(f"\n  失败模块:")
        for name, r in results.items():
            if not r["success"]:
                print(f"    - {name}: {r.get('error', '未知错误')}")

# 变更文件统计（不修改时间戳）
    print(f"\n[统计] 计算本次运行变更文件...")
    hashes_after = snapshot_tree_hashes(CONFIG.ROOT_DIR)

    changed_files = []
    for fpath, new_hash in hashes_after.items():
        old_hash = hashes_before.get(fpath, "")
        if old_hash != new_hash:
            changed_files.append(fpath)

    print(f"[统计] 检测到 {len(changed_files)} 个变更文件")
    print("[时间戳] 本脚本不做时间戳伪造；写入文件保留真实 mtime。"
          "如需统一调整，请在脚本之外使用 os.utime/touch 自行处理。")

# 最终报告
    print(f"\n{'=' * 60}")
    print(f"  成果摘要")
    print(f"{'=' * 60}")
    for name in sorted(target_modules.keys()):
        r = results.get(name, {})
        status = "\u2713" if r.get("success") else "\u2717"
        title = MODULE_DEFINITIONS[name]["innovation"]["title"]
        papers_count = len(MODULE_DEFINITIONS[name]["innovation"].get("papers", []))
        file_count = len(r.get("files_written", []))
        print(f"  {status} {name}: {title}")
        print(f"       论文: {papers_count} 篇 | 文件: {file_count} 个")

    return 0 if fail_count == 0 else 2

if __name__ == "__main__":
    sys.exit(main())
