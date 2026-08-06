# info_collection/ 意图推断模块
# 顶层模块，通过 core/compat 桥接保留旧版导入路径。
from .src.llm_intent_infer import KillChainPhase, IntentReport, LLMIntentInferrer
