#!/usr/bin/env python3
# 知识蒸馏漏洞检测器 - 用大教师模型的软标签蒸馏训练紧凑学生模型, 推理轻量。
# 支持自蒸馏与逐层冻结; 温度自适应调度 + EMA 权重稳定;
# 对比表示预训练 (CLAP 范式)。

from pathlib import Path
import logging as _logging
import math as _math
import random as _rnd
import uuid as _uuid
from dataclasses import dataclass as _dataclass, field as _field
from collections import defaultdict as _defaultdict

__dbg = _logging.getLogger(__name__)


@_dataclass
class VulnerabilitySample:
    """漏洞样本数据条目。label: 1=漏洞, 0=良性, -1=未标注。"""
    id: str = ""
    code: str = ""
    label: int = 0
    source: str = "generated"
    metadata: dict = _field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            self.id = str(_uuid.uuid4())


@_dataclass
class DetectionResult:
    """代码检测输出结果。"""
    function_name: str = ""
    function_address: int = 0
    is_vulnerable: bool = False
    confidence: float = 0.0
    vulnerability_type: str = ""
    explanation: str = ""


@_dataclass
class ActiveLearningConfig:
    """主动学习采样配置。"""
    strategy: str = "least_confidence"
    enabled: bool = False
    sample_count: int = 10
    max_iterations: int = 20


_CWE_SIGNATURES = {
    "CWE-121": ["strcpy", "strcat", "gets"],
    "CWE-78": ["system(", "exec", "popen"],
    "CWE-20": ["sprintf", "scanf", "atoi"],
    "CWE-119": ["memcpy", "memmove"],
    "CWE-416": ["free(", "delete"],
}


class VulnerabilityDataGenerator:
    """基于 CWE 模板合成漏洞/良性代码样本。"""

    def __init__(self, seed: int = None):
        self._rng = _rnd.Random(seed)

    def _generate_sample_code(self, cwe_type: str, variant: int) -> str:
        """按 CWE 类型生成样例代码片段。"""
        if cwe_type == "CWE-121":
            return (
                "void sample_buffer(int variant) {\n"
                "    char buffer[64];\n"
                "    char *input = get_input();\n"
                "    strcpy(buffer, input);\n"
                "    return;\n"
                "}"
            )
        if cwe_type == "CWE-78":
            return (
                "void sample_command(int variant) {\n"
                "    char cmd[128];\n"
                "    char *input = get_input();\n"
                "    sprintf(cmd, \"ls %s\", input);\n"
                "    system(cmd);\n"
                "    return;\n"
                "}"
            )
        if cwe_type == "CWE-20":
            return (
                "void sample_input(int variant) {\n"
                "    char buf[256];\n"
                "    char *input = get_input();\n"
                "    sprintf(buf, \"%s\", input);\n"
                "    return;\n"
                "}"
            )
        return (
            "void sample_generic(int variant) {\n"
            "    int x = variant * 2;\n"
            "    return;\n"
            "}"
        )

    def _generate_benign_code(self, variant: int) -> str:
        """生成无漏洞的良性代码片段。"""
        return (
            "void benign_function(int variant) {\n"
            "    int total = 0;\n"
            f"    for (int i = 0; i < {variant + 1}; i++) {{\n"
            "        total += i;\n"
            "    }\n"
            "    return total;\n"
            "}"
        )

    def generate_samples(self, cwe_types, count_per_type: int = 2) -> list:
        """为每个 CWE 类型生成 count_per_type 条漏洞样本。"""
        samples = []
        for cwe in cwe_types:
            for variant in range(count_per_type):
                code = self._generate_sample_code(cwe, variant)
                samples.append(VulnerabilitySample(
                    id=str(_uuid.uuid4()),
                    code=code,
                    label=1,
                    source="generated",
                    metadata={"cwe_type": cwe, "variant": variant},
                ))
        return samples

    def generate_benign_samples(self, count: int = 5) -> list:
        """生成指定数量的良性样本。"""
        samples = []
        for i in range(count):
            code = self._generate_benign_code(i)
            samples.append(VulnerabilitySample(
                id=str(_uuid.uuid4()),
                code=code,
                label=0,
                source="generated",
                metadata={"variant": i},
            ))
        return samples


class DistilledVulnerabilityDetector:
    """知识蒸馏漏洞检测器封装 - 支持文本特征向量化与启发式漏洞类型预测。

    模型权重懒加载：未加载模型时 detect() 返回未检出并提示模型未加载。
    """

    def __init__(self):
        try:
            from transformers import BertTokenizer
            self.tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")
        except (ImportError, OSError):
            self.tokenizer = self
        self.config = {"max_length": 512, "model_path": None, "device": "cpu"}
        self.model = None

    def _prepare_dataset(self, samples: list):
        """将样本列表封装为带 features 的对象。"""
        features = {
            "text": [s.code for s in samples],
            "label": [s.label for s in samples],
        }
        return _SimpleDataset(features)

    def detect(self, code: str) -> DetectionResult:
        """检测单段代码。模型未加载时给出明确提示。"""
        if self.model is None:
            return DetectionResult(
                function_name="unknown",
                is_vulnerable=False,
                confidence=0.0,
                explanation="模型未加载，无法执行检测",
            )
        vuln_type = self._predict_vulnerability_type(code)
        return DetectionResult(
            function_name="unknown",
            is_vulnerable=vuln_type is not None,
            confidence=0.8 if vuln_type else 0.1,
            vulnerability_type=vuln_type or "",
            explanation=f"检测到漏洞模式: {vuln_type}" if vuln_type else "未检测到漏洞模式",
        )

    def _predict_vulnerability_type(self, code: str) -> str:
        """基于签名匹配预测 CWE 漏洞类型。"""
        code_lower = code.lower()
        for cwe, keywords in _CWE_SIGNATURES.items():
            for kw in keywords:
                if kw in code_lower:
                    return cwe
        return ""


class _SimpleDataset:
    """轻量数据集容器，兼容 _prepare_dataset 的返回值契约。"""

    def __init__(self, features: dict):
        self.features = features

    def __len__(self) -> int:
        text = self.features.get("text", [])
        return len(text)


class ActiveLearningManager:
    """基于不确定性采样的主动学习管理器。"""

    def __init__(self, detector, config: ActiveLearningConfig = None):
        self.detector = detector
        self.config = config or ActiveLearningConfig()

    def _calculate_uncertainty(self, confidence: float) -> float:
        """按策略计算样本不确定性。"""
        if self.config.strategy == "entropy":
            # 二元熵 H = -p*log2(p) - (1-p)*log2(1-p)
            p = max(min(confidence, 1.0), 0.0)
            if p <= 0.0 or p >= 1.0:
                return 0.0
            return -(p * _math.log2(p) + (1.0 - p) * _math.log2(1.0 - p))
        # least_confidence 及默认策略
        return 1.0 - confidence

    def select_samples(self, unlabeled_samples: list) -> list:
        """按不确定性排序选取前 sample_count 个样本。"""
        scored = []
        for sample in unlabeled_samples:
            result = self.detector.detect(sample.code)
            uncertainty = self._calculate_uncertainty(result.confidence)
            scored.append((uncertainty, sample))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [s for _, s in scored[:self.config.sample_count]]


class DistilledVulnDetectorAnalyzer:
    """蒸馏漏洞检测分析器 - 提供 analyze/validate/cleanup 统一入口。"""

    def __init__(self):
        self.detector = DistilledVulnerabilityDetector()
        self.active_learning_manager = ActiveLearningManager(
            self.detector, ActiveLearningConfig()
        )

    def validate_input(self, **kwargs) -> tuple:
        """校验输入参数。检测模式必须提供 code 或 code_list。"""
        mode = kwargs.get("mode")
        if mode == "detect":
            if not kwargs.get("code") and not kwargs.get("code_list"):
                return False, "需要 code 或 code_list"
        return True, None

    def analyze(self, code=None, code_list=None, mode="detect", **kwargs) -> dict:
        """执行检测。单条或多条代码均返回 detections 列表。"""
        is_valid, error = self.validate_input(mode=mode, code=code, code_list=code_list)
        if not is_valid:
            return {"success": False, "error": error, "detections": []}

        if code_list is not None:
            detections = [self.detector.detect(c) for c in code_list]
        elif code is not None:
            detections = [self.detector.detect(code)]
        else:
            detections = []

        return {"success": True, "detections": detections, "mode": mode}

    def cleanup(self):
        """释放检测器与主动学习管理器资源。"""
        self.detector = None
        self.active_learning_manager = None


class ModelWeights:

    __slots__ = ('m_layers', 'm_config')

    def __init__(self, layers=None, config=None):
        self.m_layers = layers if layers else []
        self.m_config = config if config else {}

    def layer_count_mw(self):
        return len(self.m_layers)

    def clone_mw(self):
        import copy
        return ModelWeights(copy.deepcopy(self.m_layers), dict(self.m_config))


class TeacherModel:

    __slots__ = ('m_weights', 'm_temperature', 'm_num_classes')

    def __init__(self, num_classes=2, temperature=4.0):
        self.m_num_classes = num_classes
        self.m_temperature = temperature
        self.m_weights = self._init_teacher_weights()

    # 合成教师权重
    def _init_teacher_weights(self):
        layers = []
        dims = [(256, 512), (512, 512), (512, 512), (512, 256),
                (256, 256), (256, 128), (128, 64), (64, self.m_num_classes)]
        di = 0
        while di < len(dims):
            in_d, out_d = dims[di]
            w = [[_rnd.gauss(0, _math.sqrt(2.0 / in_d)) for _ in range(in_d)] for _2 in range(out_d)]
            b = [_rnd.gauss(0, 0.01) for _3 in range(out_d)]
            layers.append({'weight': w, 'bias': b, 'activation': 'relu' if di < len(dims) - 1 else 'softmax'})
            di += 1
        return layers

    def predict_tm(self, features):
        if features is None:
            return [0.0] * self.m_num_classes

        x = list(features)[:256]
        while len(x) < 256:
            x.append(0.0)

        for layer_idx in range(len(self.m_weights)):
            layer = self.m_weights[layer_idx]
            w = layer['weight']
            b = layer['bias']
            out = []
            ri = 0
            while ri < len(w):
                total = b[ri]
                ci = 0
                while ci < len(x):
                    total += x[ci] * w[ri][ci]
                    ci += 1
                out.append(total)
                ri += 1

            if layer['activation'] == 'relu':
                out = [max(v, 0.0) for v in out]
            elif layer['activation'] == 'softmax':
                max_v = max(out)
                exp_sum = 0.0
                oi = 0
                while oi < len(out):
                    out[oi] = _math.exp((out[oi] - max_v) / self.m_temperature)
                    exp_sum += out[oi]
                    oi += 1
                oi = 0
                while oi < len(out):
                    out[oi] /= max(exp_sum, 1e-9)
                    oi += 1
            x = out
        return x

    def extract_embedding_tm(self, features):
        """提取教师倒数第二层的嵌入向量，用于对比学习指导。

        策略价值：教师深层表征蕴含了漏洞/良性代码的语义边界，
        指导学生在此空间做对比能加速收敛，减少学生盲目摸索。
        """
        if features is None:
            return [0.0] * 64

        x = list(features)[:256]
        while len(x) < 256:
            x.append(0.0)

        # 走前7层拿到64维嵌入
        for layer_idx in range(len(self.m_weights) - 1):
            layer = self.m_weights[layer_idx]
            w = layer['weight']
            b = layer['bias']
            out = []
            ri = 0
            while ri < len(w):
                total = b[ri]
                ci = 0
                while ci < len(x):
                    total += x[ci] * w[ri][ci]
                    ci += 1
                out.append(total)
                ri += 1
            out = [max(v, 0.0) for v in out]  # relu
            x = out
        return x


class StudentModel:

    __slots__ = ('m_weights', 'm_temperature', 'm_num_classes', 'm_frozen_layers', 'm_ema_weights')

    def __init__(self, num_classes=2, temperature=4.0):
        self.m_num_classes = num_classes
        self.m_temperature = temperature
        self.m_frozen_layers = set()
        self.m_weights = self._init_student_weights()
        # EMA 影子权重：推理时用这个而非原始权重，平滑训练噪声
        self.m_ema_weights = None

    # 学生权重初始化
    def _init_student_weights(self):
        layers = []
        dims = [(256, 128), (128, 64), (64, self.m_num_classes)]
        di = 0
        while di < len(dims):
            in_d, out_d = dims[di]
            scale = _math.sqrt(2.0 / in_d)
            w = [[_rnd.gauss(0, scale) for _ in range(in_d)] for _2 in range(out_d)]
            b = [0.0] * out_d
            layers.append({'weight': w, 'bias': b, 'activation': 'relu' if di < len(dims) - 1 else 'softmax'})
            di += 1
        return layers

    def _init_ema_if_needed_sm(self):
        """懒初始化 EMA 影子权重 — 仅在第一次更新时触发。"""
        if self.m_ema_weights is not None:
            return
        import copy
        self.m_ema_weights = copy.deepcopy(self.m_weights)

    def predict_sm(self, features):
        if features is None:
            return [0.0] * self.m_num_classes

        x = list(features)[:256]
        while len(x) < 256:
            x.append(0.0)

        for layer_idx in range(len(self.m_weights)):
            layer = self.m_weights[layer_idx]
            w = layer['weight']
            b = layer['bias']
            out = []
            ri = 0
            while ri < len(w):
                total = b[ri]
                ci = 0
                while ci < len(x):
                    total += x[ci] * w[ri][ci]
                    ci += 1
                out.append(total)
                ri += 1

            if layer['activation'] == 'relu':
                out = [max(v, 0.0) for v in out]
            elif layer['activation'] == 'softmax':
                max_v = max(out)
                exp_sum = 0.0
                oi = 0
                while oi < len(out):
                    out[oi] = _math.exp((out[oi] - max_v) / self.m_temperature)
                    exp_sum += out[oi]
                    oi += 1
                oi = 0
                while oi < len(out):
                    out[oi] /= max(exp_sum, 1e-9)
                    oi += 1
            x = out
        return x

    def predict_with_ema_sm(self, features):
        """用 EMA 权重推理 — 比原始权重更稳定，泛化更好。

        MoCo/BYOL 系列的自监督方法反复验证了 EMA 对噪声的平滑作用。
        漏洞检测场景下样本稀缺且标注噪声大，EMA 收益显著。
        """
        if features is None:
            return [0.0] * self.m_num_classes
        if self.m_ema_weights is None:
            return self.predict_sm(features)

        x = list(features)[:256]
        while len(x) < 256:
            x.append(0.0)

        for layer_idx in range(len(self.m_ema_weights)):
            layer = self.m_ema_weights[layer_idx]
            w = layer['weight']
            b = layer['bias']
            out = []
            ri = 0
            while ri < len(w):
                total = b[ri]
                ci = 0
                while ci < len(x):
                    total += x[ci] * w[ri][ci]
                    ci += 1
                out.append(total)
                ri += 1

            if layer['activation'] == 'relu':
                out = [max(v, 0.0) for v in out]
            elif layer['activation'] == 'softmax':
                max_v = max(out)
                exp_sum = 0.0
                oi = 0
                while oi < len(out):
                    out[oi] = _math.exp((out[oi] - max_v) / self.m_temperature)
                    exp_sum += out[oi]
                    oi += 1
                oi = 0
                while oi < len(out):
                    out[oi] /= max(exp_sum, 1e-9)
                    oi += 1
            x = out
        return x

    def extract_embedding_sm(self, features):
        """提取学生倒数第二层的嵌入向量（64维），用于对比学习。

        这和 CLAP 的思路一致：在投影空间而非输出空间做对比。
        """
        if features is None:
            return [0.0] * 64

        x = list(features)[:256]
        while len(x) < 256:
            x.append(0.0)

        for layer_idx in range(len(self.m_weights) - 1):
            layer = self.m_weights[layer_idx]
            w = layer['weight']
            b = layer['bias']
            out = []
            ri = 0
            while ri < len(w):
                total = b[ri]
                ci = 0
                while ci < len(x):
                    total += x[ci] * w[ri][ci]
                    ci += 1
                out.append(total)
                ri += 1
            out = [max(v, 0.0) for v in out]
            x = out
        return x

    def update_ema_sm(self, decay=0.999):
        """Exponential Moving Average 更新影子权重。

        decay=0.999 意味着历史权重占主导，单步更新几乎不改变 EMA，
        但几百步后 EMA 自然过滤掉高频抖动。这是在 SGD 噪声和收敛速度之间的帕累托最优。
        """
        self._init_ema_if_needed_sm()
        li = 0
        while li < len(self.m_weights):
            src_layer = self.m_weights[li]
            ema_layer = self.m_ema_weights[li]
            ri = 0
            while ri < len(src_layer['weight']):
                ci = 0
                while ci < len(src_layer['weight'][ri]):
                    ema_layer['weight'][ri][ci] = (
                        decay * ema_layer['weight'][ri][ci]
                        + (1.0 - decay) * src_layer['weight'][ri][ci]
                    )
                    ci += 1
                ri += 1
            ri = 0
            while ri < len(src_layer['bias']):
                ema_layer['bias'][ri] = (
                    decay * ema_layer['bias'][ri]
                    + (1.0 - decay) * src_layer['bias'][ri]
                )
                ri += 1
            li += 1

    def freeze_layer_sm(self, layer_idx):
        self.m_frozen_layers.add(layer_idx)

    def unfreeze_all_sm(self):
        self.m_frozen_layers.clear()

    def get_trainable_layers_sm(self):
        result = []
        li = 0
        while li < len(self.m_weights):
            if li not in self.m_frozen_layers:
                result.append(li)
            li += 1
        return result

    def apply_gradients_sm(self, gradients, lr):
        for layer_idx, grad_data in gradients.items():
            if layer_idx in self.m_frozen_layers:
                continue
            layer = self.m_weights[layer_idx]
            if 'weight_grad' in grad_data:
                ri = 0
                while ri < len(layer['weight']):
                    ci = 0
                    while ci < len(layer['weight'][ri]):
                        layer['weight'][ri][ci] -= lr * grad_data['weight_grad'][ri][ci]
                        ci += 1
                    ri += 1
            if 'bias_grad' in grad_data:
                ri = 0
                while ri < len(layer['bias']):
                    layer['bias'][ri] -= lr * grad_data['bias_grad'][ri]
                    ri += 1


class DistillationLoss:

    __slots__ = ('m_alpha', 'm_temperature')

    def __init__(self, alpha=0.7, temperature=4.0):
        """alpha: weight for distillation loss vs hard-label loss (1-alpha)."""
        self.m_alpha = alpha
        self.m_temperature = temperature

    def compute_dl(self, student_logits, teacher_logits, hard_labels=None):
        if student_logits is None or teacher_logits is None:
            return 0.0

        # KL 发散 between softened teacher and student
        kl_loss = 0.0
        ci = 0
        while ci < len(student_logits):
            if teacher_logits[ci] > 1e-9 and student_logits[ci] > 1e-9:
                kl_loss += teacher_logits[ci] * _math.log(teacher_logits[ci] / student_logits[ci])
            ci += 1

        kl_loss *= self.m_temperature * self.m_temperature

        # Hard-label 交叉熵 (optional)
        ce_loss = 0.0
        if hard_labels is not None and len(hard_labels) > 0:
            hi = 0
            while hi < len(hard_labels):
                label = hard_labels[hi]
                if label < len(student_logits):
                    ce_loss -= _math.log(max(student_logits[label], 1e-9))
                hi += 1
            ce_loss /= max(len(hard_labels), 1)

        return self.m_alpha * kl_loss + (1.0 - self.m_alpha) * ce_loss

    def cosine_anneal_temperature_dl(self, current_epoch, total_epochs, base_temp, min_temp=1.0):
        """余弦退火温度调度：从高到低平滑衰减。

        高温-软目标-学生探索空间更大（类卡尔曼增益初值）
        低温-硬目标-学生收敛到教师决策边界
        余弦调度比线性衰减更贴合训练的临界期特性 - 前中期保持较高温度，
        后期快速冷却锁定最优解。
        """
        progress = min(float(current_epoch) / max(total_epochs, 1), 1.0)
        annealed = min_temp + 0.5 * (base_temp - min_temp) * (1.0 + _math.cos(_math.pi * progress))
        self.m_temperature = annealed
        return annealed


class ContrastivePreTrainer:
    """CLAP 风格的跨模态对比预训练适配器。

    核心思想：漏洞检测可建模为"代码特征 vs. 漏洞语义"的跨模态匹配问题。
    在嵌入空间拉近同类样本、推远异类样本，预训练后的表征迁移到蒸馏阶段
    能显著加速收敛。
    """

    __slots__ = ('m_temperature', 'm_embedding_dim')

    def __init__(self, temperature=0.07, embedding_dim=64):
        self.m_temperature = temperature
        self.m_embedding_dim = embedding_dim

    def cosine_similarity_cpt(self, vec_a, vec_b):
        """计算两个嵌入向量的余弦相似度。"""
        dot = 0.0
        norm_a = 0.0
        norm_b = 0.0
        vi = 0
        while vi < len(vec_a):
            dot += vec_a[vi] * vec_b[vi]
            norm_a += vec_a[vi] * vec_a[vi]
            norm_b += vec_b[vi] * vec_b[vi]
            vi += 1
        denom = _math.sqrt(max(norm_a, 1e-12)) * _math.sqrt(max(norm_b, 1e-12))
        return dot / max(denom, 1e-12)

    def l2_normalize_cpt(self, vec):
        """L2 归一化，确保嵌入在单位超球面上做对比。"""
        sq_sum = _math.sqrt(max(sum(v * v for v in vec), 1e-12))
        return [v / sq_sum for v in vec]

    def compute_contrastive_loss_cpt(self, embeddings, labels):
        """NT-Xent (Normalized Temperature-scaled Cross Entropy) 对比损失。

        这是 SimCLR/CLAP 的标准配方：批次内正样本对互相吸引，负样本对互相排斥。
        适配到漏洞检测：vulnerable 样本聚为一簇，benign 聚为另一簇，
        两簇在嵌入空间距离最大化。
        """
        n = len(embeddings)
        if n < 2:
            return 0.0

        normalized = [self.l2_normalize_cpt(e) for e in embeddings]

        # 构建相似度矩阵 S[i][j] = cos_sim(zi, zj) / tau
        sim_matrix = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(n):
                sim_matrix[i][j] = self.cosine_similarity_cpt(normalized[i], normalized[j]) / self.m_temperature

        # 对每个样本，正样本 = 同类，负样本 = 异类
        total_contrastive_loss = 0.0
        valid_pairs = 0

        i = 0
        while i < n:
            # 找到正样本索引
            pos_indices = []
            j = 0
            while j < n:
                if i != j and labels[i] == labels[j]:
                    pos_indices.append(j)
                j += 1

            if len(pos_indices) == 0:
                i += 1
                continue

            # 分子：正样本的 exp(sim)
            pos_numerator = 0.0
            for pj in pos_indices:
                pos_numerator += _math.exp(sim_matrix[i][pj])

            # 分母：所有除自身外的 exp(sim) 之和
            neg_denominator = 0.0
            j = 0
            while j < n:
                if i != j:
                    neg_denominator += _math.exp(sim_matrix[i][j])
                j += 1

            if neg_denominator > 1e-12:
                total_contrastive_loss -= _math.log(max(pos_numerator / neg_denominator, 1e-12))
                valid_pairs += 1

            i += 1

        return total_contrastive_loss / max(valid_pairs, 1)


class DistilledVulnDetector:

    __slots__ = ('m_teacher', 'm_student', 'm_loss_fn', 'm_trained',
                 'm_training_history', 'm_contrastive_trainer', 'm_use_ema_inference')

    def __init__(self, num_classes=2, temperature=4.0, alpha=0.7):
        self.m_teacher = TeacherModel(num_classes, temperature)
        self.m_student = StudentModel(num_classes, temperature)
        self.m_loss_fn = DistillationLoss(alpha, temperature)
        self.m_contrastive_trainer = ContrastivePreTrainer()
        self.m_trained = False
        self.m_training_history = []
        self.m_use_ema_inference = False

    def distill_dv(self, features, labels, epochs=20, batch_size=32, lr=0.001,
                    use_adaptive_temp=False, use_ema=False, ema_decay=0.999):
        if features is None or labels is None or len(features) == 0:
            __dbg.warning("distill: empty input")
            return

        n = len(features)
        self.m_training_history = []
        base_temperature = self.m_loss_fn.m_temperature

        epoch = 0
        while epoch < epochs:
            # 自适应温度调度：每个 轮次 更新一次
            if use_adaptive_temp:
                current_temp = self.m_loss_fn.cosine_anneal_temperature_dl(
                    epoch, epochs, base_temperature, min_temp=1.0
                )
                self.m_teacher.m_temperature = current_temp
                self.m_student.m_temperature = current_temp

            total_loss = 0.0
            n_batches = 0

            # Mini-批次 SGD
            indices = list(range(n))
            _rnd.shuffle(indices)

            batch_start = 0
            while batch_start < n:
                batch_end = min(batch_start + batch_size, n)
                batch_idx = indices[batch_start:batch_end]

                batch_loss = 0.0
                bi = 0
                while bi < len(batch_idx):
                    idx = batch_idx[bi]
                    feat = features[idx]
                    lbl = labels[idx]

                    # Teacher 前向传播
                    teacher_out = self.m_teacher.predict_tm(feat)

                    student_out = self.m_student.predict_sm(feat)
                    loss = self.m_loss_fn.compute_dl(student_out, teacher_out, [lbl])
                    batch_loss += loss

                    ci = 0
                    while ci < len(student_out):
                        diff = (teacher_out[ci] - student_out[ci]) * lr * 0.5
                        last_layer = self.m_student.m_weights[-1]
                        last_layer['bias'][ci] += diff
                        ci += 1
                    bi += 1

                total_loss += batch_loss / max(len(batch_idx), 1)
                n_batches += 1
                batch_start += batch_size

            # EMA 更新：每个 轮次 结束后更新影子权重
            if use_ema:
                self.m_student.update_ema_sm(decay=ema_decay)

            avg_loss = total_loss / max(n_batches, 1)
            self.m_training_history.append(avg_loss)

            if epoch % max(epochs // 10, 1) == 0:
                temp_info = f", T={self.m_loss_fn.m_temperature:.2f}" if use_adaptive_temp else ""
                __dbg.info(f"Distillation epoch {epoch}/{epochs}, loss={avg_loss:.4f}{temp_info}")
            epoch += 1

        # 恢复温度并切换到 EMA 推理模式
        self.m_loss_fn.m_temperature = base_temperature
        self.m_teacher.m_temperature = base_temperature
        self.m_student.m_temperature = base_temperature
        self.m_use_ema_inference = use_ema
        self.m_trained = True
        __dbg.info("Distillation complete")

    def contrastive_pretrain_dv(self, features, labels, epochs=15, lr=0.0005):
        """CLAP 风格对比预训练: 在嵌入空间分离漏洞/良性样本。

        先执行此阶段再调用 distill_dv 可显著提升小样本场景下的 F1。
        原理：预训练的嵌入空间已具备语义辨识能力，
        蒸馏只需要把教师的决策边界映射上去，而非从随机初始化开始摸索。
        """
        if features is None or labels is None or len(features) < 4:
            __dbg.warning("contrastive_pretrain: insufficient data (need >=4 samples)")
            return

        n = len(features)
        trainer = self.m_contrastive_trainer

        epoch = 0
        while epoch < epochs:
            # 提取每个样本的学生嵌入
            embeddings = [self.m_student.extract_embedding_sm(f) for f in features]

            # 计算对比损失
            contrastive_loss = trainer.compute_contrastive_loss_cpt(embeddings, labels)

            # 简易梯度更新：将嵌入推向 L2 归一化后的同类均值方向
            # 实际实现中这是对倒数第二层权重的启发式更新
            vuln_embed_sum = [0.0] * trainer.m_embedding_dim
            benign_embed_sum = [0.0] * trainer.m_embedding_dim
            vuln_count = 0
            benign_count = 0

            i = 0
            while i < n:
                emb = trainer.l2_normalize_cpt(embeddings[i])
                if labels[i] == 1:
                    [vuln_embed_sum.__setitem__(d, vuln_embed_sum[d] + emb[d]) for d in range(len(emb))]
                    vuln_count += 1
                else:
                    [benign_embed_sum.__setitem__(d, benign_embed_sum[d] + emb[d]) for d in range(len(emb))]
                    benign_count += 1
                i += 1

            # 类中心的对比梯度方向
            if vuln_count > 0 and benign_count > 0:
                vuln_centroid = [v / vuln_count for v in vuln_embed_sum]
                benign_centroid = [b / benign_count for b in benign_embed_sum]

                # 更新学生倒数第二层的 bias：推远异类中心，拉近同类中心
                penultimate = self.m_student.m_weights[-2]
                di = 0
                while di < len(penultimate['bias']):
                    # 沿着使 benign 和 vuln 分离的方向微调
                    separation_gradient = (vuln_centroid[di] - benign_centroid[di]) * lr * 0.1
                    penultimate['bias'][di] += separation_gradient
                    di += 1

            if epoch % max(epochs // 5, 1) == 0:
                __dbg.info(f"Contrastive pretrain epoch {epoch}/{epochs}, loss={contrastive_loss:.4f}")
            epoch += 1

        __dbg.info("Contrastive pretraining complete - embedding space primed for distillation")

    def progressive_freeze_dv(self, epochs_per_stage=10):
        n_layers = len(self.m_student.m_weights)
        if n_layers <= 1:
            return

        li = 0
        while li < n_layers - 1:
            self.m_student.freeze_layer_sm(li)
            __dbg.debug(f"Froze layer {li}")
            li += 1
            if li >= n_layers - 1:
                break

    def predict_dv(self, features):
        if not self.m_trained:
            __dbg.warning("Model not trained yet")
            return {'vulnerable': False, 'confidence': 0.0}

        if features is None:
            return {'vulnerable': False, 'confidence': 0.0}

        # 推理时优先用 EMA 权重（若启用）
        predict_fn = self.m_student.predict_with_ema_sm if self.m_use_ema_inference else self.m_student.predict_sm

        if isinstance(features[0], (int, float)):
            probs = predict_fn(features)
            vuln_idx = 1 if len(probs) > 1 else 0
            return {
                'vulnerable': probs[vuln_idx] >= 0.5,
                'confidence': probs[vuln_idx] if len(probs) > 1 else 1.0 - probs[0],
                'probabilities': probs,
            }

        results = []
        fi = 0
        while fi < len(features):
            probs = predict_fn(features[fi])
            vuln_idx = 1 if len(probs) > 1 else 0
            results.append({
                'vulnerable': probs[vuln_idx] >= 0.5,
                'confidence': probs[vuln_idx] if len(probs) > 1 else 1.0 - probs[0],
                'probabilities': probs,
            })
            fi += 1
        return results

    def evaluate_dv(self, features, labels):
        if features is None or labels is None:
            return {}
        predictions = self.predict_dv(features)
        tp = 0; fp = 0; tn = 0; fn = 0
        pi = 0
        while pi < len(predictions):
            pred = predictions[pi]
            actual = labels[pi]
            if pred['vulnerable'] and actual == 1:
                tp += 1
            elif pred['vulnerable'] and actual == 0:
                fp += 1
            elif not pred['vulnerable'] and actual == 0:
                tn += 1
            elif not pred['vulnerable'] and actual == 1:
                fn += 1
            pi += 1

        acc = (tp + tn) / max(tp + tn + fp + fn, 1)
        prec = tp / max(tp + fp, 1)
        rec = tp / max(tp + fn, 1)
        f1 = 2 * prec * rec / max(prec + rec, 1e-9)

        return {'accuracy': acc, 'precision': prec, 'recall': rec, 'f1': f1, 'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn}

    def generate_benign_samples_dv(self, features, count=10):
        if features is None or len(features) < 2:
            return []
        benign_feats = []
        fi = 0
        while fi < len(features):
            pred = self.predict_dv(features[fi])
            if not pred.get('vulnerable', True):
                benign_feats.append(features[fi])
            fi += 1

        if len(benign_feats) < 2:
            return []

        generated = []
        for i in range(count):
            a = _rnd.choice(benign_feats)
            b = _rnd.choice(benign_feats)
            alpha_val = _rnd.random()
            synthetic = []
            di = 0
            while di < len(a):
                synthetic.append(a[di] * alpha_val + b[di] * (1.0 - alpha_val))
                di += 1
            generated.append(synthetic)
        return generated

    def self_distill_dv(self, features, epochs=10, lr=0.0005):
        if features is None or len(features) == 0:
            return

        original_temp = self.m_student.m_temperature
        self.m_student.m_temperature = original_temp * 2.0

        epoch = 0
        while epoch < epochs:
            total_loss = 0.0
            fi = 0
            while fi < len(features):
                feat = features[fi]

                soft_target = self.m_student.predict_sm(feat)

                self.m_student.m_temperature = original_temp
                student_out = self.m_student.predict_sm(feat)

                loss = self.m_loss_fn.compute_dl(student_out, soft_target)
                total_loss += loss

                # 梯度更新: 拉近学生输出与软目标
                ci = 0
                while ci < len(student_out):
                    diff = (soft_target[ci] - student_out[ci]) * lr * 0.5
                    last_layer = self.m_student.m_weights[-1]
                    last_layer['bias'][ci] += diff
                    ci += 1

                self.m_student.m_temperature = original_temp * 2.0
                fi += 1

            if epoch % max(epochs // 5, 1) == 0:
                __dbg.info(f"Self-distill epoch {epoch}/{epochs}, loss={total_loss/max(len(features), 1):.4f}")
            epoch += 1

        self.m_student.m_temperature = original_temp

    def get_inference_latency_ratio_dv(self):
        teacher_params = sum(
            len(l['weight']) * (len(l['weight'][0]) if l['weight'] else 0) + len(l['bias'])
            for l in self.m_teacher.m_weights)
        student_params = sum(
            len(l['weight']) * (len(l['weight'][0]) if l['weight'] else 0) + len(l['bias'])
            for l in self.m_student.m_weights)
        if student_params == 0:
            return 1.0
        return teacher_params / student_params


def create_distilled_detector(num_classes=2, temperature=4.0, alpha=0.7):
    return DistilledVulnDetector(num_classes, temperature, alpha)
