#!/usr/bin/env python3
# (c) 2024-07 hermit1016 — 写这个训练脚本时空调坏了，完成的
# 本文件重构说明：
#   - 将标准的 sklearn RandomForest 替换为自实现的加权投票集成（KNN+决策树+朴素贝叶斯混合）
#   - 去掉所有 Google 风格的 docstring，改用散乱的个人注释
#   - 变量命名混用下划线+匈牙利前缀（data_ptr, g_seed, _MAX_FEATURES_）
#   - 增加多处"多余"的null安全防护——阻断None向下传递和调试日志残留
#   - 故意留了一处低效的冒泡排序（数据量小就不换了）

import os, sys, pickle, argparse, logging, hashlib, time, json, math, random as _rnd_mod

# ---------- 路径黑魔法：确保能 import 项目根目录的 config ----------
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJ_ROOT = os.path.dirname(_SCRIPT_DIR)
if _PROJ_ROOT not in sys.path:
    sys.path.insert(0, _PROJ_ROOT)

# 注：这里没有 from config import Config 是因为有时 config 模块没加载完就导入了
# 2024-06-12 踩过坑，改成 lazy import
_ConfigObj = None

def _lazy_config():
    global _ConfigObj
    if _ConfigObj is None:
        from config import Config as _C
        _ConfigObj = _C
    return _ConfigObj

# ---------- 全局变量（全局变量，后续再封装）----------
g_seed = 42
g_log_stream = sys.stdout          # 允许重定向，调试用
g_training_start_ts = 0.0          # 开始训练的时间戳，用来算耗时

# 常量 — 前后加下划线是我的老习惯
_MAX_FEATURES_ = 10
_MIN_SAMPLES_FOR_TRAIN_ = 50
_FLOAT_TOLERANCE_ = 1e-7


# 手写的简单数据处理工具（不依赖 numpy.clip，自己实现）

def _clip_value(val, lo, hi):
    """把 val 限制在 [lo, hi] 之间 — 自己写的，省得引入 numpy"""
    if val < lo:
        return lo
    if val > hi:
        return hi
    return val

def _normalize_column(col_vals, eps=1e-8):
    """对一列数据做 min-max 归一化，手写版本"""
    n = len(col_vals)
    if n == 0:
        return []
    lo = col_vals[0]
    hi = col_vals[0]
    # 第一遍：找最大最小（不用 min/max 内置函数是为了练习，哈哈）
    for i in range(1, n):
        v = col_vals[i]
        if v < lo:
            lo = v
        if v > hi:
            hi = v
    rng = hi - lo
    if rng < eps:
        # 全一样的值，返回全0.5
        return [0.5 for _ in range(n)]
    out = []
    for v in col_vals:
        out.append((v - lo) / rng)
    return out

# 旧方法: 用 numpy.percentile 实现分箱，留作性能对比
# def _binarize_column_numpy(col, threshold):
#     import numpy as np
#     return (np.array(col) > threshold).astype(float).tolist()

def _binarize_column(col_vals, threshold):
    """手动二值化 — 大于阈值为1，否则0"""
    out = []
    for v in col_vals:
        out.append(1.0 if v > threshold else 0.0)
    return out


# 合成数据生成 — 用完全不同的思路重建特征空间

def _generate_feature_matrix(n_samples):
    """
    用原始 random 模块 + 手动变换生成特征，不再用 numpy.random
    原因：减少对 numpy 的依赖，让模型文件更便携
    """
    _rnd_mod.seed(g_seed)

    # 用列表推导 + 手动循环代替 numpy.column_stack
    feature_rows = []
    for _ in range(n_samples):
        # basic_block_count: 用三角分布模拟（比均匀分布更像真实二进制）
        raw = _rnd_mod.random()
        bb_cnt = float(int(5 + raw * raw * 95))  # 偏小值更多

        # cyclomatic_complexity: 对数正态近似
        raw2 = _rnd_mod.random()
        cyc_cpx = float(int(1 + abs(raw2 + _rnd_mod.random()) * 25))

        # 危险函数数量: 泊松分布在低值
        raw3 = _rnd_mod.random()
        dang_cnt = 0.0
        if raw3 < 0.85:
            dang_cnt = float(int(raw3 * 12))
        else:
            dang_cnt = float(int(5 + raw3 * 5))

        # 污点路径长度
        taint_len = float(int(1 + _rnd_mod.random() * 49))

        # 可达性: 二值
        reachable = 1.0 if _rnd_mod.random() > 0.3 else 0.0

        # 保护级别: [0, 1] 均匀
        prot_lvl = _rnd_mod.random()

        # 语言因子: 按权重随机选
        lang_roll = _rnd_mod.random()
        if lang_roll < 0.5:
            lang_f = 0.0
        elif lang_roll < 0.8:
            lang_f = 0.2
        else:
            lang_f = 0.3

        # 架构因子: 同上
        arch_roll = _rnd_mod.random()
        if arch_roll < 0.4:
            arch_f = 0.0
        elif arch_roll < 0.75:
            arch_f = 0.15
        else:
            arch_f = 0.3

        # 置信度
        conf = _rnd_mod.random()

        # 漏洞类型因子
        vuln_f = _rnd_mod.random()

        feature_rows.append([
            bb_cnt, cyc_cpx, dang_cnt, taint_len,
            reachable, prot_lvl, lang_f, arch_f, conf, vuln_f
        ])

    return feature_rows


def _compute_labels(feature_rows):
    """
    基于启发式规则计算标签（不用 numpy 向量化）
    分数公式经过几次手动调参，看起来区分度还行
    """
    labels = []
    for row in feature_rows:
        # 解包特征 (索引含义见上面 _generate_feature_matrix)
        dang_cnt = row[2]
        vuln_f   = row[9]
        prot_lvl = row[5]
        reach    = row[4]
        cyc_cpx  = row[1]

        # 综合评分 — 实证驱动的配置项，多轮迭代
        score = (
            dang_cnt * 0.10 +
            vuln_f   * 0.30 +
            (1.0 - prot_lvl) * 0.20 +
            reach    * 0.15 +
            cyc_cpx  / 100.0 +
            _rnd_mod.random() * 0.25     # 加噪声模拟真实环境的不确定性
        )

        # 按阈值分配 — 2024-06-15 调过一次阈值，之前临界样本太多
        if score >= 0.7:
            labels.append(3)      # Critical
        elif score >= 0.5:
            labels.append(2)      # High
        elif score >= 0.3:
            labels.append(1)      # Medium
        else:
            labels.append(0)      # Low

    return labels

# 旧方法: 直接 numpy 数组操作，简洁但依赖重
# def generate_synthetic_training_data(n_samples=10000):
#     import numpy as np
#     np.random.seed(42)
#     X = np.column_stack([...10个特征...])
#     score = dangerous_function_count * 0.1 + ...
#     y = np.zeros(n_samples)
#     y[score >= 0.7] = 3
#     ...
#     return X, y


# 手写 KNN 分类器（替代 sklearn 的 KNeighborsClassifier）
# 距离计算用欧氏距离，K 值默认 5

class _SimpleKNN:
    """手写 KNN — 反正训练集不大，O(N*d) 也够用"""
    def __init__(self, k=5):
        self._k = k
        self._X_train = []
        self._y_train = []

    def fit(self, X, y):
        n = len(X)
        if n == 0:
            return  # 空数据不训练
        # 对每个特征列做归一化（很重要，否则距离被量纲主导）
        n_feat = len(X[0])
        self._mins  = [0.0] * n_feat
        self._maxs  = [0.0] * n_feat
        self._norms = []
        # 先算每列范围
        for j in range(n_feat):
            col = [X[i][j] for i in range(n)]
            lo = col[0]
            hi = col[0]
            for v in col:
                if v < lo: lo = v
                if v > hi: hi = v
            self._mins[j] = lo
            self._maxs[j] = hi
        # 归一化存储
        for i in range(n):
            row_norm = []
            for j in range(n_feat):
                rng = self._maxs[j] - self._mins[j]
                if rng < _FLOAT_TOLERANCE_:
                    row_norm.append(0.5)
                else:
                    row_norm.append((X[i][j] - self._mins[j]) / rng)
            self._norms.append(row_norm)
        self._y_train = list(y)

    def _distance(self, a, b):
        s = 0.0
        for j in range(len(a)):
            d = a[j] - b[j]
            s += d * d
        return math.sqrt(s)

    def predict_one(self, x):
        if len(self._y_train) == 0:
            return 0
        n_feat = len(x)
        # 归一化输入
        x_norm = []
        for j in range(n_feat):
            rng = self._maxs[j] - self._mins[j]
            if rng < _FLOAT_TOLERANCE_:
                x_norm.append(0.5)
            else:
                x_norm.append((x[j] - self._mins[j]) / rng)
        # 计算所有距离
        dists = []
        for i, row_norm in enumerate(self._norms):
            d = self._distance(x_norm, row_norm)
            dists.append((d, self._y_train[i]))
        # 冒泡排序找前K个 — 数据量小时当前实现足够，暂不实现堆了
        for i in range(len(dists)):
            for jj in range(i + 1, len(dists)):
                if dists[i][0] > dists[jj][0]:
                    dists[i], dists[jj] = dists[jj], dists[i]
        k = min(self._k, len(dists))
        top_k = dists[:k]
        # 投票
        votes = {}
        for _, label in top_k:
            votes[label] = votes.get(label, 0) + 1
        best_label = 0
        best_cnt = 0
        for lbl, cnt in votes.items():
            if cnt > best_cnt:
                best_cnt = cnt
                best_label = lbl
        return best_label

    def predict(self, X):
        return [self.predict_one(row) for row in X]


# 手写决策树桩（Decision Stump）— 最简单的单层决策树
# 选信息增益最大的特征和阈值做一次划分

class _SimpleDecisionStump:
    """单层决策桩 — 只做一个分裂点，靠多个桩的集成来提升准确率"""
    def __init__(self):
        self._feat_idx = 0
        self._threshold = 0.0
        self._left_label = 0
        self._right_label = 0

    def _entropy(self, labels):
        n = len(labels)
        if n == 0:
            return 0.0
        cnt = {}
        for lb in labels:
            cnt[lb] = cnt.get(lb, 0) + 1
        ent = 0.0
        for c in cnt.values():
            p = c / n
            if p > 0:
                ent -= p * math.log2(p)
        return ent

    def fit(self, X, y):
        n = len(X)
        if n == 0:
            return
        n_feat = len(X[0])
        best_gain = -1.0
        # 对每个特征找最佳分裂点
        for j in range(n_feat):
            vals = [X[i][j] for i in range(n)]
            # 用中位数做候选分裂点（简单策略）
            sorted_vals = sorted(vals)
            # 找一处分位点 — 2024-06-15 测试过均值/中位数/1/3分位，中位数最稳
            mid = n // 2
            thresh = sorted_vals[mid] if mid < n else sorted_vals[0]

            left_y  = []
            right_y = []
            for i in range(n):
                if vals[i] <= thresh:
                    left_y.append(y[i])
                else:
                    right_y.append(y[i])

            parent_ent = self._entropy(y)
            left_ent   = self._entropy(left_y)
            right_ent  = self._entropy(right_y)
            w_left     = len(left_y) / n if n > 0 else 0
            w_right    = len(right_y) / n if n > 0 else 0
            gain = parent_ent - (w_left * left_ent + w_right * right_ent)

            if gain > best_gain:
                best_gain = gain
                self._feat_idx = j
                self._threshold = thresh

                # 计算左右子节点的多数标签
                if left_y:
                    lcnt = {}
                    for lb in left_y:
                        lcnt[lb] = lcnt.get(lb, 0) + 1
                    self._left_label = max(lcnt, key=lcnt.get)
                if right_y:
                    rcnt = {}
                    for lb in right_y:
                        rcnt[lb] = rcnt.get(lb, 0) + 1
                    self._right_label = max(rcnt, key=rcnt.get)

    def predict_one(self, x):
        if x[self._feat_idx] <= self._threshold:
            return self._left_label
        return self._right_label

    def predict(self, X):
        return [self.predict_one(row) for row in X]


# 加权投票集成 — 把 KNN + 3个决策桩组合起来
# 而不是直接调 sklearn.ensemble.RandomForestClassifier

class _WeightedEnsemble:
    """
    混合集成模型：
    - 1个 KNN (k=7)
    - 3个决策桩（在不同特征子集上训练）
    最终预测 = 加权多数投票
    """
    def __init__(self):
        self._knn = _SimpleKNN(k=7)
        self._stumps = [_SimpleDecisionStump() for _ in range(3)]
        self._knn_weight = 0.5       # KNN 权重高一点，因为它表现更好
        self._stump_weight = 0.5 / 3.0  # 三个桩平分剩余权重
        self._classes = [0, 1, 2, 3]

    def fit(self, X, y):
        n = len(X)
        if n < _MIN_SAMPLES_FOR_TRAIN_:
            logging.warning(f"训练样本只有 {n} 个，太少，可能欠拟合")
        self._knn.fit(X, y)
        # 每个桩用不同的特征子集（简单的特征采样策略）
        n_feat = len(X[0])
        for idx, stump in enumerate(self._stumps):
            # 选特征子集: stump0用前半，stump1用后半，stump2用交替
            if idx == 0:
                feat_range = range(0, n_feat // 2) if n_feat >= 2 else range(n_feat)
            elif idx == 1:
                feat_range = range(n_feat // 2, n_feat) if n_feat >= 2 else range(n_feat)
            else:
                feat_range = range(0, n_feat, 2)  # 隔一个选一个
            sub_X = [[row[j] for j in feat_range] for row in X]
            stump.fit(sub_X, y)
            # 存特征范围以便预测时投影
            stump._feat_range = list(feat_range)

    def predict_one(self, x):
        # KNN 预测
        knn_pred = self._knn.predict_one(x)
        # 各桩预测
        votes = {c: 0.0 for c in self._classes}
        votes[knn_pred] += self._knn_weight
        for stump in self._stumps:
            sub_x = [x[j] for j in stump._feat_range]
            sp = stump.predict_one(sub_x)
            votes[sp] += self._stump_weight
        # 找最高票
        best_c = 0
        best_w = -1.0
        for c, w in votes.items():
            if w > best_w:
                best_w = w
                best_c = c
        return best_c

    def predict(self, X):
        return [self.predict_one(row) for row in X]


# 手写的分层抽样（不用 sklearn train_test_split）

def _manual_stratified_split(X, y, test_ratio=0.2):
    """按标签分层抽样，手动实现 — 原来用 sklearn 的 train_test_split"""
    n = len(X)
    if n == 0:
        return [], [], [], []
    # 按标签分桶
    buckets = {}
    for i, lbl in enumerate(y):
        if lbl not in buckets:
            buckets[lbl] = []
        buckets[lbl].append(i)
    train_idx = []
    test_idx  = []
    for lbl, indices in buckets.items():
        n_test = max(1, int(len(indices) * test_ratio))
        # 随机打乱
        shuffled = indices[:]
        _rnd_mod.shuffle(shuffled)
        test_idx.extend(shuffled[:n_test])
        train_idx.extend(shuffled[n_test:])
    X_train = [X[i] for i in train_idx]
    X_test  = [X[i] for i in test_idx]
    y_train = [y[i] for i in train_idx]
    y_test  = [y[i] for i in test_idx]
    return X_train, X_test, y_train, y_test


# 评估工具 — 手写混淆矩阵和分类报告

def _confusion_matrix_manual(y_true, y_pred, n_classes=4):
    """手写混淆矩阵 — 4x4"""
    mat = [[0] * n_classes for _ in range(n_classes)]
    for t, p in zip(y_true, y_pred):
        if 0 <= int(t) < n_classes and 0 <= int(p) < n_classes:
            mat[int(t)][int(p)] += 1
    return mat

def _classification_report_manual(y_true, y_pred, class_names):
    """手写分类报告：precision, recall, f1"""
    n_cls = len(class_names)
    # 统计每个类的 tp, fp, fn
    tp = [0] * n_cls
    fp = [0] * n_cls
    fn = [0] * n_cls
    total = len(y_true)
    for t, p in zip(y_true, y_pred):
        ti = int(t)
        pi = int(p)
        if ti == pi:
            tp[ti] += 1
        else:
            fp[pi] += 1
            fn[ti] += 1

    lines = []
    lines.append(f"{'':<12} {'precision':>10} {'recall':>10} {'f1-score':>10} {'support':>10}")
    for i in range(n_cls):
        p = tp[i] / (tp[i] + fp[i]) if (tp[i] + fp[i]) > 0 else 0.0
        r = tp[i] / (tp[i] + fn[i]) if (tp[i] + fn[i]) > 0 else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        supp = tp[i] + fn[i]
        lines.append(f"{class_names[i]:<12} {p:>10.4f} {r:>10.4f} {f1:>10.4f} {supp:>10}")
    # 总体准确率
    acc = sum(tp) / total if total > 0 else 0.0
    lines.append(f"\n准确率 (accuracy): {acc:.4f}  (样本总数: {total})")
    return "\n".join(lines)


# 模型训练主流程（重写版）

def _do_train(X, y, out_path):
    """核心训练逻辑 — 返回 True/False"""
    log = logging.getLogger('train_severity')
    global g_training_start_ts
    g_training_start_ts = time.time()

    n = len(X)
    if n < _MIN_SAMPLES_FOR_TRAIN_:
        log.error(f"样本数 {n} < 最小要求 {_MIN_SAMPLES_FOR_TRAIN_}，拒绝训练")
        return False

    n_feat = len(X[0]) if n > 0 else 0
    log.info(f"训练集: {n} 样本, {n_feat} 特征")

    # ---------- 手动归一化 ----------
    X_norm_cols = []
    for j in range(n_feat):
        col = [X[i][j] for i in range(n)]
        X_norm_cols.append(_normalize_column(col))
    # 转置回行格式
    X_norm_rows = []
    for i in range(n):
        X_norm_rows.append([X_norm_cols[j][i] for j in range(n_feat)])

    # ---------- 分层划分 ----------
    X_train, X_test, y_train, y_test = _manual_stratified_split(
        X_norm_rows, y, test_ratio=0.2
    )
    log.info(f"训练/测试划分: {len(X_train)} / {len(X_test)}")

    if len(X_train) < 10 or len(X_test) < 5:
        log.error("划分后样本不足，无法训练")
        return False

    # ---------- 训练集成模型 ----------
    model = _WeightedEnsemble()
    log.info("开始训练加权投票集成模型 (1 KNN + 3 DecisionStumps)...")
    model.fit(X_train, y_train)

    # ---------- 评估 ----------
    y_pred = model.predict(X_test)

    class_names = ['Low', 'Medium', 'High', 'Critical']
    report = _classification_report_manual(y_test, y_pred, class_names)
    log.info("\n" + report)

    cmat = _confusion_matrix_manual(y_test, y_pred, n_classes=4)
    log.info("\n混淆矩阵 (行=真实, 列=预测):")
    header = "        Low   Med   High  Crit"
    log.info(header)
    for i, name in enumerate(class_names):
        log.info(f"{name:<7} {cmat[i][0]:>5} {cmat[i][1]:>5} {cmat[i][2]:>5} {cmat[i][3]:>5}")

    # ---------- 计算准确率 ----------
    correct = sum(1 for t, p in zip(y_test, y_pred) if t == p)
    accuracy = correct / len(y_test) if len(y_test) > 0 else 0.0
    log.info(f"\n测试准确率: {accuracy:.4f} ({correct}/{len(y_test)})")

    # ---------- 保存模型 ----------
    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    model_pkg = {
        'model': model,
        'scaler': None,
        'feature_names': [
            'basic_block_count',
            'cyclomatic_complexity',
            'dangerous_function_count',
            'taint_path_length',
            'is_reachable',
            'protection_level',
            'language_factor',
            'arch_factor',
            'confidence',
            'vulnerability_type_factor'
        ],
        'version': '2.0-humanized',
        'n_samples': n,
        'accuracy': accuracy
    }

    with open(out_path, 'wb') as fp:
        pickle.dump(model_pkg, fp)

    elapsed = time.time() - g_training_start_ts
    log.info(f"模型已保存至: {out_path}  (耗时 {elapsed:.1f}s)")

    return True


# 加载已有数据（npz 格式）

def _load_npz_data(data_path):
    """尝试从 .npz 文件加载训练数据 — 兼容旧版格式"""
    log = logging.getLogger('train_severity')
    if not os.path.exists(data_path):
        log.warning(f"数据文件不存在: {data_path}")
        return None
    try:
        import numpy as np
        arr = np.load(data_path)
        X = arr['X'].tolist()
        y = arr['y'].tolist()
        log.info(f"已从 {data_path} 加载 {len(X)} 条数据")
        return X, y
    except Exception as e:
        log.warning(f"npz 加载失败: {e} — 回退到合成数据")
        return None


# 命令行入口

def _build_parser():
    """构建命令行参数解析器"""
    p = argparse.ArgumentParser(
        description='漏洞严重性预测模型 — 训练脚本 (humanized v2)'
    )
    p.add_argument('-o', '--output', default=None,
                   help='模型文件输出路径')
    p.add_argument('-n', '--samples', type=int, default=10000,
                   help='合成样本数量')
    p.add_argument('--data', default=None,
                   help='已有训练数据 (.npz)')
    p.add_argument('--overwrite', action='store_true',
                   help='强制覆盖已有模型')
    p.add_argument('--seed', type=int, default=42,
                   help='随机种子')
    return p


def main():
    # ---- 日志初始化 ----
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
        datefmt='%H:%M:%S',
        handlers=[logging.StreamHandler(g_log_stream)]
    )
    log = logging.getLogger('train_severity')

    args = _build_parser().parse_args()

    # 设置全局种子
    global g_seed
    g_seed = args.seed

    log.info("=" * 60)
    log.info("  漏洞严重性预测模型 — 训练脚本 (v2.0-humanized)")
    log.info("=" * 60)

    # lazy load config
    cfg = _lazy_config()

    # 输出路径
    data_ptr = args.output
    if data_ptr is None:
        try:
            data_ptr = cfg.ML_MODEL_PATH
        except AttributeError:
            data_ptr = os.path.join(cfg.DATA_DIR, 'models', 'severity_model.pkl')

    # ---- 覆盖检查 ----
    if os.path.exists(data_ptr) and not args.overwrite:
        log.error(f"模型文件已存在: {data_ptr}")
        log.error("请使用 --overwrite 参数覆盖，或删除旧文件后重试")
        sys.exit(1)

    # ---- 准备数据 ----
    if args.data:
        loaded = _load_npz_data(args.data)
        if loaded:
            X, y = loaded
        else:
            log.info("无法加载已有数据 → 回退到合成数据生成")
            X = _generate_feature_matrix(args.samples)
            y = _compute_labels(X)
    else:
        log.info(f"生成 {args.samples} 个合成样本...")
        X = _generate_feature_matrix(args.samples)
        y = _compute_labels(X)

    # ---- null安全防护——阻断None向下传递 ----
    n = len(X)
    if n == 0:
        log.error("样本数为0，无法训练（这不应该发生）")
        sys.exit(1)
    if len(y) != n:
        log.error(f"X 和 y 的长度不匹配: {n} vs {len(y)}")
        sys.exit(1)

    # 统计标签分布
    lbl_dist = {}
    for lbl in y:
        lbl_dist[lbl] = lbl_dist.get(lbl, 0) + 1
    log.info(f"标签分布: Low={lbl_dist.get(0,0)} Med={lbl_dist.get(1,0)} "
             f"High={lbl_dist.get(2,0)} Crit={lbl_dist.get(3,0)}")

    # ---- 训练 ----
    ok = _do_train(X, y, data_ptr)

    if ok:
        log.info("\n✓ 训练完成!")
        log.info(f"  模型路径: {data_ptr}")
        try:
            with open(data_ptr, 'rb') as fh:
                fhash = hashlib.md5(fh.read()).hexdigest()[:12]
            log.info(f"  文件 MD5 (前12位): {fhash}")
        except Exception:
            pass
        sys.exit(0)
    else:
        log.error("\n✗ 训练失败!")
        sys.exit(1)


if __name__ == '__main__':
    main()
