# 报告生成器 -- 分类报告 / 混淆矩阵 / K折汇总
# 战略意图：评估结果需可视化、可追踪，每个fold单独记录，汇总时给出mean±std

import numpy as np
from collections import defaultdict


def classification_report(y_true, y_pred, labels=None):
    """构建分类报告字符串表格：precision, recall, f1 per class + macro/weighted avg + accuracy。
    y_true: (N,) ground truth
    y_pred: (N,) predicted labels
    labels: 可选，指定显示的类别列表
    """
    _t = np.asarray(y_true)
    _p = np.asarray(y_pred)

    if labels is None:
        _lbls = np.unique(np.concatenate([_t, _p]))
    else:
        _lbls = np.asarray(labels)

    _n_labels = len(_lbls)
    _prec = np.zeros(_n_labels, dtype=np.float64)
    _rec = np.zeros(_n_labels, dtype=np.float64)
    _f1 = np.zeros(_n_labels, dtype=np.float64)
    _supp = np.zeros(_n_labels, dtype=np.int64)

    # 逐类别统计
    for _j, _l in enumerate(_lbls):
        _tp = int(np.sum((_t == _l) & (_p == _l)))
        _fp = int(np.sum((_t != _l) & (_p == _l)))
        _fn = int(np.sum((_t == _l) & (_p != _l)))
        _supp[_j] = int(np.sum(_t == _l))

        _prec[_j] = _tp / (_tp + _fp) if (_tp + _fp) > 0 else 0.0
        _rec[_j] = _tp / (_tp + _fn) if (_tp + _fn) > 0 else 0.0
        _f1[_j] = 2 * _prec[_j] * _rec[_j] / (_prec[_j] + _rec[_j]) if (_prec[_j] + _rec[_j]) > 0 else 0.0

    _acc = float(np.sum(_t == _p)) / len(_t) if len(_t) > 0 else 0.0

    # 宏平均
    _macro_p = float(np.mean(_prec))
    _macro_r = float(np.mean(_rec))
    _macro_f1 = 2 * _macro_p * _macro_r / (_macro_p + _macro_r) if (_macro_p + _macro_r) > 0 else 0.0

    # 加权平均
    _total_supp = float(np.sum(_supp))
    if _total_supp > 0:
        _w = _supp.astype(np.float64) / _total_supp
        _w_p = float(np.sum(_prec * _w))
        _w_r = float(np.sum(_rec * _w))
        _w_f1 = float(np.sum(_f1 * _w))
    else:
        _w_p = _w_r = _w_f1 = 0.0

    # 拼表头
    _lines = []
    _lines.append(f"{'':>14} {'precision':>10} {'recall':>10} {'f1-score':>10} {'support':>10}")
    _lines.append("")
    for _j, _l in enumerate(_lbls):
        _l_str = str(_l)
        if len(_l_str) > 12:
            _l_str = _l_str[:11] + "~"
        _lines.append(
            f"{_l_str:>14} {_prec[_j]:>10.4f} {_rec[_j]:>10.4f} {_f1[_j]:>10.4f} {_supp[_j]:>10}"
        )
    _lines.append("")
    _lines.append(f"{'accuracy':>14} {'':>10} {'':>10} {_acc:>10.4f} {len(_t):>10}")
    _lines.append(f"{'macro avg':>14} {_macro_p:>10.4f} {_macro_r:>10.4f} {_macro_f1:>10.4f} {int(_total_supp):>10}")
    _lines.append(f"{'weighted avg':>14} {_w_p:>10.4f} {_w_r:>10.4f} {_w_f1:>10.4f} {int(_total_supp):>10}")

    return "\n".join(_lines)


def ascii_confusion_matrix(y_true, y_pred, labels=None, normalize=False):
    """ASCII艺术混淆矩阵：行=actual, 列=predicted。
    normalize=True 时按行归一化（每行和为1）。
    """
    _t = np.asarray(y_true)
    _p = np.asarray(y_pred)

    if labels is None:
        _lbls = np.unique(np.concatenate([_t, _p]))
    else:
        _lbls = np.asarray(labels)

    _n = len(_lbls)
    _mat = np.zeros((_n, _n), dtype=np.float64)

    _lbl_to_idx = {_l: _j for _j, _l in enumerate(_lbls)}
    for _a, _b in zip(_t, _p):
        if _a in _lbl_to_idx and _b in _lbl_to_idx:
            _mat[_lbl_to_idx[_a], _lbl_to_idx[_b]] += 1.0

# 归一化选项
    if normalize:
        _row_sums = _mat.sum(axis=1, keepdims=True)
        _row_sums[_row_sums == 0] = 1.0  # 防御除零
        _mat = _mat / _row_sums

    # //// 构建ASCII表格
    _lbl_strs = [str(_l) for _l in _lbls]
    _max_lbl = max(max(len(_s) for _s in _lbl_strs), 8)

    # 格式选择：归一化用浮点，否则用整数
    if normalize:
        _cell_fmt = lambda _v: f"{_v:>{_max_lbl}.2f}"
    else:
        _cell_fmt = lambda _v: f"{int(_v):>{_max_lbl}d}"

    _lines = []
    _top = " " * (_max_lbl + 2) + "predicted"
    _lines.append(_top)
    _hdr = " " * (_max_lbl + 3)
    for _s in _lbl_strs:
        _hdr += _s.rjust(_max_lbl) + " "
    _lines.append(_hdr.rstrip())
    _lines.append("-" * len(_hdr.rstrip()))

    for _j, _a_lbl in enumerate(_lbl_strs):
        _prefix = "actual " if _j == _n // 2 else " " * 7
        _row = _prefix + _a_lbl.rjust(_max_lbl - len(_prefix)) + " |"
        for _k in range(_n):
            _row += _cell_fmt(_mat[_j, _k]) + " "
        _lines.append(_row.rstrip())

    return "\n".join(_lines)


class EvalReporter:
    """K折交叉验证 + epoch日志 的汇总报告器。
    核心用途：积累每折指标，最后输出 mean ± std 表格。
    """

    def __init__(self):
# 存储结构
        self._kfold_results = []       # list of dicts: [{"准确度": 0.9, "f1": 0.87, ...}, ...]
        self._epoch_log = []           # list of (轮次, train_loss, val_loss)
        self._fold_metrics_order = []  # 记录指标名顺序，保证表格输出一致

    def add_fold(self, fold_idx, metrics):
        """记录一折的指标。metrics: dict，如 {"accuracy": 0.92, "f1": 0.88}"""
        _entry = {"fold": fold_idx}
        _entry.update(metrics)
        self._kfold_results.append(_entry)
        # 第一次注册时记录metric key顺序
        if not self._fold_metrics_order:
            self._fold_metrics_order = [k for k in metrics.keys()]

    def add_epoch(self, epoch, train_loss, val_loss):
        """记录一个epoch的训练/验证loss"""
        self._epoch_log.append((int(epoch), float(train_loss), float(val_loss)))

    def summarize(self):
        """返回汇总dict: 每个metric的 mean, std, min, max + folds_raw"""
        if not self._kfold_results:
            return {}

        _summary = {}
# 提取所有metric名
        _metric_names = self._fold_metrics_order
        if not _metric_names:
            _metric_names = [k for k in self._kfold_results[0].keys() if k != "fold"]

        for _m in _metric_names:
            _vals = np.array([_f[_m] for _f in self._kfold_results], dtype=np.float64)
            _summary[_m] = {
                "mean": float(np.mean(_vals)),
                "std": float(np.std(_vals, ddof=1)) if len(_vals) > 1 else 0.0,
                "min": float(np.min(_vals)),
                "max": float(np.max(_vals)),
                "folds": _vals.tolist(),
            }
        _summary["num_folds"] = len(self._kfold_results)
        _summary["_raw"] = list(self._kfold_results)
        return _summary

    def to_table(self):
        """pretty-print汇总表: mean ± std 格式"""
        _s = self.summarize()
        if not _s:
            return "No folds recorded."

        _metric_names = self._fold_metrics_order
        if not _metric_names:
            _metric_names = [k for k in _s.keys() if k not in ("num_folds", "_raw")]

        _lines = []
        _lines.append(f"K-Fold Eval Summary ({_s.get('num_folds', 0)} folds):")
        _lines.append("-" * 48)
        _lines.append(f"{'metric':>16} {'mean':>10} {'std':>10} {'min':>10} {'max':>10}")
        _lines.append("-" * 48)

        for _m in _metric_names:
            if _m not in _s:
                continue
            _d = _s[_m]
            _lines.append(
                f"{_m:>16} {_d['mean']:>10.4f} {_d['std']:>10.4f} {_d['min']:>10.4f} {_d['max']:>10.4f}"
            )
        _lines.append("-" * 48)

        # //// 附上 轮次 loss 摘要
        if self._epoch_log:
            _lines.append("")
            _lines.append("Epoch Log:")
            _ep_tr = np.array([_e[1] for _e in self._epoch_log])
            _ep_vl = np.array([_e[2] for _e in self._epoch_log])
            _lines.append(f"  train_loss: {_ep_tr[-1]:.6f} (final), {np.min(_ep_tr):.6f} (best)")
            _lines.append(f"  val_loss:   {_ep_vl[-1]:.6f} (final), {np.min(_ep_vl):.6f} (best)")

        return "\n".join(_lines)
