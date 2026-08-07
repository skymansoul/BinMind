# 监督学习训练器 + 早停 + 余弦退火
# 纯 numpy 实现，为后续 PyTorch 迁移保留一致的 API 接口
# 适合小批量二进制分析任务（函数分类、漏洞检测等）

import numpy as np


# EarlyStopping: 验证损失不下降时提前终止
# min_delta 防止数值噪音导致误触发
# mode='min' 监控最小值，mode='max' 监控最大值（如准确率）

class EarlyStopping:
    """Early stopping tracker with state dict support."""
    def __init__(self, patience=10, min_delta=1e-4, mode='min'):
        self._p = patience
        self._d = min_delta
        self._mode = mode
        self._counter = 0
        self._best = np.inf if mode == 'min' else -np.inf
        self._stop = False

    def __call__(self, current_value):
        """Returns True if training should stop."""
        if self._mode == 'min':
            _better = current_value < self._best - self._d
        else:
            _better = current_value > self._best + self._d

        if _better:
            self._best = current_value
            self._counter = 0
        else:
            self._counter += 1

        self._stop = self._counter >= self._p
        return self._stop

    def state_dict(self):
        return {
            'counter': self._counter, 'best': self._best,
            'patience': self._p, 'min_delta': self._d, 'mode': self._mode
        }

    def load_state_dict(self, state):
        self._counter = state['counter']
        self._best = state['best']
        self._p = state['patience']
        self._d = state['min_delta']
        self._mode = state['mode']
        self._stop = False


# CosineAnnealingLR: 余弦退火学习率调度
# 从初始 lr 平滑衰减到 min_lr，T_max 周期后完成一个退火循环
# 适合在训练后期精细调整权重

class CosineAnnealingLR:
    """Cosine annealing learning rate scheduler."""
    def __init__(self, initial_lr, min_lr=1e-6, T_max=100):
        self._lr0 = initial_lr
        self._lr_min = min_lr
        self._T = T_max

    def __call__(self, epoch):
        """Returns learning rate for given epoch (0-indexed)."""
        _t = min(epoch, self._T)
        _lr = self._lr_min + 0.5 * (self._lr0 - self._lr_min) * \
              (1.0 + np.cos(np.pi * _t / self._T))
        return _lr


# SupervisedTrainer: 纯 numpy 监督训练器
# 设计原则：最小依赖，最大可读性
# 支持自定义 loss、早停、学习率调度、验证集

class SupervisedTrainer:
    """Pure-numpy supervised training loop with mini-batch SGD."""
    def __init__(self, model, loss_fn=None, lr=0.01, epochs=100,
                 early_stopping=None, lr_scheduler=None):
        self._model = model
        self._loss_fn = loss_fn if loss_fn is not None else self._default_loss
        self._lr = lr
        self._epochs = epochs
        self._es = early_stopping
        self._scheduler = lr_scheduler
        self._history = {'train_loss': [], 'val_loss': [], 'val_acc': []}


    @staticmethod
    def _default_loss(y_pred, y_true):
        """Cross-entropy from logits."""
        _eps = 1e-12
        _p = np.clip(y_pred, _eps, 1.0 - _eps)
        _n = y_pred.shape[0]
        _y = np.zeros_like(_p)
        _y[np.arange(_n), y_true.astype(np.int64)] = 1.0
        return -np.sum(_y * np.log(_p)) / _n

    # ////

    def fit(self, X, y, X_val=None, y_val=None):
        """
        Run full training loop.
        Returns dict with 'train_loss', 'val_loss', 'val_acc' histories.
        """
        _X = np.asarray(X, dtype=np.float64)
        _y = np.asarray(y)

        for _ep in range(self._epochs):
            # 学习率调度
            if self._scheduler is not None:
                self._lr = self._scheduler(_ep)

            # 单 轮次 训练
            _t_loss = self._train_epoch(_X, _y)
            self._history['train_loss'].append(_t_loss)

            # 验证
            if X_val is not None and y_val is not None:
                _v_loss, _v_acc = self._validate(X_val, y_val)
                self._history['val_loss'].append(_v_loss)
                self._history['val_acc'].append(_v_acc)

                # 早停检查（基于验证损失）
                if self._es is not None:
                    if self._es(_v_loss):
                        break

        return self._history

    # ////

    def _train_epoch(self, X, y):
        """Single training epoch with mini-batch SGD. Returns average loss."""
        _n = X.shape[0]
        _bs = min(32, _n)  # 小批量适合二进制分析任务
        _indices = np.arange(_n)
        np.random.shuffle(_indices)

        _total_loss = 0.0
        _batches = 0

        for _start in range(0, _n, _bs):
            _end = min(_start + _bs, _n)
            _bidx = _indices[_start:_end]
            _xb = X[_bidx]
            _yb = y[_bidx]

            # 前向
            _pred = self._model(_xb)
            _loss = self._loss_fn(_pred, _yb)
            _total_loss += float(_loss)
            _batches += 1

            # 反向传播（假设 model 有 backward 方法）
            if hasattr(self._model, 'backward'):
                self._model.backward(_loss)
                if hasattr(self._model, 'params') and hasattr(self._model, 'grads'):
                    _sgd_update(self._model.params, self._model.grads, self._lr)

        return _total_loss / max(_batches, 1)

    # ////

    def _validate(self, X_val, y_val):
        """Validation pass. Returns (loss, accuracy)."""
        _X = np.asarray(X_val, dtype=np.float64)
        _y = np.asarray(y_val)
        _pred = self._model(_X)
        _loss = self._loss_fn(_pred, _y)
        _acc = self.score(_X, _y)
        return float(_loss), _acc


    def predict(self, X):
        """Forward inference on X. Returns predicted class indices."""
        _X = np.asarray(X, dtype=np.float64)
        _out = self._model(_X)
        return np.argmax(_out, axis=1)


    def score(self, X, y):
        """Accuracy score."""
        _y = np.asarray(y)
        _pred = self.predict(X)
        return np.mean(_pred == _y)


# //////////////////////////////////////////////////////////////////////////
# 内部 SGD 更新（trainer 内部使用，避免循环导入 contrastive）

def _sgd_update(params, grads, lr=0.01):
    """SGD parameter update for numpy arrays: params[i] -= lr * grads[i]."""
    _n = min(len(params), len(grads))
    for _i in range(_n):
        params[_i] -= lr * grads[_i]
