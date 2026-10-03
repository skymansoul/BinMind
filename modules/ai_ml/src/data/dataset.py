# dataset.py 二进制函数数据集与三元组挖掘
# BinaryFuncDataset: 单样本(特征, 标签)加载
# TripletMiningDataset: FaceNet半困难三元组挖掘
# 余弦相似度在12维特征上做，不需要归一化到单位球

import json
import os
import random
import numpy as np

# 尝试导入torch，失败则回退到纯numpy模式
try:
    import torch
    from torch.utils.data import Dataset as _TorchDataset
    _HAS_TORCH = True
except ImportError:
    _TorchDataset = object
    _HAS_TORCH = False


class BinaryFuncDataset(_TorchDataset):
    """Loads binary function data from JSON or JSON-lines files.

    Each entry should have 'features' (list/array of 12 floats) and 'label' (int).
    """

    def __init__(self, json_path: str):
        self._samples = []
        self._path = json_path
        self._load()

    def _load(self):
        """Parse JSON or JSONL file into internal samples list."""
        if not os.path.exists(self._path):
            raise FileNotFoundError(f"Dataset not found: {self._path}")

        with open(self._path, 'r', encoding='utf-8') as _fh:
            _raw = _fh.read()

        # 先试整个JSON数组
        _raw_stripped = _raw.strip()
        if _raw_stripped.startswith('['):
            _data = json.loads(_raw_stripped)
            if isinstance(_data, list):
                for _item in _data:
                    self._samples.append(self._parse_item(_item))
                return

        # JSON-lines模式：逐行解析
        for _line in _raw_stripped.split('\n'):
            _line = _line.strip()
            if not _line:
                continue
            try:
                _item = json.loads(_line)
                self._samples.append(self._parse_item(_item))
            except json.JSONDecodeError:
                # 跳过损坏行
                continue

    def _parse_item(self, item: dict) -> tuple:
        _feat = item.get('features', item.get('feat', item.get('f', [])))
        _lbl = item.get('label', item.get('lbl', item.get('l', 0)))

        # 确保features是12维
        if isinstance(_feat, list):
            _feat = np.array(_feat, dtype=np.float64)
        elif isinstance(_feat, np.ndarray):
            pass
        else:
            _feat = np.zeros(12, dtype=np.float64)

        if _feat.shape[0] != 12:
            # 填充或截断到12维
            _padded = np.zeros(12, dtype=np.float64)
            _n_copy = min(len(_feat), 12)
            _padded[:_n_copy] = _feat[:_n_copy]
            _feat = _padded

        if _HAS_TORCH:
            _feat = torch.tensor(_feat, dtype=torch.float64)
            _lbl = torch.tensor(_lbl, dtype=torch.long)
        else:
            _lbl = int(_lbl)

        return (_feat, _lbl)

    def __getitem__(self, idx: int):
        return self._samples[idx]

    def __len__(self) -> int:
        return len(self._samples)


# TripletMiningDataset
class TripletMiningDataset(_TorchDataset):
    """Semi-hard triplet mining for binary function similarity.

    FaceNet approach: for each anchor, select hardest positive (same label)
    and semi-hard negative (different label, further than positive but
    within margin).
    """

    def __init__(self, json_path: str, margin: float = 0.5):
        self._samples = []       # list of (features, label)
        self._labels = []        # parallel list of labels
        self._label_to_idx = {}  # label -> list of sample indices
        self._margin = margin
        self._path = json_path
        self._load_and_index()

    def _load_and_index(self):
        """Load data and build label-index mapping for efficient triplet lookup."""
        if not os.path.exists(self._path):
            raise FileNotFoundError(f"Dataset not found: {self._path}")

        with open(self._path, 'r', encoding='utf-8') as _fh:
            _raw = _fh.read()

        _raw_stripped = _raw.strip()

        # JSON array
        _records = []
        if _raw_stripped.startswith('['):
            _records = json.loads(_raw_stripped)
        else:
            for _line in _raw_stripped.split('\n'):
                _line = _line.strip()
                if not _line:
                    continue
                try:
                    _records.append(json.loads(_line))
                except json.JSONDecodeError:
                    pass

        for _item in _records:
            _feat = _item.get('features', _item.get('feat', _item.get('f', [])))
            _lbl = _item.get('label', _item.get('lbl', _item.get('l', 0)))

            if isinstance(_feat, list):
                _feat = np.array(_feat, dtype=np.float64)
            elif not isinstance(_feat, np.ndarray):
                _feat = np.zeros(12, dtype=np.float64)

            if _feat.shape[0] != 12:
                _padded = np.zeros(12, dtype=np.float64)
                _n_copy = min(len(_feat), 12)
                _padded[:_n_copy] = _feat[:_n_copy]
                _feat = _padded

            _lbl = int(_lbl)

            if _HAS_TORCH:
                _feat = torch.tensor(_feat, dtype=torch.float64)
                _lbl = torch.tensor(_lbl, dtype=torch.long)

            _idx = len(self._samples)
            self._samples.append((_feat, _lbl))
            self._labels.append(_lbl)

            _lbl_key = int(_lbl.item()) if _HAS_TORCH else _lbl
            if _lbl_key not in self._label_to_idx:
                self._label_to_idx[_lbl_key] = []
            self._label_to_idx[_lbl_key].append(_idx)

    def _compute_similarity(self, a, b) -> float:
        """Cosine similarity between two feature vectors."""
        if _HAS_TORCH:
            _a = a.detach().numpy() if isinstance(a, torch.Tensor) else a
            _b = b.detach().numpy() if isinstance(b, torch.Tensor) else b
        else:
            _a, _b = a, b

        _a = np.asarray(_a, dtype=np.float64).flatten()
        _b = np.asarray(_b, dtype=np.float64).flatten()

        _na = np.linalg.norm(_a)
        _nb = np.linalg.norm(_b)
        if _na < 1e-10 or _nb < 1e-10:
            return 0.0
        return float(np.dot(_a, _b) / (_na * _nb))

    def _mine_triplets(self, anchor_idx: int) -> tuple:
        """Find (hardest_positive, semi_hard_negative) for a given anchor.

        Returns (pos_idx, neg_idx) or (anchor_idx, anchor_idx) on failure.
        """
        _a_feat, _a_lbl = self._samples[anchor_idx]
        _a_lbl_key = int(_a_lbl.item()) if _HAS_TORCH else _a_lbl

        # 同一标签的所有样本（排除锚点自身）
        _pos_candidates = [
            _i for _i in self._label_to_idx.get(_a_lbl_key, [])
            if _i != anchor_idx
        ]

        if not _pos_candidates:
            return (anchor_idx, anchor_idx)

# 最难正样本：相似度最低的同标签样本
        _hardest_pos = _pos_candidates[0]
        _hardest_pos_sim = self._compute_similarity(_a_feat, self._samples[_hardest_pos][0])
        for _pi in _pos_candidates[1:]:
            _sim = self._compute_similarity(_a_feat, self._samples[_pi][0])
            if _sim < _hardest_pos_sim:
                _hardest_pos_sim = _sim
                _hardest_pos = _pi

# 半困难负样本
        # 条件：sim(anchor, neg) > sim(anchor, pos) 且 < sim(anchor, pos) + margin
        _neg_candidates = []
        for _lbl, _indices in self._label_to_idx.items():
            if _lbl == _a_lbl_key:
                continue
            _neg_candidates.extend(_indices)

        if not _neg_candidates:
            return (_hardest_pos, _hardest_pos)  # 回退

        # 搜索半困难负样本
        _semi_hard_neg = None
        _semi_hard_sim = -1.0
        _lower_bound = _hardest_pos_sim
        _upper_bound = _hardest_pos_sim + self._margin

        for _ni in _neg_candidates:
            _sim = self._compute_similarity(_a_feat, self._samples[_ni][0])
            if _lower_bound < _sim < _upper_bound:
                # 半困难区间内：选最接近锚点的（相似度最高的）
                if _sim > _semi_hard_sim:
                    _semi_hard_sim = _sim
                    _semi_hard_neg = _ni

        if _semi_hard_neg is None:
            # 没有半困难样本：退化为随机负样本（非半困难策略）
            # 从所有负样本中选相似度最低的（最不像锚点的）
            _hardest_neg = _neg_candidates[0]
            _hardest_neg_sim = self._compute_similarity(_a_feat, self._samples[_hardest_neg][0])
            for _ni in _neg_candidates[1:]:
                _sim = self._compute_similarity(_a_feat, self._samples[_ni][0])
                if _sim < _hardest_neg_sim:
                    _hardest_neg_sim = _sim
                    _hardest_neg = _ni
            _semi_hard_neg = _hardest_neg

        return (_hardest_pos, _semi_hard_neg)

    def __getitem__(self, idx: int):
        _a_feat, _a_lbl = self._samples[idx]
        _pos_idx, _neg_idx = self._mine_triplets(idx)

        _p_feat, _p_lbl = self._samples[_pos_idx]
        _n_feat, _n_lbl = self._samples[_neg_idx]

        return (_a_feat, _p_feat, _n_feat)

    def __len__(self) -> int:
        return len(self._samples)


# collate_fn
def collate_fn(batch: list):
    """Batch collation for DataLoader.

    Handles both (features, label) pairs and (anchor, positive, negative) triplets.
    """
    if not batch:
        return batch

    _first = batch[0]

    # 三元组格式
    if isinstance(_first, tuple) and len(_first) == 3:
        _anchors = [_item[0] for _item in batch]
        _positives = [_item[1] for _item in batch]
        _negatives = [_item[2] for _item in batch]
        if _HAS_TORCH:
            return (
                torch.stack(_anchors),
                torch.stack(_positives),
                torch.stack(_negatives),
            )
        return (
            np.stack(_anchors),
            np.stack(_positives),
            np.stack(_negatives),
        )

    # 二值格式 (features, label)
    if isinstance(_first, tuple) and len(_first) == 2:
        _feats = [_item[0] for _item in batch]
        _lbls = [_item[1] for _item in batch]
        if _HAS_TORCH:
            return (
                torch.stack(_feats),
                torch.tensor([int(_l.item()) if hasattr(_l, 'item') else int(_l) for _l in _lbls], dtype=torch.long),
            )
        return (
            np.stack(_feats),
            np.array([int(_l) for _l in _lbls]),
        )

    # 其他：直接stack
    if _HAS_TORCH and isinstance(_first, torch.Tensor):
        return torch.stack(batch)
    return np.stack(batch)
