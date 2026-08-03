#!/usr/bin/env python3
# Pipeline 训练 configuration -- task types, checkpoint management, and
# default 超参数 presets consumed by the fine-tuning pipeline.
#
# INTJ rationale: extracting config from custom_ai_finetune_pipeline.py
# separates "what we train with" from "how we train." The pipeline module
# should orchestrate -- not own task-type enums or checkpoint hashing logic.
# This keeps the config surface narrow and allows the trainer layer to import
# config types without dragging in the full data-augmentation / curriculum /
# contrastive-采样 machinery. Single-responsibility, low coupling.

import os
import time
import hashlib


class TaskType:
    BINARY_SIMILARITY = "binary_similarity"
    VULNERABILITY_DETECTION = "vulnerability_detection"
    FUNCTION_NAMING = "function_naming"
    FUNCTION_SUMMARY = "function_summary"
    PATH_PRIORITIZATION = "path_prioritization"
    DECOMPILATION_QUALITY = "decompilation_quality"


class FineTuneCheckpoint:
    """Model checkpoint with hash-based dedup."""

    __slots__ = ('m_path', 'm_hash', 'm_metrics', 'm_timestamp')

    def __init__(self, path, metrics=None):
        self.m_path = path
        self.m_hash = self._compute_hash(path)
        self.m_metrics = metrics if metrics else {}
        self.m_timestamp = time.time()

    def _compute_hash(self, path):
        if path is None or not os.path.exists(path):
            return ''
        try:
            hasher = hashlib.sha256()
            with open(path, 'rb') as f:
                chunk = f.read(8192)
                while chunk:
                    hasher.update(chunk)
                    chunk = f.read(8192)
            return hasher.hexdigest()
        except Exception:
            return ''
