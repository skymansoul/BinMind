import logging
import os
import pickle
import json
from typing import Dict, List, Optional, Tuple, Any

from config import Config

logger = logging.getLogger(__name__)

SEVERITY_LEVELS = ['Low', 'Medium', 'High', 'Critical']
SEVERITY_MAPPING = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}


class VulnSeverityPredictor:
    """
    基于机器学习的漏洞严重性预测器
    
    使用预训练模型根据漏洞特征预测严重性级别（CVSS分数或High/Medium/Low）
    """
    
    def __init__(self, model_path: str = None):
        """
        初始化漏洞严重性预测器
        
        Args:
            model_path: 自定义模型文件路径
        """
        self.model_path = model_path or os.path.join(Config.DATA_DIR, 'models', 'severity_model.pkl')
        self.model = None
        self.scaler = None
        self.feature_names = []
        
        self._ensure_model_dir()
        
        logger.info(f"VulnSeverityPredictor 初始化完成: model_path={self.model_path}")
    
    def _ensure_model_dir(self):
        """确保模型目录存在"""
        model_dir = os.path.dirname(self.model_path)
        if model_dir and not os.path.exists(model_dir):
            os.makedirs(model_dir, exist_ok=True)
    
    def load_model(self) -> bool:
        """
        加载预训练模型
        
        Returns:
            是否成功加载模型
        """
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    model_data = pickle.load(f)
                    
                    self.model = model_data.get('model')
                    self.scaler = model_data.get('scaler')
                    self.feature_names = model_data.get('feature_names', [])
                    
                    logger.info(f"成功加载模型: {type(self.model).__name__}")
                    logger.info(f"特征数量: {len(self.feature_names)}")
                    return True
            except Exception as e:
                logger.error(f"加载模型失败: {e}")
                return False
        
        logger.warning(f"模型文件不存在: {self.model_path}")
        logger.info("将使用默认规则进行预测")
        return False
    
    def is_model_available(self) -> bool:
        """检查模型是否可用"""
        return self.model is not None
    
    def extract_features(self, vulnerability_info: Dict[str, Any]) -> List[float]:
        """
        从漏洞信息中提取特征向量
        
        Args:
            vulnerability_info: 漏洞信息字典
        
        Returns:
            特征向量
        """
        features = []
        
        features.append(self._extract_basic_block_count(vulnerability_info))
        features.append(self._extract_cyclomatic_complexity(vulnerability_info))
        features.append(self._extract_dangerous_function_count(vulnerability_info))
        features.append(self._extract_taint_path_length(vulnerability_info))
        features.append(self._extract_is_reachable(vulnerability_info))
        features.append(self._extract_protection_level(vulnerability_info))
        features.append(self._extract_language_factor(vulnerability_info))
        features.append(self._extract_arch_factor(vulnerability_info))
        features.append(self._extract_confidence(vulnerability_info))
        features.append(self._extract_vulnerability_type_factor(vulnerability_info))
        
        return features
    
    def _extract_basic_block_count(self, vuln_info: Dict[str, Any]) -> float:
        """提取基本块数量特征"""
        return float(vuln_info.get('basic_block_count', 10))
    
    def _extract_cyclomatic_complexity(self, vuln_info: Dict[str, Any]) -> float:
        """提取圈复杂度特征"""
        return float(vuln_info.get('cyclomatic_complexity', 5))
    
    def _extract_dangerous_function_count(self, vuln_info: Dict[str, Any]) -> float:
        """提取危险函数调用数量特征"""
        dangerous_funcs = vuln_info.get('dangerous_functions', [])
        return float(len(dangerous_funcs))
    
    def _extract_taint_path_length(self, vuln_info: Dict[str, Any]) -> float:
        """提取污点路径长度特征"""
        return float(vuln_info.get('taint_path_length', 5))
    
    def _extract_is_reachable(self, vuln_info: Dict[str, Any]) -> float:
        """提取是否可达入口点特征"""
        return float(vuln_info.get('is_reachable', True))
    
    def _extract_protection_level(self, vuln_info: Dict[str, Any]) -> float:
        """提取保护机制级别特征"""
        checksec = vuln_info.get('checksec', {})
        level = 0.0
        
        if checksec.get('nx', False):
            level += 0.25
        if checksec.get('pie', False):
            level += 0.25
        if checksec.get('canary', False):
            level += 0.25
        if checksec.get('relro', False) in ['Full', True]:
            level += 0.25
        
        return level
    
    def _extract_language_factor(self, vuln_info: Dict[str, Any]) -> float:
        """提取编程语言因子"""
        language = vuln_info.get('language', 'c/c++').lower()
        
        if 'rust' in language:
            return 0.3
        elif 'go' in language:
            return 0.2
        else:
            return 0.0
    
    def _extract_arch_factor(self, vuln_info: Dict[str, Any]) -> float:
        """提取架构因子"""
        arch = vuln_info.get('arch', 'unknown').lower()
        
        if '32' in arch or 'i386' in arch or 'x86' in arch:
            return 0.0
        elif '64' in arch or 'amd64' in arch or 'x86_64' in arch:
            return 0.3
        else:
            return 0.15
    
    def _extract_confidence(self, vuln_info: Dict[str, Any]) -> float:
        """提取置信度特征"""
        return float(vuln_info.get('confidence', 0.5))
    
    def _extract_vulnerability_type_factor(self, vuln_info: Dict[str, Any]) -> float:
        """提取漏洞类型因子"""
        vuln_type = vuln_info.get('type', 'unknown').lower()
        
        type_scores = {
            'buffer overflow': 1.0,
            'heap overflow': 1.0,
            'use after free': 0.9,
            'double free': 0.9,
            'format string': 0.85,
            'integer overflow': 0.7,
            'stack overflow': 0.95,
            'command injection': 0.9,
            'sql injection': 0.85,
            'path traversal': 0.6,
            'denial of service': 0.4,
            'information disclosure': 0.3
        }
        
        for type_name, score in type_scores.items():
            if type_name in vuln_type:
                return score
        
        return 0.0
    
    def predict(self, vulnerability_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        预测漏洞严重性
        
        Args:
            vulnerability_info: 漏洞信息字典
        
        Returns:
            预测结果字典，包含严重性类别和概率
        """
        features = self.extract_features(vulnerability_info)
        
        if self.model:
            return self._predict_with_model(features, vulnerability_info)
        else:
            return self._predict_with_rules(features, vulnerability_info)
    
    def _predict_with_model(self, features: List[float], vuln_info: Dict[str, Any]) -> Dict[str, Any]:
        """使用机器学习模型进行预测"""
        try:
            features_array = [features]
            
            if self.scaler:
                features_array = self.scaler.transform(features_array)
            
            prediction = self.model.predict(features_array)
            probabilities = self.model.predict_proba(features_array) if hasattr(self.model, 'predict_proba') else None
            
            predicted_severity = SEVERITY_LEVELS[int(prediction[0])]
            confidence = float(probabilities[0][int(prediction[0])]) if probabilities else 0.7
            
            return {
                'severity': predicted_severity,
                'confidence': confidence,
                'probabilities': {
                    SEVERITY_LEVELS[i]: float(probabilities[0][i])
                    for i in range(len(SEVERITY_LEVELS))
                } if probabilities else None,
                'method': 'machine_learning',
                'feature_importance': self._compute_feature_importance(features)
            }
        except Exception as e:
            logger.error(f"模型预测失败: {e}")
            return self._predict_with_rules(features, vuln_info)
    
    def _predict_with_rules(self, features: List[float], vuln_info: Dict[str, Any]) -> Dict[str, Any]:
        """使用规则引擎进行预测（回退方案）"""
        score = 0.0
        
        basic_blocks, complexity, dangerous_count, taint_length, is_reachable, \
            protection, language, arch, confidence, vuln_type = features
        
        score += min(dangerous_count * 0.2, 0.4)
        score += min(vuln_type, 0.3)
        score += (1.0 - protection) * 0.2
        score += (1.0 if is_reachable > 0.5 else 0.0) * 0.1
        
        if score >= 0.7:
            severity = 'Critical'
        elif score >= 0.5:
            severity = 'High'
        elif score >= 0.3:
            severity = 'Medium'
        else:
            severity = 'Low'
        
        return {
            'severity': severity,
            'confidence': min(confidence, 0.7),
            'probabilities': None,
            'method': 'rule_based',
            'feature_importance': None
        }
    
    def _compute_feature_importance(self, features: List[float]) -> Optional[Dict[str, float]]:
        """计算特征重要性（如果模型支持）"""
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
            return {
                name: float(importance)
                for name, importance in zip(self.feature_names, importances)
            }
        return None
    
    def predict_batch(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        批量预测漏洞严重性
        
        Args:
            vulnerabilities: 漏洞信息列表
        
        Returns:
            预测结果列表
        """
        results = []
        
        for vuln in vulnerabilities:
            result = self.predict(vuln)
            results.append({
                **vuln,
                'ml_prediction': result
            })
        
        return results
    
    def rank_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        对漏洞进行优先级排序
        
        Args:
            vulnerabilities: 漏洞信息列表（已包含预测结果）
        
        Returns:
            按严重性排序后的漏洞列表
        """
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda x: (
                severity_order.get(x.get('ml_prediction', {}).get('severity', 'Low'), 3),
                -x.get('ml_prediction', {}).get('confidence', 0.0)
            )
        )
        
        return sorted_vulns
    
    def get_feature_names(self) -> List[str]:
        """获取特征名称列表"""
        return [
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
        ]
    
    def generate_explanation(self, vulnerability_info: Dict[str, Any]) -> str:
        """
        生成预测结果解释
        
        Args:
            vulnerability_info: 漏洞信息（已包含预测结果）
        
        Returns:
            解释文本
        """
        ml_prediction = vulnerability_info.get('ml_prediction', {})
        severity = ml_prediction.get('severity', 'Unknown')
        confidence = ml_prediction.get('confidence', 0.0)
        method = ml_prediction.get('method', 'unknown')
        feature_importance = ml_prediction.get('feature_importance', {})
        
        lines = []
        lines.append(f"## ML 预测结果解释")
        lines.append("")
        lines.append(f"- **预测严重性**: {severity}")
        lines.append(f"- **置信度**: {confidence:.2f}")
        lines.append(f"- **预测方法**: {method}")
        lines.append("")
        
        if feature_importance:
            lines.append("### 特征重要性")
            sorted_importance = sorted(feature_importance.items(), key=lambda x: -x[1])
            
            for name, importance in sorted_importance[:5]:
                lines.append(f"- {name}: {importance:.4f}")
        
        return '\n'.join(lines)


def create_vuln_severity_predictor(model_path: str = None) -> VulnSeverityPredictor:
    """
    创建漏洞严重性预测器的便捷函数
    
    Args:
        model_path: 自定义模型文件路径
    
    Returns:
        VulnSeverityPredictor 实例
    """
    predictor = VulnSeverityPredictor(model_path)
    predictor.load_model()
    return predictor


def train_default_model(output_path: str = None):
    """
    训练默认模型（用于首次运行或模型更新）
    
    Args:
        output_path: 模型输出路径
    
    Returns:
        是否成功训练
    """
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import StandardScaler
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report
        import numpy as np
        
        logger.info("开始训练漏洞严重性预测模型...")
        
        X, y = _generate_synthetic_training_data()
        
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42
        )
        
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        model.fit(X_train, y_train)
        
        y_pred = model.predict(X_test)
        logger.info("模型评估报告:")
        logger.info(classification_report(y_test, y_pred, target_names=SEVERITY_LEVELS))
        
        output_path = output_path or os.path.join(Config.DATA_DIR, 'models', 'severity_model.pkl')
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        model_data = {
            'model': model,
            'scaler': scaler,
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
            ]
        }
        
        with open(output_path, 'wb') as f:
            pickle.dump(model_data, f)
        
        logger.info(f"模型已保存到: {output_path}")
        return True
    
    except ImportError as e:
        logger.error(f"缺少依赖: {e}")
        return False
    except Exception as e:
        logger.error(f"训练模型失败: {e}")
        return False


def _generate_synthetic_training_data() -> Tuple[np.ndarray, np.ndarray]:
    """生成合成训练数据"""
    import numpy as np
    
    np.random.seed(42)
    n_samples = 10000
    
    basic_block_count = np.random.randint(5, 100, n_samples).astype(float)
    cyclomatic_complexity = np.random.randint(1, 50, n_samples).astype(float)
    dangerous_function_count = np.random.randint(0, 10, n_samples).astype(float)
    taint_path_length = np.random.randint(1, 50, n_samples).astype(float)
    is_reachable = np.random.randint(0, 2, n_samples).astype(float)
    protection_level = np.random.random(n_samples)
    language_factor = np.random.choice([0.0, 0.2, 0.3], n_samples)
    arch_factor = np.random.choice([0.0, 0.15, 0.3], n_samples)
    confidence = np.random.random(n_samples)
    vuln_type_factor = np.random.random(n_samples)
    
    X = np.column_stack([
        basic_block_count,
        cyclomatic_complexity,
        dangerous_function_count,
        taint_path_length,
        is_reachable,
        protection_level,
        language_factor,
        arch_factor,
        confidence,
        vuln_type_factor
    ])
    
    score = (
        dangerous_function_count * 0.1 +
        vuln_type_factor * 0.3 +
        (1.0 - protection_level) * 0.2 +
        is_reachable * 0.15 +
        cyclomatic_complexity / 100 +
        np.random.random(n_samples) * 0.25
    )
    
    y = np.zeros(n_samples)
    y[score >= 0.7] = 3
    y[(score >= 0.5) & (score < 0.7)] = 2
    y[(score >= 0.3) & (score < 0.5)] = 1
    y[score < 0.3] = 0
    
    return X, y