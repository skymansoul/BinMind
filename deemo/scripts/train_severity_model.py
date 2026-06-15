#!/usr/bin/env python3
"""
漏洞严重性预测模型训练脚本

用于训练机器学习模型，根据漏洞特征预测其严重性级别。
生成的模型文件保存在 data/models/severity_model.pkl
"""

import os
import sys
import pickle
import argparse
import logging
from typing import Tuple

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config


def setup_logging():
    """设置日志配置"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def generate_synthetic_training_data(n_samples: int = 10000) -> Tuple:
    """
    生成合成训练数据
    
    Args:
        n_samples: 样本数量
    
    Returns:
        X: 特征矩阵
        y: 标签数组
    """
    import numpy as np
    
    np.random.seed(42)
    
    # 特征定义
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
    
    # 计算综合分数用于生成标签
    score = (
        dangerous_function_count * 0.1 +
        vuln_type_factor * 0.3 +
        (1.0 - protection_level) * 0.2 +
        is_reachable * 0.15 +
        cyclomatic_complexity / 100 +
        np.random.random(n_samples) * 0.25
    )
    
    # 根据分数分配严重性标签
    y = np.zeros(n_samples)
    y[score >= 0.7] = 3  # Critical
    y[(score >= 0.5) & (score < 0.7)] = 2  # High
    y[(score >= 0.3) & (score < 0.5)] = 1  # Medium
    y[score < 0.3] = 0  # Low
    
    return X, y


def train_model(X, y, output_path: str):
    """
    训练机器学习模型
    
    Args:
        X: 特征矩阵
        y: 标签数组
        output_path: 模型输出路径
    
    Returns:
        是否训练成功
    """
    logger = logging.getLogger(__name__)
    
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import StandardScaler
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report, confusion_matrix
        import numpy as np
        
        logger.info(f"训练样本数: {len(X)}")
        logger.info(f"特征数: {X.shape[1]}")
        
        # 数据划分
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )
        
        logger.info(f"训练集: {len(X_train)} 样本")
        logger.info(f"测试集: {len(X_test)} 样本")
        
        # 训练模型
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced',
            n_jobs=-1
        )
        
        logger.info("开始训练随机森林模型...")
        model.fit(X_train, y_train)
        
        # 评估模型
        y_pred = model.predict(X_test)
        
        logger.info("\n模型评估报告:")
        logger.info(classification_report(y_test, y_pred, target_names=['Low', 'Medium', 'High', 'Critical']))
        
        logger.info("\n混淆矩阵:")
        logger.info(confusion_matrix(y_test, y_pred))
        
        # 特征重要性
        feature_names = [
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
        
        logger.info("\n特征重要性:")
        importances = model.feature_importances_
        for name, importance in sorted(zip(feature_names, importances), key=lambda x: -x[1]):
            logger.info(f"  {name}: {importance:.4f}")
        
        # 保存模型
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        model_data = {
            'model': model,
            'scaler': scaler,
            'feature_names': feature_names,
            'version': '1.0.0',
            'n_samples': len(X),
            'accuracy': model.score(X_test, y_test)
        }
        
        with open(output_path, 'wb') as f:
            pickle.dump(model_data, f)
        
        logger.info(f"\n模型已保存到: {output_path}")
        logger.info(f"模型准确率: {model.score(X_test, y_test):.4f}")
        
        return True
        
    except ImportError as e:
        logger.error(f"缺少依赖: {e}")
        logger.error("请安装: pip install scikit-learn numpy")
        return False
    except Exception as e:
        logger.error(f"训练模型失败: {e}", exc_info=True)
        return False


def load_existing_data(data_path: str):
    """
    加载现有的训练数据（如果存在）
    
    Args:
        data_path: 数据文件路径
    
    Returns:
        X, y 或 None
    """
    logger = logging.getLogger(__name__)
    
    if os.path.exists(data_path):
        try:
            import numpy as np
            data = np.load(data_path)
            X = data['X']
            y = data['y']
            logger.info(f"已加载现有训练数据: {len(X)} 样本")
            return X, y
        except Exception as e:
            logger.warning(f"加载现有数据失败: {e}")
    
    return None


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='训练漏洞严重性预测模型')
    parser.add_argument(
        '--output',
        '-o',
        default=None,
        help='模型输出路径（默认: data/models/severity_model.pkl）'
    )
    parser.add_argument(
        '--samples',
        '-n',
        type=int,
        default=10000,
        help='生成的合成样本数量（默认: 10000）'
    )
    parser.add_argument(
        '--data',
        help='现有训练数据文件路径（.npz格式）'
    )
    parser.add_argument(
        '--overwrite',
        action='store_true',
        help='覆盖现有模型文件'
    )
    
    args = parser.parse_args()
    
    setup_logging()
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 60)
    logger.info("漏洞严重性预测模型训练脚本")
    logger.info("=" * 60)
    
    # 确定输出路径
    output_path = args.output or Config.ML_MODEL_PATH
    
    # 检查是否已存在模型
    if os.path.exists(output_path) and not args.overwrite:
        logger.error(f"模型文件已存在: {output_path}")
        logger.error("使用 --overwrite 参数覆盖现有模型")
        sys.exit(1)
    
    # 加载或生成训练数据
    if args.data:
        data = load_existing_data(args.data)
        if data:
            X, y = data
        else:
            logger.info("无法加载现有数据，生成合成数据")
            X, y = generate_synthetic_training_data(args.samples)
    else:
        logger.info(f"生成 {args.samples} 个合成训练样本...")
        X, y = generate_synthetic_training_data(args.samples)
    
    # 训练模型
    success = train_model(X, y, output_path)
    
    if success:
        logger.info("\n训练完成！")
        sys.exit(0)
    else:
        logger.error("\n训练失败！")
        sys.exit(1)


if __name__ == '__main__':
    main()
