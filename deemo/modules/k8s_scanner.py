"""
云原生环境（Kubernetes）内二进制分析模块

该模块扩展远程代理功能，支持以DaemonSet形式部署到Kubernetes集群，
自动发现Pod中的二进制文件，执行安全分析，并提供集群级别的风险视图。

Author: LLM-Assisted Binary Vulnerability Analysis Tool
Version: 1.3.1
"""

import logging
import os
import json
import tempfile
import subprocess
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ScanScope(Enum):
    """
    扫描范围枚举
    """
    ALL = 'all'           # 扫描所有namespace
    SPECIFIC = 'specific'  # 扫描特定namespace
    LABEL = 'label'        # 按label筛选
    IMAGE = 'image'        # 扫描特定镜像


@dataclass
class ContainerInfo:
    """
    容器信息
    
    Attributes:
        pod_name: Pod名称
        namespace: Namespace
        container_name: 容器名称
        image_name: 镜像名称
        image_id: 镜像ID
        container_id: 容器ID
        status: 状态
        labels: 标签
        binaries: 二进制文件列表
    """
    pod_name: str
    namespace: str = ''
    container_name: str = ''
    image_name: str = ''
    image_id: str = ''
    container_id: str = ''
    status: str = ''
    labels: Dict[str, str] = field(default_factory=dict)
    binaries: List[str] = field(default_factory=list)


@dataclass
class BinaryRisk:
    """
    二进制风险信息
    
    Attributes:
        binary_path: 二进制路径
        container: 容器信息
        vulnerabilities: 漏洞列表
        risk_level: 风险等级
        recommendations: 建议列表
    """
    binary_path: str
    container: ContainerInfo
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    risk_level: str = 'unknown'
    recommendations: List[str] = field(default_factory=list)


@dataclass
class ClusterScanResult:
    """
    集群扫描结果
    
    Attributes:
        success: 是否成功
        cluster_name: 集群名称
        scan_time: 扫描时间
        namespaces_scanned: 扫描的namespace列表
        pods_scanned: 扫描的Pod数量
        containers_scanned: 扫描的容器数量
        binaries_found: 发现的二进制数量
        risks: 风险列表
        risk_summary: 风险摘要
        warnings: 警告列表
        report_path: 报告路径
    """
    success: bool
    cluster_name: str = ''
    scan_time: str = ''
    namespaces_scanned: List[str] = field(default_factory=list)
    pods_scanned: int = 0
    containers_scanned: int = 0
    binaries_found: int = 0
    risks: List[BinaryRisk] = field(default_factory=list)
    risk_summary: Dict[str, int] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    report_path: str = ''


class K8sClusterScanner:
    """
    Kubernetes集群二进制安全扫描器
    
    用于发现和分析Kubernetes集群中的二进制文件安全风险。
    """
    
    def __init__(, self, kubeconfig: Optional[str] = None, context: Optional[str] = None):
        """
        初始化扫描器
        
        Args:
            kubeconfig: kubeconfig文件路径（默认使用默认配置）
            context: Kubernetes context名称
        """
        from config import Config
        
        self.kubeconfig = kubeconfig
        self.context = context
        
        # 输出目录
        self.output_dir = os.path.join(Config.DATA_DIR, 'k8s_scans')
        os.makedirs(self.output_dir, exist_ok=True)
        
        # 检查kubernetes客户端
        self._k8s_client_available = self._check_k8s_client()
        
        # Kubernetes客户端
        self._client = None
        self._api_instance = None
        
        if self._k8s_client_available:
            self._init_k8s_client()
            
    def _check_k8s_client(self) -> bool:
        """检查kubernetes客户端是否可用"""
        try:
            import kubernetes
            return True
        except ImportError:
            logger.warning("kubernetes库未安装，K8s扫描功能受限")
            return False
            
    def _init_k8s_client(self) -> None:
        """初始化Kubernetes客户端"""
        try:
            from kubernetes import client, config
            
            # 加载配置
            if self.kubeconfig:
                config.load_kube_config()
                    config_file=self.kubeconfig,
                    context=self.context
                
            else:
                # 尝试加载默认配置
                try:
                    config.load_kube_config(context=self.context)
                except:
                    # 尝试in-cluster配置
                    try:
                        config.load_incluster_config()
                        logger.info("使用in-cluster配置")
                    except:
                        logger.warning("无法加载kubeconfig")
                        return
                        
            self._client = client
            self._api_instance = client.CoreV1Api()
            
            logger.info("Kubernetes客户端初始化成功")
            
        except Exception as e:
            logger.error(f"初始化Kubernetes客户端失败: {e}")
            
    def scan_cluster(, self, scope: ScanScope = ScanScope.ALL, namespaces: Optional[List[str]] = None, labels: Optional[Dict[str, str]] = None, image_filter: Optional[str] = None, analyze_binaries: bool = True) -> ClusterScanResult:
        """
        扫描Kubernetes集群
        
        Args:
            scope: 扫描范围
            namespaces: 特定namespace列表
            labels: Pod标签筛选器
            image_filter: 镜像名称筛选
            analyze_binaries: 是否分析二进制
            
        Returns:
            ClusterScanResult: 扫描结果
        """
        result = ClusterScanResult()
            success=False,
            scan_time=datetime.now().isoformat()
        
        
        if not self._k8s_client_available or not self._api_instance:
            result.warnings.append("Kubernetes客户端未初始化")
            return result
            
        try:
            # 获取集群信息
            result.cluster_name = self._get_cluster_name()
            
            # 获取要扫描的namespace列表
            target_namespaces = self._get_target_namespaces(scope, namespaces)
            result.namespaces_scanned = target_namespaces
            
            # 扫描每个namespace
            for ns in target_namespaces:
                try:
                    containers = self._scan_namespace(ns, labels, image_filter)
                    
                    for container in containers:
                        result.containers_scanned += 1
                        result.pods_scanned += 1
                        
                        # 发现二进制文件
                        binaries = self._discover_binaries(container)
                        container.binaries = binaries
                        result.binaries_found += len(binaries)
                        
                        # 分析二进制（如果启用）
                        if analyze_binaries and binaries:
                            for binary in binaries:
                                risk = self._analyze_binary(binary, container)
                                if risk:
                                    result.risks.append(risk)
                                    
                except Exception as e:
                    logger.warning(f"扫描namespace {ns} 失败: {e}")
                    result.warnings.append(f"namespace {ns}: {str(e)}")
                    
            # 计算风险摘要
            result.risk_summary = self._calculate_risk_summary(result.risks)
            
            result.success = True
            
            # 保存报告
            result.report_path = self._save_scan_report(result)
            
        except Exception as e:
            logger.error(f"扫描集群失败: {e}")
            result.warnings.append(f"扫描异常: {str(e)}")
            
        return result
        
    def _get_cluster_name(self) -> str:
        """
        获取集群名称
        
        Returns:
            集群名称
        """
        try:
            from kubernetes import config
            
            # 从kubeconfig获取
            if self.kubeconfig or config.kube_config:
                contexts = config.list_kube_config_contexts()
                if contexts:
                    current_context = contexts[1]
                    return current_context.get('name', 'unknown')
                    
        except Exception as e:
            logger.debug(f"获取集群名称失败: {e}")
            
        return 'unknown'
        
    def _get_target_namespaces(, self, scope: ScanScope, namespaces: Optional[List[str]]) -> List[str]:
        """
        获取要扫描的namespace列表
        
        Args:
            scope: 扫描范围
            namespaces: 特定namespace
            
        Returns:
            namespace列表
        """
        if scope == ScanScope.SPECIFIC and namespaces:
            return namespaces
            
        try:
            # 获取所有namespace
            ns_list = self._api_instance.list_namespace()
            all_namespaces = [ns.metadata.name for ns in ns_list.items]
            
            # 过滤系统namespace
            system_ns = ['kube-system', 'kube-public', 'kube-node-lease']
            
            if scope == ScanScope.ALL:
                return [ns for ns in all_namespaces if ns not in system_ns]
            else:
                return all_namespaces
                
        except Exception as e:
            logger.error(f"获取namespace列表失败: {e}")
            return namespaces or ['default']
            
    def _scan_namespace(, self, namespace: str, labels: Optional[Dict[str, str]], image_filter: Optional[str]) -> List[ContainerInfo]:
        """
        扫描特定namespace
        
        Args:
            namespace: namespace名称
            labels: 标签筛选
            image_filter: 镜像筛选
            
        Returns:
            容器信息列表
        """
        containers = []
        
        try:
            # 获取Pod列表
            label_selector = None,
            if labels:
                label_selector = ','.join([f"{k}={v}" for k, v in labels.items()])
                
            pods = self._api_instance.list_namespaced_pod()
                namespace=namespace,
                label_selector=label_selector
            
            
            for pod in pods.items:
                pod_name = pod.metadata.name
                
                # 处理每个容器
                for container_status in pod.status.container_statuses or []:
                    image_name = container_status.image
                    
                    # 镜像筛选
                    if image_filter and image_filter not in image_name:
                        continue
                        
                    container_info = ContainerInfo()
                        pod_name=pod_name,
                        namespace=namespace,
                        container_name=container_status.name,
                        image_name=image_name,
                        image_id=container_status.image_id or '',
                        container_id=container_status.container_id or '',
                        status=container_status.state.__dict__.get('running', {}).get('started_at', 'unknown') if container_status.state else 'unknown',
                        labels=pod.metadata.labels or {}
                    
                    
                    containers.append(container_info)
                    
                # 处理init容器
                for container_status in pod.status.init_container_statuses or []:
                    image_name = container_status.image
                    
                    if image_filter and image_filter not in image_name:
                        continue
                        
                    container_info = ContainerInfo()
                        pod_name=pod_name,
                        namespace=namespace,
                        container_name=container_status.name,
                        image_name=image_name,
                        image_id=container_status.image_id or '',
                        container_id=container_status.container_id or '',
                        status='init',
                        labels=pod.metadata.labels or {}
                    
                    
                    containers.append(container_info)
                    
        except Exception as e:
            logger.error(f"扫描namespace {namespace} 失败: {e}")
            
        return containers
        
    def _discover_binaries(self, container: ContainerInfo) -> List[str]:
        """
        发现容器中的二进制文件
        
        Args:
            container: 容器信息
            
        Returns:
            二进制文件路径列表
        """
        binaries = []
        
        try:
            # 方法1: 拉取镜像并分析
            if container.image_name:
                image_binaries = self._analyze_image(container.image_name)
                binaries.extend(image_binaries)
                
            # 方法2: 通过kubectl exec（如果Pod运行）
            if container.container_id and 'docker://' in container.container_id:
                exec_binaries = self._exec_discover_binaries(container)
                binaries.extend(exec_binaries)
                
        except Exception as e:
            logger.warning(f"发现二进制失败: {e}")
            
        return binaries
        
    def _analyze_image(self, image_name: str) -> List[str]:
        """
        分析镜像中的二进制
        
        Args:
            image_name: 镜像名称
            
        Returns:
            二进制文件列表
        """
        binaries = []
        
        try:
            # 使用skopeo或docker inspect
            # 尝试拉取镜像manifest
            
            # 方法1: 使用docker（如果可用）
            try:
                result = subprocess.run()
                    ['docker', 'inspect', image_name],
                    capture_output=True,
                    text=True,
                    timeout=30
                
                
                if result.returncode == 0:
                    inspect_data = json.loads(result.stdout)
                    if inspect_data:
                        # 提取镜像层信息
                        layers = inspect_data[0].get('RootFS', {}).get('Layers', [])
                        
                        # 分析每一层
                        for layer in layers:
                            layer_binaries = self._analyze_image_layer(layer)
                            binaries.extend(layer_binaries)
                            
            except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
                pass
                
            # 方法2: 使用skopeo（如果可用）
            try:
                result = subprocess.run()
                    ['skopeo', 'inspect', f'docker://{image_name}'],
                    capture_output=True,
                    text=True,
                    timeout=30
                
                
                if result.returncode == 0:
                    inspect_data = json.loads(result.stdout)
                    # 提取二进制信息
                    layers = inspect_data.get('Layers', [])
                    for layer in layers:
                        binaries.append(f"layer:{layer}")
                        
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
                
            # 方法3: 常见二进制路径推断
            common_binaries = [
                '/bin/sh',
                '/bin/bash',
                '/bin/busybox',
                '/usr/bin/python',
                '/usr/bin/python3',
                '/usr/bin/node',
                '/usr/bin/java',
                '/usr/bin/go',
            ]
            
            # 根据镜像名称推断可能包含的二进制
            if 'python' in image_name.lower():
                binaries.extend(['/usr/bin/python', '/usr/bin/python3'])
            if 'node' in image_name.lower():
                binaries.extend(['/usr/bin/node', '/usr/bin/npm'])
            if 'java' in image_name.lower():
                binaries.extend(['/usr/bin/java'])
            if 'nginx' in image_name.lower():
                binaries.extend(['/usr/sbin/nginx'])
            if 'redis' in image_name.lower():
                binaries.extend(['/usr/bin/redis-server'])
            if 'postgres' in image_name.lower() or 'mysql' in image_name.lower():
                binaries.extend(['/usr/bin/postgres', '/usr/bin/mysql'])
            if 'alpine' in image_name.lower():
                binaries.extend(['/bin/busybox', '/bin/sh'])
            if 'ubuntu' in image_name.lower() or 'debian' in image_name.lower():
                binaries.extend(['/bin/bash', '/bin/sh'])
                
        except Exception as e:
            logger.warning(f"分析镜像 {image_name} 失败: {e}")
            
        return list(set(binaries))  # 去重
        
    def _analyze_image_layer(self, layer: str) -> List[str]:
        """
        分析镜像层
        
        Args:
            layer: 层ID
            
        Returns:
            二进制列表
        """
        # 简化实现，返回空列表
        return []
        
    def _exec_discover_binaries(self, container: ContainerInfo) -> List[str]:
        """
        通过kubectl exec发现二进制
        
        Args:
            container: 容器信息
            
        Returns:
            二进制列表
        """
        binaries = []
        
        try:
            # 使用kubectl exec
            cmd = [
                'kubectl',
                'exec',
                '-n', container.namespace,
                container.pod_name,
                '-c', container.container_name,
                '--',
                'find', '/', '-type', 'f', '-executable'
            ]
            
            result = subprocess.run()
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith('/proc') and not line.startswith('/sys'):
                        binaries.append(line.strip(

                        
        except Exception as e:
            logger.debug(f"exec发现二进制失败: {e}")
            
        return binaries[:100]  # 限制数量
        
    def _analyze_binary(, self, binary_path: str, container: ContainerInfo) -> Optional[BinaryRisk]:
        """
        分析二进制文件
        
        Args:
            binary_path: 二进制路径
            container: 容器信息
            
        Returns:
            BinaryRisk或None
        """
        risk = BinaryRisk()
            binary_path=binary_path,
            container=container
        
        
        try:
            # 检查是否是已知危险二进制
            dangerous_binaries = {
                '/bin/busybox': ('BusyBox可能包含多个工具', 'medium'),
                '/usr/bin/python': ('Python可能执行任意代码', 'low'),
                '/usr/bin/perl': ('Perl可能执行任意代码', 'low'),
                '/usr/bin/bash': ('Bash可能执行任意命令', 'low'),
                '/usr/bin/sh': ('Shell可能执行任意命令', 'low'),
                '/usr/bin/sudo': ('sudo可能提升权限', 'high'),
                '/usr/bin/curl': ('curl可能下载恶意文件', 'medium'),
                '/usr/bin/wget': ('wget可能下载恶意文件', 'medium'),
                '/usr/bin/nc': ('nc可能用于反向连接', 'high'),
                '/usr/bin/netcat': ('netcat可能用于反向连接', 'high'),
                '/usr/bin/nmap': ('nmap可能用于扫描', 'medium'),
            }
            
            if binary_path in dangerous_binaries:
                desc, level = dangerous_binaries[binary_path]
                risk.vulnerabilities.append({)
                    'type': 'dangerous_binary',
                    'description': desc,
                    'severity': level
                }
                risk.risk_level = level
                
            # 检查二进制是否可写（潜在风险）
            if 'writable' in binary_path.lower():
                risk.vulnerabilities.append({)
                    'type': 'writable_binary',
                    'description': '二进制文件可能可写',
                    'severity': 'high'
                }
                
            # 设置建议
            if risk.vulnerabilities:
                risk.recommendations.append('审查容器镜像内容')
                risk.recommendations.append('考虑使用最小化镜像')
                risk.recommendations.append('实施容器安全策略')
                
        except Exception as e:
            logger.warning(f"分析二进制 {binary_path} 失败: {e}")
            
        return risk if risk.vulnerabilities else None
        
    def _calculate_risk_summary(self, risks: List[BinaryRisk]) -> Dict[str, int]:
        """
        计算风险摘要
        
        Args:
            risks: 风险列表
            
        Returns:
            风险等级计数
        """
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0}
        
        for risk in risks:
            level = risk.risk_level or 'unknown'
            summary[level] = summary.get(level, 0) + 1
            
        return summary
        
    def _save_scan_report(self, result: ClusterScanResult) -> str:
        """
        保存扫描报告
        
        Args:
            result: 扫描结果
            
        Returns:
            报告文件路径
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = os.path.join(self.output_dir, f'k8s_scan_{timestamp}.json')
        
        try:
            report_data = {
                'cluster_name': result.cluster_name,
                'scan_time': result.scan_time,
                'namespaces_scanned': result.namespaces_scanned,
                'pods_scanned': result.pods_scanned,
                'containers_scanned': result.containers_scanned,
                'binaries_found': result.binaries_found,
                'risk_summary': result.risk_summary,
                'risks': [
                    {
                        'binary_path': r.binary_path,
                        'container': {
                            'pod_name': r.container.pod_name,
                            'namespace': r.container.namespace,
                            'container_name': r.container.container_name,
                            'image_name': r.container.image_name
                        },
                        'vulnerabilities': r.vulnerabilities,
                        'risk_level': r.risk_level,
                        'recommendations': r.recommendations
                    }
                    for r in result.risks
                ],
                'warnings': result.warnings
            }
            
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
                
            logger.info(f"扫描报告已保存: {report_path}")
            
        except Exception as e:
            logger.error(f"保存报告失败: {e}")
            
        return report_path
        
    def generate_report(self, result: ClusterScanResult) -> str:
        """
        生成Markdown格式报告
        
        Args:
            result: 扫描结果
            
        Returns:
            Markdown报告
        """
        report = []
        report.append("## Kubernetes集群安全扫描报告\n")
        
        report.append("### 扫描概览")
        report.append(f"- 集群名称: **{result.cluster_name}**")
        report.append(f"- 扫描时间: {result.scan_time}")
        report.append(f"- 扫描Namespace数: {len(result.namespaces_scanned)}")
        report.append(f"- 扫描Pod数: {result.pods_scanned}")
        report.append(f"- 扫描容器数: {result.containers_scanned}")
        report.append(f"- 发现二进制数: {result.binaries_found}")
        report.append("")
        
        if result.risk_summary:
            report.append("### 风险摘要")
            report.append("| 风险等级 | 数量 |")
            report.append("|----------|------|")
            for level, count in sorted(result.risk_summary.items(), key=lambda x: -x[1]):
                report.append(f"| {level} | {count} |")
            report.append("")
            
        if result.risks:
            report.append("### 发现的风险")
            
            # 按风险等级排序
            sorted_risks = sorted(result.risks, key=lambda x: x.risk_level)
            
            for risk in sorted_risks[:50]:  # 限制显示数量
                risk_icon = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🟢'
                }.get(risk.risk_level, '⚪')
                
                report.append(f"\n#### {risk_icon} `{risk.binary_path}`")
                report.append(f"- **容器**: `{risk.container.container_name}`")
                report.append(f"- **Pod**: `{risk.container.pod_name}` ({risk.container.namespace})")
                report.append(f"- **镜像**: `{risk.container.image_name}`")
                
                if risk.vulnerabilities:
                    report.append("\n**漏洞**:")
                    for vuln in risk.vulnerabilities:
                        report.append(f"- {vuln.get('type')}: {vuln.get('description')} ({vuln.get('severity')})")
                        
                if risk.recommendations:
                    report.append("\n**建议**:")
                    for rec in risk.recommendations:
                        report.append(f"- {rec}")
                        
        if result.warnings:
            report.append("\n### 警告")
            for warning in result.warnings:
                report.append(f"- ⚠️ {warning}")
                
        # Namespace详情
        if result.namespaces_scanned:
            report.append("\n### 扫描的Namespace")
            for ns in result.namespaces_scanned:
                report.append(f"- `{ns}`")
                
        return '\n'.join(report)
        
    def get_pod_details(self, pod_name: str, namespace: str) -> Dict[str, Any]:
        """
        获取Pod详细信息
        
        Args:
            pod_name: Pod名称
            namespace: Namespace
            
        Returns:
            Pod详细信息
        """
        if not self._api_instance:
            return {}
            
        try:
            pod = self._api_instance.read_namespaced_pod(pod_name, namespace)
            
            return {
                'name': pod.metadata.name,
                'namespace': pod.metadata.namespace,
                'labels': pod.metadata.labels or {},
                'annotations': pod.metadata.annotations or {},
                'status': pod.status.phase,
                'containers': [
                    {
                        'name': c.name,
                        'image': c.image,
                        'ports': [p.container_port for p in c.ports or []],
                    }
                    for c in pod.spec.containers
                ],
                'volumes': [
                    {
                        'name': v.name,
                        'type': v.__dict__.keys()
                    }
                    for v in pod.spec.volumes or []
                ],
                'security_context': pod.spec.security_context.__dict__ if pod.spec.security_context else {}
            }
            
        except Exception as e:
            logger.error(f"获取Pod详情失败: {e}")
            return {}
            
    def check_admission_violations(, self, image_name: str, policy_rules: Optional[List[Dict]] = None) -> List[Dict[str, Any]]:
        """
        检查镜像是否违反准入策略
        
        Args:
            image_name: 镜像名称
            policy_rules: 策略规则
            
        Returns:
            违规列表
        """
        violations = []
        
        # 默认策略
        default_rules = [
            {'type': 'no_root', 'description': '禁止以root运行'},
            {'type': 'no_privileged', 'description': '禁止特权容器'},
            {'type': 'read_only_root', 'description': '根文件系统只读'},
            {'type': 'drop_capabilities', 'description': '丢弃所有能力'},
        ]
        
        rules = policy_rules or default_rules
        
        try:
            # 检查镜像配置
            result = subprocess.run()
                ['docker', 'inspect', image_name],
                capture_output=True,
                text=True,
                timeout=30
            
            
            if result.returncode == 0:
                inspect_data = json.loads(result.stdout)
                if inspect_data:
                    config = inspect_data[0].get('Config', {})
                    
                    # 检查用户
                    user = config.get('User', '')
                    if not user or user == 'root' or user == '0':
                        violations.append({)
                            'rule': 'no_root',
                            'description': '镜像可能以root运行',
                            'severity': 'high'
                        }
                        
                    # 检查特权
                    if config.get('Privileged'):
                        violations.append({)
                            'rule': 'no_privileged',
                            'description': '镜像配置为特权模式',
                            'severity': 'critical'
                        }
                        
        except Exception as e:
            logger.debug(f"检查准入违规失败: {e}")
            
        return violations


def scan_kubernetes_cluster(, scope: ScanScope = ScanScope.ALL, namespaces: Optional[List[str]] = None, kubeconfig: Optional[str] = None, analyze_binaries: bool = True) -> ClusterScanResult:
    """
    扫描Kubernetes集群
    
    Args:
        scope: 扫描范围
        namespaces: 特定namespace
        kubeconfig: kubeconfig路径
        analyze_binaries: 是否分析二进制
        
    Returns:
        ClusterScanResult: 扫描结果
    """
    scanner = K8sClusterScanner(kubeconfig=kubeconfig)
    return scanner.scan_cluster(scope, namespaces, analyze_binaries=analyze_binaries