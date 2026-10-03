"""网络拓扑映射引擎——LLDP/CDP解析 + OS指纹识别 + 邻接关系推断。

构建网络设备节点列表和设备间链路关系，输出可作为Gephi、Cytoscape等
可视化工具的节点-边CSV导入。
"""
import logging
from collections import Counter
from typing import Dict, Any, Optional, List, Tuple

from .topology_types import (
    LldpNeighbor, OsFingerprint, NetworkDevice,
    _CAP_ROUTER, _CAP_BRIDGE, _CAP_WLAN_AP, _CAP_TELEPHONE,
)
from .topology_lldp import LldpParser
from .topology_os_fp import PassiveOsFingerprinter

_log = logging.getLogger(__name__)


class TopologyMapper:

    def __init__(self):
        self._lldp = LldpParser()
        self._os_fp = PassiveOsFingerprinter()
        self._devices: Dict[str, NetworkDevice] = {}
        self._neighbors: List[Tuple[str, str, str]] = []
        self._os_fingerprints: Dict[str, OsFingerprint] = {}

    def feed_lldp(self, raw_frame: bytes, local_intf: str = "",
                  timestamp: float = 0.0) -> Optional[LldpNeighbor]:
        """输入含LLDP的以太网帧进行解析和拓扑更新"""
        nb = self._lldp.parse(raw_frame)
        if nb is None:
            return None

        device_id = nb.chassis_id or nb.mgmt_ip or f"dev_{hash(nb)}"

        if device_id not in self._devices:
            dev_type = self._infer_device_type(nb)
            self._devices[device_id] = NetworkDevice(
                identifier=device_id,
                device_type=dev_type,
                hostname=nb.sys_name,
                mgmt_ip=nb.mgmt_ip,
                ports=[nb.port_id] if nb.port_id else [],
            )
        else:
            dev = self._devices[device_id]
            if nb.sys_name and not dev.hostname:
                dev.hostname = nb.sys_name
            if nb.mgmt_ip and not dev.mgmt_ip:
                dev.mgmt_ip = nb.mgmt_ip
            if nb.port_id and nb.port_id not in dev.ports:
                dev.ports.append(nb.port_id)

        # 记录邻接关系
        if device_id and local_intf:
            self._neighbors.append((local_intf, device_id, "LLDP"))

        return nb

    def feed_tcp_syn(self, ip: str, tcp_data: bytes,
                     ttl: int, timestamp: float = 0.0) -> Optional[OsFingerprint]:
        """输入TCP SYN包进行OS指纹识别并更新设备节点"""
        fp = self._os_fp.fingerprint(ip, tcp_data, ttl)
        if fp and fp.confidence > 0.5:
            fp.first_seen = timestamp
            self._os_fingerprints[ip] = fp
            if ip in self._devices:
                self._devices[ip].os_guess = fp.guessed_os
        return fp

    @staticmethod
    def _infer_device_type(nb: LldpNeighbor) -> str:
        """从LLDP能力位和系统描述推断网络设备角色类型"""
        caps = nb.capabilities
        desc = nb.sys_desc.upper() if nb.sys_desc else ""

        if caps & _CAP_ROUTER and caps & _CAP_BRIDGE:
            return "l3_switch"
        elif caps & _CAP_ROUTER:
            return "router"
        elif caps & _CAP_BRIDGE:
            return "switch"
        elif caps & _CAP_WLAN_AP:
            return "access_point"
        elif caps & _CAP_TELEPHONE:
            return "voip_phone"
        elif "WLC" in desc or "WIRELESS" in desc or "CONTROLLER" in desc:
            return "wireless_controller"
        elif "FIREWALL" in desc or "ASA" in desc or "PALO" in desc:
            return "firewall"
        elif "ESX" in desc or "VMWARE" in desc or "HYPERVISOR" in desc:
            return "hypervisor"

        return "unknown"

    def export_graph(self, fmt: str = "nodes_edges") -> Dict[str, Any]:
        """导出拓扑图——节点/边结构，可直接导入Gephi或networkx"""
        nodes = []
        for dev_id, dev in self._devices.items():
            fp = self._os_fingerprints.get(dev_id)
            nodes.append({
                "id": dev_id,
                "type": dev.device_type,
                "hostname": dev.hostname,
                "mgmt_ip": dev.mgmt_ip,
                "os_guess": fp.guessed_os if fp else dev.os_guess,
                "port_count": len(dev.ports),
            })

        edges = []
        for src, dst, link_type in self._neighbors:
            edges.append({
                "source": src,
                "target": dst,
                "link_type": link_type,
            })

        return {"nodes": nodes, "edges": edges, "node_count": len(nodes),
                "edge_count": len(edges)}

    def summary(self) -> Dict[str, Any]:
        dev_types = Counter(d.device_type for d in self._devices.values())
        os_types = Counter(
            fp.guessed_os for fp in self._os_fingerprints.values()
            if fp.confidence > 0.6
        )
        graph = self.export_graph()
        return {
            "devices_discovered": len(self._devices),
            "by_device_type": dict(dev_types),
            "os_fingerprints": dict(os_types.most_common()),
            "links_found": len(self._neighbors),
            "graph": graph,
            "largest_subnet": self._infer_subnet_hierarchy(),
        }

    def _infer_subnet_hierarchy(self) -> Dict[str, Any]:
        """从设备类型分布推断网络层次结构——核心→汇聚→接入"""
        roles = Counter(d.device_type for d in self._devices.values())
        return {
            "core_routers": roles.get("router", 0),
            "distribution_switches": roles.get("l3_switch", 0),
            "access_switches": roles.get("switch", 0),
            "access_points": roles.get("access_point", 0),
            "endpoints": roles.get("unknown", 0) + roles.get("voip_phone", 0),
            "max_depth": 3 if roles.get("switch", 0) > 0 else (2 if roles.get("router", 0) > 0 else 1),
        }
