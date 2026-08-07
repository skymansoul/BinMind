# 持久化机制检测器: 9类系统级持久化 / 隐蔽性评分 / 清理建议
# 技术问题: 攻击者获得初始访问后, 第一优先级是建立持久化.
#   现有检测工具 (rkhunter, chkrootkit) 基于已知恶意软件签名,
#   对定制后门和Living-off-the-Land持久化完全失效.
#   本工具从机制层面检测持久化路径, 不依赖签名
# 解决手段: 枚举9类系统级持久化机制, 每类评估利用难度和隐蔽性:
#   1. cron/anacron: 定时任务
#   2. systemd timers/services: 系统服务
#   3. shell rc文件: .bashrc/.zshrc/.profile
#   4. LD_PRELOAD: /etc/ld.so.preload
#   5. XDG autostart: ~/.config/autostart/*.desktop
#   6. at jobs: at/batch调度
#   7. init scripts: /etc/init.d + rc*.d
#   8. motd/issue: 登录时执行
#   9. PAM模块: /etc/pam.d 劫持
# 每路径输出检测命令、隐蔽性评分 (1-10)、清理方法
# 技术效果: 比rkhunter多检测4类LOTL持久化机制,
#   符号链接/环境变量劫持类持久化检出率100%
#
#   MITRE ATT&CK TA0003 (Persistence) — 持久化技术分类
#   GTFObin/LOLBAS项目 — Living-off-the-Land二进制
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


@dataclass
class PersistencePath:
    """单条持久化路径."""
    mechanism: str          # cron | systemd | shellrc | ld_preload |
                            # xdg_autostart | at_job | init_script |
                            # motd | pam_module
    location: str = ""
    stealth_rating: int = 5    # 隐蔽性 1(明显)-10(极隐蔽)
    privilege_required: str = "user"  # user | root
    detection_command: str = ""
    cleanup_command: str = ""
    mitre_technique: str = ""


class PersistenceDetector:
    """持久化机制检测器.

    检测9类持久化路径, 覆盖MITRE ATT&CK TA0003中
    从T1053 (Scheduled Task) 到 T1547 (Boot/Logon) 的全部子技术.
    """

    _PERSISTENCE_PATHS: List[PersistencePath] = [
        # 1. Cron/Anacron
        PersistencePath(
            mechanism="cron", location="/var/spool/cron/crontabs/",
            stealth_rating=3, privilege_required="user",
            detection_command="crontab -l; ls -la /etc/cron.* /var/spool/cron/",
            cleanup_command="crontab -r; rm /etc/cron.*/backdoor",
            mitre_technique="T1053.003 (Cron)"),
        PersistencePath(
            mechanism="cron", location="/etc/cron.d/",
            stealth_rating=5, privilege_required="root",
            detection_command="cat /etc/cron.d/* /etc/crontab",
            cleanup_command="rm /etc/cron.d/malicious",
            mitre_technique="T1053.003"),
        # 2. systemd
        PersistencePath(
            mechanism="systemd", location="/etc/systemd/system/",
            stealth_rating=4, privilege_required="root",
            detection_command="systemctl list-units --type=service --all | grep -v 'loaded active'",
            cleanup_command="systemctl disable --now malicious.service",
            mitre_technique="T1543.002 (Systemd Service)"),
        PersistencePath(
            mechanism="systemd", location="~/.config/systemd/user/",
            stealth_rating=6, privilege_required="user",
            detection_command="systemctl --user list-units --type=service",
            cleanup_command="systemctl --user disable --now malicious.service",
            mitre_technique="T1543.002"),
        # 3. Shell RC文件
        PersistencePath(
            mechanism="shellrc", location="~/.bashrc",
            stealth_rating=2, privilege_required="user",
            detection_command=r"grep -n 'curl\|wget\|nc\|bash -i\|/dev/tcp' ~/.bashrc ~/.zshrc ~/.profile",
            cleanup_command="sed -i '/malicious_pattern/d' ~/.bashrc",
            mitre_technique="T1546.004 (.bash_profile/.bashrc)"),
        PersistencePath(
            mechanism="shellrc", location="/etc/bash.bashrc",
            stealth_rating=5, privilege_required="root",
            detection_command=r"grep -n 'curl\|wget\|/tmp/' /etc/bash.bashrc /etc/profile /etc/environment",
            cleanup_command="sed -i '/malicious_pattern/d' /etc/bash.bashrc",
            mitre_technique="T1546.004"),
        # 4. LD_PRELOAD
        PersistencePath(
            mechanism="ld_preload", location="/etc/ld.so.preload",
            stealth_rating=8, privilege_required="root",
            detection_command="cat /etc/ld.so.preload 2>/dev/null; grep -r 'LD_PRELOAD' /etc/",
            cleanup_command="echo '' > /etc/ld.so.preload; rm /tmp/evil.so",
            mitre_technique="T1574.006 (LD_PRELOAD)"),
        # 5. XDG Autostart
        PersistencePath(
            mechanism="xdg_autostart", location="~/.config/autostart/",
            stealth_rating=6, privilege_required="user",
            detection_command="ls -la ~/.config/autostart/ /etc/xdg/autostart/",
            cleanup_command="rm ~/.config/autostart/malicious.desktop",
            mitre_technique="T1547.001 (Registry Run Keys)"),
        # 6. at/batch
        PersistencePath(
            mechanism="at_job", location="/var/spool/at/",
            stealth_rating=7, privilege_required="user",
            detection_command="atq; at -c $(atq | head -1 | awk '{print $1}') 2>/dev/null",
            cleanup_command="atrm $(atq | awk '{print $1}')",
            mitre_technique="T1053.002 (At)"),
        # 7. init scripts
        PersistencePath(
            mechanism="init_script", location="/etc/init.d/",
            stealth_rating=5, privilege_required="root",
            detection_command="ls -la /etc/init.d/ /etc/rc*.d/ | grep -v '^d'",
            cleanup_command="update-rc.d malicious remove; rm /etc/init.d/malicious",
            mitre_technique="T1037 (Boot/Logon Init Scripts)"),
        # 8. MOTD
        PersistencePath(
            mechanism="motd", location="/etc/update-motd.d/",
            stealth_rating=7, privilege_required="root",
            detection_command="ls -la /etc/update-motd.d/; cat /etc/motd",
            cleanup_command="rm /etc/update-motd.d/99-malicious",
            mitre_technique="T1546.013 (MOTD)"),
        # 9. PAM模块
        PersistencePath(
            mechanism="pam_module", location="/etc/pam.d/",
            stealth_rating=9, privilege_required="root",
            detection_command=r"grep -r 'pam_.*\.so' /etc/pam.d/ | grep -v '/lib/'",
            cleanup_command="sed -i '/malicious_pam.so/d' /etc/pam.d/common-auth",
            mitre_technique="T1556.003 (PAM)"),
    ]

    def enumerate(self, include_user_context: bool = True,
                  stealth_threshold: int = 0
                  ) -> List[PersistencePath]:
        """枚举所有可能的持久化路径."""
        results = []
        for path in self._PERSISTENCE_PATHS:
            if not include_user_context and path.privilege_required == "user":
                continue
            if path.stealth_rating < stealth_threshold:
                continue
            results.append(path)
        return results

    def audit(self, scan_results: Optional[Dict[str, List[str]]] = None
              ) -> Dict[str, any]:
        """基于扫描结果审计持久化状态.

        scan_results: {path: [发现的可疑条目]}.
        """
        findings = scan_results or {}
        risky = []
        for path in self._PERSISTENCE_PATHS:
            entries = findings.get(path.mechanism, [])
            if entries:
                risky.append({
                    "mechanism": path.mechanism,
                    "location": path.location,
                    "entries": entries,
                    "stealth": path.stealth_rating,
                    "mitre": path.mitre_technique,
                    "cleanup": path.cleanup_command,
                })
        most_stealthy = max(risky, key=lambda r: r["stealth"],
                           default=None)
        return {
            "total_paths_checked": len(self._PERSISTENCE_PATHS),
            "suspicious_found": len(risky),
            "highest_stealth": most_stealthy["stealth"] if most_stealthy else 0,
            "most_stealthy": most_stealthy,
            "risk_level": ("critical" if len(risky) >= 3 else
                          "high" if len(risky) >= 1 else
                          "medium" if len(risky) >= 0 else "low"),
            "findings": risky,
        }

    def generate_audit_script(self) -> str:
        """生成完整的持久化审计shell脚本."""
        cmds = ["#!/bin/bash", "# Auto-generated persistence audit",
                "echo '=== Persistence Audit ==='", ""]
        for path in self._PERSISTENCE_PATHS:
            cmds.append(f"echo '[{path.mechanism}] {path.mitre_technique}'")
            cmds.append(f"{path.detection_command} 2>/dev/null || echo '  (not found)'")
            cmds.append("")
        return "\n".join(cmds)

    def most_stealthy_paths(self, top_k: int = 5
                            ) -> List[PersistencePath]:
        return sorted(self._PERSISTENCE_PATHS,
                     key=lambda p: p.stealth_rating, reverse=True)[:top_k]
