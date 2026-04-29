import subprocess
import time
import asyncio
from datetime import datetime


class Blocker:
    """
    Manages iptables DROP rules for blocked IPs.
    All bans are logged to the audit log.
    """

    def __init__(self, audit_log_path: str):
        self.audit_log_path = audit_log_path
        # ip -> {'banned_at': float, 'ban_duration': int, 'level': int}
        self.banned: dict[str, dict] = {}

    def ban_ip(self, ip: str, duration_seconds: int, condition: str,
               rate: float, baseline_mean: float):
        """Add an iptables DROP rule for this IP."""
        try:
            # Check if rule already exists to avoid duplicates
            check = subprocess.run(
                ['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'],
                capture_output=True
            )
            if check.returncode != 0:
                subprocess.run(
                    ['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
                    check=True
                )
            self.banned[ip] = {
                'banned_at': time.time(),
                'ban_duration': duration_seconds,
                'level': self.banned.get(ip, {}).get('level', 0),
                'condition': condition,
            }
            self._audit(
                action='BAN',
                ip=ip,
                condition=condition,
                rate=rate,
                baseline=baseline_mean,
                duration=duration_seconds
            )
            print(f"[blocker] Banned {ip} for {duration_seconds}s | {condition}")
        except subprocess.CalledProcessError as e:
            print(f"[blocker] Failed to ban {ip}: {e}")

    def unban_ip(self, ip: str, condition: str = 'auto-unban',
                 rate: float = 0, baseline: float = 0):
        """Remove the iptables DROP rule for this IP."""
        try:
            subprocess.run(
                ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                check=True, capture_output=True
            )
            info = self.banned.pop(ip, {})
            self._audit(
                action='UNBAN',
                ip=ip,
                condition=condition,
                rate=rate,
                baseline=baseline,
                duration=0
            )
            print(f"[blocker] Unbanned {ip}")
            return info
        except subprocess.CalledProcessError:
            self.banned.pop(ip, None)
            return {}

    def is_banned(self, ip: str) -> bool:
        return ip in self.banned

    def _audit(self, action: str, ip: str, condition: str,
               rate: float, baseline: float, duration: int):
        ts = datetime.utcnow().isoformat() + 'Z'
        entry = (f"[{ts}] {action} {ip} | {condition} | "
                 f"rate={rate:.2f} | baseline={baseline:.2f} | "
                 f"duration={duration}s\n")
        try:
            with open(self.audit_log_path, 'a') as f:
                f.write(entry)
        except Exception as e:
            print(f"[blocker] Audit log error: {e}")

    def audit_baseline(self, mean: float, stddev: float):
        ts = datetime.utcnow().isoformat() + 'Z'
        entry = (f"[{ts}] BASELINE_RECALC ip=- | "
                 f"condition=recalc | rate=- | "
                 f"baseline={mean:.4f} | stddev={stddev:.4f} | duration=-\n")
        try:
            with open(self.audit_log_path, 'a') as f:
                f.write(entry)
        except Exception as e:
            print(f"[blocker] Audit log error: {e}")
