import time
from collections import deque, defaultdict


WHITELISTED_IPS = {
    "44.202.222.29",   # server public IP
    "127.0.0.1",       # localhost
    "10.0.1.34",       # server private IP
    "98.97.77.114",    # your home IP — remove temporarily to test
}


class AnomalyDetector:
    """
    Maintains two sliding window deques:
      - self.global_window: all requests in the last 60 seconds
      - self.ip_windows[ip]: requests from that IP in the last 60 seconds

    Each deque holds timestamps. To get the current rate, count
    how many timestamps are within the window (evicting old ones first).

    Z-score = (current_rate - baseline_mean) / baseline_stddev
    Flag if z_score > threshold OR rate > multiplier * mean.
    """

    def __init__(self, config: dict):
        self.window_seconds = config['sliding_window_seconds']
        self.z_threshold = config['z_score_threshold']
        self.rate_multiplier = config['rate_multiplier']
        self.error_multiplier = config['error_rate_multiplier']

        # Merge hardcoded and config whitelists
        self.whitelist = WHITELISTED_IPS | set(config.get('whitelisted_ips', []))

        # Global sliding window: deque of request timestamps
        self.global_window: deque = deque()

        # Per-IP sliding windows — defaultdict auto-creates deque for new IPs
        self.ip_windows: dict[str, deque] = defaultdict(deque)

        # Per-IP error windows (4xx/5xx)
        self.ip_error_windows: dict[str, deque] = defaultdict(deque)

        # Track which IPs have been flagged recently (avoid spam)
        self.flagged_ips: dict[str, float] = {}
        self.flag_cooldown = 30  # seconds before re-flagging same IP

    def is_whitelisted(self, ip: str) -> bool:
        """Check IP against whitelist and private IP ranges."""
        if ip in self.whitelist:
            return True
        private_prefixes = (
            "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
            "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.", "192.168.", "127."
        )
        return any(ip.startswith(p) for p in private_prefixes)

    def record(self, ip: str, timestamp: float, status: int):
        """
        Record a request into the sliding windows.
        Uses current time (timestamp) for window management.
        Evicts entries older than window_seconds from the left of each deque.
        """
        cutoff = timestamp - self.window_seconds

        # Always update global window (even for whitelisted IPs)
        self.global_window.append(timestamp)
        while self.global_window and self.global_window[0] < cutoff:
            self.global_window.popleft()

        # Skip per-IP tracking for whitelisted IPs
        if self.is_whitelisted(ip):
            return

        # Update per-IP window using defaultdict — auto-creates deque
        win = self.ip_windows[ip]
        win.append(timestamp)
        while win and win[0] < cutoff:
            win.popleft()

        # Update per-IP error window
        if status >= 400:
            ewin = self.ip_error_windows[ip]
            ewin.append(timestamp)
            while ewin and ewin[0] < cutoff:
                ewin.popleft()

    def check_ip(self, ip: str, baseline: dict) -> dict | None:
        """
        Check if this IP is anomalous.
        Returns a dict describing the anomaly, or None if normal.
        """
        # Never flag whitelisted IPs
        if self.is_whitelisted(ip):
            return None

        # Respect cooldown — don't repeatedly flag the same IP
        last_flag = self.flagged_ips.get(ip, 0)
        if time.time() - last_flag < self.flag_cooldown:
            return None

        # Use defaultdict directly so we get the actual stored deque
        win = self.ip_windows[ip]
        rate = len(win)

        # Need at least 10 requests before flagging
        if rate < 10:
            return None

        mean = baseline['mean']
        stddev = baseline['stddev']

        # Check error rate — tighten thresholds if IP has high error rate
        ewin = self.ip_error_windows[ip]
        error_rate = len(ewin)
        effective_z = self.z_threshold
        effective_mult = self.rate_multiplier

        if baseline['error_mean'] > 0:
            if error_rate > baseline['error_mean'] * self.error_multiplier:
                effective_z = self.z_threshold * 0.6
                effective_mult = self.rate_multiplier * 0.6

        # Compute z-score
        if stddev > 0:
            z_score = (rate - mean) / stddev
        else:
            z_score = 0.0

        # Check anomaly conditions
        fired_reason = None
        if z_score > effective_z:
            fired_reason = f"z_score={z_score:.2f} > {effective_z}"
        elif mean > 0 and rate > mean * effective_mult:
            fired_reason = f"rate={rate} > {effective_mult}x mean={mean:.2f}"

        if fired_reason:
            self.flagged_ips[ip] = time.time()
            print(f"[detector] ANOMALY {ip}: {fired_reason} "
                  f"rate={rate} mean={mean:.2f} stddev={stddev:.2f}")
            return {
                'type': 'ip',
                'ip': ip,
                'rate': rate,
                'z_score': z_score,
                'reason': fired_reason,
                'error_rate': error_rate,
            }
        return None

    def check_global(self, baseline: dict) -> dict | None:
        """Check if the global traffic rate is anomalous."""
        rate = len(self.global_window)
        mean = baseline['mean']
        stddev = baseline['stddev']

        if stddev > 0:
            z_score = (rate - mean) / stddev
        else:
            z_score = 0.0

        fired_reason = None
        if z_score > self.z_threshold:
            fired_reason = f"global z_score={z_score:.2f} > {self.z_threshold}"
        elif mean > 0 and rate > mean * self.rate_multiplier:
            fired_reason = f"global rate={rate} > {self.rate_multiplier}x mean={mean:.2f}"

        if fired_reason:
            print(f"[detector] GLOBAL ANOMALY: {fired_reason}")
            return {
                'type': 'global',
                'rate': rate,
                'z_score': z_score,
                'reason': fired_reason,
            }
        return None

    def get_top_ips(self, n=10) -> list:
        """Return top N IPs by request count in the sliding window."""
        ip_counts = {ip: len(win) for ip, win in self.ip_windows.items()
                     if len(win) > 0}
        return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def get_global_rate(self) -> int:
        return len(self.global_window)
