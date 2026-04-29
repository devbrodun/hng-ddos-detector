import time
import math
from collections import deque


class BaselineTracker:
    """
    Maintains a rolling 30-minute window of per-second request counts.
    Splits into per-hour slots so the current hour's data is preferred
    when it has enough samples (>= 5 minutes worth).

    The baseline is recalculated every `recalc_interval` seconds.
    """

    def __init__(self, window_minutes=30, recalc_interval=60,
                 floor_mean=0.1, floor_stddev=0.1):
        self.window_seconds = window_minutes * 60
        self.recalc_interval = recalc_interval
        self.floor_mean = floor_mean
        self.floor_stddev = floor_stddev

        # Rolling window: deque of (timestamp, count) tuples
        # Each entry = number of requests in that 1-second bucket
        self.window: deque = deque()

        # Per-hour slots: hour_key -> list of per-second counts
        self.hour_slots: dict = {}

        # Current baseline values
        self.effective_mean = floor_mean
        self.effective_stddev = floor_stddev
        self.effective_error_mean = floor_mean

        # For error rate baseline
        self.error_window: deque = deque()

        self._last_recalc = 0.0
        self._last_bucket_time = 0
        self._bucket_count = 0
        self._bucket_error_count = 0

    def record_request(self, timestamp: float, is_error: bool = False):
        """Call once per parsed log line."""
        bucket = int(timestamp)  # 1-second bucket

        if bucket != self._last_bucket_time:
            # New second — commit the old bucket
            if self._last_bucket_time > 0:
                self._commit_bucket(self._last_bucket_time,
                                    self._bucket_count,
                                    self._bucket_error_count)
            self._last_bucket_time = bucket
            self._bucket_count = 0
            self._bucket_error_count = 0

        self._bucket_count += 1
        if is_error:
            self._bucket_error_count += 1

    def _commit_bucket(self, ts: int, count: int, error_count: int):
        """Add a completed 1-second bucket to the rolling window."""
        now = time.time()
        cutoff = now - self.window_seconds
        hour_key = time.strftime('%Y-%m-%d-%H', time.localtime(ts))

        # Add to rolling window
        self.window.append((ts, count))
        self.error_window.append((ts, error_count))

        # Evict old entries
        while self.window and self.window[0][0] < cutoff:
            self.window.popleft()
        while self.error_window and self.error_window[0][0] < cutoff:
            self.error_window.popleft()

        # Add to hour slot
        if hour_key not in self.hour_slots:
            self.hour_slots[hour_key] = []
        self.hour_slots[hour_key].append(count)

        # Evict hour slots older than 2 hours
        current_hour = time.strftime('%Y-%m-%d-%H')
        keys_to_drop = [k for k in self.hour_slots
                        if k < time.strftime('%Y-%m-%d-%H',
                           time.localtime(now - 7200))]
        for k in keys_to_drop:
            del self.hour_slots[k]

    def maybe_recalculate(self) -> bool:
        """
        Recalculate mean/stddev if the interval has elapsed.
        Returns True if recalculation happened.
        """
        now = time.time()
        if now - self._last_recalc < self.recalc_interval:
            return False
        self._last_recalc = now
        self._recalculate()
        return True

    def _recalculate(self):
        """Compute mean and stddev from the best available data."""
        current_hour = time.strftime('%Y-%m-%d-%H')
        hour_data = self.hour_slots.get(current_hour, [])

        # Prefer current hour if we have >= 5 minutes of data
        MIN_SAMPLES = 300  # 5 min * 60 sec
        if len(hour_data) >= MIN_SAMPLES:
            counts = hour_data
        else:
            counts = [c for _, c in self.window]

        if len(counts) < 2:
            return  # Not enough data yet

        mean = sum(counts) / len(counts)
        variance = sum((x - mean) ** 2 for x in counts) / len(counts)
        stddev = math.sqrt(variance)

        # Apply floors to prevent triggering on perfectly normal low traffic
        self.effective_mean = max(mean, self.floor_mean)
        self.effective_stddev = max(stddev, self.floor_stddev)

        # Error baseline
        error_counts = [c for _, c in self.error_window]
        if error_counts:
            self.effective_error_mean = max(
                sum(error_counts) / len(error_counts), self.floor_mean)

    def get_baseline(self):
        return {
            'mean': self.effective_mean,
            'stddev': self.effective_stddev,
            'error_mean': self.effective_error_mean,
            'samples': len(self.window),
        }
