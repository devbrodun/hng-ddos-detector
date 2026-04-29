import asyncio
import time
from blocker import Blocker
from notifier import Notifier


class Unbanner:
    """
    Implements the backoff unban schedule:
      First ban:  unban after 10 min
      Second ban: unban after 30 min
      Third ban:  unban after 2 hours
      Fourth ban: permanent (never unbanned automatically)
    """

    def __init__(self, blocker: Blocker, notifier: Notifier,
                 schedule: list[int]):
        self.blocker = blocker
        self.notifier = notifier
        self.schedule = schedule  # e.g. [600, 1800, 7200, -1]
        # Track how many times each IP has been banned
        self.ban_counts: dict[str, int] = {}

    def on_ban(self, ip: str):
        """Call this when an IP is freshly banned."""
        self.ban_counts[ip] = self.ban_counts.get(ip, 0) + 1

    def get_ban_duration(self, ip: str) -> int:
        """Return the ban duration in seconds for the current ban level."""
        level = self.ban_counts.get(ip, 1) - 1
        level = min(level, len(self.schedule) - 1)
        return self.schedule[level]

    async def run(self):
        """Background loop — check for expired bans every 10 seconds."""
        while True:
            await asyncio.sleep(10)
            now = time.time()
            to_unban = []

            for ip, info in list(self.blocker.banned.items()):
                duration = info.get('ban_duration', 600)
                if duration == -1:
                    continue  # Permanent — skip
                if now - info['banned_at'] >= duration:
                    to_unban.append(ip)

            for ip in to_unban:
                info = self.blocker.banned.get(ip, {})
                self.blocker.unban_ip(ip, condition='auto-unban')
                await self.notifier.send_unban_alert(
                    ip=ip,
                    duration=info.get('ban_duration', 0),
                    ban_count=self.ban_counts.get(ip, 1)
                )
