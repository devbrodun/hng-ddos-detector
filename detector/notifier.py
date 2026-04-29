import aiohttp
import time
from datetime import datetime


class Notifier:
    """Sends alerts to Slack via webhook URL."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self._last_global_alert = 0
        self.global_alert_cooldown = 60  # Don't spam global alerts

    async def _post(self, text: str):
        if not self.webhook_url or 'YOUR' in self.webhook_url:
            print(f"[notifier] (no webhook) {text}")
            return
        try:
            async with aiohttp.ClientSession() as session:
                await session.post(
                    self.webhook_url,
                    json={"text": text},
                    timeout=aiohttp.ClientTimeout(total=5)
                )
        except Exception as e:
            print(f"[notifier] Slack error: {e}")

    async def send_ban_alert(self, ip: str, condition: str,
                             rate: float, baseline: float,
                             duration: int):
        ts = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        dur_str = f"{duration}s" if duration != -1 else "PERMANENT"
        text = (
            f":rotating_light: *IP BANNED*\n"
            f"• IP: `{ip}`\n"
            f"• Condition: {condition}\n"
            f"• Rate: {rate:.1f} req/60s\n"
            f"• Baseline mean: {baseline:.2f}\n"
            f"• Ban duration: {dur_str}\n"
            f"• Time: {ts}"
        )
        await self._post(text)

    async def send_unban_alert(self, ip: str, duration: int, ban_count: int):
        ts = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        text = (
            f":white_check_mark: *IP UNBANNED*\n"
            f"• IP: `{ip}`\n"
            f"• Served ban duration: {duration}s\n"
            f"• Total bans: {ban_count}\n"
            f"• Time: {ts}"
        )
        await self._post(text)

    async def send_global_alert(self, condition: str, rate: float,
                                baseline: float):
        now = time.time()
        if now - self._last_global_alert < self.global_alert_cooldown:
            return
        self._last_global_alert = now
        ts = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        text = (
            f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
            f"• Condition: {condition}\n"
            f"• Global rate: {rate:.1f} req/60s\n"
            f"• Baseline mean: {baseline:.2f}\n"
            f"• Time: {ts}\n"
            f"• Action: Slack alert only (no blanket IP block)"
        )
        await self._post(text)
