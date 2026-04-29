import asyncio
import yaml
import time
import sys

from monitor import tail_log
from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier
from dashboard import run_dashboard, update_state, record_baseline


def load_config(path='config.yaml') -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


async def main():
    config = load_config()
    print("[main] Starting HNG Anomaly Detection Engine")
    print(f"[main] Config: z={config['z_score_threshold']} "
          f"mult={config['rate_multiplier']} "
          f"window={config['sliding_window_seconds']}s")

    baseline = BaselineTracker(
        window_minutes=config['baseline_window_minutes'],
        recalc_interval=config['baseline_recalc_interval'],
        floor_mean=config['baseline_floor_mean'],
        floor_stddev=config['baseline_floor_stddev'],
    )
    detector = AnomalyDetector(config)
    blocker = Blocker(audit_log_path=config['audit_log_path'])
    notifier = Notifier(webhook_url=config['slack_webhook_url'])
    unbanner = Unbanner(
        blocker=blocker,
        notifier=notifier,
        schedule=config['unban_schedule']
    )

    run_dashboard(
        host=config['dashboard_host'],
        port=config['dashboard_port']
    )
    print(f"[main] Dashboard at http://0.0.0.0:{config['dashboard_port']}")

    asyncio.create_task(unbanner.run())

    queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
    asyncio.create_task(tail_log(config['log_path'], queue))

    print("[main] Entering main processing loop")
    last_ui_update = 0.0

    while True:
        processed = 0
        while not queue.empty() and processed < 500:
            record = await queue.get()
            ip = record['source_ip']
            now = time.time()
            status = int(record.get('status', 200))
            is_error = status >= 400

            baseline.record_request(record['_parsed_time'], is_error=is_error)
            detector.record(ip, now, status)

            if not blocker.is_banned(ip):
                anomaly = detector.check_ip(ip, baseline.get_baseline())
                if anomaly:
                    duration = unbanner.get_ban_duration(ip)
                    unbanner.on_ban(ip)
                    blocker.ban_ip(
                        ip=ip,
                        duration_seconds=duration,
                        condition=anomaly['reason'],
                        rate=anomaly['rate'],
                        baseline_mean=baseline.effective_mean,
                    )
                    asyncio.create_task(notifier.send_ban_alert(
                        ip=ip,
                        condition=anomaly['reason'],
                        rate=anomaly['rate'],
                        baseline=baseline.effective_mean,
                        duration=duration,
                    ))

            processed += 1

        # Check global anomaly
        global_anomaly = detector.check_global(baseline.get_baseline())
        if global_anomaly:
            asyncio.create_task(notifier.send_global_alert(
                condition=global_anomaly['reason'],
                rate=global_anomaly['rate'],
                baseline=baseline.effective_mean,
            ))

        # Recalculate baseline if due
        if baseline.maybe_recalculate():
            b = baseline.get_baseline()
            blocker.audit_baseline(b['mean'], b['stddev'])
            # Feed the dashboard graph
            record_baseline(b['mean'], b['stddev'])
            print(f"[main] Baseline recalc: mean={b['mean']:.4f} "
                  f"stddev={b['stddev']:.4f} samples={b['samples']}")

        # Update dashboard every second
        now = time.time()
        if now - last_ui_update >= 1:
            b = baseline.get_baseline()
            update_state(
                banned_ips=dict(blocker.banned),
                global_rate=detector.get_global_rate(),
                top_ips=detector.get_top_ips(),
                baseline=b,
            )
            last_ui_update = now

        await asyncio.sleep(0.05)


if __name__ == '__main__':
    asyncio.run(main())
