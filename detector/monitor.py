import asyncio
import json
import aiofiles
import os
import time


async def tail_log(log_path: str, queue: asyncio.Queue):
    """
    Continuously tail the Nginx access log.
    We seek to the end on startup so we don't replay old traffic,
    then yield new lines as they arrive — like `tail -f`.
    """
    # Wait until the log file exists (Nginx may not have written it yet)
    while not os.path.exists(log_path):
        print(f"[monitor] Waiting for log file: {log_path}")
        await asyncio.sleep(2)

    async with aiofiles.open(log_path, mode='r') as f:
        # Seek to end — don't replay historical traffic
        await f.seek(0, 2)
        print(f"[monitor] Tailing {log_path}")

        while True:
            line = await f.readline()
            if not line:
                await asyncio.sleep(0.05)  # No new line yet, wait a bit
                continue
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                # Normalise: ensure all expected fields exist
                record.setdefault('source_ip', '0.0.0.0')
                record.setdefault('timestamp', '')
                record.setdefault('method', 'GET')
                record.setdefault('path', '/')
                record.setdefault('status', 200)
                record.setdefault('response_size', 0)
                record['_parsed_time'] = time.time()
                await queue.put(record)
            except json.JSONDecodeError:
                pass  # Skip malformed lines
