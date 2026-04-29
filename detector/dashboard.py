from flask import Flask, render_template_string, jsonify
import psutil
import time
import threading
from collections import deque

app = Flask(__name__)

_state = {
    'banned_ips': {},
    'global_rate': 0,
    'top_ips': [],
    'baseline': {'mean': 0, 'stddev': 0},
    'uptime_start': time.time(),
}

# Store baseline history for the graph — (timestamp, mean, stddev)
_baseline_history = deque(maxlen=200)

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>HNG Anomaly Detector</title>
<meta http-equiv="refresh" content="3">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
  body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
  h1 { color: #58a6ff; }
  h2 { color: #8b949e; border-bottom: 1px solid #30363d; padding-bottom: 4px; }
  table { border-collapse: collapse; width: 100%; }
  th { background: #161b22; color: #8b949e; padding: 6px 12px; text-align: left; }
  td { padding: 6px 12px; border-bottom: 1px solid #21262d; }
  .badge { padding: 2px 8px; border-radius: 4px; font-size: 12px; }
  .banned { background: #3d1c1c; color: #f85149; }
  .ok { background: #1c3d2d; color: #3fb950; }
  .stat { display: inline-block; background: #161b22; border: 1px solid #30363d;
          border-radius: 6px; padding: 12px 20px; margin: 8px; min-width: 140px; }
  .stat-val { font-size: 28px; color: #58a6ff; }
  .stat-label { font-size: 11px; color: #8b949e; margin-top: 4px; }
  .chart-container { background: #161b22; border: 1px solid #30363d;
                     border-radius: 6px; padding: 16px; margin: 16px 0; }
</style>
</head>
<body>
<h1>&#x1F6E1; HNG Anomaly Detection Engine</h1>
<p style="color:#8b949e">Auto-refreshes every 3 seconds | {{ now }}</p>

<div>
  <div class="stat">
    <div class="stat-val">{{ global_rate }}</div>
    <div class="stat-label">req / 60s (global)</div>
  </div>
  <div class="stat">
    <div class="stat-val">{{ banned_count }}</div>
    <div class="stat-label">banned IPs</div>
  </div>
  <div class="stat">
    <div class="stat-val">{{ "%.2f"|format(mean) }}</div>
    <div class="stat-label">baseline mean</div>
  </div>
  <div class="stat">
    <div class="stat-val">{{ "%.2f"|format(stddev) }}</div>
    <div class="stat-label">baseline stddev</div>
  </div>
  <div class="stat">
    <div class="stat-val">{{ cpu }}%</div>
    <div class="stat-label">CPU usage</div>
  </div>
  <div class="stat">
    <div class="stat-val">{{ mem }}%</div>
    <div class="stat-label">Memory usage</div>
  </div>
  <div class="stat">
    <div class="stat-val">{{ uptime }}</div>
    <div class="stat-label">uptime</div>
  </div>
</div>

<h2>Baseline Over Time</h2>
<div class="chart-container">
  {% if has_history %}
  <canvas id="baselineChart" height="80"></canvas>
  {% else %}
  <p style="color:#8b949e; text-align:center; padding: 40px 0;">
    &#x23F3; Waiting for baseline data — recalculates every 60 seconds...
  </p>
  {% endif %}
</div>

<h2>Banned IPs</h2>
{% if banned_ips %}
<table>
  <tr><th>IP</th><th>Banned at</th><th>Duration</th><th>Condition</th></tr>
  {% for ip, info in banned_ips.items() %}
  <tr>
    <td><span class="badge banned">{{ ip }}</span></td>
    <td>{{ info.banned_at_str }}</td>
    <td>{{ info.duration_str }}</td>
    <td>{{ info.condition }}</td>
  </tr>
  {% endfor %}
</table>
{% else %}
<p style="color:#3fb950">No IPs currently banned &#x2713;</p>
{% endif %}

<h2>Top 10 Source IPs (last 60s)</h2>
<table>
  <tr><th>IP</th><th>Requests (60s window)</th><th>Status</th></tr>
  {% for ip, count in top_ips %}
  <tr>
    <td>{{ ip }}</td>
    <td>{{ count }}</td>
    <td>
      {% if ip in banned_ips %}
        <span class="badge banned">BANNED</span>
      {% else %}
        <span class="badge ok">OK</span>
      {% endif %}
    </td>
  </tr>
  {% endfor %}
</table>

{% if has_history %}
<script>
const labels = {{ labels | tojson }};
const means  = {{ means  | tojson }};
const stddevs = {{ stddevs | tojson }};

const ctx = document.getElementById('baselineChart').getContext('2d');
new Chart(ctx, {
  type: 'line',
  data: {
    labels: labels,
    datasets: [
      {
        label: 'Effective Mean (req/s)',
        data: means,
        borderColor: '#58a6ff',
        backgroundColor: 'rgba(88,166,255,0.1)',
        tension: 0.3,
        fill: true,
        pointRadius: 2,
      },
      {
        label: 'Stddev',
        data: stddevs,
        borderColor: '#3fb950',
        backgroundColor: 'rgba(63,185,80,0.1)',
        tension: 0.3,
        fill: false,
        pointRadius: 2,
        borderDash: [4, 4],
      }
    ]
  },
  options: {
    responsive: true,
    plugins: {
      legend: { labels: { color: '#8b949e' } }
    },
    scales: {
      x: {
        ticks: { color: '#8b949e', maxTicksLimit: 12 },
        grid:  { color: '#21262d' }
      },
      y: {
        ticks: { color: '#8b949e' },
        grid:  { color: '#21262d' }
      }
    }
  }
});
</script>
{% endif %}
</body>
</html>
"""

def _uptime_str(seconds: float) -> str:
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return f"{h:02d}:{m:02d}:{s:02d}"

@app.route('/')
def index():
    from datetime import datetime, timezone
    state = _state
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    uptime = _uptime_str(time.time() - state['uptime_start'])

    banned_ips = {}
    for ip, info in state['banned_ips'].items():
        dur = info.get('ban_duration', 0)
        banned_ips[ip] = {
            'banned_at_str': datetime.fromtimestamp(
                info['banned_at']).strftime('%H:%M:%S'),
            'duration_str': 'PERMANENT' if dur == -1 else f"{dur}s",
            'condition': info.get('condition', '-'),
        }

    # Build graph data from history
    # FIX: guard against empty history so Chart.js is never called with empty arrays
    history_list = list(_baseline_history)
    has_history  = len(history_list) > 0

    labels  = [h[0] for h in history_list]
    means   = [round(h[1], 4) for h in history_list]
    stddevs = [round(h[2], 4) for h in history_list]

    return render_template_string(
        DASHBOARD_HTML,
        now=now,
        global_rate=state['global_rate'],
        banned_count=len(state['banned_ips']),
        mean=state['baseline'].get('mean', 0),
        stddev=state['baseline'].get('stddev', 0),
        cpu=psutil.cpu_percent(interval=None),
        mem=psutil.virtual_memory().percent,
        uptime=uptime,
        top_ips=state['top_ips'],
        banned_ips=banned_ips,
        has_history=has_history,
        labels=labels,
        means=means,
        stddevs=stddevs,
    )

@app.route('/api/metrics')
def metrics():
    return jsonify({
        'global_rate': _state['global_rate'],
        'banned_count': len(_state['banned_ips']),
        'baseline': _state['baseline'],
        'top_ips': _state['top_ips'],
        'cpu': psutil.cpu_percent(interval=None),
        'mem': psutil.virtual_memory().percent,
    })

def update_state(banned_ips, global_rate, top_ips, baseline):
    _state['banned_ips'] = banned_ips
    _state['global_rate'] = global_rate
    _state['top_ips'] = top_ips
    _state['baseline'] = baseline

def record_baseline(mean: float, stddev: float):
    """Call this every time baseline is recalculated to feed the graph."""
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime('%H:%M')
    _baseline_history.append((ts, mean, stddev))

def run_dashboard(host='0.0.0.0', port=8080):
    t = threading.Thread(
        target=lambda: app.run(host=host, port=port, debug=False, use_reloader=False),
        daemon=True
    )
    t.start()
