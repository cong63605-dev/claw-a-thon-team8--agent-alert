import os
import re
import time
import uuid
import datetime
import requests
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

# ==============================================================================
# CONFIG
# ==============================================================================
GRAFANA_URL     = os.getenv("GRAFANA_URL")
GRAFANA_TOKEN   = os.getenv("GRAFANA_TOKEN")
DATA_SOURCE_UID = os.getenv("DATA_SOURCE_UID")
AGENT_PORT      = int(os.getenv("AGENT_PORT", "5000"))
AGENT_DEBUG     = os.getenv("AGENT_DEBUG", "false").lower() == "true"

_missing = [k for k, v in {"GRAFANA_URL": GRAFANA_URL, "GRAFANA_TOKEN": GRAFANA_TOKEN,
                             "DATA_SOURCE_UID": DATA_SOURCE_UID}.items() if not v]
if _missing:
    raise RuntimeError(f"❌ Thiếu env vars: {', '.join(_missing)}")

THRESHOLDS = {
    "cpu":  {"warn": float(os.getenv("CPU_WARN",  "70")), "crit": float(os.getenv("CPU_CRIT",  "85"))},
    "ram":  {"warn": float(os.getenv("RAM_WARN",  "75")), "crit": float(os.getenv("RAM_CRIT",  "90"))},
    "disk": {"warn": float(os.getenv("DISK_WARN", "80")), "crit": float(os.getenv("DISK_CRIT", "90"))},
}
RECOVERY_THRESHOLDS = {
    "CPU":  float(os.getenv("RECOVERY_CPU",  "65")),
    "RAM":  float(os.getenv("RECOVERY_RAM",  "70")),
    "DISK": float(os.getenv("RECOVERY_DISK", "75")),
}
TIME_WINDOWS = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}
PATTERNS     = {"cpu": "CPU load", "ram": "Memory used", "disk": "Service: fs_"}

ALERT_ICONS = {"CPU": "🖥️", "RAM": "🧠", "DISK": "💾", "HOST_DOWN": "🔌", "UNKNOWN": "❓"}
DECISION_META = {
    "NAGIOS_FLAP":            ("✅", 92, "Server UP — Nagios false alarm"),
    "NODE_EXPORTER_DOWN":     ("🔴", 88, "Node exporter không phản hồi"),
    "NODE_DOWN_CONFIRMED":    ("🔴", 96, "Server xác nhận DOWN bởi Prometheus"),
    "NODE_DOWN_UNVERIFIED":   ("⚠️", 55, "Server có thể DOWN — chưa verify được"),
    "IO_BOTTLENECK":          ("⏳", 80, "I/O wait cao — không phải CPU thật"),
    "REAL_HIGH_CPU":          ("🔥", 85, "CPU thực sự cao"),
    "FALSE_ALARM_CPU":        ("✅", 78, "CPU ổn định — Nagios lấy spike ngắn"),
    "ANOMALY_CPU_SPIKE":      ("📈", 82, "CPU tăng đột biến so với baseline"),
    "FALSE_ALARM_RAM":        ("✅", 80, "RAM ổn định — page cache chưa reclaim"),
    "ANOMALY_MEMORY_LEAK":    ("🚨", 84, "Dấu hiệu memory leak"),
    "REAL_HIGH_RAM":          ("🔥", 83, "RAM thực sự cao"),
    "FALSE_ALARM_DISK":       ("✅", 82, "Disk ổn định — write spike tạm thời"),
    "ANOMALY_DISK_EXPLOSION": ("💥", 88, "Disk tăng bất thường"),
    "REAL_CRITICAL_DISK":     ("🚨", 90, "Disk đầy thật"),
    "DISK_WARN":              ("⚠️", 70, "Disk vượt ngưỡng warn"),
    "CONFIRMED_RECOVERY":     ("✅", 95, "Đã phục hồi — Prometheus xác nhận"),
    "UNVERIFIED_RECOVERY":    ("⚠️", 50, "Nagios báo OK nhưng metric vẫn cao"),
    "RECOVERY_NO_MATCH":      ("ℹ️", 60, "Recovery nhận được nhưng không tìm thấy alert gốc"),
}


def enrich_result(result: dict) -> dict:
    decision  = result.get("decision", "")
    atype     = result.get("alert_type", "UNKNOWN")
    host      = result.get("host", "?")
    ip        = result.get("target_ip", "?")
    sev       = result.get("severity", {})
    metrics   = result.get("metrics", {})
    mount     = result.get("mountpoint", "")

    icon           = ALERT_ICONS.get(atype, "❓")
    d_icon, conf, short = DECISION_META.get(decision, ("❓", 50, decision.replace("_", " ")))

    color      = sev.get("color", "green")
    level_map  = {"green": "ok", "yellow": "warn", "orange": "warn", "red": "crit"}
    alert_level = level_map.get(color, "info")
    if decision in ("NAGIOS_FLAP", "FALSE_ALARM_CPU", "FALSE_ALARM_RAM", "FALSE_ALARM_DISK"):
        alert_level = "info"

    pct = (metrics.get("current_cpu_pct") or metrics.get("current_used_pct")
           or result.get("current_metric_pct"))
    pct_str   = f" — {pct:.1f}%" if pct is not None else ""
    mount_str = f" [{mount}]" if mount else ""
    summary   = f"{icon} {atype}{mount_str} | {host} ({ip}){pct_str} | {short}"

    result["_meta"] = {
        "summary":       summary,
        "icon":          icon,
        "decision_icon": d_icon,
        "short_label":   short,
        "confidence":    conf,
        "alert_level":   alert_level,
        "agent_version": "2.3",
    }
    return result


app = Flask(__name__)
CORS(app)

alert_history: deque = deque(maxlen=100)
active_alerts: dict  = {}


# ==============================================================================
# HELPERS
# ==============================================================================
def gb(b: float) -> float:   return round(b / (1024 ** 3), 2)
def now_iso() -> str:        return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
def make_id() -> str:        return str(uuid.uuid4())[:8]
def akey(h, s, m=""): return f"{h}::{s}::{m}"
def safe_ratio(n, d):  return round(n / d, 3) if d and d > 0 else 1.0

def schedule_removal(alert_id: str, delay: int = 12) -> None:
    import threading
    def _r():
        time.sleep(delay)
        for item in [a for a in alert_history if a.get("alert_id") == alert_id]:
            try: alert_history.remove(item); print(f"🗑️  Removed {alert_id}")
            except ValueError: pass
    threading.Thread(target=_r, daemon=True).start()


# ==============================================================================
# GRAFANA QUERY
# ==============================================================================
def _query_once(promql: str, lookback: int = 0) -> float | None:
    now_ms = int((time.time() - lookback) * 1000)
    try:
        r = requests.post(
            f"{GRAFANA_URL}/api/ds/query",
            headers={"Authorization": f"Bearer {GRAFANA_TOKEN}", "Content-Type": "application/json"},
            json={"queries": [{"datasource": {"uid": DATA_SOURCE_UID, "type": "prometheus"},
                               "expr": promql, "refId": "A", "range": True}],
                  "from": str(now_ms - 300_000), "to": str(now_ms)},
            timeout=10,
        )
        if r.status_code in (401, 403, 404): return None
        if r.status_code == 200:
            frames = r.json().get("results", {}).get("A", {}).get("frames", [])
            if frames:
                vals = frames[0].get("data", {}).get("values", [])
                if len(vals) >= 2 and vals[1]: return float(vals[1][-1])
    except Exception as e: print(f"❌ Grafana: {e}")
    return None

def query(promql: str, lookback: int = 0, retries: int = 1) -> float | None:
    for attempt in range(retries + 1):
        r = _query_once(promql, lookback)
        if r is not None: return r
        if attempt < retries: time.sleep(1)
    return None

def query_parallel(tasks: dict) -> dict:
    results = {}
    with ThreadPoolExecutor(max_workers=min(len(tasks), 8)) as pool:
        futures = {pool.submit(_query_once, p, lb): k for k, (p, lb) in tasks.items()}
        for f in as_completed(futures):
            try: results[futures[f]] = f.result()
            except: results[futures[f]] = None
    return results

def sample_trend(promql: str) -> dict:
    tasks = {"now": (promql, 0)}
    tasks.update({l: (promql, s) for l, s in TIME_WINDOWS.items()})
    return query_parallel(tasks)

def is_node_up(instance: str) -> tuple:
    raw = query(f'up{{instance="{instance}"}}')
    if raw is None: return None, None
    return (True, 1.0) if raw == 1.0 else (False, raw)


# ==============================================================================
# TREND + SEVERITY
# ==============================================================================
def build_trend(samples: dict, crit: float) -> dict:
    wh = {"7d": -168, "24h": -24, "6h": -6, "1h": -1, "now": 0}
    pts = sorted([(wh[k], v) for k, v in samples.items() if v is not None], key=lambda p: p[0])
    slope = 0.0
    if len(pts) >= 2:
        n = len(pts); sx = sum(p[0] for p in pts); sy = sum(p[1] for p in pts)
        sxy = sum(p[0]*p[1] for p in pts); sxx = sum(p[0]**2 for p in pts)
        d = n*sxx - sx**2; slope = (n*sxy - sx*sy) / d if d else 0.0
    cur = samples.get("now") or 0.0
    if slope > 0.5:    direction = "📈 TĂNG NHANH"
    elif slope > 0.1:  direction = "↗️  Tăng nhẹ"
    elif slope < -0.5: direction = "📉 Đang giảm"
    else:              direction = "➡️  Ổn định"
    eta = None
    if slope > 0 and cur < crit:
        hrs = (crit - cur) / slope
        eta = ("ALREADY EXCEEDED" if hrs <= 0 else f"~{int(hrs*60)} minutes" if hrs < 1
               else f"~{hrs:.1f} hours" if hrs < 24 else f"~{hrs/24:.1f} days")
    return {"samples": {k: round(v,2) if v is not None else None for k,v in samples.items()},
            "slope_per_hour": round(slope,3), "direction": direction,
            "time_to_critical_at": f"{crit}%", "eta_critical": eta or "Không có xu hướng tăng"}

def severity(pct: float, growth: float, slope: float, thr: dict) -> dict:
    w, c = thr["warn"], thr["crit"]
    if pct >= c:   lv = 50
    elif pct >= w: lv = 25 + 25*((pct-w)/(c-w))
    else:          lv = 25*(pct/w)
    total = round(min(100, max(0, lv + min(30,(growth-1)*15 if growth>1 else 0) + min(20,abs(slope)*4 if slope>0 else 0))))
    if total >= 80:   return {"score": total, "label": "CRITICAL 🔴", "color": "red"}
    elif total >= 60: return {"score": total, "label": "HIGH 🟠",     "color": "orange"}
    elif total >= 40: return {"score": total, "label": "MEDIUM 🟡",   "color": "yellow"}
    else:             return {"score": total, "label": "LOW 🟢",      "color": "green"}

def make_alert(alert_type, host, ip, sev, decision, diagnosis, hypotheses, actions,
               metrics=None, trend=None, **extra):
    return {"alert_type": alert_type, "host": host, "target_ip": ip, "severity": sev,
            "decision": decision, "diagnosis": diagnosis, "root_cause_hypothesis": hypotheses,
            "recommended_actions": actions, "metrics": metrics or {}, "trend": trend,
            "timestamp": now_iso(), **extra}


# ==============================================================================
# HANDLERS — TECHNICAL DIAGNOSIS + ACTIONS
# ==============================================================================
def handle_nagios_flap(host: str, ip: str) -> dict:
    return make_alert(
        "HOST_DOWN", host, ip,
        sev={"score": 10, "label": "INFO 🟢", "color": "green"},
        decision="NAGIOS_FLAP",
        diagnosis=(
            f"✅ Server {host} ({ip}) ĐANG HOẠT ĐỘNG BÌNH THƯỜNG. "
            f"Prometheus xác nhận up=1 tại thời điểm này. "
            f"Alert này là Nagios false positive — node_exporter vẫn đang scrape bình thường."
        ),
        hypotheses=[
            "Nagios ICMP check timeout do network jitter tạm thời (< 1s)",
            "max_check_attempts chưa đủ trước khi notify — Nagios gửi alert quá sớm",
            "Firewall stateful table overflow làm drop ICMP ngắn hạn",
            "Nagios poller bị CPU contention lúc schedule check",
        ],
        actions=[
            f"# Verify ngay — nếu có response là false alarm:",
            f"ping -c 20 -i 0.2 {ip}",
            f"curl -s http://{ip}:9100/metrics | head -5  # check node_exporter",
            f"# Xem lịch sử check trong Nagios:",
            f"grep '{host}' /var/log/nagios/nagios.log | tail -20",
            f"# Nếu tái diễn thường xuyên — tăng retry trước khi notify:",
            f"# Sửa host config: max_check_attempts=4, retry_interval=1",
        ],
        prometheus_up_raw=1.0, prometheus_up_check=True, prometheus_confirmed=False,
    )


def handle_node_down(host: str, ip: str, instance: str) -> dict:
    return make_alert(
        "HOST_DOWN", host, ip,
        sev={"score": 100, "label": "CRITICAL 🔴", "color": "red"},
        decision="NODE_EXPORTER_DOWN",
        diagnosis=(
            f"Node Exporter tại {instance} không phản hồi — Prometheus scrape thất bại. "
            f"Có thể node đã crash, exporter bị OOM kill, hoặc network partition."
        ),
        hypotheses=[
            "OOM Killer đã kill node_exporter (kiểm tra /var/log/kern.log hoặc dmesg)",
            "Node bị kernel panic hoặc hard lockup",
            "Network partition — route đến node bị mất",
            "Firewall rule thay đổi block port 9100",
            "Disk full khiến node_exporter không write được PID file và exit",
        ],
        actions=[
            f"# Bước 1 — Kiểm tra node còn sống không:",
            f"ping -c 5 {ip}",
            f"ssh {ip} 'uptime && hostname'",
            f"# Bước 2 — Kiểm tra node_exporter process:",
            f"ssh {ip} 'systemctl status node_exporter --no-pager'",
            f"ssh {ip} 'journalctl -u node_exporter --since \"10 minutes ago\" --no-pager'",
            f"# Bước 3 — Kiểm tra OOM kill:",
            f"ssh {ip} 'dmesg | grep -E \"oom|killed\" | tail -20'",
            f"ssh {ip} 'grep -i \"out of memory\" /var/log/syslog | tail -10'",
            f"# Bước 4 — Restart nếu cần:",
            f"ssh {ip} 'systemctl restart node_exporter && systemctl status node_exporter'",
            f"# Bước 5 — Verify Prometheus thấy lại:",
            f"curl -s 'http://localhost:9090/api/v1/query?query=up{{instance=\"{instance}\"}}' | python3 -m json.tool",
        ],
    )


def handle_cpu(alert_text: str, host: str, ip: str, instance: str) -> dict:
    print("🧠 [CPU] Phân tích song song...")
    load_match    = re.search(r"15min\s+load\s+(\d+(?:\.\d+)?)", alert_text)
    cores_match   = re.search(r"at\s+(\d+)\s+CPUs", alert_text)
    nagios_load   = float(load_match.group(1))  if load_match  else 0.0
    cores         = int(cores_match.group(1))   if cores_match else 1
    load_per_core = nagios_load / cores

    promql = f'(100 - (avg by(instance)(rate(node_cpu_seconds_total{{instance="{instance}",mode="idle"}}[5m])) * 100))'
    samples = sample_trend(promql)
    current = samples["now"]
    if current is None:
        return {"status": "failed", "reason": "Không lấy được CPU metric."}

    past_7d = samples.get("7d") or current
    growth  = safe_ratio(current, past_7d)
    trend   = build_trend(samples, THRESHOLDS["cpu"]["crit"])
    sev     = severity(current, growth, trend["slope_per_hour"], THRESHOLDS["cpu"])

    # ── IO_BOTTLENECK ─────────────────────────────────────────────────────
    if current < 50.0 and load_per_core > 2.0:
        decision  = "IO_BOTTLENECK"
        diagnosis = (
            f"CPU usage thực tế chỉ {current:.1f}% nhưng load average 15m = {nagios_load:.1f} "
            f"({load_per_core:.1f}x per core trên {cores} cores). "
            f"Đây là dấu hiệu điển hình của I/O wait — process đang block chờ disk/network I/O, "
            f"không phải CPU bị saturate. Kiểm tra %iowait trong iostat hoặc iotop để xác nhận."
        )
        hypotheses = [
            "Storage IOPS bị bão hòa — disk queue depth tăng cao",
            "Database full table scan hoặc missing index gây I/O spike",
            "NFS/CIFS mount bị lag hoặc network storage timeout",
            "RAID rebuild/resync đang chạy ngầm chiếm I/O bandwidth",
            "Log rotation với compression đang chạy (gzip/zstd nặng I/O)",
        ]
        actions = [
            f"# Xác nhận I/O wait — nếu %iowait > 20% thì confirmed:",
            f"ssh {ip} 'iostat -x 1 5'",
            f"# Tìm process đang chờ I/O nhiều nhất:",
            f"ssh {ip} 'iotop -o -P -b -n 3'",
            f"# Xem disk queue và throughput real-time:",
            f"ssh {ip} 'dstat -d -D sda,sdb --top-io 1 10'",
            f"# Kiểm tra disk latency (await > 20ms là vấn đề):",
            f"ssh {ip} 'iostat -x 1 5 | awk \"/^Device/,0\" | column -t'",
            f"# Nếu là database — xem slow queries:",
            f"ssh {ip} 'tail -100 /var/log/mysql/slow.log 2>/dev/null || tail -100 /var/log/postgresql/postgresql-*.log 2>/dev/null'",
            f"# Xem có RAID đang rebuild không:",
            f"ssh {ip} 'cat /proc/mdstat 2>/dev/null || true'",
        ]

    # ── REAL_HIGH_CPU ─────────────────────────────────────────────────────
    elif current >= THRESHOLDS["cpu"]["crit"]:
        decision  = "REAL_HIGH_CPU"
        slope_note = f" Trend: {trend['slope_per_hour']:+.1f}%/h — ETA critical: {trend['eta_critical']}." if trend["slope_per_hour"] > 0.5 else ""
        diagnosis = (
            f"CPU thực sự đang cao ở {current:.1f}% (ngưỡng crit: {THRESHOLDS['cpu']['crit']}%). "
            f"Load average 15m = {nagios_load:.1f} ({load_per_core:.1f}x/core).{slope_note} "
            f"So với baseline 7d: {past_7d:.1f}% → growth {growth:.1f}x. "
            f"Cần xác định process nào đang chiếm CPU và liệu có liên quan đến deployment hay traffic spike."
        )
        hypotheses = [
            "Deployment mới có performance regression (compiler optimization flag, N+1 query)",
            "Traffic spike thật — autoscale chưa kịp kick in",
            "Scheduled cron job nặng (backup, report generation, data migration)",
            "Infinite loop hoặc deadlock trong application code",
            "Crypto/mining malware nếu growth đột biến và không giải thích được",
            "JVM/GC pressure nếu là Java service (full GC liên tục)",
        ]
        actions = [
            f"# Bước 1 — Top 10 process ăn CPU nhiều nhất:",
            f"ssh {ip} 'ps aux --sort=-%cpu | head -12'",
            f"# Bước 2 — Xem chi tiết threads của process nghi ngờ (thay PID):",
            f"ssh {ip} 'top -H -b -n 1 -p <PID> | head -30'",
            f"# Bước 3 — Nếu là Java — check GC và thread dump:",
            f"ssh {ip} 'jstat -gcutil <PID> 1000 5  # GC stats'",
            f"ssh {ip} 'jstack <PID> > /tmp/threaddump.txt && head -100 /tmp/threaddump.txt'",
            f"# Bước 4 — Perf flamegraph nhanh (nếu có perf):",
            f"ssh {ip} 'perf top -p <PID> --sort=comm,dso -g --no-children 2>/dev/null | head -30'",
            f"# Bước 5 — Check deployment gần nhất:",
            f"ssh {ip} 'ls -lt /opt/app/releases/ | head -5 2>/dev/null || git -C /opt/app log --oneline -5 2>/dev/null'",
            f"# Bước 6 — So sánh CPU mode breakdown (user vs sys vs iowait):",
            f"ssh {ip} 'mpstat -P ALL 1 3'",
        ]

    # ── FALSE_ALARM_CPU ───────────────────────────────────────────────────
    else:
        decision  = "FALSE_ALARM_CPU"
        diagnosis = (
            f"CPU hiện tại {current:.1f}% — dưới ngưỡng warn ({THRESHOLDS['cpu']['warn']}%). "
            f"Nagios báo load = {nagios_load:.1f} nhưng Prometheus thấy CPU thực tế thấp hơn nhiều. "
            f"Nhiều khả năng Nagios đã poll đúng vào 1 spike ngắn (< {THRESHOLDS['cpu']['crit']}%) "
            f"đã tự hết. Theo dõi thêm — không cần action ngay."
        )
        hypotheses = [
            f"Spike ngắn trong Nagios polling window — CPU đã về {current:.1f}% (bình thường)",
            "Nagios check_interval quá thưa, bắt được outlier không đại diện",
            "Kernel task scheduler spike khi Nagios poll (Heisenbug)",
        ]
        actions = [
            f"# Verify trend 5 phút gần nhất trên Prometheus:",
            f"curl -sg 'http://localhost:9090/api/v1/query_range?query={promql}&start=$(date -d-5min +%s)&end=$(date +%s)&step=15' | python3 -m json.tool | grep value",
            f"# Nếu không tái diễn trong 15 phút — đóng ticket",
            f"# Set up alert rule đúng hơn (rate window 5m thay vì instant check):",
            f"# expr: avg_over_time(cpu_usage[5m]) > {THRESHOLDS['cpu']['crit']}",
        ]

    # ── ANOMALY override ──────────────────────────────────────────────────
    if growth >= 2.0 and current > 20.0:
        decision   = "ANOMALY_CPU_SPIKE"
        diagnosis += (
            f"\n⚠️  ANOMALY: CPU tăng {growth:.1f}x so với baseline 7d "
            f"({past_7d:.1f}% → {current:.1f}%). Đây là bất thường — "
            f"cần correlate với deployment history và traffic metrics."
        )
        actions.insert(0, f"# ANOMALY — Correlate ngay với deployment + traffic:")
        actions.insert(1, f"ssh {ip} 'ls -lt /opt/app/releases/ | head -3 2>/dev/null'")
        actions.insert(2, f"# So sánh RPS trên load balancer với 7d trước")

    return make_alert(
        "CPU", host, ip, sev, decision, diagnosis, hypotheses, actions,
        metrics={"current_cpu_pct": round(current,2), "nagios_load_15min": nagios_load,
                 "system_cores": cores, "load_per_core": round(load_per_core,2),
                 "baseline_7d_cpu_pct": round(past_7d,2), "growth_ratio": growth},
        trend=trend,
    )


def handle_ram(alert_text: str, host: str, ip: str, instance: str) -> dict:
    print("🧠 [RAM] Phân tích song song...")
    ram_match  = re.search(r"this\s+is\s+(\d+(?:\.\d+)?)\%", alert_text)
    nagios_pct = float(ram_match.group(1)) if ram_match else 0.0

    q_avail = f'node_memory_MemAvailable_bytes{{instance="{instance}"}}'
    q_total = f'node_memory_MemTotal_bytes{{instance="{instance}"}}'
    raw = query_parallel({"avail": (q_avail,0), "total": (q_total,0),
                          "p_avail": (q_avail, TIME_WINDOWS["7d"]),
                          "p_total": (q_total, TIME_WINDOWS["7d"])})

    avail, total = raw["avail"], raw["total"]
    if avail is None or total is None:
        return {"status": "failed", "reason": "Không lấy được RAM metrics."}

    used_now  = total - avail
    used_past = (raw["p_total"] - raw["p_avail"]) if (raw["p_total"] and raw["p_avail"]) else used_now
    real_pct  = (1 - avail/total) * 100
    avail_pct = (avail/total) * 100
    growth    = safe_ratio(used_now, used_past)

    q_pct   = f'(1-(node_memory_MemAvailable_bytes{{instance="{instance}"}}/node_memory_MemTotal_bytes{{instance="{instance}"}})) * 100'
    samples = sample_trend(q_pct)
    trend   = build_trend(samples, THRESHOLDS["ram"]["crit"])
    sev     = severity(real_pct, growth, trend["slope_per_hour"], THRESHOLDS["ram"])

    # ── FALSE_ALARM_RAM ───────────────────────────────────────────────────
    if real_pct < THRESHOLDS["ram"]["warn"] and growth < 1.5:
        decision  = "FALSE_ALARM_RAM"
        diagnosis = (
            f"RAM thực tế {real_pct:.1f}% used, còn {gb(avail)} GB available ({avail_pct:.1f}% free) "
            f"trên tổng {gb(total)} GB. Nagios báo {nagios_pct:.1f}% — có thể đã tính cả page cache/buffers. "
            f"Linux kernel intentionally dùng RAM cho cache để tăng performance; "
            f"MemAvailable ({gb(avail)} GB) là chỉ số đúng để đánh giá pressure thực sự."
        )
        hypotheses = [
            "Nagios dùng MemUsed thay vì MemAvailable để tính % — sai metric",
            "Page cache lớn sau batch job — kernel sẽ tự reclaim khi cần",
            "Slab cache (dentry/inode cache) chưa được shrink",
        ]
        actions = [
            f"# Xem breakdown chi tiết — chú ý MemAvailable (không phải MemFree):",
            f"ssh {ip} 'free -h && echo --- && cat /proc/meminfo | grep -E \"MemTotal|MemFree|MemAvail|Buffers|Cached|Slab\"'",
            f"# Nếu MemAvailable > 1GB — KHÔNG cần action, system ổn:",
            f"ssh {ip} 'awk \"/MemAvailable/{{printf \\\"Available: %.1f GB\\\\n\\\", $2/1024/1024}}\" /proc/meminfo'",
            f"# Nếu muốn drop page cache thủ công (KHÔNG nên trừ khi cần thiết):",
            f"# ssh {ip} 'sync && echo 3 > /proc/sys/vm/drop_caches'  # chỉ khi thật sự cần",
            f"# Fix Nagios — dùng check_mem với --available flag hoặc custom script",
        ]

    # ── ANOMALY_MEMORY_LEAK ───────────────────────────────────────────────
    elif growth >= 2.0 and real_pct > 40.0:
        slope_note = f" Tốc độ tăng: {trend['slope_per_hour']:+.2f}%/h — ETA OOM: {trend['eta_critical']}." if trend["slope_per_hour"] > 0.1 else ""
        decision  = "ANOMALY_MEMORY_LEAK"
        diagnosis = (
            f"RAM consumed tăng {growth:.1f}x so với baseline 7d "
            f"({gb(used_past)} GB → {gb(used_now)} GB used, {real_pct:.1f}% total). "
            f"Còn lại {gb(avail)} GB available.{slope_note} "
            f"Pattern này consistent với memory leak hoặc runaway process — "
            f"cần identify process, check heap growth, và quyết định restart hay rollback."
        )
        hypotheses = [
            "Java heap leak — objects không được GC vì strong reference cycle",
            "Python memory leak — generator/iterator không close, hoặc global cache không bounded",
            "Go runtime memory không trả về OS (mmap fragmentation)",
            "Connection pool leak — DB/Redis connection không được release",
            "Container không có memory limit → cgroup không throttle",
            f"Thời điểm bắt đầu tăng có thể correlate với deployment mới",
        ]
        actions = [
            f"# Bước 1 — Top process theo RSS (Resident Set Size):",
            f"ssh {ip} 'ps aux --sort=-%mem | head -15 | awk \"{{print $2,$4,$6/1024\\\"MB\\\",$11}}\"'",
            f"# Bước 2 — Xem RSS/VSZ của process theo PID detail:",
            f"ssh {ip} 'cat /proc/$(pgrep -n <service_name>)/status | grep -E \"VmRSS|VmPeak|VmSize\"'",
            f"# Bước 3 — Nếu Java — heap analysis:",
            f"ssh {ip} 'jmap -heap <PID>  # xem heap usage'",
            f"ssh {ip} 'jmap -histo:live <PID> | head -30  # top object types by size'",
            f"ssh {ip} 'jcmd <PID> GC.run && jmap -heap <PID>  # force GC rồi check'",
            f"# Bước 4 — Nếu Python — check với memory_profiler hoặc tracemalloc:",
            f"# Thêm vào code: import tracemalloc; tracemalloc.start() rồi snapshot",
            f"# Bước 5 — Valgrind/heaptrack nếu là C/C++ service:",
            f"ssh {ip} 'heaptrack <binary> 2>/dev/null || valgrind --leak-check=full <binary>'",
            f"# Bước 6 — Check container memory stats:",
            f"ssh {ip} 'docker stats --no-stream --format \"{{{{.Name}}}}\\t{{{{.MemUsage}}}}\\t{{{{.MemPerc}}}}\"'",
            f"# Bước 7 — Nếu cần restart khẩn cấp (sau khi lấy heap dump):",
            f"ssh {ip} 'systemctl restart <service>  # hoặc docker restart <container>'",
        ]

    # ── REAL_HIGH_RAM ─────────────────────────────────────────────────────
    else:
        slope_note = f" Trend: {trend['slope_per_hour']:+.2f}%/h." if abs(trend["slope_per_hour"]) > 0.1 else ""
        decision  = "REAL_HIGH_RAM"
        diagnosis = (
            f"RAM thực sự cao: {real_pct:.1f}% used ({gb(used_now)} GB / {gb(total)} GB), "
            f"còn {gb(avail)} GB available ({avail_pct:.1f}% free).{slope_note} "
            f"Nagios báo {nagios_pct:.1f}%. Growth ratio so với 7d: {growth:.1f}x. "
            f"OOM killer sẽ bắt đầu kill process khi MemAvailable < ~2% total "
            f"({gb(total * 0.02):.1f} GB)."
        )
        hypotheses = [
            "Traffic tăng thật — application cần thêm heap để serve request",
            "Large dataset được load vào memory (cache warm-up, model loading)",
            "Batch job hoặc ETL đang xử lý dataset lớn trong memory",
        ]
        actions = [
            f"# Bước 1 — RAM còn bao nhiêu trước khi OOM:",
            f"ssh {ip} 'free -h && awk \"/MemAvailable/{{printf \\\"Available: %.1f GB (%.1f%% free)\\\\n\\\", $2/1024/1024, $2/{total/1024}*100}}\" /proc/meminfo'",
            f"# Bước 2 — Top process theo actual RSS:",
            f"ssh {ip} 'ps aux --sort=-%mem --no-headers | head -10 | awk \"{{printf \\\"PID=%s RSS=%.0fMB CMD=%s\\\\n\\\", $2, $6/1024, $11}}\"'",
            f"# Bước 3 — Xem OOM score của các process (cao = dễ bị kill):",
            f"ssh {ip} 'for pid in $(ls /proc | grep -E \"^[0-9]+$\" | head -20); do oom=$(cat /proc/$pid/oom_score 2>/dev/null); [ \"$oom\" -gt 100 ] 2>/dev/null && echo \"PID=$pid OOM=$oom CMD=$(cat /proc/$pid/comm 2>/dev/null)\"; done | sort -t= -k3 -rn | head -10'",
            f"# Bước 4 — Check swap usage (nếu swap đang được dùng nhiều = memory pressure cao):",
            f"ssh {ip} 'swapon --show && vmstat -s | grep -E \"swap|memory\"'",
            f"# Bước 5 — Xem kernel đang reclaim được không (kswapd hoạt động):",
            f"ssh {ip} 'vmstat 1 5 | awk \"{{print $7,$8,$14,$15,$16,$17}}\" | column -t'",
        ]

    return make_alert(
        "RAM", host, ip, sev, decision, diagnosis, hypotheses, actions,
        metrics={"total_ram_gb": gb(total), "available_ram_gb": gb(avail),
                 "current_used_ram_gb": gb(used_now), "available_pct": round(avail_pct,2),
                 "baseline_7d_used_gb": gb(used_past), "current_used_pct": round(real_pct,2),
                 "nagios_reported_pct": nagios_pct, "growth_ratio": growth},
        trend=trend,
    )


def handle_disk(alert_text: str, host: str, ip: str, instance: str) -> dict:
    print("💾 [DISK] Phân tích song song...")
    svc_match  = re.search(r"Service:\s+(fs_[^\s]+)", alert_text)
    mountpoint = svc_match.group(1).split("fs_")[1] if svc_match else "/"

    # Parse nagios reported % và trend từ alert text
    nagios_pct_m   = re.search(r"(\d+(?:\.\d+)?)\%\s+used", alert_text)
    nagios_size_m   = re.search(r"\((\d+(?:\.\d+)?)\s+of\s+(\d+(?:\.\d+)?)\s+GB\)", alert_text)
    nagios_trend_m  = re.search(r"trend:\s+([+-]?\d+(?:\.\d+)?GB\s*/\s*24\s*hours)", alert_text)
    nagios_pct      = float(nagios_pct_m.group(1))  if nagios_pct_m  else 0.0
    nagios_trend    = nagios_trend_m.group(1).strip() if nagios_trend_m else None

    q_avail = f'node_filesystem_avail_bytes{{instance="{instance}",mountpoint="{mountpoint}"}}'
    q_total = f'node_filesystem_size_bytes{{instance="{instance}",mountpoint="{mountpoint}"}}'
    raw = query_parallel({"avail": (q_avail,0), "total": (q_total,0),
                          "p_avail": (q_avail, TIME_WINDOWS["7d"]),
                          "p_total": (q_total, TIME_WINDOWS["7d"])})

    avail, total = raw["avail"], raw["total"]
    if avail is None or total is None:
        return {"status": "failed", "reason": f"Không lấy được disk metric: {mountpoint}"}

    used_now  = total - avail
    used_past = (raw["p_total"] - raw["p_avail"]) if (raw["p_total"] and raw["p_avail"]) else used_now
    real_pct  = 100 - (avail/total)*100
    avail_gb  = gb(avail)
    growth    = safe_ratio(used_now, used_past)

    q_pct   = f'(1-(node_filesystem_avail_bytes{{instance="{instance}",mountpoint="{mountpoint}"}}/node_filesystem_size_bytes{{instance="{instance}",mountpoint="{mountpoint}"}})) * 100'
    samples = sample_trend(q_pct)
    trend   = build_trend(samples, THRESHOLDS["disk"]["crit"])
    sev     = severity(real_pct, growth, trend["slope_per_hour"], THRESHOLDS["disk"])

    trend_note = f" Nagios trend: {nagios_trend}." if nagios_trend else ""
    eta_note   = f" ETA full: {trend['eta_critical']}." if trend["eta_critical"] != "Không có xu hướng tăng" else ""

    # ── FALSE_ALARM_DISK ──────────────────────────────────────────────────
    if real_pct < THRESHOLDS["disk"]["warn"] and growth < 1.5:
        decision  = "FALSE_ALARM_DISK"
        diagnosis = (
            f"Disk {mountpoint} thực tế {real_pct:.1f}% used ({gb(used_now)}/{gb(total)} GB), "
            f"còn {avail_gb} GB free. Nagios báo {nagios_pct:.1f}%.{trend_note} "
            f"Có thể Nagios poll đúng lúc có write burst tạm thời đã kết thúc. "
            f"Prometheus cross-check xác nhận disk ổn định."
        )
        hypotheses = [
            "Write burst ngắn (log rotate, backup, core dump) đã kết thúc",
            "Nagios check_disk không exclude tmpfs/overlay mounts làm tính sai",
            f"Filesystem reserved blocks (5% default) làm Nagios tính % sai thực tế",
        ]
        actions = [
            f"# Verify thực tế:",
            f"ssh {ip} 'df -h {mountpoint} && df -i {mountpoint}  # check cả inode'",
            f"# Xem reserved blocks (tune2fs chỉ áp dụng cho ext4):",
            f"ssh {ip} 'tune2fs -l $(df {mountpoint} | awk \"NR==2{{print $1}}\") 2>/dev/null | grep \"Reserved block count\"'",
            f"# Nếu false alarm tái diễn — adjust Nagios threshold hoặc exclude reserved blocks:",
            f"# check_disk -w 80% -c 90% -p {mountpoint} -u GB  # dùng -u để dùng actual used",
        ]

    # ── ANOMALY_DISK_EXPLOSION ────────────────────────────────────────────
    elif growth >= 2.0 and real_pct > 50.0:
        decision  = "ANOMALY_DISK_EXPLOSION"
        diagnosis = (
            f"Disk {mountpoint} đang tăng bất thường: {growth:.1f}x so với 7d trước "
            f"({gb(used_past)} GB → {gb(used_now)} GB used, {real_pct:.1f}%).{trend_note}{eta_note} "
            f"Còn {avail_gb} GB free. Tốc độ tăng {trend['slope_per_hour']:+.2f}%/h. "
            f"Cần tìm ngay thư mục nào đang tăng và dừng việc write không cần thiết."
        )
        hypotheses = [
            "Log rotation bị disable hoặc logrotate config sai — log tích lũy không giới hạn",
            "Core dump files lớn (OOM/crash) tích lũy trong /var/crash hoặc /tmp",
            "Container overlay layers tích lũy — không prune định kỳ",
            "Database WAL/binlog không được truncate (PostgreSQL WAL, MySQL binlog)",
            "Audit log hoặc access log không rotate (Nginx, Apache, Tomcat)",
            "Backup job ghi vào disk local thay vì remote storage",
        ]
        actions = [
            f"# Bước 1 — Tìm ngay thư mục lớn nhất:",
            f"ssh {ip} 'du -h {mountpoint} --max-depth=2 2>/dev/null | sort -rh | head -20'",
            f"# Bước 2 — Tìm file lớn nhất (> 500MB):",
            f"ssh {ip} 'find {mountpoint} -type f -size +500M -printf \"%s\\t%p\\n\" 2>/dev/null | sort -rn | head -20 | awk \"{{printf \\\"%.1fGB\\t%s\\n\\\", $1/1024/1024/1024, $2}}\"'",
            f"# Bước 3 — Tìm core dump / crash files:",
            f"ssh {ip} 'find / -name \"core.*\" -o -name \"*.dump\" -o -name \"*.hprof\" 2>/dev/null | xargs ls -lh 2>/dev/null | sort -k5 -rh | head -10'",
            f"# Bước 4 — Kiểm tra log files chưa rotate:",
            f"ssh {ip} 'find /var/log -type f -size +100M -printf \"%k KB\\t%p\\n\" 2>/dev/null | sort -rn | head -15'",
            f"# Bước 5 — Docker cleanup nếu là Docker host:",
            f"ssh {ip} 'docker system df && docker system prune -f'",
            f"# Bước 6 — DB WAL cleanup:",
            f"ssh {ip} 'ls -lh /var/lib/postgresql/*/main/pg_wal/ 2>/dev/null | tail -5  # PostgreSQL'",
            f"ssh {ip} 'ls -lhS /var/lib/mysql/*-bin.* 2>/dev/null | head -10  # MySQL binlog'",
            f"# Bước 7 — Journald log cleanup:",
            f"ssh {ip} 'journalctl --disk-usage && journalctl --vacuum-size=500M'",
        ]

    # ── REAL_CRITICAL_DISK ────────────────────────────────────────────────
    elif real_pct >= THRESHOLDS["disk"]["crit"]:
        decision  = "REAL_CRITICAL_DISK"
        diagnosis = (
            f"⚠️ CRITICAL: Disk {mountpoint} đầy thật {real_pct:.1f}% "
            f"({gb(used_now)}/{gb(total)} GB), chỉ còn {avail_gb} GB free.{trend_note}{eta_note} "
            f"Khi disk đầy 100%, process không write được sẽ crash, "
            f"database sẽ corrupt, và SSH login có thể fail (nếu /var/log đầy). "
            f"CẦN GIẢI PHÓNG NGAY trong {('< 1 giờ' if avail_gb < 5 else '< 4 giờ')}."
        )
        hypotheses = [
            "Log files tích lũy — logrotate không chạy hoặc sai config",
            "Core dump files từ recent crash",
            "Temp files không được cleanup (/tmp, /var/tmp)",
            "Database data files tăng không kiểm soát",
        ]
        actions = [
            f"# 🚨 KHẨN CẤP — Giải phóng nhanh nhất:",
            f"ssh {ip} 'journalctl --vacuum-size=100M  # xóa systemd journal'",
            f"ssh {ip} 'find /tmp /var/tmp -type f -atime +1 -delete 2>/dev/null  # xóa tmp cũ'",
            f"ssh {ip} 'find /var/log -name \"*.gz\" -mtime +3 -delete  # xóa compressed log cũ'",
            f"ssh {ip} 'find / -name \"core.*\" -size +10M -delete 2>/dev/null  # xóa core dump'",
            f"# Tìm và xóa file lớn nhất ngay:",
            f"ssh {ip} 'du -h {mountpoint} --max-depth=3 2>/dev/null | sort -rh | head -15'",
            f"ssh {ip} 'find {mountpoint} -type f -size +1G 2>/dev/null | xargs ls -lh | sort -k5 -rh'",
            f"# Docker cleanup nếu applicable:",
            f"ssh {ip} 'docker system prune -af --volumes 2>/dev/null  # WARNING: xóa stopped containers + unused volumes'",
            f"# Check và xóa DB binlog/WAL:",
            f"ssh {ip} 'mysql -e \"PURGE BINARY LOGS BEFORE DATE_SUB(NOW(), INTERVAL 2 DAY);\" 2>/dev/null'",
            f"ssh {ip} 'psql -c \"SELECT pg_size_pretty(pg_database_size(current_database()));\" 2>/dev/null'",
            f"# Verify sau khi cleanup:",
            f"ssh {ip} 'df -h {mountpoint}'",
        ]

    # ── DISK_WARN ─────────────────────────────────────────────────────────
    else:
        decision  = "DISK_WARN"
        diagnosis = (
            f"Disk {mountpoint} ở {real_pct:.1f}% ({gb(used_now)}/{gb(total)} GB used), "
            f"còn {avail_gb} GB free — vượt warn threshold ({THRESHOLDS['disk']['warn']}%) "
            f"nhưng chưa critical ({THRESHOLDS['disk']['crit']}%).{trend_note}{eta_note} "
            f"Growth ratio: {growth:.1f}x so với 7d. "
            f"Nếu trend tiếp tục cần lên kế hoạch expand hoặc cleanup trong tuần này."
        )
        hypotheses = [
            "Tăng trưởng dữ liệu bình thường, chưa cần action khẩn",
            "Log hoặc backup tích lũy tự nhiên — cần review retention policy",
        ]
        actions = [
            f"# Review breakdown disk usage:",
            f"ssh {ip} 'df -h {mountpoint} && du -h {mountpoint} --max-depth=2 2>/dev/null | sort -rh | head -15'",
            f"# Kiểm tra inode (có thể hết inode dù còn space):",
            f"ssh {ip} 'df -i {mountpoint}'",
            f"# Xem log retention policy:",
            f"ssh {ip} 'cat /etc/logrotate.d/* | grep -E \"rotate|size|daily|weekly\" | head -20'",
            f"# Estimate khi nào đầy dựa trên trend (ETA): {trend['eta_critical']}",
            f"# Lên kế hoạch: expand disk, cleanup log cũ, hoặc move data sang storage tier khác",
        ]

    return make_alert(
        "DISK", host, ip, sev, decision, diagnosis, hypotheses, actions,
        metrics={"total_disk_gb": gb(total), "available_disk_gb": avail_gb,
                 "current_used_disk_gb": gb(used_now), "available_pct": round(100-real_pct,2),
                 "baseline_7d_used_gb": gb(used_past), "current_used_pct": round(real_pct,2),
                 "nagios_reported_pct": nagios_pct, "growth_ratio": growth},
        trend=trend, mountpoint=mountpoint,
    )


# ==============================================================================
# DISPATCHER + RECOVERY (không đổi)
# ==============================================================================
HANDLER_RULES = [
    (lambda t: PATTERNS["cpu"]  in t, handle_cpu),
    (lambda t: PATTERNS["ram"]  in t, handle_ram),
    (lambda t: PATTERNS["disk"] in t, handle_disk),
]

def detect_service(text: str) -> tuple[str, str]:
    if PATTERNS["cpu"]  in text: return "CPU", ""
    if PATTERNS["ram"]  in text: return "RAM", ""
    m = re.search(r"Service:\s+(fs_[^\s]+)", text)
    if m: return "DISK", m.group(1).replace("fs_","",1)
    return "UNKNOWN", ""

def handle_recovery(alert_text: str, host: str, ip: str, instance: str) -> dict:
    print("🟢 [RECOVERY] Xử lý...")
    svc, mountpoint = detect_service(alert_text)
    key = akey(host, svc, mountpoint)
    verify_q = {
        "CPU":  f'100-(avg(rate(node_cpu_seconds_total{{instance="{instance}",mode="idle"}}[5m]))*100)',
        "RAM":  f'(1-(node_memory_MemAvailable_bytes{{instance="{instance}"}}/node_memory_MemTotal_bytes{{instance="{instance}"}})) * 100',
        "DISK": f'(1-(node_filesystem_avail_bytes{{instance="{instance}",mountpoint="{mountpoint}"}}/node_filesystem_size_bytes{{instance="{instance}",mountpoint="{mountpoint}"}})) * 100',
    }.get(svc)
    current_val  = query(verify_q) if verify_q else None
    threshold    = RECOVERY_THRESHOLDS.get(svc, 70.0)
    verified_ok  = (current_val < threshold) if current_val is not None else True
    original_id  = active_alerts.get(key)
    found        = False
    if original_id and verified_ok:
        for a in alert_history:
            if a.get("alert_id") == original_id:
                a.update({"status": "RECOVERED", "recovered_at": now_iso(),
                           "recovery_verified": True,
                           "recovery_metric": round(current_val,2) if current_val else None})
                found = True; schedule_removal(original_id, 12); break
        del active_alerts[key]
    result = {
        "alert_type": svc, "notification_type": "RECOVERY", "host": host, "target_ip": ip,
        "mountpoint": mountpoint or None, "alert_key": key, "original_alert_id": original_id,
        "grafana_verified": verified_ok, "current_metric_pct": round(current_val,2) if current_val else None,
        "found_and_cleared": found, "severity": {"score":0,"label":"RECOVERED 🟢","color":"green"},
        "decision": "CONFIRMED_RECOVERY" if (verified_ok and found) else "UNVERIFIED_RECOVERY" if not verified_ok else "RECOVERY_NO_MATCH",
        "diagnosis": (f"✅ {svc} trên {host} đã phục hồi. Metric {current_val:.1f}%." if verified_ok and current_val
                      else f"⚠️ Nagios báo RECOVERY nhưng {svc} vẫn {current_val:.1f}%." if not verified_ok and current_val
                      else f"Nagios báo RECOVERY cho {svc} trên {host}."),
        "timestamp": now_iso(), "is_recovery": True,
    }
    return enrich_result(result)

def process_alert(alert_text: str) -> dict:
    print("\n" + "="*80)
    is_rec = "Notification Type: RECOVERY" in alert_text
    print(f"🤖 [SRE AGENT v2.3] {'RECOVERY' if is_rec else 'PROBLEM'} — {alert_text[:100]}...")
    print("-"*80)
    ip_match   = re.search(r"Address:\s+(\d{1,3}(?:\.\d{1,3}){3})", alert_text)
    raw_ip     = ip_match.group(1) if ip_match else "0.0.0.0"
    instance   = f"{raw_ip}:9100"
    host_match = re.search(r"(?:Host:|Nagios:)\s+([^\s,]+)", alert_text)
    host_name  = host_match.group(1) if host_match else "Unknown-Host"

    if is_rec:
        result = handle_recovery(alert_text, host_name, raw_ip, instance)
        print(f"✅ {result['decision']}"); print("="*80); return result

    is_host_down = ("State: DOWN" in alert_text or
        ("PROBLEM" in alert_text and "Service:" not in alert_text
         and "State:" not in alert_text and "Info:" in alert_text))

    if is_host_down:
        up_status, up_raw = is_node_up(instance)
        print(f"  🔍 Prometheus up={up_raw}")
        if up_status is True:
            result = handle_nagios_flap(host_name, raw_ip)
        elif up_status is False:
            result = handle_node_down(host_name, raw_ip, instance)
            result.update({"prometheus_up_raw": 0.0, "prometheus_up_check": False, "prometheus_confirmed": True})
            active_alerts[akey(host_name, "HOST_DOWN")] = make_id()
        else:
            result = handle_node_down(host_name, raw_ip, instance)
            result.update({"prometheus_up_raw": None, "prometheus_up_check": None, "prometheus_confirmed": False})
            result["diagnosis"] += " ⚠️ Không verify được qua Prometheus."
            active_alerts[akey(host_name, "HOST_DOWN")] = make_id()
        result["alert_id"] = make_id()
        alert_history.appendleft(result)
        print(f"✅ {result['decision']}"); print("="*80)
        return enrich_result(result)

    up_status, up_raw = is_node_up(instance)
    print(f"  🔍 Prometheus up={up_raw}")
    if up_status is False:
        result = handle_node_down(host_name, raw_ip, instance)
        result.update({"alert_id": make_id(), "prometheus_up_raw": 0.0, "prometheus_up_check": False, "prometheus_confirmed": True})
        active_alerts[akey(host_name, "HOST_DOWN")] = result["alert_id"]
        alert_history.appendleft(result); return enrich_result(result)
    if up_status is None: print("  ⚠️ Grafana unreachable — trying anyway")
    else: print("  ✅ Node UP — proceeding")

    for predicate, handler in HANDLER_RULES:
        if predicate(alert_text):
            result = handler(alert_text, host_name, raw_ip, instance)
            aid = make_id(); result["alert_id"] = aid
            svc, mount = detect_service(alert_text)
            active_alerts[akey(host_name, svc, mount)] = aid
            alert_history.appendleft(result)
            print(f"✅ {result.get('decision')} | {result.get('severity',{}).get('label')}")
            print("="*80); return enrich_result(result)

    result = {"status": "ignored", "host": host_name, "target_ip": raw_ip,
              "message": "Alert không thuộc danh mục xử lý tự động.", "timestamp": now_iso()}
    alert_history.appendleft(result); return result


# ==============================================================================
# FLASK ENDPOINTS
# ==============================================================================
@app.route("/webhook/nagios", methods=["POST"])
def nagios_webhook():
    try:
        body = request.get_json()
        if not body or "Nagios Alert" not in body:
            return jsonify({"status": "error", "message": "Thiếu trường 'Nagios Alert'"}), 400
        return jsonify(process_alert(body["Nagios Alert"])), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/history", methods=["GET"])
def get_history():
    limit = min(int(request.args.get("limit", 50)), 100)
    inc_re = request.args.get("include_recovered", "1") != "0"
    feed = [
        a for a in alert_history
        if not a.get("is_recovery")
        and a.get("status") != "ignored"
        and a.get("status") != "failed"       # ← thêm dòng này
        and a.get("alert_type")               # ← phải có alert_type
        and (inc_re or a.get("status") != "RECOVERED")
    ]
    return jsonify(feed[:limit]), 200

@app.route("/api/simulate", methods=["POST"])
def simulate_alert():
    body = request.get_json() or {}
    atype = body.get("type","cpu").upper(); level = body.get("severity","high").lower()
    sev_map = {"low":{"score":25,"label":"LOW 🟢","color":"green"},
               "medium":{"score":50,"label":"MEDIUM 🟡","color":"yellow"},
               "high":{"score":75,"label":"HIGH 🟠","color":"orange"},
               "critical":{"score":95,"label":"CRITICAL 🔴","color":"red"}}
    fake = {"alert_type":atype,"host":f"sim-{atype.lower()}-host","target_ip":"10.50.0.1",
            "severity":sev_map.get(level,sev_map["high"]),
            "decision":f"SIM_{atype}_{level.upper()}",
            "diagnosis":f"[SIMULATION] {atype} alert at {level}.",
            "root_cause_hypothesis":["Simulated"],"recommended_actions":["Demo only"],
            "metrics":{"current_used_pct":{"low":45,"medium":65,"high":82,"critical":95}.get(level,82)},
            "trend":{"samples":{"now":82,"1h":78,"6h":70,"24h":60,"7d":50},
                     "slope_per_hour":1.5,"direction":"📈 TĂNG NHANH","eta_critical":"~6 hours"},
            "timestamp":now_iso(),"simulated":True}
    alert_history.appendleft(enrich_result(fake)); return jsonify(fake), 200

@app.route("/api/recheck", methods=["POST"])
def recheck_alert():
    body = request.get_json() or {}; alert_id = body.get("alert_id","").strip()
    if not alert_id: return jsonify({"status":"error","message":"Thiếu alert_id"}), 400
    target = next((a for a in alert_history if a.get("alert_id")==alert_id), None)
    if not target: return jsonify({"status":"error","message":f"Không tìm thấy {alert_id}"}), 404
    atype = target.get("alert_type",""); ip = target.get("target_ip","")
    host  = target.get("host",""); mountpoint = target.get("mountpoint","") or ""
    instance = f"{ip}:9100"; print(f"\n🔄 [RECHECK] {atype} on {host}")
    if atype == "HOST_DOWN":
        up_status, _ = is_node_up(instance)
        target["recheck_at"] = now_iso(); target["recheck_count"] = target.get("recheck_count",0)+1
        if up_status is True:
            target.update({"status":"RECOVERED","recovered_at":now_iso(),"recovery_verified":True,"recovery_metric":1.0})
            active_alerts.pop(akey(host,"HOST_DOWN"), None)
            return jsonify({"status":"RECOVERED","alert_id":alert_id,"verdict":"RECOVERED",
                            "message":f"✅ Node {host} ({ip}) đã online trở lại!","recheck_at":now_iso()}), 200
        return jsonify({"status":"STILL_DOWN","alert_id":alert_id,"verdict":"STILL_ALERTING",
                        "message":f"❌ Node {host} ({ip}) vẫn chưa phản hồi.","recheck_at":now_iso()}), 200
    promql_map = {
        "CPU":  f'100-(avg(rate(node_cpu_seconds_total{{instance="{instance}",mode="idle"}}[5m]))*100)',
        "RAM":  f'(1-(node_memory_MemAvailable_bytes{{instance="{instance}"}}/node_memory_MemTotal_bytes{{instance="{instance}"}})) * 100',
        "DISK": f'(1-(node_filesystem_avail_bytes{{instance="{instance}",mountpoint="{mountpoint}"}}/node_filesystem_size_bytes{{instance="{instance}",mountpoint="{mountpoint}"}})) * 100',
    }
    promql = promql_map.get(atype)
    if not promql: return jsonify({"status":"error","message":f"Không hỗ trợ recheck {atype}"}), 400
    current_val = query(promql)
    target["recheck_at"] = now_iso(); target["recheck_count"] = target.get("recheck_count",0)+1
    target["last_recheck_val"] = round(current_val,2) if current_val else None
    if current_val is None:
        return jsonify({"status":"error","alert_id":alert_id,"verdict":"GRAFANA_UNREACHABLE",
                        "message":"⚠️ Không kết nối được Grafana.","recheck_at":now_iso()}), 200
    threshold = RECOVERY_THRESHOLDS.get(atype, 70.0)
    is_recovered = current_val < threshold
    if is_recovered:
        target.update({"status":"RECOVERED","recovered_at":now_iso(),"recovery_verified":True,
                       "recovery_metric":round(current_val,2),"severity":{"score":0,"label":"RECOVERED 🟢","color":"green"}})
        active_alerts.pop(akey(host,atype,mountpoint), None); schedule_removal(alert_id,12)
        verdict = "RECOVERED"; message = f"✅ {atype} trên {host} hồi phục! {current_val:.1f}% < {threshold}%."
    else:
        growth = target.get("metrics",{}).get("growth_ratio",1.0) or 1.0
        target["severity"] = severity(current_val, growth, 0, THRESHOLDS.get(atype.lower(),THRESHOLDS["cpu"]))
        verdict = "STILL_ALERTING"; message = f"⚠️ {atype} trên {host} vẫn {current_val:.1f}% (recovery < {threshold}%)."
        target["diagnosis"] = f"[Recheck #{target['recheck_count']}] {message} " + (target.get("diagnosis","").split("[Recheck")[0]).strip()
    return jsonify({"status":"ok","alert_id":alert_id,"alert_type":atype,"host":host,
                    "current_val":round(current_val,2),"threshold":threshold,"verdict":verdict,
                    "message":message,"new_severity":target["severity"],
                    "recheck_at":now_iso(),"recheck_count":target["recheck_count"]}), 200

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status":"ok","version":"2.3","alerts_in_history":len(alert_history)}), 200

@app.route("/debug/grafana", methods=["GET"])
def debug_grafana():
    try:
        r = requests.post(f"{GRAFANA_URL}/api/ds/query",
            headers={"Authorization":f"Bearer {GRAFANA_TOKEN}","Content-Type":"application/json"},
            json={"queries":[{"datasource":{"uid":DATA_SOURCE_UID,"type":"prometheus"},
                              "expr":"up","refId":"A","range":True}],
                  "from":str(int((time.time()-300)*1000)),"to":str(int(time.time()*1000))},
            timeout=10)
        return jsonify({"grafana_url":GRAFANA_URL,"data_source_uid":DATA_SOURCE_UID,
                        "status_code":r.status_code,"response_snippet":r.text[:2000]}), 200
    except Exception as e:
        return jsonify({"error":str(e),"grafana_url":GRAFANA_URL}), 502

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=AGENT_PORT, debug=AGENT_DEBUG)