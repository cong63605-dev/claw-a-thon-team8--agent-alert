"""
Nagios Alert Simulator v2
=========================================
3 cách dùng:
  python nagios_sim_v2.py                          # interactive
  python nagios_sim_v2.py --file alerts.json       # from file
  python nagios_sim_v2.py --inline '{"Nagios Alert":"..."}'
"""
import requests, json, re, sys, time, argparse, textwrap
from datetime import datetime

# ── ANSI ──────────────────────────────────────────────────────────────────────
R="\033[91m"; Y="\033[93m"; G="\033[92m"; B="\033[94m"
C="\033[96m"; M="\033[95m"; DIM="\033[2m"; W="\033[97m"
RST="\033[0m"; BOLD="\033[1m"

def ts(): return datetime.now().strftime("%H:%M:%S")

def hr(char="─", w=72): print(DIM + char*w + RST)

def col(color: str) -> str:
    return {"red":R,"orange":Y,"yellow":Y,"green":G}.get(color, W)

# ── Alert label ────────────────────────────────────────────────────────────────
def detect_label(text: str) -> str:
    host = re.search(r"Host:\s+([^\s,]+)", text)
    ip   = re.search(r"Address:\s+(\d{1,3}(?:\.\d{1,3}){3})", text)
    host = host.group(1) if host else (ip.group(1) if ip else "unknown")
    tag  = "RECOVERY" if "RECOVERY" in text else "PROBLEM"
    if "CPU load"    in text:
        m = re.search(r"load\s+(\d+(?:\.\d+)?)", text)
        return f"CPU {tag} — {host}  load={m.group(1) if m else '?'}"
    if "Memory used" in text:
        m = re.search(r"this is\s+(\d+(?:\.\d+)?)\%", text)
        return f"RAM {tag} — {host}  {m.group(1)+'%' if m else ''}"
    if "fs_"         in text:
        s = re.search(r"Service:\s+(fs_[^\s]+)", text)
        p = re.search(r"(\d+(?:\.\d+)?)\%\s+used", text)
        mnt = s.group(1).replace("fs_","",1) if s else "/"
        return f"DISK {tag} — {host}  {mnt}  {p.group(1)+'%' if p else ''}"
    if "State: DOWN"  in text:
        return f"HOST DOWN — {host}"
    return f"ALERT {tag} — {host}"

# ── Parse ──────────────────────────────────────────────────────────────────────
def parse_input(raw: str) -> list[dict]:
    raw = raw.strip()
    if not raw: return []
    try:
        p = json.loads(raw)
        return _val(p if isinstance(p, list) else [p])
    except json.JSONDecodeError:
        pass
    results = []
    for chunk in re.split(r'\n(?=\s*\{)', raw):
        chunk = chunk.strip()
        if not chunk: continue
        try:
            obj = json.loads(chunk)
            if isinstance(obj, dict): results.append(obj)
        except json.JSONDecodeError as e:
            print(f"{Y}⚠  Skipping: {e}{RST}")
    return _val(results)

def _val(items):
    out = []
    for i in items:
        if "Nagios Alert" in i: out.append(i)
        else: print(f"{Y}⚠  Missing 'Nagios Alert' — skipped{RST}")
    return out

# ── Print result ───────────────────────────────────────────────────────────────
def print_result(r: dict, latency: float):
    meta    = r.get("_meta", {})
    atype   = r.get("alert_type", "UNKNOWN")
    host    = r.get("host", "?")
    ip      = r.get("target_ip", "?")
    sev     = r.get("severity", {})
    score   = sev.get("score", 0)
    slabel  = sev.get("label", "?")
    scolor  = col(sev.get("color", "green"))
    decision= r.get("decision", "N/A").replace("_", " ")
    diag    = r.get("diagnosis", "")
    actions = r.get("recommended_actions", [])
    metrics = r.get("metrics", {})
    trend   = r.get("trend") or {}
    prom_up = r.get("prometheus_up_check")

    # summary line from _meta
    summary   = meta.get("summary", "")
    d_icon    = meta.get("decision_icon", "")
    conf      = meta.get("confidence", "?")
    short     = meta.get("short_label", "")
    alevel    = meta.get("alert_level", "")
    alevel_c  = {"ok": G, "info": B, "warn": Y, "crit": R}.get(alevel, W)

    print()
    hr("─")
    # Row 1: summary
    if summary:
        print(f"  {BOLD}{summary}{RST}")
        hr("·")

    # Row 2: severity + confidence
    print(f"  {W}Severity  :{RST} {scolor}{BOLD}{score:>3}/100  {slabel}{RST}"
          f"   {DIM}│{RST}  {W}Confidence:{RST} {BOLD}{conf}%{RST}"
          f"   {DIM}│{RST}  {alevel_c}{alevel.upper()}{RST}"
          f"   {DIM}│{RST}  {G}⏱ {latency:.2f}s{RST}")

    # Row 3: decision
    print(f"  {W}Decision  :{RST} {scolor}{d_icon}  {decision}{RST}")
    if short:
        print(f"  {W}Summary   :{RST} {DIM}{short}{RST}")

    # Row 4: prometheus check
    if prom_up is not None:
        pstr  = f"{G}UP ✅{RST}" if prom_up else f"{R}DOWN ❌{RST}"
        cnote = f"{DIM}(Prometheus confirmed){RST}" if r.get("prometheus_confirmed") else f"{Y}(Prometheus sees UP — flap?){RST}"
        print(f"  {W}Prometheus:{RST} up = {pstr}  {cnote}")

    if r.get("status") == "failed":
        print(f"  {R}⚠  FAILED: {r.get('reason','?')}{RST}")
        return

    # Diagnosis
    if diag:
        hr("·")
        print(f"  {W}Diagnosis:{RST}")
        for line in textwrap.wrap(diag, 68):
            print(f"    {line}")

    # Metrics
    METRIC_MAP = {
        "current_cpu_pct":      ("CPU now",       "%"),
        "current_used_pct":     ("Used now",      "%"),
        "growth_ratio":         ("Growth",        "×"),
        "system_cores":         ("Cores",         ""),
        "load_per_core":        ("Load/core",     ""),
        "total_ram_gb":         ("RAM total",     " GB"),
        "current_used_ram_gb":  ("RAM used",      " GB"),
        "available_ram_gb":     ("RAM free",      " GB"),
        "baseline_7d_used_gb":  ("Baseline 7d",   " GB"),
        "total_disk_gb":        ("Disk total",    " GB"),
        "current_used_disk_gb": ("Disk used",     " GB"),
        "available_disk_gb":    ("Disk free",     " GB"),
    }
    if metrics:
        hr("·")
        print(f"  {W}Metrics:{RST}")
        rows = [(label, val, unit) for key,(label,unit) in METRIC_MAP.items()
                if (val := metrics.get(key)) is not None]
        # 2-column layout
        for i in range(0, len(rows), 2):
            left  = rows[i]
            right = rows[i+1] if i+1 < len(rows) else None
            def fmt(label, val, unit):
                c = (R if val>=90 else Y if val>=75 else G) if unit=="%"\
                  else (R if val>=2.0 else Y if val>=1.5 else G) if unit=="×"\
                  else W
                return f"  {DIM}{label:<16}{RST}{c}{val}{unit}{RST}"
            line = fmt(*left)
            if right: line += "   " + fmt(*right)
            print(line)

    # Trend sparkline
    if trend.get("samples"):
        hr("·")
        smp    = trend["samples"]
        keys   = ["7d","24h","6h","1h","now"]
        values = [smp.get(k) for k in keys]
        max_v  = max((v for v in values if v is not None), default=1)

        # Mini bar chart (unicode blocks)
        BLOCKS = " ▁▂▃▄▅▆▇█"
        bars   = ""
        for v in values:
            if v is None:
                bars += DIM + "  — " + RST
            else:
                idx = max(0, min(8, round((v / max(max_v, 0.001)) * 8)))
                bc  = R if v >= 90 else Y if v >= 75 else G
                bars += bc + BLOCKS[idx]*2 + f"{v:>4.0f}%" + RST + " "

        eta = trend.get("eta_critical", "—")
        ec  = R if ("hour" in str(eta) or "min" in str(eta)) else G
        print(f"  {W}Trend:{RST}  {trend.get('direction','?')}   ETA critical: {ec}{eta}{RST}")
        print(f"  {bars}")
        print(f"  {DIM}{''.join(f'{k:>7}' for k in keys)}{RST}")

    # Actions
    if actions:
        hr("·")
        print(f"  {W}Actions:{RST}")
        for a in actions:
            is_cmd = any(a.startswith(x) for x in ("ssh","docker","ping","find","cat","curl")) or "|" in a
            icon   = f"  {C}${RST}" if is_cmd else f"  {DIM}›{RST}"
            print(f"{icon} {a}")
    print()


def print_sending(label: str, idx: int, total: int, dry: bool):
    hr("═")
    tag = f"{M}DRY RUN{RST}" if dry else f"{C}→ POST{RST}"
    print(f"{DIM}[{ts()}]{RST}  [{tag}]  {idx}/{total}  {BOLD}{W}{label}{RST}")


def print_summary(results: list[dict]):
    if not results: return
    hr("═")
    print(f"  {BOLD}{W}SUMMARY{RST}")
    hr("═")
    print(f"  {'#':<4} {'Host':<26} {'Type':<8} {'Sc':>4}  {'Conf':>5}  Decision")
    hr()
    for i, r in enumerate(results, 1):
        meta  = r.get("_meta", {})
        host  = (r.get("host") or "?")[:25]
        atype = (r.get("alert_type") or "?")[:7]
        sev   = r.get("severity", {})
        score = sev.get("score", 0)
        conf  = meta.get("confidence", "?")
        c     = col(sev.get("color","green"))
        icon  = meta.get("decision_icon", "")
        dec   = (r.get("decision") or r.get("message") or "?").replace("_"," ")[:28]
        if r.get("status") == "failed":
            print(f"  {i:<4} {host:<26} {R}FAILED{RST}   {'—':>4}  {'—':>5}  {dec}")
        else:
            print(f"  {i:<4} {host:<26} {B}{atype:<8}{RST} {c}{score:>4}{RST}  {DIM}{conf:>4}%{RST}  {icon} {dec}")
    hr("═")
    ok    = sum(1 for r in results if r.get("status") != "failed")
    crits = sum(1 for r in results if r.get("severity",{}).get("score",0) >= 80)
    flaps = sum(1 for r in results if r.get("decision") == "NAGIOS_FLAP")
    print(f"  Sent {len(results)}  ·  OK {G}{ok}{RST}  ·  Critical {R}{crits}{RST}  ·  Flap {Y}{flaps}{RST}")
    hr("═")


# ── Fire ───────────────────────────────────────────────────────────────────────
def fire(payload: dict, url: str) -> dict | None:
    try:
        t0   = time.time()
        resp = requests.post(url, headers={"Content-Type":"application/json"},
                             json=payload, timeout=120)
        lat  = time.time() - t0
        if resp.status_code == 200:
            r = resp.json()
            print_result(r, lat)
            return r
        print(f"  {R}❌ HTTP {resp.status_code}: {resp.text[:200]}{RST}")
        return {"status":"failed","reason":f"HTTP {resp.status_code}"}
    except requests.exceptions.ConnectionError:
        print(f"\n  {R}❌ Connection refused — agent chưa chạy tại {url}{RST}\n")
        return {"status":"failed","reason":"Connection refused"}
    except requests.exceptions.Timeout:
        print(f"  {R}❌ Timeout{RST}")
        return {"status":"failed","reason":"Timeout"}
    except Exception as e:
        print(f"  {R}❌ {e}{RST}")
        return {"status":"failed","reason":str(e)}


def run_batch(payloads: list[dict], url: str, dry: bool, delay: float) -> list[dict]:
    results = []
    total   = len(payloads)
    for i, p in enumerate(payloads, 1):
        label = detect_label(p.get("Nagios Alert",""))
        print_sending(label, i, total, dry)
        if dry:
            print(f"  {DIM}{p.get('Nagios Alert','')[:110]}...{RST}")
        else:
            r = fire(p, url)
            if r: results.append(r)
        if i < total: time.sleep(delay)
    return results


# ── Interactive ────────────────────────────────────────────────────────────────
BANNER = f"""
{BOLD}{W}  ╔══════════════════════════════════════════╗
  ║   SRE Simulator v2  —  ZaloPay Infra    ║
  ╚══════════════════════════════════════════╝{RST}
  {DIM}Paste JSON alert → Enter×2 gửi  ·  Ctrl+C thoát{RST}
"""

def interactive_mode(url: str, dry: bool):
    print(BANNER)
    all_results, count = [], 0
    while True:
        print(f"\n{C}┌─ Paste alert{RST}")
        lines = []
        try:
            while True:
                line = input(f"{C}│{RST} ")
                if line.strip().lower() in ("q","quit","exit"): raise KeyboardInterrupt
                if line == "" and lines and lines[-1] == "": break
                lines.append(line)
        except KeyboardInterrupt:
            print(f"\n{Y}👋 Thoát.{RST}")
            if all_results: print_summary(all_results)
            break
        except EOFError:
            break
        raw = "\n".join(lines).strip()
        if not raw: continue
        payloads = parse_input(raw)
        if not payloads:
            print(f"  {R}❌ Không parse được JSON{RST}")
            continue
        results = run_batch(payloads, url, dry, delay=0)
        all_results.extend(results)
        count += len(payloads)
        print(f"{DIM}  [Total session: {count} alert(s)]{RST}")


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Nagios Sim v2")
    parser.add_argument("--url",     default="http://localhost:5000/webhook/nagios")
    parser.add_argument("--file",    help="JSON file")
    parser.add_argument("--inline",  help="Single alert JSON")
    parser.add_argument("--delay",   type=float, default=2.0)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    print(f"\n{BOLD}{W}  🚀 NAGIOS SIMULATOR v2  {RST}{DIM}{args.url}{RST}")
    if args.dry_run: print(f"  {M}DRY RUN{RST}")
    hr("═")

    if args.inline:
        payloads = parse_input(args.inline)
        if not payloads: print(f"{R}❌ Parse error{RST}"); sys.exit(1)
        results = run_batch(payloads, args.url, args.dry_run, delay=0)
        print_summary(results)
        return

    if args.file:
        try:    raw = open(args.file, encoding="utf-8").read()
        except FileNotFoundError:
            print(f"{R}❌ File không tồn tại: {args.file}{RST}"); sys.exit(1)
        payloads = parse_input(raw)
        if not payloads: print(f"{R}❌ Không có alert hợp lệ{RST}"); sys.exit(1)
        print(f"  {len(payloads)} alert(s)  delay={args.delay}s\n")
        results = run_batch(payloads, args.url, args.dry_run, args.delay)
        print_summary(results)
        return

    interactive_mode(args.url, args.dry_run)

if __name__ == "__main__":
    main()