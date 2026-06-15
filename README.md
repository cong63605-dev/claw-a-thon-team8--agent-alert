

Hệ thống tự động phân tích alert từ Nagios, query Grafana để double-check metric thực tế, và đưa ra diagnosis + recommended actions cho team.

---

## Kiến trúc tổng quan

```
Nagios Alert
     │
     ▼
nagios_sim_v2.py          ← Simulator (test) hoặc Nagios thật
     │  POST /webhook/nagios
     ▼
agent.py           ← Agent xử lý, query Grafana, phân tích
     │  GET /api/history
     ▼
dashboard.html        ← Dashboard hiển thị realtime trên browser
```

---

## Cấu trúc file

```
agent/
├── agent_v2.py       # Agent chính — Flask API
├── nagios_sim_v2.py      # Simulator — test gửi alert
├── dashboard.html    # Dashboard UI
├── requirements.txt      # Python dependencies
├── Dockerfile
├── docker-compose.yml
├── .env                  # Config thật — KHÔNG commit git
├── .env.example          # Template — an toàn để commit
└── .gitignore
```

---

## Cài đặt

### Yêu cầu

- Docker + Docker Compose
- Python 3.12+ (chỉ cần cho simulator)

### Bước 1 — Tạo file `.env`

```bash
cp .env.example .env
```

Mở `.env` và điền giá trị thật:

```env
GRAFANA_URL=https://test.vn
GRAFANA_TOKEN=glsa_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
DATA_SOURCE_UID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

AGENT_PORT=5000
AGENT_DEBUG=false

CPU_WARN=70
CPU_CRIT=85
RAM_WARN=75
RAM_CRIT=90
DISK_WARN=80
DISK_CRIT=90

RECOVERY_CPU=65
RECOVERY_RAM=70
RECOVERY_DISK=75
```

### Bước 2 — Cài Python packages cho simulator

```bash
pip install requests
```

---

## Chạy hệ thống

### Terminal 1 — Start Agent (Docker)

```bash
# Build và chạy
docker compose up -d --build

# Kiểm tra agent sống
curl http://localhost:5000/health
# {"alerts_in_history": 0, "status": "ok", "version": "2.0"}

# Xem log realtime
docker compose logs -f
```

### Terminal 2 — Mở Dashboard

```bash
python -m http.server 8080
```

Mở browser vào: `http://localhost:8080/dashboard.html`

Dashboard tự poll agent mỗi 15 giây — không cần refresh tay.

### Terminal 3 — Chạy Simulator

```bash
python nagios_sim_v2.py
```

---

## Gửi alert bằng Simulator

### Interactive mode (mặc định)

```bash
python nagios_sim_v2.py
```

Paste JSON alert vào terminal, **Enter 2 lần** để gửi:

```
┌─ Paste alert (Enter×2 gửi)
│ {"Nagios Alert":"Notification Type: PROBLEM Service: fs_/ ..."}
│
│         ← Enter lần 2 → gửi ngay
```

Paste nhiều alert cùng lúc cũng được — simulator tự tách từng object.

### Các format alert hỗ trợ

**DISK:**
```json
{"Nagios Alert":"Notification Type: PROBLEM Service: fs_/ Host: TEST_server1 Address: 10.50.1.64 State: WARNING Date/Time: Sat Jun 13 16:43:53 ICT 2026 Additional Info: WARN - 97.5% used (530.78 of 544.4 GB)"}
```

**RAM:**
```json
{"Nagios Alert":"Notification Type: PROBLEM Service: Memory used Host: TEST_server12 Address: 10.50.1.33 State: CRITICAL Date/Time: Sat Jun 13 14:51:42 ICT 2026 Additional Info: CRIT - 126.81 GB used (this is 100.9% of 125.63 GB RAM), critical at 100.0%"}
```

**CPU:**
```json
{"Nagios Alert":"Notification Type: PROBLEM Service: CPU load Host: TEST_server3 Address: 10.50.1.44 State: WARNING Date/Time: Thu Jun 11 10:17:27 ICT 2026 Additional Info: WARN - 15min load 599.55 at 40 CPUs, (warning level at 10.00)"}
```

**HOST DOWN:**
```json
{"Nagios Alert":"PROBLEM Host: TEST_server4 State: DOWN Address: 10.50.1.15 Info: CRITICAL - Socket timeout after 10 seconds Date/Time: Fri Jun 12 11:18:41 ICT 2026"}
```

**RECOVERY:**
```json
{"Nagios Alert":"Notification Type: RECOVERY Service: fs_/ Host:TEST_server5 Address: 10.50.1.64 State: OK Additional Info: OK - 61.0% used"}
```

### Các flag của simulator

```bash
# Gửi từ file JSON
python nagios_sim_v2.py --file alerts.json

# Gửi 1 alert inline
python nagios_sim_v2.py --inline '{"Nagios Alert":"..."}'

# Xem payload mà không gửi
python nagios_sim_v2.py --dry-run

# Đổi delay giữa các alert (giây)
python nagios_sim_v2.py --file alerts.json --delay 5

# Đổi endpoint nếu agent chạy port khác
python nagios_sim_v2.py --url http://localhost:8080/webhook/nagios
```

---

## Tính năng Dashboard

### Alert feed (panel trái)
- Hiển thị tất cả alert đang active
- Color-coded theo severity: 🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low
- Alert recovered tự mờ và biến mất sau 10 giây

### Alert detail (panel phải)
Khi click vào 1 alert sẽ thấy:

- **Severity score** — 0 đến 100
- **Live metrics** — giá trị hiện tại từ Grafana (GB, %)
- **Trend chart** — sparkline 7d → 24h → 6h → 1h → now
- **ETA critical** — dự đoán thời gian đến ngưỡng nguy hiểm
- **Diagnosis** — phân tích nguyên nhân
- **Root cause hypotheses** — các nguyên nhân có thể
- **Recommended actions** — lệnh shell sẵn sàng copy

### Nút Recheck
Bấm **⟳ Recheck** trên bất kỳ alert nào để agent query Grafana ngay lập tức:

- Metric đã xuống dưới ngưỡng → alert chuyển **xanh RECOVERED**, tự xóa sau 10s
- Metric vẫn cao → hiển thị giá trị mới nhất, severity được tính lại
- Grafana offline → thông báo không verify được

---

## API Endpoints

| Method | Endpoint | Mô tả |
|---|---|---|
| `POST` | `/webhook/nagios` | Nhận alert từ Nagios hoặc simulator |
| `GET` | `/api/history` | Lấy danh sách alert cho dashboard |
| `POST` | `/api/recheck` | Recheck 1 alert theo `alert_id` |
| `GET` | `/health` | Kiểm tra agent còn sống |

### `/webhook/nagios`

```bash
curl -X POST http://localhost:5000/webhook/nagios \
  -H "Content-Type: application/json" \
  -d '{"Nagios Alert":"Notification Type: PROBLEM Service: fs_/ Host: server-01 Address: 10.50.1.64 State: CRITICAL Additional Info: CRIT - 95% used"}'
```

### `/api/recheck`

```bash
curl -X POST http://localhost:5000/api/recheck \
  -H "Content-Type: application/json" \
  -d '{"alert_id": "a3f2c1b8"}'
```

### `/api/history`

```bash
# Lấy 50 alert gần nhất (mặc định)
curl http://localhost:5000/api/history

# Lấy 10 alert, không bao gồm recovered
curl http://localhost:5000/api/history?limit=10&include_recovered=0
```

---

## Cách agent xử lý alert

```
Nhận alert
    │
    ├─ RECOVERY? → verify Grafana → update alert gốc → xóa khỏi history sau 12s
    │
    └─ PROBLEM?
          │
          ├─ Prometheus: up{instance="IP:9100"}
          │     = 1   → node UP, tiếp tục
          │     = 0   → node DOWN, handle_node_down()
          │     = None → Grafana offline, thử tiếp
          │
          ├─ Detect loại alert: CPU / RAM / DISK / HOST_DOWN
          │
          ├─ Query Grafana 5 window: now / 1h / 6h / 24h / 7d
          │
          ├─ Linear regression → slope → ETA critical
          │
          ├─ Compute severity score 0–100
          │
          └─ Return diagnosis + root_cause + recommended_actions
```

---

## Deploy lại khi sửa code

```bash
# Sửa code xong → rebuild và restart (downtime ~3s)
docker compose up -d --build

# Xem log ngay sau deploy
docker compose logs -f

# Rollback nếu có lỗi
docker compose down
git checkout sre_agent_v2.py
docker compose up -d --build
```

---

## Thresholds mặc định

| Metric | Warn | Critical | Recovery |
|---|---|---|---|
| CPU | 70% | 85% | < 65% |
| RAM | 75% | 90% | < 70% |
| Disk | 80% | 90% | < 75% |

Thay đổi trong `.env` — không cần sửa code, không cần rebuild image.

---

## Troubleshooting

**Agent không start:**
```bash
docker compose logs agent
# Thường do thiếu biến trong .env
```

**Simulator không kết nối được agent:**
```bash
curl http://localhost:5000/health
# Nếu lỗi → agent chưa chạy hoặc sai port
```

**Alert không hiện trên dashboard:**
```bash
# Mở F12 → Console xem lỗi CORS
# Fix: mở dashboard qua http server, không mở file:// trực tiếp
python -m http.server 8080
# Vào: http://localhost:8080/sre_dashboard.html
```

**Grafana trả về lỗi 401:**
```bash
# Kiểm tra GRAFANA_TOKEN trong .env còn hiệu lực
curl -H "Authorization: Bearer $GRAFANA_TOKEN" https://[LINK]/api/health
```
