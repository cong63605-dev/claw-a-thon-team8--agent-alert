# ==============================================================================
# SRE Agent — Dockerfile
# Build: docker build -t sre-agent .
# Run:   docker run --env-file .env -p 5000:5000 sre-agent
# ==============================================================================

FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install dependencies first (layer cache — chỉ rebuild khi requirements thay đổi)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY agent.py .

# Không copy .env vào image — truyền qua --env-file hoặc docker-compose
# .env sẽ được mount hoặc inject lúc runtime

# Port agent lắng nghe
EXPOSE 8080

# Chạy bằng gunicorn trong production (ổn định hơn Flask dev server)
# Nếu muốn dùng Flask dev server: đổi thành "python agent.py"
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${AGENT_PORT:-5000} --workers 2 --timeout 30 agent:app"]