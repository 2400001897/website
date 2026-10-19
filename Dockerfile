FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Ho_Chi_Minh

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && ln -sf /usr/share/zoneinfo/$TZ /etc/localtime \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/
COPY static/ static/
# sinh placeholder neu chua co flag.txt (moi truong that se cung cap rieng)
RUN test -f flag.txt || echo "FLAG{placeholder}" > flag.txt

# non-root user (uid/gid 1000 = trung voi user `deploy` tren host
# de ghi duoc bind-mount: website_b.db, victim_bot.state.json, artifacts/)
RUN useradd --uid 1000 --user-group appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000
CMD ["python", "app.py"]
