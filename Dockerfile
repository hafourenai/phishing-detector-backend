FROM python:3.11-slim

WORKDIR /app

# System deps (ML safe)
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright Chromium + its system dependencies
# PLAYWRIGHT_BROWSERS_PATH keeps browser inside /app so appuser can access it after chown
ENV PLAYWRIGHT_BROWSERS_PATH=/app/.playwright-browsers
RUN playwright install --with-deps chromium

COPY . .

# Non-root user (good practice)
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# HF Spaces WAJIB port 7860
EXPOSE 7860

CMD ["gunicorn", \
     "--bind", "0.0.0.0:7860", \
     "--workers", "1", \
     "--threads", "4", \
     "--timeout", "120", \
     "phishing_url_detector:app"]

