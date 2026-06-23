FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PCRM_HOST=0.0.0.0 \
    PCRM_PORT=8000

WORKDIR /app

# deps first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# app
COPY . .
RUN chmod +x entrypoint.sh \
    && useradd --create-home --uid 10001 app \
    && mkdir -p /app/data \
    && chown -R app /app/data
USER app

EXPOSE 8000
ENTRYPOINT ["./entrypoint.sh"]
CMD ["collect"]
