FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    HOST=0.0.0.0 \
    PORT=8080 \
    MAMAN_ROSA_DATA_DIR=/persistent/data \
    MAMAN_ROSA_BACKUP_DIR=/persistent/backups \
    MAMAN_ROSA_PUBLIC_DIR=/opt/maman-rosa \
    MAMAN_ROSA_COOKIE_SECURE=1

WORKDIR /opt/maman-rosa/server
RUN pip install --no-cache-dir cryptography==46.0.2
COPY public/espace-maman-rosa.html /opt/maman-rosa/espace-maman-rosa.html
COPY public/logo.jpeg /opt/maman-rosa/logo.jpeg
COPY server/server.py ./server.py

RUN useradd --system --uid 10001 --create-home mamanrosa \
    && mkdir -p /persistent/data /persistent/backups \
    && chown -R mamanrosa:mamanrosa /opt/maman-rosa /persistent

USER mamanrosa
EXPOSE 8080
VOLUME ["/persistent"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)" || exit 1

CMD ["python", "server.py"]
