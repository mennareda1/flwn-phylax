# Phylax, the security review service, as a container.
#
#   docker build -t phylax .
#   docker run --rm -p 8080:8080 -e SERVICE_API_KEYS="me:scan+fix+read:<a key from: python -m security_service.api --new-key>" phylax
#
# What is in the image: the service and the pinned packages it needs (constraints-runtime.txt), nothing else. No tests, no benchmark, no .env, no keys.
# Every secret (the API keys, the Azure Foundry key) is passed in as an environment variable when the container starts.
# The service keeps scans in memory, so run ONE copy of it.

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SERVICE_HOST=0.0.0.0 \
    SERVICE_PORT=8080

WORKDIR /app

# Dependencies first, so a code change does not reinstall them. Exact versions: the ones the whole test suite passed with.
COPY requirements-runtime.txt constraints-runtime.txt ./
RUN pip install -r requirements-runtime.txt -c constraints-runtime.txt

COPY security_service ./security_service

# Run as an ordinary user, not root.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin phylax \
    && chown -R phylax:phylax /app
USER phylax

EXPOSE 8080

# Healthy = the service answers /healthz. (/readyz also checks that the checks it relies on are available.)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request as u; u.urlopen('http://127.0.0.1:' + os.environ.get('SERVICE_PORT', '8080') + '/healthz', timeout=4)"]

LABEL org.opencontainers.image.source="https://github.com/mennareda1/flwn-phylax" \
      org.opencontainers.image.title="Phylax" \
      org.opencontainers.image.description="Security review service: scans code, offers verified corrections, never changes files"

CMD ["python", "-m", "security_service.api"]
