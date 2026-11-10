# Container image for the local policy decision service. Not built or published by this repository.
FROM python:3.13-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN groupadd --system app && useradd --system --gid app --home /app app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /root/.cache
COPY examples/devops-network.yaml ./policy.yaml
USER app
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)" || exit 1
CMD ["ztnet", "serve", "--policy", "/app/policy.yaml", "--host", "0.0.0.0", "--port", "8080"]
