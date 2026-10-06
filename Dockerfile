# IAM Agent — REST control plane + MCP server.
#
# The image runs the API by default. Override the command to run the MCP server
# over stdio instead (`docker run -i iam-agent mcp`), or the CLI.

FROM python:3.11-slim AS base

# ldap3 needs no system libraries, but the on-prem AD connector talks LDAPS and
# therefore needs a CA bundle; ca-certificates is already present in slim, and
# tzdata keeps hire/leave date arithmetic in the operator's zone rather than UTC.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first, so a source-only change does not invalidate this layer.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

COPY config ./config
COPY scripts ./scripts

# Runtime state: audit log, approval queue, runs, and the persisted simulated
# estate. Declared a volume because losing the approval queue across a container
# restart would strand every parked run.
RUN mkdir -p /app/data && useradd --create-home --uid 10001 iamagent \
    && chown -R iamagent:iamagent /app
VOLUME ["/app/data"]

USER iamagent

# 0.0.0.0 is the configured default; stated here so the container is reachable
# from outside regardless of what .env says.
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status==200 else 1)"

ENTRYPOINT ["iam-agent"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
