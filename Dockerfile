# syntax=docker/dockerfile:1

# fossa-mcp — single-tenant, read-only FOSSA MCP server.
# See DECISIONS.md for the rationale behind the mcp==1.28.x pin and the
# single-tenant deployment model this image is built around.

ARG PYTHON_BASE=registry.suse.com/bci/python:3.13
ARG UV_VERSION=0.11.32

# ---------------------------------------------------------------------------
# Builder: resolve the locked dependency set and install the project with uv.
# Nothing in this stage ships in the runtime image except the venv and the
# generated third-party license file.
# ---------------------------------------------------------------------------
FROM ${PYTHON_BASE} AS builder

COPY --from=ghcr.io/astral-sh/uv:${UV_VERSION} /uv /uvx /usr/local/bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /build

# Resolve and install dependencies first, from the lockfile alone, so this
# layer is cached independently of application source changes.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# Now install the project itself as a real (non-editable) package — the
# runtime stage ships only /opt/venv, not a copy of ./src to import against.
COPY src/ ./src/
COPY scripts/ ./scripts/
COPY README.md LICENSE NOTICE ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

# Generate the consolidated third-party license file from what's actually
# installed in the venv (see DECISIONS.md §3 — certifi is MPL-2.0).
RUN /opt/venv/bin/python scripts/generate_third_party_licenses.py /build/THIRD_PARTY_LICENSES.txt

# ---------------------------------------------------------------------------
# Runtime: only the venv, source, and license material. No uv, no git, no
# build headers, no dev dependencies.
# ---------------------------------------------------------------------------
FROM ${PYTHON_BASE} AS runtime

ARG BUILD_REVISION=unknown
ARG BUILD_VERSION=0.1.0
ARG BUILD_SOURCE=https://github.com/rashford/fossa-mcp

LABEL org.opencontainers.image.source=${BUILD_SOURCE} \
      org.opencontainers.image.version=${BUILD_VERSION} \
      org.opencontainers.image.revision=${BUILD_REVISION} \
      org.opencontainers.image.licenses=Apache-2.0 \
      org.opencontainers.image.description="Read-only, single-tenant MCP server for the FOSSA API. Unofficial; not affiliated with FOSSA, Inc."

RUN useradd --no-create-home --uid 1000 --shell /usr/sbin/nologin fossa

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY --from=builder --chown=fossa:fossa /opt/venv /opt/venv
COPY --from=builder --chown=fossa:fossa /build/THIRD_PARTY_LICENSES.txt /app/THIRD_PARTY_LICENSES.txt
COPY --chown=fossa:fossa LICENSE NOTICE /app/

USER fossa

# Meaningful only for --transport streamable-http; the stdio path has no
# listening socket to probe, so it is intentionally not health-checked here.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request,os,sys; sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"FOSSA_HTTP_PORT\",\"8000\")}/healthz', timeout=2).status == 200 else 1)"]

ENTRYPOINT ["fossa-mcp"]
CMD ["--transport", "stdio"]
