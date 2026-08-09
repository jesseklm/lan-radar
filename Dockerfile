FROM python:3.14-alpine AS builder
ADD https://astral.sh/uv/0.12.3/install.sh /uv-installer.sh
RUN sh /uv-installer.sh
ENV PATH="/root/.local/bin/:$PATH"
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
ENV UV_NO_DEV=1
ENV UV_PYTHON_DOWNLOADS=0
COPY --exclude=.git/ --exclude=.venv/ . /app
WORKDIR /app
RUN uv sync --locked

FROM python:3.14-alpine
COPY --from=builder /app /app
RUN apk add --no-cache libpcap
ARG BUILD_VERSION=0.0.1
ARG BUILD_ARCH=amd64
LABEL io.hass.version="${BUILD_VERSION}" io.hass.type="app" io.hass.arch="${BUILD_ARCH}"
ENV PATH="/app/.venv/bin:$PATH"
WORKDIR /data
EXPOSE 8099
CMD ["python", "/app/lan_radar.py"]
