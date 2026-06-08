FROM python:3.12-slim AS builder
WORKDIR /build
COPY . .
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.12-slim
LABEL org.opencontainers.image.title="cognis-aegis"
LABEL org.opencontainers.image.description="AEGIS — AI Agent Permission & Access Auditor (Cognis Neural Suite)"
LABEL org.opencontainers.image.source="https://github.com/cognis-digital/aegis"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="Cognis Digital"
LABEL org.opencontainers.image.url="https://cognis.digital"

WORKDIR /work
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl[mcp,web,yaml]
EXPOSE 8000
ENTRYPOINT ["aegis"]
CMD ["--help"]
