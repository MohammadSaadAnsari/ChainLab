FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY vnf_configs/common/entrypoint.sh /app/entrypoint.sh
COPY vnf_configs/policer/start.sh /app/start.sh
RUN chmod +x /app/entrypoint.sh /app/start.sh
CMD ["/app/entrypoint.sh"]
