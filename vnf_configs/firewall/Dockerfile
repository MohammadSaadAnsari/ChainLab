FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends nftables \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir scapy==2.6.1
COPY vnf_configs/common/entrypoint.sh /app/entrypoint.sh
COPY vnf_configs/firewall/start.sh /app/start.sh
COPY vnf_configs/firewall/rules.nft /app/rules.nft
COPY vnf_configs/firewall/observe.py /app/observe.py
RUN chmod +x /app/entrypoint.sh /app/start.sh
CMD ["/app/entrypoint.sh"]
