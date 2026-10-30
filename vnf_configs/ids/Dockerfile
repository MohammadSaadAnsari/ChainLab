FROM python:3.11-slim-bookworm

RUN pip install --no-cache-dir scapy==2.6.1
COPY vnf_configs/common/entrypoint.sh /app/entrypoint.sh
COPY vnf_configs/ids/start.sh /app/start.sh
COPY vnf_configs/ids/ids.py /app/ids.py
COPY vnf_configs/ids/signature.py /app/signature.py
RUN chmod +x /app/entrypoint.sh /app/start.sh
CMD ["/app/entrypoint.sh"]
