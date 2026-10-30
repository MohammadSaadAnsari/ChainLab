FROM python:3.10-slim-bookworm

# Ryu 4.34's setup.py needs the legacy easy_install helper. Build in an
# isolated Python 3.10 image rather than changing the host's Python packages.
RUN pip install --no-cache-dir 'setuptools==57.5.0' wheel \
    && pip install --no-cache-dir --no-build-isolation \
       'ryu==4.34' 'eventlet==0.41.3'

WORKDIR /app
COPY sfc_controller.py sfc_policy.py ryu_bootstrap.py dashboard.html /app/
ENV PYTHONPATH=/app
CMD ["python3", "ryu_bootstrap.py", "--ofp-tcp-listen-port", "6633", \
     "--wsapi-host", "0.0.0.0", "--wsapi-port", "8080", \
     "/app/sfc_controller.py"]
