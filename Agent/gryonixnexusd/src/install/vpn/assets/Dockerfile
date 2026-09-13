FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard-tools iproute2 iptables qrencode ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask==3.0.3
COPY app.py /app/app.py
COPY index.html /app/index.html
COPY login.html /app/login.html
COPY reset.html /app/reset.html
WORKDIR /app
CMD ["python", "app.py"]
