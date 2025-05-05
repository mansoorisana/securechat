FROM python:3.11-slim

WORKDIR /app


RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV TNS_ADMIN=/app/Wallet_securechatDB

# python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


COPY . .

EXPOSE 10000


ENTRYPOINT [ "sh", "-c", "\
    mkdir -p \"$TNS_ADMIN\" && \
    echo \"$WALLET_B64\" | base64 -d | tar -xz -C \"$TNS_ADMIN\" && \
    exec \"$@\"\
", "--" ]

CMD ["uvicorn", "websocket:app", "--host", "0.0.0.0", "--port", "10000"]