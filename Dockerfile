FROM python:3.11-slim
WORKDIR /app

# install Python + TLS
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# copy & unpack your slim wallet right into TNS_ADMIN
ENV TNS_ADMIN=/app/Wallet_securechatDB
COPY slim_wallet.tar.gz.b64 /tmp/slim_wallet.b64
RUN mkdir -p "$TNS_ADMIN" \
 && base64 -d /tmp/slim_wallet.b64 | tar -xz -C "$TNS_ADMIN"

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# rest of your code
COPY . .

EXPOSE 10000
CMD ["uvicorn", "websocket:app", "--host", "0.0.0.0", "--port", "10000"]