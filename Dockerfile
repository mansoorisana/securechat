FROM python:3.11-slim

WORKDIR /app
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# install Python deps first
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy your app code
COPY . .

# bring in your slim wallet
COPY wallet.tar.gz /tmp/wallet.tar.gz

# extract it into your TNS_ADMIN directory
RUN mkdir -p /app/Wallet_securechatDB && \
    tar -xzf /tmp/wallet.tar.gz -C /app/Wallet_securechatDB

ENV TNS_ADMIN=/app/Wallet_securechatDB

EXPOSE 10000

ENTRYPOINT [ "uvicorn", "websocket:app", "--host", "0.0.0.0", "--port", "10000" ]
