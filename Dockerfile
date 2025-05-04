FROM python:3.11-slim


WORKDIR /app

#importats b64 db wallet blob
COPY db_wallet.tar.gz.b64 /tmp/db_wallet.tar.gz.b64

#decodes 
RUN mkdir -p /app/Wallet_securechatDB && \
    base64 -d /tmp/db_wallet.tar.gz.b64 \
      | tar -xz --strip-components=1 -C /app/Wallet_securechatDB

# env declaration
ENV TNS_ADMIN=/app/Wallet_securechatDB


# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

EXPOSE 10000

# Default command
CMD ["uvicorn", "websocket:app", "--host", "0.0.0.0", "--port", "10000"]
