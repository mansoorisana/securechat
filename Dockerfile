FROM python:3.11-slim


WORKDIR /app

# env declaration
ENV TNS_ADMIN=/app/Wallet_securechatDB

# Oracle client deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential && \
    rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

EXPOSE 10000

# gets path to db 
ENTRYPOINT [ "sh", "-c", "\
    mkdir -p \"$TNS_ADMIN\" && \
    echo \"$WALLET_B64\" | base64 -d | tar -xz -C \"$TNS_ADMIN\" && \
    exec \"$@\"\
", "--" ]

# Default command
CMD ["uvicorn", "websocket:app", "--host", "0.0.0.0", "--port", "10000"]
