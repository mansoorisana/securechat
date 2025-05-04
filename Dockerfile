FROM python:3.11-slim

# Oracle client deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      libaio1 \
      unzip \
      build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# gets db env path 
ENV TNS_ADMIN=/app/Wallet_securechatDB

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

EXPOSE 10000

# gets oracle db 
ENTRYPOINT [ "sh", "-c", "\
    mkdir -p \"$TNS_ADMIN\" && \
    echo \"$WALLET_B64\" | base64 -d | tar -xz -C \"$TNS_ADMIN\" && \
    exec \"$@\"\
", "--" ]

# default run command
CMD ["uvicorn", "websocket:app", "--host", "0.0.0.0", "--port", "10000"]
