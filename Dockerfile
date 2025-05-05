FROM python:3.11-slim


WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*
  
# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

EXPOSE 10000

# Default command
CMD ["uvicorn", "websocket:app", "--host", "0.0.0.0", "--port", "10000"]
