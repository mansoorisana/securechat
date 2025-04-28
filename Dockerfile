# official slim Python image
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && \
apt-get install -y --no-install-recommends build-essential && \
rm -rf /var/lib/apt/lists/*

# setting working directory inside container
WORKDIR /app

# copying dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copying app code
COPY . .

# Flask and WebSocket  ports
EXPOSE 5000 8765

# starting main script for server
CMD ["python", "websocket.py"]
