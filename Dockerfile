FROM python:3.11-slim

# Build tools 
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# future mySQL stuff

# Copy Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your project (client/, uploads/, main.py, etc.)
COPY . .

# Expose the port Uvicorn will listen on
EXPOSE 10000

# Launch via Uvicorn; your FastAPI app is in main.py
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]
