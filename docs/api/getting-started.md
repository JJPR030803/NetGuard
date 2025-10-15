# API Getting Started

This guide will help you get started with the Network Security Suite API.

## Installation

The API is included with the Network Security Suite:

```bash
# Install with API dependencies
uv sync --extras api

# Or with poetry
poetry install --extras api
```

## Starting the Server

### Development Mode

```bash
# Start with auto-reload
uvicorn network_security_suite.api.main:app --reload

# With custom port
uvicorn network_security_suite.api.main:app --reload --port 8080
```

### Production Mode

```bash
# Production server with Gunicorn
gunicorn network_security_suite.api.main:app \
  -w 4 \
  -k uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000
```

## First API Call

### Get API Status

```python
import requests

# Get status
response = requests.get("http://localhost:8000/api/status")
print(response.json())
```

Expected response:
```json
{
  "status": "online",
  "version": "1.0.0",
  "uptime": 3600
}
```

### Check API Health

```bash
curl http://localhost:8000/api/health
```

## Authentication

### Using API Key

```python
import requests
import os

API_KEY = os.getenv("NETGUARD_API_KEY")
headers = {"X-API-Key": API_KEY}

response = requests.get(
    "http://localhost:8000/api/capture/status",
    headers=headers
)
```

### Environment Variables

```bash
export NETGUARD_API_KEY="your-api-key-here"
```

## Common Operations

### Start Packet Capture

```python
import requests

# Configure capture
config = {
    "interface": "eth0",
    "packet_count": 1000,
    "filter": "tcp port 80",
    "output_file": "capture.parquet"
}

# Start capture
response = requests.post(
    "http://localhost:8000/api/capture/start",
    json=config
)

capture_id = response.json()["capture_id"]
print(f"Capture started: {capture_id}")
```

### Check Capture Status

```python
# Get status
response = requests.get(
    f"http://localhost:8000/api/capture/status/{capture_id}"
)

status = response.json()
print(f"Status: {status['state']}")
print(f"Packets: {status['packets_captured']}")
```

### Stop Capture

```python
# Stop capture
response = requests.post(
    f"http://localhost:8000/api/capture/stop/{capture_id}"
)

print(response.json())
```

### Get Captured Packets

```python
# Get packets
response = requests.get(
    "http://localhost:8000/api/packets",
    params={"limit": 10}
)

packets = response.json()["packets"]
for packet in packets:
    print(f"{packet['src_ip']} -> {packet['dst_ip']}")
```

## Error Handling

### Handle HTTP Errors

```python
import requests

try:
    response = requests.post(url, json=data)
    response.raise_for_status()
    result = response.json()
except requests.exceptions.HTTPError as e:
    print(f"HTTP error: {e}")
except requests.exceptions.ConnectionError:
    print("Connection failed")
except requests.exceptions.Timeout:
    print("Request timeout")
```

### Check Response Status

```python
response = requests.get(url)

if response.status_code == 200:
    data = response.json()
elif response.status_code == 404:
    print("Resource not found")
elif response.status_code == 401:
    print("Unauthorized")
else:
    print(f"Error: {response.status_code}")
```

## Interactive API Documentation

Visit the interactive API documentation:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

These provide:
- Complete API reference
- Try it out functionality
- Request/response examples
- Schema definitions

## Next Steps

- Explore [API endpoints](endpoints.md)
- See more [examples](examples.md)
- Read the [API reference](index.md)
