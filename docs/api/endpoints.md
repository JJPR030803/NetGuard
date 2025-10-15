# API Endpoints Reference

Complete reference for all API endpoints.

## Status Endpoints

### GET /api/status

Get API server status.

**Response:**
```json
{
  "status": "online",
  "version": "1.0.0",
  "uptime": 3600
}
```

### GET /api/health

Health check endpoint.

**Response:**
```json
{
  "healthy": true
}
```

## Capture Endpoints

### POST /api/capture/start

Start a new packet capture.

**Request:**
```json
{
  "interface": "eth0",
  "packet_count": 1000,
  "filter": "tcp port 80",
  "output_file": "capture.parquet"
}
```

**Response:**
```json
{
  "capture_id": "abc123",
  "status": "started"
}
```

### POST /api/capture/stop/{capture_id}

Stop an active capture.

**Response:**
```json
{
  "capture_id": "abc123",
  "status": "stopped",
  "packets_captured": 856
}
```

### GET /api/capture/status/{capture_id}

Get capture status.

**Response:**
```json
{
  "capture_id": "abc123",
  "state": "running",
  "packets_captured": 500,
  "start_time": "2024-01-15T10:30:00Z"
}
```

### GET /api/capture/statistics/{capture_id}

Get detailed capture statistics.

**Response:**
```json
{
  "capture_id": "abc123",
  "packets_captured": 1000,
  "packets_dropped": 5,
  "bytes_captured": 500000,
  "protocols": {
    "TCP": 800,
    "UDP": 150,
    "ICMP": 50
  }
}
```

## Packet Endpoints

### GET /api/packets

Get captured packets with pagination.

**Query Parameters:**
- `limit`: Number of packets (default: 100)
- `offset`: Offset for pagination (default: 0)
- `protocol`: Filter by protocol
- `src_ip`: Filter by source IP
- `dst_ip`: Filter by destination IP

**Response:**
```json
{
  "packets": [...],
  "total": 1000,
  "limit": 100,
  "offset": 0
}
```

### GET /api/packets/{packet_id}

Get specific packet details.

**Response:**
```json
{
  "id": "pkt_123",
  "timestamp": "2024-01-15T10:30:00Z",
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "protocol": "TCP",
  "length": 1500
}
```

## Analysis Endpoints

### POST /api/analysis/run

Run analysis on captured data.

**Request:**
```json
{
  "capture_id": "abc123",
  "analysis_type": "threat_detection",
  "parameters": {
    "threshold": 0.8
  }
}
```

**Response:**
```json
{
  "analysis_id": "analysis_456",
  "status": "queued"
}
```

### GET /api/analysis/results/{analysis_id}

Get analysis results.

**Response:**
```json
{
  "analysis_id": "analysis_456",
  "status": "completed",
  "results": {
    "threats_detected": 3,
    "anomalies": 5
  }
}
```

## See Also

- [Getting Started](getting-started.md)
- [API Overview](index.md)
