# Architecture Overview

This document provides a high-level overview of the NetGuard system architecture, design patterns, and key architectural decisions.

## System Architecture

```mermaid
graph TD
    A[Network Interface] -->|Raw Packets| B[Packet Capture Engine]
    B -->|Parsed Packets| C[Packet Queue]
    C -->|Structured Data| D[Parquet Storage]
    D -->|Bulk Processing| E[ML Preprocessing]
    E -->|Features| F[Protocol Analyzers]
    F -->|Analysis Results| G[Workflow Engine]
    G -->|Reports| H[API/Dashboard]

    I[YAML Config] -.->|Configure| B
    I -.->|Configure| E

    J[Performance Metrics] -.->|Monitor| B
    J -.->|Monitor| E

    K[Logging System] -.->|Log| B
    K -.->|Log| E
    K -.->|Log| F
```

## Module Architecture

### 1. Sniffer Module

**Purpose**: Real-time packet capture and initial processing

```mermaid
graph LR
    A[Network Interface] --> B[Scapy Sniffer]
    B --> C[Packet Parser]
    C --> D[Packet Queue]
    D --> E[Packet Models]
    E --> F[Parquet Writer]
    F --> G[Storage]

    H[Config] -.-> B
    I[Loggers] -.-> C
    J[Perf Metrics] -.-> D
```

**Key Components**:
- `PacketCapture`: Main capture engine with threading
- `ParquetProcessor`: Efficient columnar storage
- `SnifferConfig`: Configuration management
- `Packet/PacketLayer`: Data models

**Design Patterns**:
- **Producer-Consumer**: Packet queue with threads
- **Builder**: Configuration construction
- **Strategy**: Different capture strategies
- **Observer**: Multi-logger system

### 2. ML Preprocessing Module

**Purpose**: Feature extraction and protocol analysis

```mermaid
graph TD
    A[Parquet Files] --> B[NetworkParquetAnalysis]
    B --> C{Protocol Router}
    C -->|TCP| D[TCP Analyzer]
    C -->|UDP| E[UDP Analyzer]
    C -->|IP| F[IP Analyzer]
    C -->|DNS| G[DNS Analyzer]
    C -->|Others| H[Other Analyzers]

    D --> I[Workflow Engine]
    E --> I
    F --> I
    G --> I
    H --> I

    I --> J[WorkflowReport]
    J --> K[JSON/Dict Output]
```

**Protocol Analyzers**:

| Analyzer | Size | Complexity | Purpose |
|----------|------|------------|---------|
| TCP | 26KB | High | Connection tracking, flags, attacks |
| UDP | 25KB | Medium | Stateless analysis, port scanning |
| IP | 20KB | Medium | Routing, fragmentation, geolocation |
| Flow | 12KB | High | Traffic patterns, sessions |
| Anomaly | 11KB | High | Statistical anomaly detection |
| DNS | 9KB | Medium | Query analysis, tunneling |
| ICMP | 8KB | Low | Ping, traceroute, attacks |
| ARP | 7KB | Low | Address resolution, spoofing |

**Design Patterns**:
- **Strategy**: Different analyzer implementations
- **Template Method**: Base analyzer pattern
- **Factory**: Analyzer selection
- **Facade**: Workflow simplification

### 3. Models Module

**Purpose**: Data structures and validation

```python
# Data Flow
Raw Packet (bytes)
    ↓
Scapy Packet (scapy.Packet)
    ↓
Packet Model (Pydantic)
    ↓
DataFrame Row (Polars/Pandas)
    ↓
Parquet File (storage)
```

**Key Models**:
- `Packet`: Main packet representation
- `PacketLayer`: Protocol layer abstraction
- Database schemas for persistence

**Design Patterns**:
- **Data Transfer Object (DTO)**: Packet models
- **Value Object**: Immutable packet layers
- **Validation**: Pydantic validators

### 4. Utils Module

**Purpose**: Shared utilities and cross-cutting concerns

```mermaid
graph TD
    A[Utils Module] --> B[ConfigBuilder]
    A --> C[PerformanceMetrics]
    A --> D[Logger]

    B --> E[Fluent API]
    C --> F[Timing Decorators]
    D --> G[Structured Logging]

    H[Sniffer] -.uses.-> B
    H -.uses.-> C
    H -.uses.-> D

    I[ML] -.uses.-> C
    I -.uses.-> D
```

**Design Patterns**:
- **Builder**: Fluent configuration API
- **Decorator**: Performance timing
- **Singleton**: Logger instances
- **Adapter**: Logging abstraction

### 5. API Module (Planned)

**Purpose**: External access and integration

```mermaid
graph LR
    A[Client] -->|HTTP/WS| B[FastAPI]
    B --> C[Auth Middleware]
    C --> D[Rate Limiter]
    D --> E{Route Handler}

    E -->|/capture| F[Capture Control]
    E -->|/analyze| G[Analysis Trigger]
    E -->|/reports| H[Report Retrieval]
    E -->|/ws/stream| I[Real-time Stream]

    F --> J[Sniffer Module]
    G --> K[ML Module]
    H --> L[Storage]
    I --> M[WebSocket Manager]
```

**Planned Features**:
- RESTful endpoints
- WebSocket for real-time data
- OAuth2/JWT authentication
- Rate limiting
- API documentation (OpenAPI)

## Data Flow

### Capture Flow

```mermaid
sequenceDiagram
    participant N as Network
    participant S as Sniffer
    participant Q as Queue
    participant P as Processor
    participant D as Disk

    N->>S: Raw packet
    S->>S: Parse with Scapy
    S->>Q: Enqueue packet
    Q->>P: Dequeue packet
    P->>P: Convert to model
    P->>D: Write to Parquet

    Note over S,P: Threaded processing
    Note over D: Batched writes
```

### Analysis Flow

```mermaid
sequenceDiagram
    participant U as User
    participant W as Workflow
    participant A as Analyzer
    participant D as Disk
    participant R as Report

    U->>W: Request analysis
    W->>D: Load Parquet
    D->>W: DataFrame
    W->>A: Analyze(df)
    A->>A: Protocol analysis
    A->>W: Results
    W->>R: Generate report
    R->>U: JSON/Dict

    Note over A: Multiple analyzers
    Note over R: Structured output
```

## Design Principles

### 1. Separation of Concerns

Each module has a clear, single responsibility:
- **Sniffer**: Capture and store
- **ML**: Analyze and extract features
- **Models**: Define data structures
- **Utils**: Provide shared functionality
- **API**: External interface

### 2. Dependency Inversion

High-level modules depend on abstractions:
```python
# Good: Depends on interface
class PacketCapture:
    def __init__(self, config: ConfigInterface):
        self.config = config

# Bad: Depends on concrete class
class PacketCapture:
    def __init__(self, yaml_file: str):
        self.config = YAMLConfig(yaml_file)
```

### 3. Open/Closed Principle

Extensible without modification:
```python
# Add new analyzer without modifying existing code
class CustomAnalyzer(BaseAnalyzer):
    def analyze(self, df: pl.DataFrame) -> dict:
        # Custom implementation
        pass
```

### 4. Performance First

- Use Polars over Pandas for large datasets
- Parquet for efficient storage and columnar access
- Thread-safe queues for concurrent processing
- Memory-bounded deques to prevent OOM

### 5. Configuration Over Code

- YAML files for all settings
- Pydantic validation
- Environment variables support
- No hard-coded values

## Threading Model

### Packet Capture Threading

```python
# Main Thread: Packet capture
Thread 1: sniff(iface, prn=callback)
    ↓
# Worker Thread: Packet processing
Thread 2: process_queue()
    ↓ (queue)
# Background Thread: Periodic flush
Thread 3: flush_to_disk()
```

**Thread Safety**:
- `Queue`: Thread-safe packet queue
- `Lock`: Protects shared state
- `deque`: Atomic operations
- No shared mutable state

### Analysis Threading

ML preprocessing is currently single-threaded but designed for parallelization:

```python
# Future: Parallel analysis
with ProcessPoolExecutor() as executor:
    futures = [
        executor.submit(analyze_tcp, df),
        executor.submit(analyze_udp, df),
        executor.submit(analyze_dns, df),
    ]
```

## Storage Architecture

### Parquet Format

**Advantages**:
- Columnar storage (fast analytics queries)
- Excellent compression (10x smaller than CSV)
- Schema evolution support
- Fast column selection

**Schema**:
```
packet_capture.parquet
├── timestamp: datetime
├── src_ip: str
├── dst_ip: str
├── src_port: int16
├── dst_port: int16
├── protocol: str
├── length: int32
├── flags: str
└── raw_data: binary
```

### Storage Patterns

```mermaid
graph TD
    A[Packet Stream] --> B{Batch Buffer}
    B -->|Every 1000 packets| C[Parquet Write]
    B -->|Every 5 minutes| C
    C --> D[Compressed Parquet]

    E[Analyzer] --> F[Read Parquet]
    F --> G[Lazy Evaluation]
    G --> H[Filter & Transform]
    H --> I[Results]

    style D fill:#90EE90
    style I fill:#87CEEB
```

## Configuration Architecture

### Hierarchical Configuration

```yaml
# System-level
system:
  log_level: INFO
  workers: 4

# Module-level
sniffer:
  interface: eth0
  buffer_size: 1000

ml:
  chunk_size: 100000
  parallel: true

# Feature-level
analyzers:
  tcp:
    track_connections: true
    detect_scans: true
```

### Configuration Loading

```python
# Priority order (highest to lowest)
1. CLI arguments
2. Environment variables (NETGUARD_*)
3. Config file (--config)
4. Defaults in code
```

## Error Handling Architecture

### Error Hierarchy

```python
NetGuardError (base)
├── SnifferError
│   ├── InterfaceError
│   ├── CaptureError
│   └── DataConversionError
├── MLError
│   ├── AnalyzerError
│   ├── WorkflowError
│   └── PreprocessingError
├── ConfigError
│   └── ValidationError
└── StorageError
    ├── ParquetError
    └── FileSystemError
```

### Error Handling Strategy

```python
# Fail fast for configuration
if not config.is_valid():
    raise ConfigError("Invalid configuration")

# Graceful degradation for analysis
try:
    result = analyzer.analyze(df)
except AnalyzerError as e:
    logger.warning(f"Analyzer failed: {e}")
    result = None  # Continue with other analyzers

# Retry for transient failures
@retry(max_attempts=3, backoff=exponential)
def write_parquet(df, path):
    df.write_parquet(path)
```

## Performance Characteristics

### Packet Capture

- **Throughput**: ~10,000 packets/sec (depends on hardware)
- **Memory**: ~100MB for 10k packet buffer
- **Latency**: <1ms packet processing
- **Storage**: ~1GB/hour at 1000 pkt/sec

### ML Analysis

- **Batch Size**: 100k rows optimal
- **Processing Speed**: ~500k rows/sec (Polars)
- **Memory**: ~2GB for 1M packet analysis
- **Parallelization**: Linear scaling up to CPU cores

## Scalability Considerations

### Vertical Scaling

Current architecture supports:
- ✅ Multi-core processing (threading)
- ✅ Large memory datasets (Polars lazy)
- ✅ Fast storage (Parquet compression)

### Horizontal Scaling (Future)

Planned distributed architecture:
```mermaid
graph TD
    A[Capture Agent 1] -->|Kafka| D[Analysis Server]
    B[Capture Agent 2] -->|Kafka| D
    C[Capture Agent 3] -->|Kafka| D

    D --> E[Analysis Worker 1]
    D --> F[Analysis Worker 2]
    D --> G[Analysis Worker 3]

    E --> H[(Shared Storage)]
    F --> H
    G --> H

    H --> I[API Server]
    I --> J[Dashboard]
```

## Security Architecture

### Defense in Depth

1. **Input Validation**: Pydantic models
2. **Type Safety**: MyPy strict mode
3. **Dependency Scanning**: Bandit, pre-commit
4. **Least Privilege**: Capability-based capture
5. **Data Encryption**: Planned for storage
6. **API Authentication**: Planned OAuth2/JWT

### Security Boundaries

```mermaid
graph TD
    A[External Network] -->|Untrusted| B[Packet Capture]
    B -->|Validated| C[Storage]
    C -->|Sanitized| D[Analysis]
    D -->|Filtered| E[API]
    E -->|Authenticated| F[Client]

    style A fill:#ffcccc
    style C fill:#ccffcc
    style F fill:#ccccff
```

## Future Architecture

### Roadmap Components

1. **Distributed Capture**:
   - Multiple capture agents
   - Message queue (Kafka/RabbitMQ)
   - Central coordinator

2. **Real-time Pipeline**:
   - Stream processing (Flink/Spark)
   - In-memory analytics (Redis)
   - WebSocket feeds

3. **ML Integration**:
   - Model training pipeline
   - Online learning
   - Model registry (MLflow)

4. **Monitoring**:
   - Prometheus metrics
   - Grafana dashboards
   - Alert manager

## Conclusion

NetGuard follows **clean architecture principles** with:
- Clear module boundaries
- Dependency inversion
- Testable components
- Performance-first design
- Extensibility without modification

The architecture supports both **current requirements** (single-node capture and analysis) and **future scaling** (distributed, real-time, ML-powered).
