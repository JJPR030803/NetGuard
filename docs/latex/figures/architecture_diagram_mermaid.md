graph TD
    subgraph "Network Security Suite"
        PS[Packet Sniffer Module] --> |1. Capture packets| PS
        PS --> |2. Extract metadata| DB[(Database)]
        PS --> |3. Forward for analysis| AE[Analysis Engine]
        AE --> |4. Analyze based on rules| AE
        AE --> |5. Forward for ML analysis| ML[Machine Learning Module]
        ML --> |6. Detect anomalies| ML
        ML --> |7. Store results| DB
        AE --> |Store analysis results| DB
        API[API Layer] --> |8. Access data| DB
        API --> |Provide data| FD[Frontend Dashboard]
        FD --> |User interaction| FD
    end

    subgraph "External Systems"
        NET[Network Traffic] --> PS
        EXT[External Applications] --> API
    end

    subgraph "Deployment Options"
        SD[Standalone Deployment]
        DD[Distributed Deployment]
        CD[Containerized Deployment]
    end

    subgraph "Technology Stack"
        BE[Backend: Python 3.9+]
        PC[Packet Capture: Scapy 2.5.0+]
        AF[API: FastAPI 0.104.1+]
        AS[ASGI: Uvicorn]
        DV[Data Validation: Pydantic 2.5.0+]
        DP[Data Processing: Pandas, NumPy]
        ML_T[ML: Scikit-learn 1.3.0+]
        AP[Async: Asyncio 3.4.3+]
        AU[Auth: JWT, bcrypt]
        ORM[ORM: SQLAlchemy 2.0.0+]
        DM[Migrations: Alembic 1.12.0+]
        FE[Frontend: React]
        DC[Containers: Docker, Docker Compose]
    end

    classDef core fill:#f9f,stroke:#333,stroke-width:2px;
    classDef external fill:#bbf,stroke:#333,stroke-width:1px;
    classDef deployment fill:#bfb,stroke:#333,stroke-width:1px;
    classDef tech fill:#fbb,stroke:#333,stroke-width:1px;
    
    class PS,AE,ML,API,DB,FD core;
    class NET,EXT external;
    class SD,DD,CD deployment;
    class BE,PC,AF,AS,DV,DP,ML_T,AP,AU,ORM,DM,FE,DC tech;