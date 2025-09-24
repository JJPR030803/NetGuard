graph TD
    NET[Network Traffic] --> PS[Packet Sniffer Module]
    PS --> |1. Extract metadata| DB[(Database)]
    PS --> |2. Forward for analysis| AE[Analysis Engine]
    AE --> |3. Analyze based on rules| AE
    AE --> |4. Forward for ML analysis| ML[Machine Learning Module]
    ML --> |5. Detect anomalies| ML
    ML --> |6. Store results| DB
    AE --> |Store analysis results| DB
    API[API Layer] --> |7. Access data| DB
    API --> |8. Provide data| FD[Frontend Dashboard]
    EXT[External Applications] --> API

    classDef core fill:#f9f,stroke:#333,stroke-width:2px;
    classDef external fill:#bbf,stroke:#333,stroke-width:1px;
    
    class PS,AE,ML,API,DB,FD core;
    class NET,EXT external;