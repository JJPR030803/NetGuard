from typing_extensions import Set
from dataclasses import dataclass, field


@dataclass
class AnalysisConfig:
    time_window: str = "1m"
    min_packets_threshold: int = 100
    protocols: Set[str] = field(default_factory=lambda: {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"})


if __name__ == "__main__":
    config = AnalysisConfig()
    print(config.min_packets_threshold)
    print(config.protocols)
