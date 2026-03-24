"""Configuration for LocalBypass."""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Config:
    # Proxy listen settings
    host: str = "127.0.0.1"
    port: int = 8080

    # Strategy: auto | direct | tls_split | tls_fragment | http_split | disorder
    strategy: str = "auto"

    # For fragment-based strategies: size of first chunk in bytes
    fragment_size: int = 2

    # Timeout for a single connection attempt during probing (seconds)
    probe_timeout: float = 5.0

    # File to persist successful strategies across restarts
    cache_file: str = "strategy_cache.json"

    # Max threads for the proxy server
    max_threads: int = 256

    # Log level override per request
    verbose: bool = False

    # Delay between fragments in seconds (0 = no delay)
    fragment_delay: float = 0.0
