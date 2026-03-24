"""
Adaptive strategy detector.

For each (host, port) it tries strategies in order and remembers which one
succeeded.  Results are persisted to a JSON file so they survive restarts.
"""
import json
import logging
import os
import socket
import threading
import time
from typing import Optional

from bypass.config import Config
from bypass.strategies import STRATEGIES, AUTO_PROBE_ORDER, strategy_direct

log = logging.getLogger(__name__)

# How long a probe connection is given to succeed (seconds)
PROBE_TIMEOUT = 4.0
# Probe handshake: send this and expect any data back within timeout
PROBE_TLS_HELLO = bytes.fromhex(
    "160301"        # TLS 1.0 record header (type=handshake, version)
    "00f1"          # record length placeholder
    "01"            # handshake type: ClientHello
    "0000ed"        # handshake length
    "0303"          # TLS 1.2
    + "00" * 32     # random
    + "00"          # session id length
    "0022"          # cipher suites length
    "c02bc02cc02fc030cca9cca8c013c014009c009d002f0035000a"
    "0100"          # compression methods
    "0000"          # extensions length = 0 (no SNI — just check TCP connectivity)
)


class StrategyDetector:
    def __init__(self, config: Config):
        self.config = config
        self._cache: dict[str, str] = {}
        self._lock = threading.Lock()
        self._load_cache()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def best_strategy(self, host: str, port: int) -> str:
        """
        Return the name of the best known strategy for this host:port.
        If none is known and config.strategy == 'auto', runs probing.
        """
        if self.config.strategy != "auto":
            return self.config.strategy

        key = f"{host}:{port}"
        with self._lock:
            cached = self._cache.get(key)
        if cached:
            log.debug("detector: cache hit %s -> %s", key, cached)
            return cached

        best = self._probe(host, port)
        with self._lock:
            self._cache[key] = best
        self._save_cache()
        log.info("detector: %s -> %s (probed)", key, best)
        return best

    def invalidate(self, host: str, port: int) -> None:
        """Remove cached entry so it gets re-probed next time."""
        key = f"{host}:{port}"
        with self._lock:
            self._cache.pop(key, None)
        self._save_cache()

    # ------------------------------------------------------------------
    # Probing
    # ------------------------------------------------------------------

    def _probe(self, host: str, port: int) -> str:
        """Try strategies in AUTO_PROBE_ORDER, return first that connects."""
        for name in AUTO_PROBE_ORDER:
            if self._try_strategy(name, host, port):
                return name
        log.warning("detector: all strategies failed for %s:%d, using direct", host, port)
        return "direct"

    def _try_strategy(self, name: str, host: str, port: int) -> bool:
        """
        Open a fresh TCP connection, apply strategy with a probe payload,
        check that we get any response bytes back.
        Returns True on success.
        """
        try:
            sock = socket.create_connection((host, port), timeout=PROBE_TIMEOUT)
            sock.settimeout(PROBE_TIMEOUT)
            try:
                fn = STRATEGIES[name]
                # Use a minimal TLS-like hello as probe payload
                fn(sock, PROBE_TLS_HELLO, self.config)
                # Any response at all means the connection wasn't blocked
                data = sock.recv(16)
                if data:
                    log.debug("detector: strategy %s succeeded for %s:%d", name, host, port)
                    return True
            finally:
                sock.close()
        except Exception as e:
            log.debug("detector: strategy %s failed for %s:%d: %s", name, host, port, e)
        return False

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load_cache(self) -> None:
        path = self.config.cache_file
        if not os.path.exists(path):
            return
        try:
            with open(path, "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._cache = data
                log.debug("detector: loaded %d cached entries from %s", len(data), path)
        except Exception as e:
            log.warning("detector: failed to load cache: %s", e)

    def _save_cache(self) -> None:
        path = self.config.cache_file
        try:
            with self._lock:
                snapshot = dict(self._cache)
            with open(path, "w") as f:
                json.dump(snapshot, f, indent=2)
        except Exception as e:
            log.warning("detector: failed to save cache: %s", e)
