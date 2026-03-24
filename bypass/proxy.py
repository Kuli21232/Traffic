"""
LocalBypass HTTP/HTTPS proxy server.

Supports:
  - CONNECT tunnelling (HTTPS, any TCP)
  - Plain HTTP forwarding with Host-based bypass

For each connection the proxy:
  1. Parses the request.
  2. Asks StrategyDetector for the best known bypass strategy.
  3. Opens a TCP connection to the target.
  4. Applies the strategy to the first client→server chunk.
  5. Relays the rest of the traffic transparently.
"""
import logging
import socket
import threading
from typing import Optional

from bypass.config import Config
from bypass.detector import StrategyDetector
from bypass.relay import relay
from bypass.strategies import STRATEGIES, strategy_direct

log = logging.getLogger(__name__)

CONNECT_OK = b"HTTP/1.1 200 Connection established\r\n\r\n"
CONNECT_ERR = b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
READ_TIMEOUT = 30.0
CHUNK = 65536


class BypassProxy:
    def __init__(self, host: str, port: int, config: Config):
        self.host = host
        self.port = port
        self.config = config
        self.detector = StrategyDetector(config)
        self._server_sock: Optional[socket.socket] = None

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(256)
        log.info("Proxy listening on %s:%d", self.host, self.port)

        while True:
            try:
                client, addr = self._server_sock.accept()
            except KeyboardInterrupt:
                break
            except Exception as e:
                log.error("accept error: %s", e)
                continue

            t = threading.Thread(
                target=self._handle,
                args=(client, addr),
                daemon=True,
            )
            t.start()

    # ------------------------------------------------------------------
    # Connection handler
    # ------------------------------------------------------------------

    def _handle(self, client: socket.socket, addr: tuple) -> None:
        client.settimeout(READ_TIMEOUT)
        try:
            # Read the initial HTTP request line + headers
            header_data = self._recv_headers(client)
            if not header_data:
                return

            first_line = header_data.split(b"\r\n")[0].decode("utf-8", errors="replace")
            parts = first_line.split()
            if len(parts) < 3:
                return

            method, target, version = parts[0], parts[1], parts[2]

            if method.upper() == "CONNECT":
                self._handle_connect(client, target)
            else:
                self._handle_http(client, method, target, version, header_data)
        except Exception as e:
            log.debug("handler error from %s: %s", addr, e)
        finally:
            try:
                client.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # CONNECT (HTTPS / any TCP tunnel)
    # ------------------------------------------------------------------

    def _handle_connect(self, client: socket.socket, target: str) -> None:
        host, _, port_str = target.rpartition(":")
        port = int(port_str) if port_str.isdigit() else 443

        strategy_name = self.detector.best_strategy(host, port)
        log.info("CONNECT %s:%d via %s", host, port, strategy_name)

        server = self._connect_target(host, port)
        if server is None:
            client.sendall(CONNECT_ERR)
            return

        # Acknowledge the tunnel
        client.sendall(CONNECT_OK)

        # Read first client→server chunk (TLS ClientHello or first app data)
        client.settimeout(READ_TIMEOUT)
        try:
            first_chunk = client.recv(CHUNK)
        except Exception:
            server.close()
            return

        if not first_chunk:
            server.close()
            return

        # Apply DPI bypass strategy to the first chunk
        try:
            strategy_fn = STRATEGIES.get(strategy_name, strategy_direct)
            strategy_fn(server, first_chunk, self.config)
        except Exception as e:
            log.warning("strategy %s failed for %s:%d: %s — invalidating cache",
                        strategy_name, host, port, e)
            self.detector.invalidate(host, port)
            server.close()
            return

        # Relay the rest transparently
        relay(client, server)
        server.close()

    # ------------------------------------------------------------------
    # Plain HTTP forwarding
    # ------------------------------------------------------------------

    def _handle_http(
        self,
        client: socket.socket,
        method: str,
        target: str,
        version: str,
        header_data: bytes,
    ) -> None:
        # Parse host and path from absolute URL (http://host/path)
        if target.startswith("http://"):
            target = target[7:]
        host_path = target.split("/", 1)
        host_port = host_path[0]
        path = "/" + host_path[1] if len(host_path) > 1 else "/"

        if ":" in host_port:
            host, port_str = host_port.rsplit(":", 1)
            port = int(port_str)
        else:
            host = host_port
            port = 80

        strategy_name = self.detector.best_strategy(host, port)
        log.info("HTTP %s %s:%d via %s", method, host, port, strategy_name)

        server = self._connect_target(host, port)
        if server is None:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        # Rebuild request with relative path
        lines = header_data.split(b"\r\n")
        lines[0] = f"{method} {path} {version}".encode()
        rebuilt = b"\r\n".join(lines)

        try:
            strategy_fn = STRATEGIES.get(strategy_name, strategy_direct)
            strategy_fn(server, rebuilt, self.config)
        except Exception as e:
            log.warning("strategy failed: %s", e)
            server.close()
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        relay(client, server)
        server.close()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _connect_target(self, host: str, port: int) -> Optional[socket.socket]:
        try:
            sock = socket.create_connection((host, port), timeout=self.config.probe_timeout)
            sock.settimeout(READ_TIMEOUT)
            return sock
        except Exception as e:
            log.warning("cannot connect to %s:%d: %s", host, port, e)
            return None

    @staticmethod
    def _recv_headers(sock: socket.socket) -> bytes:
        """Read HTTP headers (up to the blank line) from socket."""
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                return b""
            buf += chunk
            if len(buf) > 65536:  # sanity limit
                return b""
        return buf
