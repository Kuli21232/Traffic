"""Integration test: proxy correctly tunnels a CONNECT request."""
import socket
import threading
import time
import unittest

from bypass.config import Config
from bypass.proxy import BypassProxy


def find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestConnectTunnel(unittest.TestCase):
    """Start proxy + echo server, verify CONNECT tunnel works end-to-end."""

    def setUp(self):
        # Echo server
        self.echo_port = find_free_port()
        self.echo_data: list[bytes] = []
        self._start_echo()

        # Proxy
        self.proxy_port = find_free_port()
        cfg = Config(
            host="127.0.0.1",
            port=self.proxy_port,
            strategy="direct",  # no bypass needed for loopback
            probe_timeout=2.0,
            cache_file="/tmp/test_strategy_cache.json",
        )
        self.proxy = BypassProxy("127.0.0.1", self.proxy_port, cfg)
        self._proxy_thread = threading.Thread(target=self.proxy.start, daemon=True)
        self._proxy_thread.start()
        time.sleep(0.1)  # let server bind

    def _start_echo(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.echo_port))
        srv.listen(4)
        self._echo_srv = srv

        def serve():
            while True:
                try:
                    conn, _ = srv.accept()
                except Exception:
                    break
                threading.Thread(target=self._echo_conn, args=(conn,), daemon=True).start()

        threading.Thread(target=serve, daemon=True).start()

    def _echo_conn(self, conn):
        try:
            conn.settimeout(2.0)
            data = conn.recv(4096)
            if data:
                self.echo_data.append(data)
                conn.sendall(b"ECHO:" + data)
        except Exception:
            pass
        finally:
            conn.close()

    def test_connect_tunnel(self):
        client = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5)
        client.settimeout(5)

        # Send CONNECT
        connect_req = f"CONNECT 127.0.0.1:{self.echo_port} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        client.sendall(connect_req.encode())

        # Read 200 response
        resp = b""
        while b"\r\n\r\n" not in resp:
            resp += client.recv(256)
        self.assertIn(b"200", resp)

        # Send payload through tunnel
        payload = b"Hello from test"
        client.sendall(payload)

        # Read echo
        echoed = client.recv(128)
        client.close()

        self.assertEqual(echoed, b"ECHO:" + payload)

    def tearDown(self):
        try:
            self._echo_srv.close()
        except Exception:
            pass


if __name__ == "__main__":
    unittest.main()
