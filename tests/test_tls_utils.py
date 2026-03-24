"""Unit tests for TLS ClientHello parsing."""
import struct
import unittest
from bypass.tls_utils import is_tls_client_hello, extract_sni, find_sni_offset


def build_client_hello(sni: str) -> bytes:
    """Build a minimal TLS 1.2 ClientHello with the given SNI."""
    sni_bytes = sni.encode()
    sni_ext = (
        b"\x00\x00"                              # ext type: server_name
        + struct.pack("!H", len(sni_bytes) + 5) # ext length
        + struct.pack("!H", len(sni_bytes) + 3) # server_name_list length
        + b"\x00"                                # name_type: host_name
        + struct.pack("!H", len(sni_bytes))     # name length
        + sni_bytes
    )
    extensions = struct.pack("!H", len(sni_ext)) + sni_ext

    body = (
        b"\x03\x03"       # version TLS 1.2
        + b"\x00" * 32    # random
        + b"\x00"         # session id length
        + b"\x00\x02"     # cipher suites length
        + b"\xc0\x2b"     # one cipher suite
        + b"\x01\x00"     # compression methods
        + extensions
    )

    hs_header = b"\x01" + struct.pack("!I", len(body))[1:]  # type + 3-byte length
    record = b"\x16\x03\x01" + struct.pack("!H", len(hs_header) + len(body)) + hs_header + body
    return record


class TestTlsUtils(unittest.TestCase):
    def setUp(self):
        self.hello = build_client_hello("example.com")

    def test_is_client_hello(self):
        self.assertTrue(is_tls_client_hello(self.hello))

    def test_not_client_hello_random(self):
        self.assertFalse(is_tls_client_hello(b"\x00" * 20))

    def test_extract_sni(self):
        self.assertEqual(extract_sni(self.hello), "example.com")

    def test_extract_sni_various(self):
        for hostname in ["google.com", "sub.domain.example.org", "x.io"]:
            hello = build_client_hello(hostname)
            self.assertEqual(extract_sni(hello), hostname)

    def test_find_sni_offset(self):
        offset = find_sni_offset(self.hello)
        self.assertIsNotNone(offset)
        sni = "example.com"
        self.assertEqual(self.hello[offset:offset + len(sni)], sni.encode())

    def test_extract_sni_too_short(self):
        self.assertIsNone(extract_sni(b"\x16\x03\x01"))


class TestStrategySmoke(unittest.TestCase):
    """Smoke-test strategies against a loopback echo server."""

    def _echo_server(self):
        import socket, threading
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        received = []

        def serve():
            conn, _ = srv.accept()
            data = b""
            conn.settimeout(1.0)
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except Exception:
                pass
            received.append(data)
            conn.close()
            srv.close()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        return port, received, t

    def _run_strategy(self, name: str, payload: bytes):
        import socket
        from bypass.config import Config
        from bypass.strategies import STRATEGIES

        port, received, t = self._echo_server()
        sock = socket.create_connection(("127.0.0.1", port), timeout=2)
        STRATEGIES[name](sock, payload, Config())
        sock.close()
        t.join(timeout=2)
        return received[0] if received else b""

    def test_direct_delivers_full_payload(self):
        data = b"Hello, world!"
        result = self._run_strategy("direct", data)
        self.assertEqual(result, data)

    def test_tls_split_delivers_full_payload(self):
        hello = build_client_hello("test.example.com")
        result = self._run_strategy("tls_split", hello)
        self.assertEqual(result, hello)

    def test_tls_fragment_delivers_full_payload(self):
        hello = build_client_hello("test.example.com")
        result = self._run_strategy("tls_fragment", hello)
        self.assertEqual(result, hello)

    def test_http_split_delivers_full_payload(self):
        req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result = self._run_strategy("http_split", req)
        self.assertEqual(result, req)


if __name__ == "__main__":
    unittest.main()
