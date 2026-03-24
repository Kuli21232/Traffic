"""
DPI bypass strategies.

Each strategy is a callable:
    apply(sock: socket, data: bytes, config: Config) -> None

It sends `data` to `sock` in a way that confuses DPI while the destination
receives the complete stream intact.
"""
import socket
import time
import logging
from typing import Callable

from bypass.config import Config
from bypass.tls_utils import is_tls_client_hello, find_sni_offset

log = logging.getLogger(__name__)


def _send_all(sock: socket.socket, data: bytes) -> None:
    """Send all bytes, handling partial writes."""
    view = memoryview(data)
    total = 0
    while total < len(data):
        sent = sock.send(view[total:])
        if sent == 0:
            raise ConnectionError("Socket closed during send")
        total += sent


def _enable_nodelay(sock: socket.socket) -> None:
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


# ---------------------------------------------------------------------------
# Strategy: direct
# ---------------------------------------------------------------------------

def strategy_direct(sock: socket.socket, data: bytes, config: Config) -> None:
    """Send data as-is, no manipulation."""
    _send_all(sock, data)


# ---------------------------------------------------------------------------
# Strategy: tls_split
# ---------------------------------------------------------------------------

def strategy_tls_split(sock: socket.socket, data: bytes, config: Config) -> None:
    """
    Split TLS ClientHello at the SNI offset (or at byte 3 as fallback).
    Two TCP segments arrive at DPI instead of one reassembled hello,
    preventing SNI extraction from a single segment.
    """
    _enable_nodelay(sock)

    split_at = config.fragment_size  # default split point

    if is_tls_client_hello(data):
        sni_off = find_sni_offset(data)
        if sni_off and sni_off > 0:
            # Split in the middle of the SNI string
            split_at = sni_off + len(data[sni_off:]) // 2
            log.debug("tls_split: splitting at SNI midpoint offset=%d", split_at)
        else:
            # Fall back: split after TLS record type+version (byte 3)
            split_at = 3

    split_at = max(1, min(split_at, len(data) - 1))
    _send_all(sock, data[:split_at])
    if config.fragment_delay > 0:
        time.sleep(config.fragment_delay)
    _send_all(sock, data[split_at:])


# ---------------------------------------------------------------------------
# Strategy: tls_fragment
# ---------------------------------------------------------------------------

def strategy_tls_fragment(sock: socket.socket, data: bytes, config: Config) -> None:
    """
    Send TLS ClientHello in chunks of `fragment_size` bytes each.
    Very aggressive fragmentation — effective against strict DPI but slower.
    """
    _enable_nodelay(sock)
    size = max(1, config.fragment_size)

    for i in range(0, len(data), size):
        chunk = data[i:i + size]
        _send_all(sock, chunk)
        if config.fragment_delay > 0:
            time.sleep(config.fragment_delay)


# ---------------------------------------------------------------------------
# Strategy: http_split
# ---------------------------------------------------------------------------

def strategy_http_split(sock: socket.socket, data: bytes, config: Config) -> None:
    """
    Split HTTP request so that 'Host:' header is not in the first segment.
    Confuses HTTP-based DPI/SNI blocking.
    """
    _enable_nodelay(sock)

    host_pos = data.lower().find(b"host:")
    if host_pos > 0:
        # Send everything before 'Host:' as first segment
        split_at = host_pos
        log.debug("http_split: splitting before Host header at offset=%d", split_at)
    else:
        # Generic split at fragment_size
        split_at = max(1, min(config.fragment_size, len(data) - 1))

    split_at = max(1, min(split_at, len(data) - 1))
    _send_all(sock, data[:split_at])
    if config.fragment_delay > 0:
        time.sleep(config.fragment_delay)
    _send_all(sock, data[split_at:])


# ---------------------------------------------------------------------------
# Strategy: disorder
# ---------------------------------------------------------------------------

def strategy_disorder(sock: socket.socket, data: bytes, config: Config) -> None:
    """
    Send the first fragment with a low IP TTL so it dies in transit,
    then send the full data normally.  The destination only gets the full
    message; DPI reassembly is disrupted by the ghost first segment.

    NOTE: This strategy requires a raw socket helper and root privileges.
    Falls back to tls_split when privileges are unavailable.
    """
    try:
        _disorder_impl(sock, data, config)
    except PermissionError:
        log.warning("disorder: no permission for raw socket, falling back to tls_split")
        strategy_tls_split(sock, data, config)


def _disorder_impl(sock: socket.socket, data: bytes, config: Config) -> None:
    import struct

    _enable_nodelay(sock)

    # Get peer address from established socket
    peer = sock.getpeername()
    peer_ip = peer[0]
    peer_port = peer[1]

    split_at = max(1, min(config.fragment_size, len(data) - 1))
    first_chunk = data[:split_at]

    # Send the ghost fragment with TTL=1 via raw UDP-like trick:
    # We use IP_TTL socket option on a temporary raw connection.
    raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    raw.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
    try:
        raw.connect((peer_ip, peer_port))
        raw.send(first_chunk)
    except Exception as e:
        log.debug("disorder ghost send failed (expected): %s", e)
    finally:
        raw.close()

    # Small delay so ghost packet is already dead
    time.sleep(0.01)

    # Send full data on the real socket — destination will use this
    _send_all(sock, data)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

STRATEGIES: dict[str, Callable] = {
    "direct":       strategy_direct,
    "tls_split":    strategy_tls_split,
    "tls_fragment": strategy_tls_fragment,
    "http_split":   strategy_http_split,
    "disorder":     strategy_disorder,
}

# Ordered list for auto-probing (fastest/least intrusive first)
AUTO_PROBE_ORDER = ["direct", "tls_split", "http_split", "tls_fragment", "disorder"]
