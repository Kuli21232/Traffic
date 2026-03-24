"""TLS ClientHello parsing utilities for DPI bypass."""
import struct


# TLS record content types
TLS_HANDSHAKE = 0x16
TLS_HANDSHAKE_CLIENT_HELLO = 0x01

# SNI extension type
EXT_SERVER_NAME = 0x0000


def is_tls_client_hello(data: bytes) -> bool:
    """Return True if data starts with a TLS ClientHello record."""
    if len(data) < 9:
        return False
    content_type = data[0]
    handshake_type = data[5]
    return content_type == TLS_HANDSHAKE and handshake_type == TLS_HANDSHAKE_CLIENT_HELLO


def extract_sni(data: bytes) -> str | None:
    """Extract SNI hostname from a TLS ClientHello record, or None."""
    if not is_tls_client_hello(data):
        return None
    try:
        # Skip: TLS record header (5) + handshake header (4) + version (2) + random (32)
        pos = 5 + 4 + 2 + 32
        if pos >= len(data):
            return None

        # Session ID
        session_id_len = data[pos]
        pos += 1 + session_id_len

        # Cipher suites
        cipher_len = struct.unpack("!H", data[pos:pos+2])[0]
        pos += 2 + cipher_len

        # Compression methods
        comp_len = data[pos]
        pos += 1 + comp_len

        # Extensions
        if pos + 2 > len(data):
            return None
        ext_total = struct.unpack("!H", data[pos:pos+2])[0]
        pos += 2
        end = pos + ext_total

        while pos + 4 <= end:
            ext_type = struct.unpack("!H", data[pos:pos+2])[0]
            ext_len  = struct.unpack("!H", data[pos+2:pos+4])[0]
            pos += 4
            if ext_type == EXT_SERVER_NAME:
                # server_name_list_length (2) + name_type (1) + name_length (2) + name
                if pos + 5 > end:
                    break
                sni_list_len = struct.unpack("!H", data[pos:pos+2])[0]
                name_type    = data[pos+2]
                name_len     = struct.unpack("!H", data[pos+3:pos+5])[0]
                if name_type == 0:  # host_name
                    return data[pos+5:pos+5+name_len].decode("utf-8", errors="ignore")
            pos += ext_len
    except Exception:
        pass
    return None


def find_sni_offset(data: bytes) -> int | None:
    """Return byte offset where SNI hostname starts inside data, or None."""
    if not is_tls_client_hello(data):
        return None
    try:
        pos = 5 + 4 + 2 + 32
        session_id_len = data[pos]; pos += 1 + session_id_len
        cipher_len = struct.unpack("!H", data[pos:pos+2])[0]; pos += 2 + cipher_len
        comp_len = data[pos]; pos += 1 + comp_len
        if pos + 2 > len(data): return None
        ext_total = struct.unpack("!H", data[pos:pos+2])[0]
        pos += 2
        end = pos + ext_total
        while pos + 4 <= end:
            ext_type = struct.unpack("!H", data[pos:pos+2])[0]
            ext_len  = struct.unpack("!H", data[pos+2:pos+4])[0]
            pos += 4
            if ext_type == EXT_SERVER_NAME:
                return pos + 5  # start of hostname bytes
            pos += ext_len
    except Exception:
        pass
    return None
