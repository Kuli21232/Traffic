"""
Bidirectional socket relay with optional obfuscation layer.

After the first DPI-bypassed chunk is sent, traffic is relayed transparently
in both directions using two threads.
"""
import logging
import select
import socket
import threading

log = logging.getLogger(__name__)

CHUNK = 65536  # relay buffer size


def relay(client: socket.socket, server: socket.socket) -> None:
    """
    Relay bytes between client <-> server until one side closes.
    Runs two threads (one per direction) that terminate together.
    """
    done = threading.Event()

    def pipe(src: socket.socket, dst: socket.socket, label: str) -> None:
        try:
            while not done.is_set():
                ready, _, _ = select.select([src], [], [], 1.0)
                if not ready:
                    continue
                data = src.recv(CHUNK)
                if not data:
                    break
                _send_all(dst, data)
        except Exception as e:
            log.debug("relay %s: %s", label, e)
        finally:
            done.set()

    t1 = threading.Thread(target=pipe, args=(client, server, "client→server"), daemon=True)
    t2 = threading.Thread(target=pipe, args=(server, client, "server→client"), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def _send_all(sock: socket.socket, data: bytes) -> None:
    view = memoryview(data)
    total = 0
    while total < len(data):
        sent = sock.send(view[total:])
        if sent == 0:
            raise ConnectionError("socket closed")
        total += sent
