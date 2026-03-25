package com.localbypass

import android.util.Log
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

private const val TAG = "BypassProxy"
private const val READ_TIMEOUT_MS = 30_000
private const val CHUNK = 65536

data class ProxyConfig(
    val port: Int = 8080,
    val strategy: String = "tls_split",
    val fragmentSize: Int = 100,
    val fragmentDelayMs: Long = 0,
)

class BypassProxy(private val cfg: ProxyConfig, private val onLog: (String) -> Unit) {

    private val pool = Executors.newCachedThreadPool()
    private var server: ServerSocket? = null
    val connections = AtomicLong(0)

    /** Blocking — call from a background thread. */
    fun run() {
        server = ServerSocket(cfg.port).also { it.reuseAddress = true }
        log("Proxy started on 127.0.0.1:${cfg.port}  strategy=${cfg.strategy}")
        try {
            while (!server!!.isClosed) {
                val client = server!!.accept()
                connections.incrementAndGet()
                pool.execute { handle(client) }
            }
        } catch (ignored: Exception) {}
        log("Proxy stopped")
    }

    fun stop() {
        runCatching { server?.close() }
        pool.shutdownNow()
    }

    // ── per-connection ───────────────────────────────────────────────────────

    private fun handle(client: Socket) {
        client.soTimeout = READ_TIMEOUT_MS
        try {
            val headerBytes = readHeaders(client) ?: return
            val firstLine = headerBytes.split(b("\r\n"))[0].toString(Charsets.UTF_8)
            val parts = firstLine.trim().split(" ")
            if (parts.size < 2) return

            val method = parts[0].uppercase()
            val target = parts[1]

            if (method == "CONNECT") handleConnect(client, target, headerBytes)
            else                     handleHttp(client, method, target, parts.getOrElse(2) { "HTTP/1.1" }, headerBytes)
        } catch (e: Exception) {
            Log.d(TAG, "handler: $e")
        } finally {
            runCatching { client.close() }
            connections.decrementAndGet()
        }
    }

    // ── HTTPS CONNECT tunnel ─────────────────────────────────────────────────

    private fun handleConnect(client: Socket, target: String, @Suppress("UNUSED_PARAMETER") headerBytes: ByteArray) {
        val (host, port) = parseHostPort(target, 443)
        val remote = connectTarget(host, port) ?: run {
            client.getOutputStream().write(b("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
            return
        }
        client.getOutputStream().write(b("HTTP/1.1 200 Connection established\r\n\r\n"))
        client.getOutputStream().flush()

        // First chunk = TLS ClientHello (or first app data)
        val first = try {
            val buf = ByteArray(CHUNK)
            val n = client.getInputStream().read(buf)
            if (n > 0) buf.copyOf(n) else null
        } catch (ignored: Exception) { null }
        if (first == null || first.isEmpty()) { remote.close(); return }

        val sni = if (TlsUtils.isClientHello(first)) TlsUtils.extractSni(first) ?: host else host
        log("CONNECT $sni:$port  strategy=${cfg.strategy}")

        try {
            Strategies.apply(cfg.strategy, remote, first, cfg.fragmentSize, cfg.fragmentDelayMs)
        } catch (e: Exception) {
            log("Strategy error: $e")
            remote.close()
            return
        }
        Relay.relay(client, remote)
    }

    // ── plain HTTP ───────────────────────────────────────────────────────────

    private fun handleHttp(
        client: Socket, method: String, target: String, version: String, headerBytes: ByteArray
    ) {
        val url = if (target.startsWith("http://")) target.substring(7) else target
        val slashIdx = url.indexOf('/')
        val hostPart = if (slashIdx == -1) url else url.substring(0, slashIdx)
        val path = if (slashIdx == -1) "/" else url.substring(slashIdx)
        val (host, port) = parseHostPort(hostPart, 80)

        val remote = connectTarget(host, port) ?: run {
            client.getOutputStream().write(b("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
            return
        }
        log("HTTP $method $host:$port  strategy=${cfg.strategy}")

        // Rebuild request with relative path
        val lines = headerBytes.split(b("\r\n")).toMutableList()
        lines[0] = b("$method $path $version")
        val rebuilt = lines.joinToByteArray(b("\r\n"))

        try {
            Strategies.apply(cfg.strategy, remote, rebuilt, cfg.fragmentSize, cfg.fragmentDelayMs)
        } catch (e: Exception) {
            log("Strategy error: $e"); remote.close(); return
        }
        Relay.relay(client, remote)
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private fun connectTarget(host: String, port: Int): Socket? = try {
        Socket(host, port).also { it.soTimeout = READ_TIMEOUT_MS }
    } catch (e: Exception) {
        log("Cannot connect to $host:$port — $e"); null
    }

    private fun readHeaders(sock: Socket): ByteArray? {
        val buf = mutableListOf<Byte>()
        val input = sock.getInputStream()
        val end = b("\r\n\r\n")
        while (true) {
            val b = input.read()
            if (b == -1) return null
            buf.add(b.toByte())
            if (buf.size > 65536) return null
            if (buf.size >= 4) {
                val tail = buf.subList(buf.size - 4, buf.size)
                if (tail[0] == end[0] && tail[1] == end[1] && tail[2] == end[2] && tail[3] == end[3])
                    return buf.toByteArray()
            }
        }
    }

    private fun parseHostPort(target: String, defaultPort: Int): Pair<String, Int> {
        val lastColon = target.lastIndexOf(':')
        return if (lastColon > 0) {
            val port = target.substring(lastColon + 1).toIntOrNull() ?: defaultPort
            Pair(target.substring(0, lastColon), port)
        } else {
            Pair(target, defaultPort)
        }
    }

    private fun log(msg: String) {
        Log.i(TAG, msg)
        onLog(msg)
    }

    private fun b(s: String) = s.toByteArray(Charsets.ISO_8859_1)

    private fun ByteArray.split(delimiter: ByteArray): List<ByteArray> {
        val result = mutableListOf<ByteArray>()
        var start = 0
        for (i in 0..size - delimiter.size) {
            if (delimiter.indices.all { this[i + it] == delimiter[it] }) {
                result.add(copyOfRange(start, i))
                start = i + delimiter.size
            }
        }
        result.add(copyOfRange(start, size))
        return result
    }

    private fun List<ByteArray>.joinToByteArray(sep: ByteArray): ByteArray {
        val total = sumOf { it.size } + maxOf(0, (size - 1) * sep.size)
        val out = ByteArray(total)
        var pos = 0
        forEachIndexed { i, arr ->
            arr.copyInto(out, pos); pos += arr.size
            if (i < size - 1) { sep.copyInto(out, pos); pos += sep.size }
        }
        return out
    }

    @Suppress("UNUSED")
    private fun OutputStream.write(s: String) = write(s.toByteArray(Charsets.ISO_8859_1))
}
