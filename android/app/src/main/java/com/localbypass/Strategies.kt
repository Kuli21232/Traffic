package com.localbypass

import java.net.Socket

/**
 * DPI-bypass strategies — Kotlin port of bypass/strategies.py.
 *
 * Each strategy sends [data] to [remote] in a way that confuses
 * deep-packet inspection while the destination receives the full stream.
 */
object Strategies {

    val ALL = listOf("direct", "tls_split", "tls_fragment", "http_split")

    fun apply(name: String, remote: Socket, data: ByteArray, fragmentSize: Int, fragmentDelayMs: Long) {
        when (name) {
            "tls_split"    -> tlsSplit(remote, data, fragmentDelayMs)
            "tls_fragment" -> tlsFragment(remote, data, fragmentSize, fragmentDelayMs)
            "http_split"   -> httpSplit(remote, data, fragmentDelayMs)
            else           -> direct(remote, data)
        }
    }

    // ── direct ──────────────────────────────────────────────────────────────

    private fun direct(remote: Socket, data: ByteArray) {
        remote.getOutputStream().apply { write(data); flush() }
    }

    // ── tls_split ────────────────────────────────────────────────────────────

    private fun tlsSplit(remote: Socket, data: ByteArray, delayMs: Long) {
        remote.tcpNoDelay = true
        val splitAt = if (TlsUtils.isClientHello(data)) {
            val sniOff = TlsUtils.findSniOffset(data)
            if (sniOff != null && sniOff > 0) {
                // split in the middle of the SNI string
                sniOff + (data.size - sniOff) / 2
            } else 3
        } else {
            minOf(3, data.size - 1)
        }.coerceIn(1, data.size - 1)

        val out = remote.getOutputStream()
        out.write(data, 0, splitAt); out.flush()
        if (delayMs > 0) Thread.sleep(delayMs)
        out.write(data, splitAt, data.size - splitAt); out.flush()
    }

    // ── tls_fragment ─────────────────────────────────────────────────────────

    private fun tlsFragment(remote: Socket, data: ByteArray, size: Int, delayMs: Long) {
        remote.tcpNoDelay = true
        val out = remote.getOutputStream()
        val chunkSize = maxOf(1, size)
        var i = 0
        while (i < data.size) {
            val end = minOf(i + chunkSize, data.size)
            out.write(data, i, end - i); out.flush()
            if (delayMs > 0) Thread.sleep(delayMs)
            i = end
        }
    }

    // ── http_split ────────────────────────────────────────────────────────────

    private fun httpSplit(remote: Socket, data: ByteArray, delayMs: Long) {
        remote.tcpNoDelay = true
        val text = String(data, Charsets.ISO_8859_1).lowercase()
        val hostPos = text.indexOf("host:")
        val splitAt = if (hostPos > 0) hostPos
                      else maxOf(1, minOf(3, data.size - 1))

        val out = remote.getOutputStream()
        out.write(data, 0, splitAt); out.flush()
        if (delayMs > 0) Thread.sleep(delayMs)
        out.write(data, splitAt, data.size - splitAt); out.flush()
    }
}
