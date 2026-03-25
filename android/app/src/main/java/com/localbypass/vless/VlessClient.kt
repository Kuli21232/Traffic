package com.localbypass.vless

import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * VLESS protocol client (version 0).
 *
 * Header layout (client → server):
 *   version(1=0x00) | uuid(16) | addons_len(1) | command(1=TCP) |
 *   dst_port(2 BE)  | addr_type(1) | addr | data...
 *
 * Response header (server → client):
 *   version(1=0x00) | addons_len(1) | addons | data...
 */
class VlessClient(
    private val cfg: VlessConfig,
    /** Called before socket.connect() to exclude from VPN tunnel. */
    private val protect: (Socket) -> Boolean = { true }
) {
    fun connect(targetHost: String, targetPort: Int): Socket {
        val raw = Socket()
        protect(raw)
        raw.connect(InetSocketAddress(cfg.host, cfg.port), TIMEOUT_MS)
        raw.soTimeout = TIMEOUT_MS

        val socket: Socket = if (cfg.security == "tls" || cfg.security == "reality") {
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            val ssl = factory.createSocket(raw, cfg.host, cfg.port, true) as SSLSocket
            val sni = cfg.sni.ifEmpty { cfg.host }
            val params = SSLParameters().also {
                it.serverNames = listOf(SNIHostName(sni))
            }
            ssl.sslParameters = params
            ssl.startHandshake()
            ssl
        } else {
            raw
        }

        val out = socket.getOutputStream()

        // UUID → 16 raw bytes
        val uuidBytes = ByteArray(16).also { b ->
            val msb = cfg.uuid.mostSignificantBits
            val lsb = cfg.uuid.leastSignificantBits
            for (i in 0..7) b[i]     = (msb ushr (56 - i * 8)).toByte()
            for (i in 0..7) b[i + 8] = (lsb ushr (56 - i * 8)).toByte()
        }

        // Address encoding
        val isIpv4 = targetHost.matches(Regex("\\d{1,3}(\\.\\d{1,3}){3}"))
        val (addrType, addrBytes) = if (isIpv4) {
            val parts = targetHost.split(".").map { it.toInt().toByte() }.toByteArray()
            0x01.toByte() to parts
        } else {
            val domain = targetHost.toByteArray(Charsets.UTF_8)
            val encoded = ByteArray(1 + domain.size)
            encoded[0] = domain.size.toByte()
            domain.copyInto(encoded, 1)
            0x02.toByte() to encoded
        }

        // Build header
        val header = ByteArray(1 + 16 + 1 + 1 + 2 + 1 + addrBytes.size)
        var p = 0
        header[p++] = 0x00                               // version
        uuidBytes.copyInto(header, p); p += 16
        header[p++] = 0x00                               // addons length
        header[p++] = 0x01                               // command = TCP
        header[p++] = (targetPort ushr 8).toByte()
        header[p++] = (targetPort and 0xFF).toByte()
        header[p++] = addrType
        addrBytes.copyInto(header, p)

        out.write(header)
        out.flush()

        // Read response header
        val inp = socket.getInputStream()
        val respVersion = inp.read()
        check(respVersion == 0x00) { "VLESS bad response version: $respVersion" }
        val addonsLen = inp.read()
        if (addonsLen > 0) {
            val skip = ByteArray(addonsLen)
            var read = 0
            while (read < addonsLen) {
                val n = inp.read(skip, read, addonsLen - read)
                check(n >= 0) { "VLESS response truncated" }
                read += n
            }
        }

        return socket
    }

    companion object {
        private const val TIMEOUT_MS = 10_000
    }
}
