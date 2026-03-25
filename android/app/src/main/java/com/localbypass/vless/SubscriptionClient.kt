package com.localbypass.vless

import android.util.Base64
import java.net.URL
import javax.net.ssl.HttpsURLConnection

data class ServerEntry(
    val name: String,
    val protocol: String,   // "vless", "vmess", "trojan", "ss", …
    val config: VlessConfig?,
    val rawUrl: String
) {
    val connectable: Boolean get() = config != null
    override fun toString(): String = buildString {
        if (!connectable) append("⚠ ")
        append(name)
        append("  [${protocol.uppercase()}]")
    }
}

object SubscriptionClient {

    fun fetch(subscriptionUrl: String): List<ServerEntry> {
        val url   = URL(subscriptionUrl)
        val conn  = url.openConnection() as HttpsURLConnection
        conn.setRequestProperty("User-Agent", "v2rayNG/1.8.0")
        conn.setRequestProperty("Accept", "*/*")
        conn.connectTimeout = 12_000
        conn.readTimeout    = 15_000

        val body = conn.inputStream.use { it.bufferedReader().readText() }
        conn.disconnect()

        // Standard V2Ray subscription: base64-encoded list of proxy URLs
        val text = try {
            String(Base64.decode(body.trim(), Base64.DEFAULT), Charsets.UTF_8)
        } catch (ignored: Exception) {
            body    // already plain text
        }

        return text.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .mapNotNull { parseEntry(it) }
            .toList()
    }

    private fun parseEntry(line: String): ServerEntry? {
        val proto = line.substringBefore("://").lowercase()
        return when {
            line.startsWith("vless://") -> {
                val cfg = VlessConfig.parse(line)
                val name = cfg?.name?.ifEmpty { null }
                    ?: line.substringAfter("#", "").ifEmpty { null }
                    ?: "${cfg?.host ?: "?"}"
                ServerEntry(name, "vless", cfg, line)
            }
            line.startsWith("vmess://") || line.startsWith("trojan://") ||
            line.startsWith("ss://")    || line.startsWith("hysteria2://") -> {
                val name = line.substringAfter("#", "").ifEmpty {
                    "${proto.uppercase()} server"
                }
                ServerEntry(name, proto, null, line)
            }
            else -> null
        }
    }
}
