package com.localbypass.vless

import java.net.URLDecoder
import java.util.UUID

data class VlessConfig(
    val uuid: UUID,
    val host: String,
    val port: Int,
    val security: String = "tls",   // "tls" | "none" | "reality"
    val sni: String = "",
    val name: String = ""
) {
    val displayName: String get() = name.ifEmpty { "$host:$port" }

    companion object {
        fun parse(url: String): VlessConfig? = runCatching {
            if (!url.startsWith("vless://")) return null

            val noScheme = url.removePrefix("vless://")

            // Fragment (#name)
            val fragIdx = noScheme.indexOf('#')
            val name = if (fragIdx >= 0)
                URLDecoder.decode(noScheme.substring(fragIdx + 1), "UTF-8") else ""
            val noFrag = if (fragIdx >= 0) noScheme.substring(0, fragIdx) else noScheme

            // Query (?key=val&...)
            val qIdx = noFrag.indexOf('?')
            val query = if (qIdx >= 0) noFrag.substring(qIdx + 1) else ""
            val userHost = if (qIdx >= 0) noFrag.substring(0, qIdx) else noFrag

            val params = query.split("&")
                .filter { it.contains('=') }
                .associate { kv ->
                    val eq = kv.indexOf('=')
                    kv.substring(0, eq) to URLDecoder.decode(kv.substring(eq + 1), "UTF-8")
                }

            // uuid@host:port
            val atIdx = userHost.lastIndexOf('@')
            if (atIdx < 0) return null
            val uuidStr = userHost.substring(0, atIdx)
            val hostPort = userHost.substring(atIdx + 1)

            val (host, port) = if (hostPort.startsWith('[')) {
                // IPv6 [::1]:443
                val bracket = hostPort.indexOf(']')
                val h = hostPort.substring(1, bracket)
                val p = hostPort.substring(bracket + 2).toIntOrNull() ?: 443
                h to p
            } else {
                val lastColon = hostPort.lastIndexOf(':')
                if (lastColon > 0)
                    hostPort.substring(0, lastColon) to (hostPort.substring(lastColon + 1).toIntOrNull() ?: 443)
                else
                    hostPort to 443
            }

            val uuid = UUID.fromString(uuidStr)
            val security = params["security"] ?: "tls"
            val sni = params["sni"] ?: params["host"] ?: host

            VlessConfig(uuid, host, port, security, sni, name)
        }.getOrNull()
    }
}
