package com.localbypass

object TlsUtils {

    private const val TLS_HANDSHAKE: Byte = 0x16.toByte().toByte()
    private const val CLIENT_HELLO: Byte = 0x01

    fun isClientHello(data: ByteArray): Boolean {
        if (data.size < 9) return false
        return data[0] == TLS_HANDSHAKE && data[5] == CLIENT_HELLO
    }

    /** Returns byte offset where the SNI hostname bytes start, or null. */
    fun findSniOffset(data: ByteArray): Int? {
        if (!isClientHello(data)) return null
        return try {
            // Skip: record header(5) + handshake header(4) + version(2) + random(32)
            var pos = 5 + 4 + 2 + 32
            if (pos >= data.size) return null

            val sessionIdLen = data[pos].toInt() and 0xFF
            pos += 1 + sessionIdLen

            if (pos + 2 > data.size) return null
            val cipherLen = u16(data, pos)
            pos += 2 + cipherLen

            if (pos >= data.size) return null
            val compLen = data[pos].toInt() and 0xFF
            pos += 1 + compLen

            if (pos + 2 > data.size) return null
            val extTotal = u16(data, pos)
            pos += 2
            val end = pos + extTotal

            while (pos + 4 <= end && pos + 4 <= data.size) {
                val extType = u16(data, pos)
                val extLen = u16(data, pos + 2)
                pos += 4
                if (extType == 0x0000) {
                    // SNI extension: list_len(2) + name_type(1) + name_len(2) + name
                    return if (pos + 5 <= data.size) pos + 5 else null
                }
                pos += extLen
            }
            null
        } catch (_: Exception) {
            null
        }
    }

    /** Extracts SNI hostname string from TLS ClientHello. */
    fun extractSni(data: ByteArray): String? {
        val offset = findSniOffset(data) ?: return null
        return try {
            if (offset + 2 > data.size) return null
            val nameLen = u16(data, offset - 2)
            if (offset + nameLen > data.size) return null
            String(data, offset, nameLen, Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    private fun u16(data: ByteArray, pos: Int): Int =
        ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
}
