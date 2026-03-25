package com.localbypass.vpn

import java.net.InetAddress

// ── TCP flag constants ────────────────────────────────────────────────────────
object Flags {
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10
}

/** Parsed view over a raw IPv4/TCP byte array. Does not copy; all fields read on demand. */
class Packet(private val raw: ByteArray, val length: Int) {

    // ── IPv4 ─────────────────────────────────────────────────────────────────
    val ipVersion:   Int  get() = (raw[0].toInt() and 0xF0) ushr 4
    val ipIhl:       Int  get() = (raw[0].toInt() and 0x0F) * 4
    val ipTotalLen:  Int  get() = u16(raw, 2)
    val ipProto:     Byte get() = raw[9]
    val srcAddr: InetAddress get() = InetAddress.getByAddress(raw.copyOfRange(12, 16))
    val dstAddr: InetAddress get() = InetAddress.getByAddress(raw.copyOfRange(16, 20))

    // ── TCP (offset = ipIhl) ─────────────────────────────────────────────────
    private val t: Int get() = ipIhl
    val srcPort:      Int  get() = u16(raw, t)
    val dstPort:      Int  get() = u16(raw, t + 2)
    val seqNum:       Long get() = u32(raw, t + 4)
    val ackNum:       Long get() = u32(raw, t + 8)
    val tcpHdrLen:    Int  get() = ((raw[t + 12].toInt() and 0xF0) ushr 4) * 4
    val tcpFlags:     Int  get() = raw[t + 13].toInt() and 0xFF

    val isSyn: Boolean get() = tcpFlags and Flags.SYN != 0 && tcpFlags and Flags.ACK == 0
    val isAck: Boolean get() = tcpFlags and Flags.ACK != 0
    val isFin: Boolean get() = tcpFlags and Flags.FIN != 0
    val isRst: Boolean get() = tcpFlags and Flags.RST != 0
    val isPsh: Boolean get() = tcpFlags and Flags.PSH != 0

    val payloadOffset: Int get() = t + tcpHdrLen
    val payloadLen:    Int get() = length - payloadOffset
    fun payload(): ByteArray = raw.copyOfRange(payloadOffset, length)

    val isTcp: Boolean get() = ipVersion == 4 && ipProto == 6.toByte()

    companion object {

        // ── Packet builder ────────────────────────────────────────────────────
        fun tcp(
            src: InetAddress, srcPort: Int,
            dst: InetAddress, dstPort: Int,
            seq: Long, ack: Long,
            flags: Int,
            window: Int = 65535,
            payload: ByteArray = ByteArray(0)
        ): ByteArray {
            val ipLen  = 20
            val tcpLen = 20
            val total  = ipLen + tcpLen + payload.size
            val buf    = ByteArray(total)

            // IPv4 header
            buf[0]  = 0x45.toByte()             // version=4, IHL=5
            buf[1]  = 0x00                       // DSCP
            putU16(buf, 2, total)
            buf[4]  = 0x00; buf[5] = 0x01        // identification
            buf[6]  = 0x40.toByte()              // DF flag
            buf[7]  = 0x00
            buf[8]  = 0x40                       // TTL = 64
            buf[9]  = 0x06                       // TCP
            buf[10] = 0x00; buf[11] = 0x00       // checksum placeholder
            src.address.copyInto(buf, 12)
            dst.address.copyInto(buf, 16)
            putU16(buf, 10, ipChecksum(buf, 0, ipLen))

            // TCP header
            putU16(buf, ipLen,     srcPort)
            putU16(buf, ipLen + 2, dstPort)
            putU32(buf, ipLen + 4, seq)
            putU32(buf, ipLen + 8, ack)
            buf[ipLen + 12] = 0x50.toByte()      // data offset = 5 (20 bytes)
            buf[ipLen + 13] = flags.toByte()
            putU16(buf, ipLen + 14, window)
            buf[ipLen + 16] = 0x00; buf[ipLen + 17] = 0x00  // checksum placeholder
            buf[ipLen + 18] = 0x00; buf[ipLen + 19] = 0x00  // urgent

            if (payload.isNotEmpty()) payload.copyInto(buf, ipLen + tcpLen)

            putU16(buf, ipLen + 16, tcpChecksum(buf, src.address, dst.address, ipLen, tcpLen + payload.size))
            return buf
        }

        // ── Checksum helpers ─────────────────────────────────────────────────
        private fun ipChecksum(buf: ByteArray, off: Int, len: Int): Int {
            var sum = 0
            var i = off
            while (i < off + len - 1) {
                sum += u16(buf, i); i += 2
            }
            if (len % 2 != 0) sum += (buf[off + len - 1].toInt() and 0xFF) shl 8
            while (sum ushr 16 != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
            return sum.inv() and 0xFFFF
        }

        private fun tcpChecksum(buf: ByteArray, srcIp: ByteArray, dstIp: ByteArray, tcpOff: Int, tcpLen: Int): Int {
            val pseudo = ByteArray(12 + tcpLen)
            srcIp.copyInto(pseudo, 0)
            dstIp.copyInto(pseudo, 4)
            pseudo[8]  = 0x00
            pseudo[9]  = 0x06                       // TCP
            putU16(pseudo, 10, tcpLen)
            buf.copyInto(pseudo, 12, tcpOff, tcpOff + tcpLen)
            pseudo[28] = 0x00; pseudo[29] = 0x00    // zero checksum field
            return ipChecksum(pseudo, 0, pseudo.size)
        }

        // ── Byte utils ───────────────────────────────────────────────────────
        fun u16(b: ByteArray, i: Int): Int =
            ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)

        fun u32(b: ByteArray, i: Int): Long =
            ((b[i].toLong() and 0xFF) shl 24) or
            ((b[i+1].toLong() and 0xFF) shl 16) or
            ((b[i+2].toLong() and 0xFF) shl  8) or
             (b[i+3].toLong() and 0xFF)

        private fun putU16(b: ByteArray, i: Int, v: Int) {
            b[i]   = (v ushr 8).toByte()
            b[i+1] = (v and 0xFF).toByte()
        }

        private fun putU32(b: ByteArray, i: Int, v: Long) {
            b[i]   = (v ushr 24).toByte()
            b[i+1] = (v ushr 16).toByte()
            b[i+2] = (v ushr  8).toByte()
            b[i+3] = (v and 0xFF).toByte()
        }
    }
}
