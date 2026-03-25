package com.localbypass.vpn

import android.util.Log
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

private const val TAG     = "TunForwarder"
private const val MTU     = 32767
private const val TIMEOUT = 30_000

/**
 * Reads raw IPv4/TCP packets from the TUN fd, intercepts each TCP connection,
 * and relays it through [socketFactory] (VLESS or direct).
 *
 * TCP state machine is intentionally minimal:
 *   SYN → async connect real socket → SYN-ACK
 *   PSH/ACK → forward payload to real socket
 *   real socket data → PSH-ACK back to TUN
 *   FIN / RST → close session
 */
class TunForwarder(
    private val tunFd: FileDescriptor,
    /** Returns a socket already connected to [host]:[port] (optionally via VLESS). */
    private val socketFactory: (host: String, port: Int) -> Socket,
    private val onLog: (String) -> Unit
) {
    private val running  = AtomicBoolean(true)
    private val pool     = Executors.newCachedThreadPool()
    private val sessions = ConcurrentHashMap<String, TcpSession>()

    // ── stats ─────────────────────────────────────────────────────────────────
    val bytesIn  = AtomicLong(0)
    val bytesOut = AtomicLong(0)

    // ── main loop ─────────────────────────────────────────────────────────────
    fun run() {
        val inp  = FileInputStream(tunFd)
        val outp = FileOutputStream(tunFd)
        val buf  = ByteArray(MTU)

        while (running.get()) {
            val n = try { inp.read(buf) }
            catch (e: Exception) { if (running.get()) Log.e(TAG, "read: $e"); break }
            if (n <= 0) continue

            val pkt = Packet(buf.copyOf(n), n)
            if (!pkt.isTcp) continue

            val key = "${pkt.srcAddr.hostAddress}:${pkt.srcPort}"

            when {
                pkt.isSyn             -> handleSyn(pkt, key, outp)
                pkt.isRst             -> sessions.remove(key)?.close()
                pkt.isFin             -> handleFin(pkt, key, outp)
                pkt.isAck || pkt.isPsh -> handleData(pkt, key, outp)
            }
        }
        sessions.values.forEach { it.close() }
        sessions.clear()
        pool.shutdownNow()
    }

    fun stop() { running.set(false) }

    // ── SYN ──────────────────────────────────────────────────────────────────
    private fun handleSyn(pkt: Packet, key: String, out: FileOutputStream) {
        val dstHost = pkt.dstAddr.hostAddress ?: return
        val dstPort = pkt.dstPort

        // Snapshot immutable fields needed in the async thread
        val srcAddr  = pkt.srcAddr
        val srcPort  = pkt.srcPort
        val dstAddr  = pkt.dstAddr
        val clientSeq = pkt.seqNum

        pool.execute {
            val real = try {
                socketFactory(dstHost, dstPort)
            } catch (e: Exception) {
                onLog("✗ $dstHost:$dstPort — $e")
                val rst = Packet.tcp(dstAddr, dstPort, srcAddr, srcPort,
                    0L, clientSeq + 1, Flags.RST or Flags.ACK)
                synchronized(out) { runCatching { out.write(rst) } }
                return@execute
            }

            val session = TcpSession(
                srcAddr = srcAddr, srcPort = srcPort,
                dstAddr = dstAddr, dstPort = dstPort,
                clientInitSeq = clientSeq,
                realSocket = real,
                tunOut = out,
                bytesIn = bytesIn, bytesOut = bytesOut
            )
            sessions[key] = session
            session.sendSynAck()
            onLog("⇌ $dstHost:$dstPort")

            // Pump: real socket → TUN
            pool.execute {
                session.pumpFromReal()
                sessions.remove(key)
            }
        }
    }

    // ── data (PSH+ACK or plain ACK) ───────────────────────────────────────────
    private fun handleData(pkt: Packet, key: String, out: FileOutputStream) {
        val session = sessions[key] ?: return
        if (pkt.payloadLen > 0) {
            session.forwardToReal(pkt.payload())
            session.ackNum = (pkt.seqNum + pkt.payloadLen) and 0xFFFFFFFFL
            session.sendAck()
        }
    }

    // ── FIN ──────────────────────────────────────────────────────────────────
    private fun handleFin(pkt: Packet, key: String, out: FileOutputStream) {
        val session = sessions.remove(key) ?: return
        session.ackNum = (pkt.seqNum + 1) and 0xFFFFFFFFL
        session.sendFinAck()
        session.close()
    }
}

// ── Per-connection state ──────────────────────────────────────────────────────
class TcpSession(
    val srcAddr: InetAddress,
    val srcPort: Int,
    val dstAddr: InetAddress,
    val dstPort: Int,
    clientInitSeq: Long,
    private val realSocket: Socket,
    private val tunOut: FileOutputStream,
    private val bytesIn: AtomicLong,
    private val bytesOut: AtomicLong
) {
    // Our side's sequence number (server → client direction)
    var seqNum: Long = (System.nanoTime() ushr 16) and 0xFFFFFFFFL
    // Next byte we expect from client
    var ackNum: Long = (clientInitSeq + 1) and 0xFFFFFFFFL

    // ── send helpers ─────────────────────────────────────────────────────────
    fun sendSynAck() {
        write(Packet.tcp(dstAddr, dstPort, srcAddr, srcPort, seqNum, ackNum,
            Flags.SYN or Flags.ACK))
        seqNum = (seqNum + 1) and 0xFFFFFFFFL
    }

    fun sendAck() {
        write(Packet.tcp(dstAddr, dstPort, srcAddr, srcPort, seqNum, ackNum, Flags.ACK))
    }

    fun sendFinAck() {
        write(Packet.tcp(dstAddr, dstPort, srcAddr, srcPort, seqNum, ackNum,
            Flags.FIN or Flags.ACK))
        seqNum = (seqNum + 1) and 0xFFFFFFFFL
    }

    private fun sendData(data: ByteArray) {
        write(Packet.tcp(dstAddr, dstPort, srcAddr, srcPort, seqNum, ackNum,
            Flags.PSH or Flags.ACK, payload = data))
        seqNum = (seqNum + data.size) and 0xFFFFFFFFL
        bytesOut.addAndGet(data.size.toLong())
    }

    private fun write(pkt: ByteArray) {
        synchronized(tunOut) { runCatching { tunOut.write(pkt) } }
    }

    // ── relay helpers ────────────────────────────────────────────────────────
    fun forwardToReal(data: ByteArray) {
        runCatching {
            realSocket.getOutputStream().apply { write(data); flush() }
            bytesIn.addAndGet(data.size.toLong())
        }
    }

    /** Blocking: reads from real socket and writes packets back to TUN. */
    fun pumpFromReal() {
        val buf = ByteArray(65536)
        try {
            val inp = realSocket.getInputStream()
            var n: Int
            while (inp.read(buf).also { n = it } != -1) {
                if (n <= 0) continue
                sendData(buf.copyOf(n))
            }
        } catch (ignored: Exception) {
        } finally {
            runCatching { sendFinAck() }
            close()
        }
    }

    fun close() { runCatching { realSocket.close() } }
}
