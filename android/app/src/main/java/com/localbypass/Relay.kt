package com.localbypass

import java.net.Socket
import java.util.concurrent.CountDownLatch

/** Bidirectional transparent relay between two sockets. */
object Relay {

    private const val BUF = 65536

    fun relay(a: Socket, b: Socket) {
        val done = CountDownLatch(1)

        fun pump(src: Socket, dst: Socket) = Thread {
            try {
                val buf = ByteArray(BUF)
                val input = src.getInputStream()
                val output = dst.getOutputStream()
                var n: Int
                while (input.read(buf).also { n = it } != -1) {
                    output.write(buf, 0, n)
                    output.flush()
                }
            } catch (_: Exception) {
            } finally {
                runCatching { a.close() }
                runCatching { b.close() }
                done.countDown()
            }
        }.apply { isDaemon = true; start() }

        pump(a, b)
        pump(b, a)
        done.await()
    }
}
