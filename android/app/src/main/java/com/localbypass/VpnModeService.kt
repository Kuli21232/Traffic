package com.localbypass

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import com.localbypass.vless.VlessClient
import com.localbypass.vless.VlessConfig
import com.localbypass.vpn.TunForwarder
import java.net.InetSocketAddress
import java.net.Socket

class VpnModeService : VpnService() {

    private var vpnIface: ParcelFileDescriptor? = null
    private var forwarder: TunForwarder? = null
    private var thread: Thread? = null

    override fun onBind(intent: Intent?) = super.onBind(intent)

    override fun onCreate() {
        super.onCreate()
        getSystemService(NotificationManager::class.java)
            .createNotificationChannel(
                NotificationChannel(CH_ID, "VPN Service", NotificationManager.IMPORTANCE_LOW)
                    .also { it.description = "LocalBypass VPN tunnel" }
            )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val vlessUrl = intent?.getStringExtra(EXTRA_VLESS_URL)
        val cfg      = vlessUrl?.let { VlessConfig.parse(it) }

        startForeground(NOTIF_ID, buildNotification(cfg))

        // Build TUN interface
        val iface = Builder()
            .setSession("LocalBypass")
            .addAddress("10.255.0.1", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .addDnsServer("1.1.1.1")
            .setMtu(32767)
            .establish()

        if (iface == null) {
            log("VPN permission denied")
            broadcastState("stopped")
            stopSelf()
            return START_NOT_STICKY
        }
        vpnIface = iface

        // Socket factory: VLESS or direct (protected from loop)
        val factory: (String, Int) -> Socket = if (cfg != null) {
            val client = VlessClient(cfg) { sock -> protect(sock) }
            { host, port -> client.connect(host, port) }
        } else {
            { host, port ->
                Socket().also { sock ->
                    protect(sock)
                    sock.connect(InetSocketAddress(host, port), 10_000)
                    sock.soTimeout = 30_000
                }
            }
        }

        forwarder = TunForwarder(iface.fileDescriptor, factory) { msg -> log(msg) }

        thread = Thread {
            broadcastState("running")
            log("VPN started${if (cfg != null) " → ${cfg.displayName}" else " (direct)"}")
            forwarder!!.run()
            log("VPN stopped")
            broadcastState("stopped")
            stopSelf()
        }.also { it.isDaemon = true; it.start() }

        // Stats ticker
        Thread {
            while (thread?.isAlive == true) {
                Thread.sleep(2000)
                val fwd = forwarder ?: break
                broadcastStats(fwd.bytesIn.get(), fwd.bytesOut.get())
            }
        }.also { it.isDaemon = true; it.start() }

        return START_NOT_STICKY
    }

    override fun onDestroy() {
        forwarder?.stop()
        thread?.interrupt()
        runCatching { vpnIface?.close() }
        super.onDestroy()
    }

    // ── helpers ───────────────────────────────────────────────────────────────
    private fun log(msg: String) = broadcast(ProxyService.ACTION_LOG, msg)
    private fun broadcastState(s: String) = broadcast(ProxyService.ACTION_STATE, s)
    private fun broadcastStats(inn: Long, out: Long) =
        broadcast(ACTION_STATS, "$inn/$out")

    private fun broadcast(action: String, payload: String) {
        LocalBroadcastManager.getInstance(this)
            .sendBroadcast(Intent(action).putExtra(ProxyService.EXTRA_PAYLOAD, payload))
    }

    private fun buildNotification(cfg: VlessConfig?): Notification {
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, CH_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("LocalBypass VPN")
            .setContentText(if (cfg != null) "Via ${cfg.displayName}" else "Direct (no VLESS)")
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val EXTRA_VLESS_URL = "vless_url"
        const val ACTION_STATS    = "com.localbypass.STATS"
        private const val CH_ID   = "vpn_ch"
        private const val NOTIF_ID = 2
    }
}
