package com.localbypass

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.localbroadcastmanager.content.LocalBroadcastManager

class ProxyService : Service() {

    private var proxy: BypassProxy? = null
    private var proxyThread: Thread? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val port     = intent?.getIntExtra(EXTRA_PORT, 8080) ?: 8080
        val strategy = intent?.getStringExtra(EXTRA_STRATEGY) ?: "tls_split"
        val fragSize = intent?.getIntExtra(EXTRA_FRAG_SIZE, 100) ?: 100
        val fragDelay= intent?.getLongExtra(EXTRA_FRAG_DELAY, 0L) ?: 0L

        startForeground(NOTIF_ID, buildNotification(port, strategy))

        val cfg = ProxyConfig(port, strategy, fragSize, fragDelay)
        proxy = BypassProxy(cfg) { msg -> broadcast(ACTION_LOG, msg) }

        proxyThread = Thread {
            try {
                broadcast(ACTION_STATE, "running")
                proxy!!.run()
            } catch (ignored: Exception) {
            } finally {
                broadcast(ACTION_STATE, "stopped")
                stopSelf()
            }
        }.also { it.isDaemon = true; it.start() }

        return START_NOT_STICKY
    }

    override fun onDestroy() {
        proxy?.stop()
        proxyThread?.interrupt()
        super.onDestroy()
    }

    // ── notification ────────────────────────────────────────────────────────

    private fun createNotificationChannel() {
        val ch = NotificationChannel(CH_ID, "Proxy Service", NotificationManager.IMPORTANCE_LOW)
        ch.description = "LocalBypass running in background"
        getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
    }

    private fun buildNotification(port: Int, strategy: String): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CH_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("LocalBypass active")
            .setContentText("Port $port  ·  $strategy")
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    // ── broadcast helper ─────────────────────────────────────────────────────

    private fun broadcast(action: String, payload: String) {
        val i = Intent(action).putExtra(EXTRA_PAYLOAD, payload)
        LocalBroadcastManager.getInstance(this).sendBroadcast(i)
    }

    companion object {
        const val EXTRA_PORT       = "port"
        const val EXTRA_STRATEGY   = "strategy"
        const val EXTRA_FRAG_SIZE  = "frag_size"
        const val EXTRA_FRAG_DELAY = "frag_delay"
        const val EXTRA_PAYLOAD    = "payload"

        const val ACTION_STATE = "com.localbypass.STATE"
        const val ACTION_LOG   = "com.localbypass.LOG"

        private const val CH_ID   = "proxy_channel"
        private const val NOTIF_ID = 1
    }
}
