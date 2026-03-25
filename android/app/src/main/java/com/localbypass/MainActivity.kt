package com.localbypass

import android.Manifest
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import com.localbypass.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var b: ActivityMainBinding
    private var running = false

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val payload = intent.getStringExtra(ProxyService.EXTRA_PAYLOAD) ?: return
            when (intent.action) {
                ProxyService.ACTION_STATE -> setRunning(payload == "running")
                ProxyService.ACTION_LOG   -> appendLog(payload)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityMainBinding.inflate(layoutInflater)
        setContentView(b.root)

        // Strategy dropdown
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, Strategies.ALL)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        b.spinnerStrategy.adapter = adapter

        b.btnStartStop.setOnClickListener { if (running) stopProxy() else startProxy() }

        b.tvProxyAddress.setOnClickListener { copyAddress() }

        LocalBroadcastManager.getInstance(this).registerReceiver(
            receiver,
            IntentFilter().apply {
                addAction(ProxyService.ACTION_STATE)
                addAction(ProxyService.ACTION_LOG)
            }
        )

        requestNotificationPermission()
    }

    override fun onDestroy() {
        LocalBroadcastManager.getInstance(this).unregisterReceiver(receiver)
        super.onDestroy()
    }

    // ── proxy control ────────────────────────────────────────────────────────

    private fun startProxy() {
        val port = b.etPort.text.toString().toIntOrNull()
        if (port == null || port !in 1024..65535) {
            b.etPort.error = "1024–65535"
            return
        }
        val strategy = b.spinnerStrategy.selectedItem as String
        val fragSize  = b.etFragSize.text.toString().toIntOrNull() ?: 100
        val fragDelay = b.etFragDelay.text.toString().toLongOrNull() ?: 0L

        val intent = Intent(this, ProxyService::class.java).apply {
            putExtra(ProxyService.EXTRA_PORT,       port)
            putExtra(ProxyService.EXTRA_STRATEGY,   strategy)
            putExtra(ProxyService.EXTRA_FRAG_SIZE,  fragSize)
            putExtra(ProxyService.EXTRA_FRAG_DELAY, fragDelay)
        }
        startForegroundService(intent)
        appendLog("Starting proxy on port $port…")
    }

    private fun stopProxy() {
        stopService(Intent(this, ProxyService::class.java))
    }

    // ── UI helpers ────────────────────────────────────────────────────────────

    private fun setRunning(isRunning: Boolean) {
        running = isRunning
        if (isRunning) {
            b.btnStartStop.text = "■  STOP"
            b.btnStartStop.setBackgroundColor(getColor(R.color.stopped))
            b.tvStatus.text = "● Running"
            b.tvStatus.setTextColor(getColor(R.color.running))
            val port = b.etPort.text.toString().trim()
            b.tvProxyAddress.text = "127.0.0.1:$port  (tap to copy)"
            b.tvProxyAddress.alpha = 1f
        } else {
            b.btnStartStop.text = "▶  START"
            b.btnStartStop.setBackgroundColor(getColor(R.color.running))
            b.tvStatus.text = "● Stopped"
            b.tvStatus.setTextColor(getColor(R.color.stopped))
            b.tvProxyAddress.text = "—"
            b.tvProxyAddress.alpha = 0.4f
        }
    }

    private fun appendLog(msg: String) {
        val ts = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
            .format(java.util.Date())
        val line = "[$ts] $msg\n"
        b.tvLog.append(line)
        // auto-scroll
        val scroll = b.scrollLog
        scroll.post { scroll.fullScroll(android.view.View.FOCUS_DOWN) }
    }

    private fun copyAddress() {
        if (!running) return
        val text = "127.0.0.1:${b.etPort.text}"
        val cm = getSystemService(ClipboardManager::class.java)
        cm.setPrimaryClip(ClipData.newPlainText("proxy", text))
        Toast.makeText(this, "Copied: $text", Toast.LENGTH_SHORT).show()
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
            }
        }
    }
}
