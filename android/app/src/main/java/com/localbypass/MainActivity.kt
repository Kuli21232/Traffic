package com.localbypass

import android.Manifest
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import com.localbypass.databinding.ActivityMainBinding
import com.localbypass.vless.ServerEntry
import com.localbypass.vless.SubscriptionClient
import com.localbypass.vless.VlessConfig

class MainActivity : AppCompatActivity() {

    private lateinit var b: ActivityMainBinding
    private var running  = false
    private var vpnMode  = false   // false = HTTP Proxy, true = VPN
    private var servers  = listOf<ServerEntry>()

    // ── broadcast receiver ────────────────────────────────────────────────────
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            val payload = intent.getStringExtra(ProxyService.EXTRA_PAYLOAD) ?: return
            when (intent.action) {
                ProxyService.ACTION_STATE  -> setRunning(payload == "running")
                ProxyService.ACTION_LOG    -> appendLog(payload)
                VpnModeService.ACTION_STATS -> updateStats(payload)
            }
        }
    }

    // ── lifecycle ─────────────────────────────────────────────────────────────
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityMainBinding.inflate(layoutInflater)
        setContentView(b.root)

        // Strategy spinner
        ArrayAdapter(this, android.R.layout.simple_spinner_item, Strategies.ALL)
            .also { it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }
            .also { b.spinnerStrategy.adapter = it }

        // Mode toggle
        b.btnModeProxy.setOnClickListener { switchMode(false) }
        b.btnModeVpn.setOnClickListener   { switchMode(true)  }

        // Subscription
        b.btnLoadSub.setOnClickListener { loadSubscription() }

        // VLESS URL parse/validate
        b.btnParseVless.setOnClickListener { validateVless() }

        // Start / Stop
        b.btnStartStop.setOnClickListener { if (running) stopAll() else startAll() }

        // Copy proxy address
        b.tvProxyAddress.setOnClickListener { copyAddress() }

        // Clear log
        b.btnClearLog.setOnClickListener { b.tvLog.text = "" }

        LocalBroadcastManager.getInstance(this).registerReceiver(
            receiver,
            IntentFilter().apply {
                addAction(ProxyService.ACTION_STATE)
                addAction(ProxyService.ACTION_LOG)
                addAction(VpnModeService.ACTION_STATS)
            }
        )

        requestNotificationPermission()
        switchMode(false)
    }

    override fun onDestroy() {
        LocalBroadcastManager.getInstance(this).unregisterReceiver(receiver)
        super.onDestroy()
    }

    // ── VPN permission result ─────────────────────────────────────────────────
    @Suppress("OVERRIDE_DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQ && resultCode == Activity.RESULT_OK) {
            launchVpn()
        } else if (requestCode == VPN_REQ) {
            toast("VPN permission denied")
        }
    }

    // ── mode toggle ───────────────────────────────────────────────────────────
    private fun switchMode(vpn: Boolean) {
        if (running) return     // can't switch while running
        vpnMode = vpn

        val activeColor   = getColor(R.color.accent)
        val inactiveColor = getColor(R.color.surface)
        val activeText    = getColor(R.color.white)
        val inactiveText  = getColor(R.color.text_secondary)

        b.btnModeProxy.setBackgroundColor(if (!vpn) activeColor else inactiveColor)
        b.btnModeProxy.setTextColor(if (!vpn) activeText else inactiveText)
        b.btnModeVpn.setBackgroundColor(if (vpn) activeColor else inactiveColor)
        b.btnModeVpn.setTextColor(if (vpn) activeText else inactiveText)

        b.cardProxySettings.visibility = if (!vpn) android.view.View.VISIBLE else android.view.View.GONE
        b.cardVpnSettings.visibility   = if (vpn) android.view.View.VISIBLE else android.view.View.GONE
        b.tvProxyAddress.visibility    = if (!vpn) android.view.View.VISIBLE else android.view.View.GONE
        b.tvStats.visibility           = if (vpn) android.view.View.VISIBLE else android.view.View.GONE
    }

    // ── start / stop ──────────────────────────────────────────────────────────
    private fun startAll() {
        if (vpnMode) startVpn() else startProxy()
    }

    private fun stopAll() {
        if (vpnMode) stopService(Intent(this, VpnModeService::class.java))
        else         stopService(Intent(this, ProxyService::class.java))
    }

    private fun startProxy() {
        val port = b.etPort.text.toString().toIntOrNull()
        if (port == null || port !in 1024..65535) {
            b.etPort.error = "1024–65535"; return
        }
        val intent = Intent(this, ProxyService::class.java).apply {
            putExtra(ProxyService.EXTRA_PORT,       port)
            putExtra(ProxyService.EXTRA_STRATEGY,   b.spinnerStrategy.selectedItem as String)
            putExtra(ProxyService.EXTRA_FRAG_SIZE,  b.etFragSize.text.toString().toIntOrNull() ?: 100)
            putExtra(ProxyService.EXTRA_FRAG_DELAY, b.etFragDelay.text.toString().toLongOrNull() ?: 0L)
        }
        startForegroundService(intent)
        appendLog("Starting HTTP proxy on port $port…")
    }

    private fun startVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(intent, VPN_REQ)
        } else {
            launchVpn()
        }
    }

    private fun launchVpn() {
        // Priority: selected subscription server > manual vless URL > direct
        val selectedServer = servers.getOrNull(b.spinnerServers.selectedItemPosition)
        val vlessUrl = when {
            selectedServer?.connectable == true -> selectedServer.rawUrl
            else -> b.etVlessUrl.text.toString().trim()
        }
        val intent = Intent(this, VpnModeService::class.java)
        if (vlessUrl.isNotEmpty()) intent.putExtra(VpnModeService.EXTRA_VLESS_URL, vlessUrl)
        startForegroundService(intent)
        val label = selectedServer?.name ?: if (vlessUrl.isNotEmpty()) "VLESS" else "direct"
        appendLog("Starting VPN ($label)…")
    }

    // ── Subscription loading ──────────────────────────────────────────────────
    private fun loadSubscription() {
        val url = b.etSubUrl.text.toString().trim()
        if (url.isEmpty()) { toast("Paste a subscription URL first"); return }

        b.btnLoadSub.isEnabled = false
        b.btnLoadSub.text = "…"

        Thread {
            val result = runCatching { SubscriptionClient.fetch(url) }
            runOnUiThread {
                b.btnLoadSub.isEnabled = true
                b.btnLoadSub.text = "Load"
                result.onSuccess { list ->
                    if (list.isEmpty()) {
                        toast("No servers found in subscription")
                        return@onSuccess
                    }
                    servers = list
                    val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, list)
                    adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
                    b.spinnerServers.adapter = adapter
                    b.layoutServerList.visibility = android.view.View.VISIBLE
                    val connectable = list.count { it.connectable }
                    appendLog("Loaded ${list.size} servers ($connectable connectable)")
                }
                result.onFailure { e ->
                    toast("Failed to load: ${e.message}")
                    appendLog("Subscription error: $e")
                }
            }
        }.start()
    }

    // ── VLESS validation ──────────────────────────────────────────────────────
    private fun validateVless() {
        val url = b.etVlessUrl.text.toString().trim()
        if (url.isEmpty()) { toast("Paste a vless:// URL first"); return }
        val cfg = VlessConfig.parse(url)
        if (cfg == null) {
            b.tvVlessInfo.text = "❌ Invalid VLESS URL"
            b.tvVlessInfo.setTextColor(getColor(R.color.stopped))
        } else {
            b.tvVlessInfo.text =
                "✓ ${cfg.displayName}  •  ${cfg.security.uppercase()}  •  ${cfg.host}:${cfg.port}"
            b.tvVlessInfo.setTextColor(getColor(R.color.running))
        }
        b.tvVlessInfo.visibility = android.view.View.VISIBLE
    }

    // ── UI helpers ────────────────────────────────────────────────────────────
    private fun setRunning(isRunning: Boolean) {
        running = isRunning
        b.btnStartStop.text = if (isRunning) "■  STOP" else "▶  START"
        b.btnStartStop.setBackgroundColor(
            getColor(if (isRunning) R.color.stopped else R.color.running))

        b.tvStatus.text = if (isRunning) "● Running" else "● Stopped"
        b.tvStatus.setTextColor(getColor(if (isRunning) R.color.running else R.color.stopped))

        // Mode buttons: lock while running
        b.btnModeProxy.isEnabled = !isRunning
        b.btnModeVpn.isEnabled   = !isRunning

        if (!isRunning) {
            b.tvProxyAddress.text  = "—"
            b.tvProxyAddress.alpha = 0.4f
            b.tvStats.text         = ""
        } else if (!vpnMode) {
            val port = b.etPort.text.toString().trim()
            b.tvProxyAddress.text  = "127.0.0.1:$port  (tap to copy)"
            b.tvProxyAddress.alpha = 1f
        }
    }

    private fun updateStats(payload: String) {
        val parts = payload.split("/")
        if (parts.size != 2) return
        val inn  = parts[0].toLongOrNull() ?: return
        val outt = parts[1].toLongOrNull() ?: return
        b.tvStats.text = "↓ ${fmt(inn)}   ↑ ${fmt(outt)}"
    }

    private fun fmt(bytes: Long): String = when {
        bytes < 1024        -> "${bytes} B"
        bytes < 1024 * 1024 -> "${"%.1f".format(bytes / 1024.0)} KB"
        else                -> "${"%.2f".format(bytes / 1024.0 / 1024.0)} MB"
    }

    private fun appendLog(msg: String) {
        val ts = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date())
        b.tvLog.append("[$ts] $msg\n")
        b.scrollLog.post { b.scrollLog.fullScroll(android.view.View.FOCUS_DOWN) }
    }

    private fun copyAddress() {
        if (!running || vpnMode) return
        val text = "127.0.0.1:${b.etPort.text}"
        val cm = getSystemService(ClipboardManager::class.java)
        cm.setPrimaryClip(ClipData.newPlainText("proxy", text))
        toast("Copied: $text")
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
    }

    companion object {
        private const val VPN_REQ = 100
    }
}
