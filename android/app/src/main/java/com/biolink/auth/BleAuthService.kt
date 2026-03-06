package com.biolink.auth

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.ParcelUuid
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleService
import io.ktor.client.HttpClient
import io.ktor.client.engine.android.Android
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.Executors

/**
 * Foreground service that:
 *  1. Scans for the Arch BLE peripheral advertising [Constants.BLE_SERVICE_UUID].
 *  2. On discovery (with sufficient RSSI), connects and reads the challenge characteristic.
 *  3. Pops a [BiometricPrompt] to unlock the private key.
 *  4. Signs the 32-byte challenge and writes the signature back via BLE.
 *  5. Simultaneously attempts a WebSocket fallback channel (race condition – first wins).
 */
@SuppressLint("MissingPermission")
class BleAuthService : LifecycleService() {

    companion object {
        private const val TAG = "BleAuthService"

        fun start(context: Context) {
            val intent = Intent(context, BleAuthService::class.java)
            ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, BleAuthService::class.java))
        }
    }

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    private val serviceJob = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.IO + serviceJob)

    private var bleScanner: BluetoothLeScanner? = null
    private var gatt: BluetoothGatt? = null
    private var wsJob: Job? = null

    /** The 32-byte challenge currently being processed. */
    @Volatile
    private var pendingChallenge: ByteArray? = null

    private val wsClient = HttpClient(Android) {
        install(WebSockets)
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(Constants.NOTIF_ID_SERVICE, buildServiceNotification())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        startBleScanning()
        return START_STICKY
    }

    override fun onDestroy() {
        stopBleScanning()
        gatt?.disconnect()
        gatt?.close()
        wsClient.close()
        serviceJob.cancel()
        super.onDestroy()
    }

    // -------------------------------------------------------------------------
    // BLE scanning
    // -------------------------------------------------------------------------

    private fun startBleScanning() {
        val btManager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        val btAdapter: BluetoothAdapter = btManager.adapter ?: run {
            Log.e(TAG, "Bluetooth not available")
            return
        }
        bleScanner = btAdapter.bluetoothLeScanner
        val filter = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(Constants.BLE_SERVICE_UUID))
            .build()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_POWER)
            .build()
        bleScanner?.startScan(listOf(filter), settings, scanCallback)
        Log.i(TAG, "BLE scan started for UUID ${Constants.BLE_SERVICE_UUID}")
    }

    private fun stopBleScanning() {
        bleScanner?.stopScan(scanCallback)
        bleScanner = null
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val rssi = result.rssi
            Log.d(TAG, "Found device ${result.device.address} RSSI=$rssi")
            if (rssi < Constants.RSSI_THRESHOLD) {
                Log.d(TAG, "RSSI too low ($rssi < ${Constants.RSSI_THRESHOLD}), ignoring")
                return
            }
            stopBleScanning()
            connectToDevice(result.device)
        }

        override fun onScanFailed(errorCode: Int) {
            Log.e(TAG, "BLE scan failed: $errorCode")
        }
    }

    // -------------------------------------------------------------------------
    // BLE GATT connection
    // -------------------------------------------------------------------------

    private fun connectToDevice(device: BluetoothDevice) {
        Log.i(TAG, "Connecting to ${device.address}")
        gatt = device.connectGatt(this, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
    }

    private val gattCallback = object : BluetoothGattCallback() {

        override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    Log.i(TAG, "GATT connected, discovering services…")
                    g.discoverServices()
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    Log.i(TAG, "GATT disconnected, restarting scan")
                    gatt?.close()
                    gatt = null
                    startBleScanning()
                }
            }
        }

        override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                Log.e(TAG, "Service discovery failed: $status")
                return
            }
            val service = g.getService(Constants.BLE_SERVICE_UUID) ?: run {
                Log.e(TAG, "BioLink service not found")
                return
            }

            // Write our public key to the pairing characteristic (idempotent after first pair)
            val pubKeyChar = service.getCharacteristic(Constants.PUBKEY_CHAR_UUID)
            if (pubKeyChar != null && KeystoreManager.hasKeyPair()) {
                val pubKeyBytes = KeystoreManager.getPublicKey()?.encoded ?: return
                writeCharacteristic(g, pubKeyChar, pubKeyBytes)
            }

            // Enable notifications on the challenge characteristic
            val challengeChar = service.getCharacteristic(Constants.CHALLENGE_CHAR_UUID) ?: return
            g.setCharacteristicNotification(challengeChar, true)
            val descriptor = challengeChar.getDescriptor(
                UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
            )
            if (descriptor != null) {
                writeDescriptor(g, descriptor, BluetoothGattDescriptor.ENABLE_INDICATION_VALUE)
            }
        }

        override fun onCharacteristicChanged(
            g: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray
        ) {
            if (characteristic.uuid == Constants.CHALLENGE_CHAR_UUID) {
                Log.i(TAG, "Challenge received (${value.size} bytes)")
                handleChallenge(g, value)
            }
        }

        // Legacy callback for API < 33
        @Suppress("DEPRECATION")
        override fun onCharacteristicChanged(
            g: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic
        ) {
            if (characteristic.uuid == Constants.CHALLENGE_CHAR_UUID) {
                val value = characteristic.value ?: return
                Log.i(TAG, "Challenge received (${value.size} bytes) [legacy]")
                handleChallenge(g, value)
            }
        }

        override fun onCharacteristicWrite(
            g: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            Log.d(TAG, "Write to ${characteristic.uuid} status=$status")
        }
    }

    // -------------------------------------------------------------------------
    // Auth flow
    // -------------------------------------------------------------------------

    /**
     * Receives the 32-byte challenge from Arch and starts the BLE + WS race.
     */
    private fun handleChallenge(g: BluetoothGatt, challenge: ByteArray) {
        if (challenge.size != 32) {
            Log.e(TAG, "Invalid challenge length: ${challenge.size}")
            return
        }
        pendingChallenge = challenge

        notifyAuthRequest()

        // Start WebSocket race in parallel
        val wsUrl = getSharedPreferences(Constants.PREFS_NAME, MODE_PRIVATE)
            .getString(Constants.PREF_ARCH_WS_URL, null)
        if (wsUrl != null) {
            wsJob = scope.launch { attemptWsFallback(wsUrl, challenge) }
        }

        // Trigger biometric prompt via broadcast so MainActivity can show it
        sendBroadcast(
            Intent(ACTION_AUTH_REQUEST).apply {
                putExtra(EXTRA_CHALLENGE, challenge)
                putExtra(EXTRA_USE_BLE, true)
            }
        )
    }

    /**
     * Called by [MainActivity] (via [AuthResultReceiver]) after a successful biometric sign.
     */
    fun deliverSignature(signature: ByteArray) {
        wsJob?.cancel()
        scope.launch {
            sendSignatureViaBle(signature)
        }
    }

    private suspend fun sendSignatureViaBle(signature: ByteArray) {
        val g = gatt ?: return
        val service = g.getService(Constants.BLE_SERVICE_UUID) ?: return
        val sigChar = service.getCharacteristic(Constants.SIGNATURE_CHAR_UUID) ?: return
        writeCharacteristic(g, sigChar, signature)
        Log.i(TAG, "Signature written via BLE (${signature.size} bytes)")
    }

    // -------------------------------------------------------------------------
    // WebSocket fallback
    // -------------------------------------------------------------------------

    private suspend fun attemptWsFallback(wsUrl: String, challenge: ByteArray) {
        withTimeoutOrNull(Constants.WS_TIMEOUT_MS) {
            try {
                wsClient.webSocket(wsUrl) {
                    Log.i(TAG, "WS connected to $wsUrl")
                    // Wait for the server to echo back the same challenge as JSON
                    for (frame in incoming) {
                        if (frame is Frame.Text) {
                            val json = JSONObject(frame.readText())
                            val wsChallenge = json.optString("challenge")
                            // Convert hex challenge from server and match local copy
                            val serverBytes = try {
                                wsChallenge.chunked(2)
                                    .map { it.toInt(16).toByte() }.toByteArray()
                            } catch (_: NumberFormatException) {
                                Log.w(TAG, "WS: malformed hex challenge from server")
                                continue
                            }
                            if (serverBytes.contentEquals(challenge)) {
                                // Let the biometric result deliver the signature here too
                                Log.i(TAG, "WS challenge matched; awaiting biometric result")
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "WS fallback failed: ${e.message}")
            }
        }
    }

    // -------------------------------------------------------------------------
    // Notification helpers
    // -------------------------------------------------------------------------

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            Constants.NOTIF_CHANNEL_ID,
            Constants.NOTIF_CHANNEL_NAME,
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "BioLink authentication service"
        }
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(channel)
    }

    private fun buildServiceNotification(): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, Constants.NOTIF_CHANNEL_ID)
            .setContentTitle("BioLink Active")
            .setContentText("Scanning for authentication requests…")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun notifyAuthRequest() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val pi = PendingIntent.getActivity(
            this, 1,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notif = NotificationCompat.Builder(this, Constants.NOTIF_CHANNEL_ID)
            .setContentTitle("BioLink: Authenticate")
            .setContentText("Tap to verify your fingerprint")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pi)
            .build()
        nm.notify(Constants.NOTIF_ID_AUTH_REQUEST, notif)
    }

    // -------------------------------------------------------------------------
    // Compat write helpers (API 33 changed write APIs)
    // -------------------------------------------------------------------------

    @Suppress("DEPRECATION")
    private fun writeCharacteristic(
        g: BluetoothGatt,
        char: BluetoothGattCharacteristic,
        value: ByteArray
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            g.writeCharacteristic(char, value, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT)
        } else {
            char.value = value
            g.writeCharacteristic(char)
        }
    }

    @Suppress("DEPRECATION")
    private fun writeDescriptor(
        g: BluetoothGatt,
        descriptor: BluetoothGattDescriptor,
        value: ByteArray
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            g.writeDescriptor(descriptor, value)
        } else {
            descriptor.value = value
            g.writeDescriptor(descriptor)
        }
    }

    companion object ActionNames {
        const val ACTION_AUTH_REQUEST = "com.biolink.auth.ACTION_AUTH_REQUEST"
        const val EXTRA_CHALLENGE = "challenge"
        const val EXTRA_USE_BLE = "use_ble"
    }
}
