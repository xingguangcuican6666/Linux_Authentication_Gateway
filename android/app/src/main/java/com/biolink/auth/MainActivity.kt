package com.biolink.auth

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import com.biolink.auth.databinding.ActivityMainBinding
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import java.security.Signature

/**
 * Single-screen activity that:
 *  - Generates / displays the public key as a QR code for pairing with Arch.
 *  - Receives auth-request broadcasts from [BleAuthService] and pops a [BiometricPrompt].
 *  - Stores the WebSocket URL for the fallback channel.
 */
class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "MainActivity"
    }

    private lateinit var binding: ActivityMainBinding

    // -------------------------------------------------------------------------
    // Permissions
    // -------------------------------------------------------------------------

    private val requiredPermissions: Array<String>
        get() = buildList {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                add(Manifest.permission.BLUETOOTH_SCAN)
                add(Manifest.permission.BLUETOOTH_CONNECT)
                add(Manifest.permission.BLUETOOTH_ADVERTISE)
            } else {
                add(Manifest.permission.BLUETOOTH)
                add(Manifest.permission.BLUETOOTH_ADMIN)
                add(Manifest.permission.ACCESS_FINE_LOCATION)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                add(Manifest.permission.POST_NOTIFICATIONS)
            }
        }.toTypedArray()

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        val denied = grants.filterValues { !it }.keys
        if (denied.isEmpty()) {
            onPermissionsGranted()
        } else {
            Toast.makeText(this, "Permissions denied: $denied", Toast.LENGTH_LONG).show()
            Log.e(TAG, "Denied: $denied")
        }
    }

    // -------------------------------------------------------------------------
    // Broadcast receiver – receives challenge from BleAuthService
    // -------------------------------------------------------------------------

    private val authReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == BleAuthService.ACTION_AUTH_REQUEST) {
                Log.d(TAG, "Auth request broadcast received.")
                val challenge = intent.getByteArrayExtra(BleAuthService.EXTRA_CHALLENGE)
                if (challenge == null) {
                    Log.e(TAG, "Auth request received but no challenge extra found.")
                    return
                }
                Log.d(TAG, "Challenge extracted, size: ${challenge.size}")
                showBiometricPrompt(challenge)
            }
        }
    }

    // -------------------------------------------------------------------------
    // Activity lifecycle
    // -------------------------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupUi()

        // Initialise key pair on first launch
        if (!KeystoreManager.hasKeyPair()) {
            KeystoreManager.generateKeyPair()
            Toast.makeText(this, "Key pair generated in TEE", Toast.LENGTH_SHORT).show()
        }
        displayPublicKeyQr()

        checkAndRequestPermissions()
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter(BleAuthService.ACTION_AUTH_REQUEST)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(authReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(authReceiver, filter)
        }
    }

    override fun onPause() {
        super.onPause()
        unregisterReceiver(authReceiver)
    }

    // -------------------------------------------------------------------------
    // UI setup
    // -------------------------------------------------------------------------

    private fun setupUi() {
        binding.btnGenerateKey.setOnClickListener {
            KeystoreManager.generateKeyPair()
            displayPublicKeyQr()
            Toast.makeText(this, "New key pair generated", Toast.LENGTH_SHORT).show()
        }

        binding.btnStartService.setOnClickListener {
            BleAuthService.start(this)
            binding.tvStatus.text = getString(R.string.status_scanning)
        }

        binding.btnStopService.setOnClickListener {
            BleAuthService.stop(this)
            binding.tvStatus.text = getString(R.string.status_stopped)
        }

        binding.btnSaveWsUrl.setOnClickListener {
            val url = binding.etWsUrl.text.toString().trim()
            if (url.isNotEmpty()) {
                getSharedPreferences(Constants.PREFS_NAME, MODE_PRIVATE).edit()
                    .putString(Constants.PREF_ARCH_WS_URL, url)
                    .apply()
                Toast.makeText(this, "WebSocket URL saved", Toast.LENGTH_SHORT).show()
            }
        }

        // Populate saved WS URL
        val savedUrl = getSharedPreferences(Constants.PREFS_NAME, MODE_PRIVATE)
            .getString(Constants.PREF_ARCH_WS_URL, "")
        binding.etWsUrl.setText(savedUrl)
    }

    // -------------------------------------------------------------------------
    // QR code display
    // -------------------------------------------------------------------------

    private fun displayPublicKeyQr() {
        val pubKey = KeystoreManager.getPublicKey() ?: return
        val b64 = Base64.encodeToString(pubKey.encoded, Base64.NO_WRAP)
        binding.tvPublicKeyB64.text = b64
        binding.ivQrCode.setImageBitmap(generateQrBitmap(b64))
    }

    private fun generateQrBitmap(content: String, size: Int = 600): Bitmap {
        val writer = QRCodeWriter()
        val matrix = writer.encode(content, BarcodeFormat.QR_CODE, size, size)
        val pixels = IntArray(size * size) { i ->
            val x = i % size
            val y = i / size
            if (matrix[x, y]) android.graphics.Color.BLACK else android.graphics.Color.WHITE
        }
        val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565)
        bmp.setPixels(pixels, 0, size, 0, 0, size, size)
        return bmp
    }

    // -------------------------------------------------------------------------
    // Biometric prompt
    // -------------------------------------------------------------------------

    private fun showBiometricPrompt(challenge: ByteArray) {
        Log.d(TAG, "showBiometricPrompt called.")
        if (!canUseBiometrics()) {
            Log.w(TAG, "Biometrics not available or not enrolled.")
            Toast.makeText(this, "Biometrics not available", Toast.LENGTH_SHORT).show()
            return
        }
        Log.d(TAG, "Biometrics are available.")

        val signature: Signature = try {
            KeystoreManager.initSignature()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to init signature: ${e.message}")
            Toast.makeText(this, "Key unavailable – regenerate key pair", Toast.LENGTH_LONG).show()
            return
        }

        val cryptoObject = BiometricPrompt.CryptoObject(signature)
        val executor = ContextCompat.getMainExecutor(this)

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.biometric_title))
            .setSubtitle(getString(R.string.biometric_subtitle))
            .setDescription(getString(R.string.biometric_description))
            .setNegativeButtonText(getString(R.string.biometric_cancel))
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        val biometricPrompt = BiometricPrompt(
            this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val sig = result.cryptoObject?.signature ?: return
                    sig.update(challenge)
                    val signatureBytes = sig.sign()
                    Log.i(TAG, "Biometric auth succeeded, signature ${signatureBytes.size} bytes")

                    // Deliver via the service (handles BLE write + WS)
                    (application as? BioLinkApp)?.authService?.deliverSignature(signatureBytes)

                    runOnUiThread {
                        binding.tvStatus.text = getString(R.string.status_auth_success)
                    }
                }

                override fun onAuthenticationFailed() {
                    Log.w(TAG, "Biometric auth failed")
                    runOnUiThread {
                        binding.tvStatus.text = getString(R.string.status_auth_failed)
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    Log.e(TAG, "Biometric error $errorCode: $errString")
                    runOnUiThread {
                        binding.tvStatus.text = getString(R.string.status_auth_error, errString)
                    }
                }
            }
        )
        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }

    private fun canUseBiometrics(): Boolean {
        val bm = BiometricManager.from(this)
        return bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS
    }

    // -------------------------------------------------------------------------
    // Permissions
    // -------------------------------------------------------------------------

    private fun checkAndRequestPermissions() {
        val missing = requiredPermissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isEmpty()) {
            onPermissionsGranted()
        } else {
            permissionLauncher.launch(missing.toTypedArray())
        }
    }

    private fun onPermissionsGranted() {
        Log.i(TAG, "All permissions granted")
        BleAuthService.start(this)
        binding.tvStatus.text = getString(R.string.status_scanning)
    }
}
