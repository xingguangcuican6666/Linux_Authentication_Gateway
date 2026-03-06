package com.biolink.adbauth

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.Signature

class AdbAuthActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "AdbAuthActivity"
        const val ACTION_AUTH = "com.biolink.adbauth.ACTION_AUTH"
        const val ACTION_GET_PUBKEY = "com.biolink.adbauth.ACTION_GET_PUBKEY"
        const val EXTRA_CHALLENGE = "challenge"

        // Result file names
        private const val RESULT_FILE_NAME = "adb_auth_result.txt"
        private const val PUBKEY_FILE_NAME = "adb_pubkey.txt"

        fun getResultFile(context: Context): File {
            return File(context.cacheDir, RESULT_FILE_NAME)
        }

        fun getPubkeyFile(context: Context): File {
            return File(context.cacheDir, PUBKEY_FILE_NAME)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // This activity is headless, no UI to set
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        if (intent == null) {
            logAndWriteResult("FAIL: No intent received", "NO_INTENT")
            finish()
            return
        }

        when (intent.action) {
            ACTION_AUTH -> {
                // Get challenge as Base64 string and decode
                val challengeB64 = intent.getStringExtra(EXTRA_CHALLENGE)
                if (challengeB64.isNullOrEmpty()) {
                    logAndWriteResult("FAIL: No challenge provided", "NO_CHALLENGE")
                    finish()
                    return
                }
                val challenge = try {
                    Base64.decode(challengeB64, Base64.NO_WRAP)
                } catch (e: IllegalArgumentException) {
                    logAndWriteResult("FAIL: Invalid Base64 challenge: ${e.message}", "INVALID_CHALLENGE_B64")
                    finish()
                    return
                }
                Log.d(TAG, "Auth request received with challenge size: ${challenge.size}")
                showBiometricPrompt(challenge)
            }
            ACTION_GET_PUBKEY -> {
                Log.d(TAG, "Public key request received")
                if (!KeystoreManager.hasKeyPair()) {
                    Log.i(TAG, "Generating new key pair for ADB Auth.")
                    KeystoreManager.generateKeyPair()
                }
                val pubKey = KeystoreManager.getPublicKey()
                if (pubKey != null) {
                    val pubKeyB64 = Base64.encodeToString(pubKey.encoded, Base64.NO_WRAP)
                    logAndWriteResult("OK", pubKeyB64, getPubkeyFile(this))
                } else {
                    logAndWriteResult("FAIL: Failed to get public key", "NO_PUBKEY")
                }
                finish()
            }
            else -> {
                logAndWriteResult("FAIL: Unknown action: ${intent.action}", "UNKNOWN_ACTION")
                finish()
            }
        }
    }

    private fun showBiometricPrompt(challenge: ByteArray) {
        if (!canUseBiometrics()) {
            logAndWriteResult("FAIL: Biometrics not available or not enrolled.", "BIOMETRICS_UNAVAILABLE")
            finish()
            return
        }

        val signature: Signature = try {
            KeystoreManager.initSignature()
        } catch (e: Exception) {
            logAndWriteResult("FAIL: Failed to init signature: ${e.message}", "INIT_SIGNATURE_FAILED")
            finish()
            return
        }

        val cryptoObject = BiometricPrompt.CryptoObject(signature)
        val executor = ContextCompat.getMainExecutor(this)

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("BioLink ADB Auth")
            .setSubtitle("Verify your fingerprint to authenticate")
            .setDescription("Confirm your identity using your biometric credential.")
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        val biometricPrompt = BiometricPrompt(
            this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val sig = result.cryptoObject?.signature ?: run {
                        logAndWriteResult("FAIL: Biometric success but no signature object", "NO_SIG_OBJECT")
                        finish()
                        return
                    }
                    sig.update(challenge)
                    val signatureBytes = sig.sign()
                    val signatureB64 = Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
                    Log.i(TAG, "Biometric auth succeeded, signature ${signatureBytes.size} bytes")
                    logAndWriteResult("OK", signatureB64)
                    finish()
                }

                override fun onAuthenticationFailed() {
                    Log.w(TAG, "Biometric auth failed")
                    logAndWriteResult("FAIL", "AUTH_FAILED")
                    finish()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    Log.e(TAG, "Biometric error $errorCode: $errString")
                    logAndWriteResult("FAIL: Biometric error $errorCode: $errString", "AUTH_ERROR:$errorCode")
                    finish()
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

    private fun logAndWriteResult(logMessage: String, resultString: String, file: File = getResultFile(this)) {
        Log.d(TAG, logMessage)
        try {
            FileOutputStream(file).use {
                it.write(resultString.toByteArray())
            }
        } catch (e: IOException) {
            Log.e(TAG, "Failed to write result to file: ${e.message}")
        }
    }
}
