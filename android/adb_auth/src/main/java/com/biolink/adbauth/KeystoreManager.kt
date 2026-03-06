package com.biolink.adbauth

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import javax.crypto.Cipher

/**
 * Manages the ECDSA key-pair stored inside the Android Keystore / TEE.
 *
 * - The private key **never** leaves the secure hardware element.
 * - `setUserAuthenticationRequired(true)` means the private key can only be
 *   used after a successful biometric (fingerprint) authentication.
 * - On devices with a StrongBox chip the key is generated inside that chip;
 *   otherwise it falls back to the regular TEE.
 */
object KeystoreManager {

    private const val TAG = "KeystoreManager"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    // -------------------------------------------------------------------------
    // Key lifecycle
    // -------------------------------------------------------------------------

    /**
     * Generates a new ECDSA P-256 key-pair inside the TEE.
     * If a key with [Constants.KEYSTORE_ALIAS] already exists it is deleted first
     * so callers can force re-pairing.
     */
    fun generateKeyPair() {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (ks.containsAlias(Constants.KEYSTORE_ALIAS)) {
            Log.i(TAG, "Deleting existing key before regeneration")
            ks.deleteEntry(Constants.KEYSTORE_ALIAS)
        }

        val spec = KeyGenParameterSpec.Builder(
            Constants.KEYSTORE_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            // Private key usage requires fresh biometric confirmation each time
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                0,   // validity: 0 = must authenticate for every use
                KeyProperties.AUTH_BIOMETRIC_STRONG
            )
            // Invalidate on new biometric enrolment (security best-practice)
            .setInvalidatedByBiometricEnrollment(true)
            // Try StrongBox first; fall back gracefully if unavailable
            .apply {
                try {
                    setIsStrongBoxBacked(true)
                } catch (_: Exception) {
                    Log.w(TAG, "StrongBox not available, using TEE")
                }
            }
            .build()

        val kpg = KeyPairGenerator.getInstance(
            Constants.KEY_ALGORITHM, ANDROID_KEYSTORE
        )
        kpg.initialize(spec)
        kpg.generateKeyPair()
        Log.i(TAG, "ECDSA P-256 key generated in TEE")
    }

    /** Returns true when a key-pair with [Constants.KEYSTORE_ALIAS] already exists. */
    fun hasKeyPair(): Boolean {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return ks.containsAlias(Constants.KEYSTORE_ALIAS)
    }

    /** Retrieves the public key; returns null if no key-pair has been generated. */
    fun getPublicKey(): PublicKey? {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return ks.getCertificate(Constants.KEYSTORE_ALIAS)?.publicKey
    }

    /**
     * Returns a [Signature] object initialised with the private key for signing.
     *
     * The caller must associate this [Signature] with a [BiometricPrompt.CryptoObject]
     * and let the biometric stack unlock the private key before calling [Signature.sign].
     */
    fun initSignature(): Signature {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val privateKey = ks.getKey(Constants.KEYSTORE_ALIAS, null) as PrivateKey
        return Signature.getInstance(Constants.SIGNATURE_ALGORITHM).apply {
            initSign(privateKey)
        }
    }

    /**
     * Verifies [signature] (DER-encoded ECDSA) over [challenge] using [publicKeyBytes]
     * (X.509 SubjectPublicKeyInfo encoded).
     *
     * Used by unit tests and the Arch-side mirror implementation; the daemon
     * uses Python's `cryptography` library for the same operation.
     */
    fun verifySignature(
        challenge: ByteArray,
        signature: ByteArray,
        publicKeyBytes: ByteArray
    ): Boolean {
        return try {
            val kf = java.security.KeyFactory.getInstance("EC")
            val pubKey = kf.generatePublic(java.security.spec.X509EncodedKeySpec(publicKeyBytes))
            Signature.getInstance(Constants.SIGNATURE_ALGORITHM).run {
                initVerify(pubKey)
                update(challenge)
                verify(signature)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Signature verification failed: ${e.message}")
            false
        }
    }
}
