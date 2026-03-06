package com.biolink.adbauth

import java.util.UUID

/**
 * Application-wide constants for the ADB authentication module.
 */
object Constants {

    // -------------------------------------------------------------------------
    // Android Keystore
    // -------------------------------------------------------------------------

    /** Alias used to store the ECDSA key-pair in Android Keystore / TEE. */
    const val KEYSTORE_ALIAS = "biolink_ecdsa_key_adb" // Changed alias to avoid conflict

    /** EC curve for the signing key pair. */
    const val KEY_ALGORITHM = "EC"

    /** JCA algorithm used to sign the challenge. */
    const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

    // -------------------------------------------------------------------------
    // Preferences
    // -------------------------------------------------------------------------

    const val PREFS_NAME = "biolink_adb_prefs" // Changed preference name
}