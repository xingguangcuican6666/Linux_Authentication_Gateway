package com.biolink.auth

import java.util.UUID

/**
 * Application-wide constants shared between the Android app components and the Arch daemon.
 *
 * The BLE service UUID and characteristic UUIDs **must** match the values configured in the
 * Arch-side `biolink_daemon.py`.
 */
object Constants {

    // -------------------------------------------------------------------------
    // BLE identifiers  (must match arch-daemon/biolink_daemon.py)
    // -------------------------------------------------------------------------

    /** Primary GATT service advertised by the Arch daemon. */
    val BLE_SERVICE_UUID: UUID = UUID.fromString("12345678-1234-5678-1234-56789abcdef0")

    /**
     * Characteristic written by Arch → Android: a 32-byte random challenge.
     * Properties: WRITE | INDICATE
     */
    val CHALLENGE_CHAR_UUID: UUID = UUID.fromString("12345678-1234-5678-1234-56789abcdef1")

    /**
     * Characteristic written by Android → Arch: the ECDSA signature over the challenge.
     * Properties: WRITE
     */
    val SIGNATURE_CHAR_UUID: UUID = UUID.fromString("12345678-1234-5678-1234-56789abcdef2")

    /**
     * Characteristic written by Android → Arch: the DER-encoded public key (one-time pairing).
     * Properties: READ | WRITE
     */
    val PUBKEY_CHAR_UUID: UUID = UUID.fromString("12345678-1234-5678-1234-56789abcdef3")

    // -------------------------------------------------------------------------
    // Android Keystore
    // -------------------------------------------------------------------------

    /** Alias used to store the ECDSA key-pair in Android Keystore / TEE. */
    const val KEYSTORE_ALIAS = "biolink_ecdsa_key"

    /** EC curve for the signing key pair. */
    const val KEY_ALGORITHM = "EC"

    /** JCA algorithm used to sign the challenge. */
    const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

    // -------------------------------------------------------------------------
    // BLE scanning
    // -------------------------------------------------------------------------

    /**
     * Minimum RSSI (dBm) required to consider an Arch device "nearby".
     *
     * - `-70 dBm` ≈ ~10 m line-of-sight (permissive; typical for same-room use).
     * - `-60 dBm` ≈ ~5 m  (stricter; recommended for high-security environments).
     * - `-50 dBm` ≈ ~2 m  (very strict; requires being close to the monitor).
     *
     * Adjust downward (more negative) to increase the allowed range, or upward
     * (less negative) to require closer proximity.
     */
    const val RSSI_THRESHOLD = -70

    /** How many milliseconds to wait for a BLE connection before timing out. */
    const val BLE_CONNECT_TIMEOUT_MS = 10_000L

    // -------------------------------------------------------------------------
    // WebSocket fallback
    // -------------------------------------------------------------------------

    /** Default WebSocket port used by the Arch daemon when in LAN mode. */
    const val WS_DEFAULT_PORT = 7777

    /** Timeout for a complete WebSocket authentication round-trip (ms). */
    const val WS_TIMEOUT_MS = 15_000L

    // -------------------------------------------------------------------------
    // Notifications
    // -------------------------------------------------------------------------

    const val NOTIF_CHANNEL_ID = "biolink_service"
    const val NOTIF_CHANNEL_NAME = "BioLink Auth Service"
    const val NOTIF_ID_SERVICE = 1
    const val NOTIF_ID_AUTH_REQUEST = 2

    // -------------------------------------------------------------------------
    // Preferences
    // -------------------------------------------------------------------------

    const val PREFS_NAME = "biolink_prefs"
    const val PREF_PAIRED_DEVICE_ADDRESS = "paired_device_address"
    const val PREF_ARCH_WS_URL = "arch_ws_url"
}
