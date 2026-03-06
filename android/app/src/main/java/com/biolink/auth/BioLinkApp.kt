package com.biolink.auth

import android.app.Application

/**
 * Application class – holds a reference to the bound [BleAuthService] instance
 * so that [MainActivity] can call [BleAuthService.deliverSignature] after a
 * successful biometric authentication.
 *
 * The service binding is optional; the service also receives the signature via
 * an [Intent] broadcast as a fallback.
 */
class BioLinkApp : Application() {

    /** Non-null while [BleAuthService] is running and has been bound. */
    var authService: BleAuthService? = null
}
