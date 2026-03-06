# BioLink-4FA – Linux Authentication Gateway

[![Android CI](https://github.com/xingguangcuican6666/Linux_Authentication_Gateway/actions/workflows/android.yml/badge.svg)](https://github.com/xingguangcuican6666/Linux_Authentication_Gateway/actions/workflows/android.yml)

A **4FA (Four-Factor Authentication)** system for Arch Linux + Hyprland that adds
**phone presence (BLE) + hardware fingerprint (TEE)** on top of the existing
**password + face (Howdy)** stack.

```
Factor 1: UNIX password          (pam_unix)
Factor 2: Face recognition       (Howdy / pam_howdy)
Factor 3: Phone BLE proximity    (BioLink daemon – confirms you are near the PC)
Factor 4: Hardware fingerprint   (BioLink Android app – TEE-backed ECDSA signature)
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Arch Linux (Hyprland)                                       │
│                                                              │
│  PAM stack                                                   │
│    pam_unix  ──►  pam_howdy  ──►  pam_exec biolink-client   │
│                                          │                   │
│                                   Unix socket                │
│                                          │                   │
│                               ┌──────────▼──────────┐       │
│                               │  biolink_daemon.py   │       │
│                               │  • BLE GATT server   │       │
│                               │  • WebSocket server  │       │
│                               └──────┬───────┬───────┘       │
└──────────────────────────────────────┼───────┼───────────────┘
                                       │ BLE   │ WebSocket (LAN)
                               ┌───────▼───────▼────────┐
                               │   Android (BioLink App) │
                               │   • BLE GATT client     │
                               │   • Android Keystore    │
                               │   • BiometricPrompt     │
                               │   • TEE ECDSA signing   │
                               └────────────────────────┘
```

### Dual-link (Race Condition) Design

The daemon simultaneously sends the challenge over **BLE** and **WebSocket**.
Whichever channel gets the signed response back first wins:

- **BLE** – works without Wi-Fi; physical proximity is itself a security layer.
- **WebSocket** – near-instant on LAN when Wi-Fi is up.

---

## Repository Layout

```
.
├── android/                    Kotlin Android app (BLE + Keystore + BiometricPrompt)
│   ├── app/src/main/
│   │   ├── AndroidManifest.xml
│   │   └── java/com/biolink/auth/
│   │       ├── BioLinkApp.kt         Application class
│   │       ├── BleAuthService.kt     Foreground BLE service + WS fallback
│   │       ├── Constants.kt          Shared UUIDs / constants
│   │       ├── KeystoreManager.kt    TEE key generation & ECDSA signing
│   │       └── MainActivity.kt       QR pairing UI + BiometricPrompt
│   └── gradle/libs.versions.toml
│
├── arch-daemon/                Python daemon (BlueZ + WebSocket + PAM)
│   ├── biolink_daemon.py       Main BLE GATT server & WS server
│   ├── biolink_client.py       PAM pam_exec client
│   ├── biolink_pair.py         One-time pairing helper
│   ├── biolink.service         systemd unit file
│   ├── pam-config.example      PAM stack examples
│   ├── install.sh              Installation script
│   ├── requirements.txt        Python dependencies
│   └── tests/
│       └── test_biolink.py     Unit tests (ECDSA, state machine, bypass)
│
└── .github/workflows/
    └── android.yml             CI: build → sign → GitHub Release
```

---

## Quick Start

### 1. Android App

#### Option A – Download signed APK (recommended)

Download the latest signed APK from [Releases](../../releases) and install it on your phone.

#### Option B – Build from source

```bash
cd android
./gradlew assembleRelease
```

> **CI builds** are automatically signed and published to GitHub Releases when a
> `v*` tag is pushed (see [GitHub CI/CD](#github-cicd) below).

#### First-time setup on the phone

1. Open the **BioLink 4FA** app.
2. Grant all requested permissions (Bluetooth, Notifications).
3. The app generates an ECDSA P-256 key pair inside the **Android Keystore / TEE**.
   The **private key never leaves the secure hardware element**.
4. The QR code / Base64 string displayed is the **public key** – copy it for pairing.

---

### 2. Arch Linux Daemon

#### Install

```bash
# Clone / copy the repo, then:
sudo bash arch-daemon/install.sh
```

This installs:
- `/usr/lib/biolink/biolink_daemon.py` – the daemon
- `/usr/bin/biolink-client` – the PAM exec client
- `/usr/bin/biolink-pair` – the pairing helper
- `/etc/systemd/system/biolink.service` – the systemd unit

#### Pair with your phone

```bash
# Paste the Base64 public key from the app:
sudo biolink-pair --pubkey "<paste Base64 here>"

# Or interactively:
sudo biolink-pair
```

The public key is saved to `/etc/biolink/pubkey.pem`.

#### Verify the daemon is running

```bash
systemctl status biolink
journalctl -u biolink -f
```

---

### 3. PAM Integration

Edit your lockscreen PAM file.  For **hyprlock**:

```bash
sudo nano /etc/pam.d/hyprlock
```

Add the BioLink line (see `arch-daemon/pam-config.example` for the full stack):

```
# 4FA stack
auth  required  pam_unix.so
auth  required  pam_howdy.so
auth  required  pam_exec.so expose_authtok /usr/bin/biolink-client
```

> ⚠️ **Test in a separate terminal before closing your current session.**

---

## Emergency Bypass

If your phone is unavailable (lost, discharged, …), use the emergency bypass token:

```bash
# Set up the bypass (do this now, before you need it):
echo -n 'your-offline-secret' | sha256sum | awk '{print $1}' \
  | sudo tee /etc/biolink/bypass_hash > /dev/null

# Print a copy and store it somewhere physically safe (paper, safe, etc.)
```

At login time, set the environment variable **before** the PAM session:

```bash
export BIOLINK_BYPASS_TOKEN='your-offline-secret'
```

---

## GitHub CI/CD

The workflow in `.github/workflows/android.yml`:

| Step | Description |
|------|-------------|
| Checkout | Pull source |
| Java 17 | Set up build environment |
| Decode keystore | Base64-decode `RELEASE_KEYSTORE` secret → `release.jks` |
| Build | `./gradlew assembleRelease` |
| Sign APK | V2/V3 signature via `r0adkll/sign-android-release` |
| Upload artifact | Always (debug: PR; signed: push to main) |
| Create Release | On `v*` tag push – attaches signed APK |

### Required Secrets

| Secret | Description |
|--------|-------------|
| `RELEASE_KEYSTORE` | `base64 release.jks` |
| `RELEASE_KEYSTORE_PASSWORD` | Keystore password |
| `RELEASE_KEY_ALIAS` | Key alias inside keystore |
| `RELEASE_KEY_PASSWORD` | Key password |

Generate a keystore:

```bash
keytool -genkey -v -keystore release.jks \
  -alias biolink -keyalg EC -keysize 256 \
  -validity 10000 -storetype PKCS12

# Encode for GitHub Secret:
base64 -w 0 release.jks
```

---

## Security Notes

- The Android private key is generated inside the **TEE (Trusted Execution Environment)**
  or **StrongBox** and is bound to biometric authentication
  (`setUserAuthenticationRequired(true)`).  The key is invalidated automatically
  if new fingerprints are enrolled.
- BLE physical proximity provides an implicit "something you have / are near" factor.
- The 32-byte challenge is freshly generated with `secrets.token_bytes(32)` for
  every authentication event – no replay attacks.
- The PAM bypass uses SHA-256 hashed token comparison to avoid storing secrets in
  plaintext on disk.
- The systemd unit runs as a dedicated `biolink` system user with
  `NoNewPrivileges=true` and a strict `CapabilityBoundingSet`.

---

## Development

### Run Python tests

```bash
cd arch-daemon
pip install -r requirements.txt pytest
python -m pytest tests/ -v
```

### Lint Android code

```bash
cd android
./gradlew lint
```

### Build debug APK

```bash
cd android
./gradlew assembleDebug
# Output: app/build/outputs/apk/debug/app-debug.apk
```
