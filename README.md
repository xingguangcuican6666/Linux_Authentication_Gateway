# BioLink-ADB – Linux Authentication Gateway

[![Android CI](https://github.com/xingguangcuican6666/Linux_Authentication_Gateway/actions/workflows/android.yml/badge.svg)](https://github.com/xingguangcuican6666/Linux_Authentication_Gateway/actions/workflows/android.yml)

一个用于 Arch Linux + Hyprland 的**基于 ADB 的指纹认证系统**，它在现有的
**密码 + 人脸识别 (Howdy)** 栈之上，增加了**手机硬件指纹 (TEE)** 认证。

```
Factor 1: UNIX password          (pam_unix)
Factor 2: Face recognition       (Howdy / pam_howdy)
Factor 3: Phone hardware fingerprint (BioLink AdbAuth App – TEE-backed ECDSA signature)
```

---

## 架构

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
│                               │  • ADB interaction   │       │
│                               └──────────┬───────────┘       │
└──────────────────────────────────────────┼───────────────────┘
                                           │ ADB
                               ┌───────────▼───────────┐
                               │  Android (AdbAuth App)  │
                               │  • Receives ADB intents │
                               │  • Android Keystore     │
                               │  • BiometricPrompt      │
                               │  • TEE ECDSA signing    │
                               └─────────────────────────┘
```

---

## 仓库布局

```
.
├── android/                    Kotlin Android 项目
│   ├── app/                    原始的 BLE 认证 App (不再使用)
│   ├── adb_auth/               无头 ADB 认证 App
│   │   ├── src/main/
│   │   │   ├── AndroidManifest.xml
│   │   │   └── java/com/biolink/adbauth/
│   │   │       ├── AdbAuthActivity.kt    ADB 命令入口，BiometricPrompt + 签名
│   │   │       ├── Constants.kt          共享常量
│   │   │       └── KeystoreManager.kt    TEE 密钥生成 & ECDSA 签名
│   │   └── build.gradle.kts
│   ├── build.gradle.kts
│   └── settings.gradle.kts
│
├── arch-daemon/                Python 守护进程 (ADB + PAM)
│   ├── biolink_daemon.py       主守护进程，处理 PAM 请求和 ADB 通信
│   ├── biolink_client.py       PAM pam_exec 客户端
│   ├── biolink.service         systemd 单元文件
│   ├── pam-config.example      PAM 栈示例
│   ├── install.sh              安装脚本
│   ├── requirements.txt        Python 依赖
│   └── tests/
│       └── test_biolink.py     单元测试 (ECDSA, 状态机, 绕过)
│
└── .github/workflows/
    └── android.yml             CI: build → sign → GitHub Release
```

---

## 快速开始

### 1. 手机端 AdbAuth App

请确保您的 Android 设备已开启 USB 调试，并通过数据线连接到此电脑。

#### 构建并安装 App

1.  **构建 ADB 认证应用:**
    ```bash
    cd android
    ./gradlew :adb_auth:assembleDebug
    ```
    这将在 `android/adb_auth/build/outputs/apk/debug/adb_auth-debug.apk` 生成一个调试 APK 文件。

2.  **安装应用至手机:**
    ```bash
    adb install ./adb_auth/build/outputs/apk/debug/adb_auth-debug.apk
    ```
    请确保 `adb` 工具已安装并可在 PATH 中找到。

#### 首次设置与配对

1.  **在手机上进行首次设置 (生成密钥):**
    在应用安装后，第一次尝试配对时，App 会自动生成一个 ECDSA P-256 密钥对，存储在 **Android Keystore / TEE** 中。**私钥永远不会离开安全硬件单元**。
2.  **进行公钥配对:**
    ```bash
    sudo /usr/lib/biolink/biolink_daemon.py --pair
    ```
    此时手机上会弹出指纹认证提示，请验证。验证成功后，公钥将从手机检索并保存到 `/etc/biolink/pubkey.pem`。

### 2. Arch Linux 守护进程

#### 安装

```bash
# 克隆 / 复制仓库，然后:
sudo bash arch-daemon/install.sh
```

这将安装:
- `/usr/lib/biolink/biolink_daemon.py` – 守护进程
- `/usr/bin/biolink-client` – PAM exec 客户端
- `/etc/systemd/system/biolink.service` – systemd 单元文件

#### 验证守护进程是否运行

```bash
systemctl status biolink
journalctl -u biolink -f
```

---

### 3. PAM 集成

编辑您的锁屏 PAM 文件。对于 **hyprlock**:

```bash
sudo nano /etc/pam.d/hyprlock
```

添加 BioLink 行 (请参阅 `arch-daemon/pam-config.example` 获取完整栈示例):

```
# 认证栈
auth  required  pam_unix.so
auth  required  pam_howdy.so
auth  required  pam_exec.so expose_authtok /usr/bin/biolink-client
```

> ⚠️ **警告**: 在完全测试通过之前，请勿关闭您的当前终端会话，以免被锁定。

---

## 紧急绕过

如果您的手机不可用 (丢失、没电等)，请使用紧急绕过令牌:

```bash
# 设置绕过令牌 (请立即设置，以防需要):
echo -n 'your-offline-secret' | sha256sum | awk '{print $1}' 
  | sudo tee /etc/biolink/bypass_hash > /dev/null

# 打印一份副本并将其存储在物理安全的地方 (纸质备份、保险箱等)
```

登录时，在 PAM 会话**之前**设置环境变量:

```bash
export BIOLINK_BYPASS_TOKEN='your-offline-secret'
```

---

## GitHub CI/CD

工作流 `.github/workflows/android.yml` 将需要更新以构建 `adb_auth` 模块。

| 步骤 | 描述 |
|------|-------------|
| Checkout | 拉取源代码 |
| Java 17 | 设置构建环境 |
| Decode keystore | Base64 解码 `RELEASE_KEYSTORE` 密钥 → `release.jks` |
| Build | `./gradlew :adb_auth:assembleRelease` |
| Sign APK | 通过 `r0adkll/sign-android-release` 进行 V2/V3 签名 |
| Upload artifact | 始终 (调试: PR; 签名: push 到主分支) |
| Create Release | 在 `v*` 标签 push 时 – 附加签名 APK |

### 所需 Secrets

| Secret | 描述 |
|--------|-------------|
| `RELEASE_KEYSTORE` | `base64 release.jks` |
| `RELEASE_KEYSTORE_PASSWORD` | 密钥库密码 |
| `RELEASE_KEY_ALIAS` | 密钥库内的别名 |
| `RELEASE_KEY_PASSWORD` | 密钥密码 |

生成密钥库:

```bash
keytool -genkey -v -keystore release.jks 
  -alias biolink -keyalg EC -keysize 256 
  -validity 10000 -storetype PKCS12

# 编码为 GitHub Secret:
base64 -w 0 release.jks
```

---

## 安全注意事项

- Android 私钥在 **TEE (可信执行环境)** 或 **StrongBox** 中生成，并与生物识别认证绑定
  (`setUserAuthenticationRequired(true)`)。如果注册了新的指纹，密钥将自动失效。
- 32 字节的挑战是针对每个认证事件使用 `secrets.token_bytes(32)` 新生成的 – 没有重放攻击。
- PAM 绕过使用 SHA-256 哈希令牌比较，以避免在磁盘上以明文形式存储密钥。
- systemd 单元以专用的 `biolink` 系统用户身份运行，具有 `NoNewPrivileges=true` 和严格的 `CapabilityBoundingSet`。

---

## 开发

### 运行 Python 测试

```bash
cd arch-daemon
pip install -r requirements.txt pytest
python -m pytest tests/ -v
```

### Lint Android 代码

```bash
cd android
./gradlew lint
```

### 构建调试 APK

```bash
cd android
./gradlew :adb_auth:assembleDebug
# Output: adb_auth/build/outputs/apk/debug/adb_auth-debug.apk
```
I will use `write_file` to replace the entire `README.md` content.