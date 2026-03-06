#!/usr/bin/env bash
# install.sh – 为 Arch Linux 优化的 BioLink 守护进程安装脚本 (ADB 版)
# 使用方法: sudo ./install.sh
set -euo pipefail

# 检查权限
if [[ $EUID -ne 0 ]]; then
   echo "错误: 此脚本必须以 root 权限运行 (sudo)"
   exit 1
fi

echo "==> 正在安装 BioLink Arch 守护进程 (ADB 版)"

# ── 1. 检查 ADB 工具 ────────────────────────────────────────────────────────
echo "  -> 检查 ADB 工具..."
if ! command -v adb &> /dev/null; then
    echo "错误: ADB 工具未找到。请安装 Android Platform Tools 并确保 adb 在 PATH 中。"
    echo "例如: sudo pacman -S android-platform-tools (Arch Linux)"
    exit 1
fi
echo "     [+] ADB 工具已找到"


# ── 2. 用户与组配置 ────────────────────────────────────────────────────────
echo "  -> 配置系统用户与用户组"

# 创建 biolink 系统用户
if ! id biolink &>/dev/null; then
    useradd --system --no-create-home --shell /usr/bin/nologin 
        --comment "BioLink 4FA daemon (ADB)" biolink
    echo "     [+] 已创建系统用户 'biolink'"
else
    echo "     [~] 发现现有用户 'biolink'"
fi

# 确保 /etc/biolink 目录的权限正确，以便守护进程可以读写公钥
chown biolink:biolink /etc/biolink || true # 确保 biolink 用户有权限，否则创建
chmod 700 /etc/biolink


# ── 3. 安装程序文件 ─────────────────────────────────────────────────────────
echo "  -> 安装守护进程可执行文件至系统路径"

# 确保目标目录存在
install -dm755 /usr/lib/biolink

# 安装脚本并赋予执行权限
install -m755 "$(dirname "$0")/biolink_daemon.py" /usr/lib/biolink/biolink_daemon.py
install -m755 "$(dirname "$0")/biolink_client.py" /usr/bin/biolink-client
# biolink_pair.py 不再需要安装

# ── 4. 配置文件目录 ─────────────────────────────────────────────────────────
echo "  -> 初始化配置目录 /etc/biolink"
install -dm750 /etc/biolink
# 归属权交给 biolink 用户，确保守护进程可读写公钥文件
chown biolink:biolink /etc/biolink
chmod 700 /etc/biolink


# ── 5. Systemd 服务配置 ──────────────────────────────────────────────────────
echo "  -> 激活 Systemd 服务"
install -Dm644 "$(dirname "$0")/biolink.service" /etc/systemd/system/biolink.service

systemctl daemon-reload
systemctl enable --now biolink.service

echo ""
echo "==> 守护进程安装成功！"
echo ""
echo "====> 手机端 ADB 认证应用部署"
echo "请确保您的 Android 设备已开启 USB 调试，并通过数据线连接到此电脑。"
echo "然后按照以下步骤部署认证应用并进行配对:"
echo "  1. 构建 ADB 认证应用:"
echo "     (在项目根目录下执行) cd android && ./gradlew :adb_auth:assembleDebug"
echo "  2. 安装应用至手机:"
echo "     adb install ./adb_auth/build/outputs/apk/debug/adb_auth-debug.apk"
echo "  3. 进行公钥配对:"
echo "     sudo /usr/lib/biolink/biolink_daemon.py --pair"
echo "     (此时手机上会弹出指纹认证提示，请验证)"
echo ""
echo "====> PAM 配置 (最后一步)"
echo "  在 /etc/pam.d/ 相关的登录配置文件中加入 BioLink 验证行 (参考 pam-config.example)。"
echo "  例如，对于 sudo: 编辑 /etc/pam.d/sudo 并添加:"
echo "     auth      required   pam_exec.so expose_authtok /usr/bin/biolink-client"
echo "  **警告**: 在完全测试通过之前，请勿关闭您的当前终端会话，以免被锁定。"
echo ""
echo "安装完成！"
