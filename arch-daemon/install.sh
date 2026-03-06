#!/usr/bin/env bash
# install.sh – Install the BioLink Arch daemon
# Run as root: sudo bash install.sh
set -euo pipefail

echo "==> Installing BioLink Arch Daemon"

# ── 1. Python dependencies ──────────────────────────────────────────────────
echo "  -> Installing Python dependencies"
pip install --quiet -r "$(dirname "$0")/requirements.txt"

# ── 2. Create system user ────────────────────────────────────────────────────
if ! id biolink &>/dev/null; then
    useradd --system --no-create-home --shell /usr/bin/nologin \
        --comment "BioLink 4FA daemon" biolink
    echo "  -> Created system user 'biolink'"
fi

# Add biolink user to the bluetooth group so it can use BlueZ
usermod -aG bluetooth biolink

# ── 3. Install daemon files ───────────────────────────────────────────────────
install -Dm755 "$(dirname "$0")/biolink_daemon.py" /usr/lib/biolink/biolink_daemon.py
install -Dm755 "$(dirname "$0")/biolink_client.py" /usr/bin/biolink-client
install -Dm755 "$(dirname "$0")/biolink_pair.py"   /usr/bin/biolink-pair

# ── 4. Config directory ───────────────────────────────────────────────────────
install -dm750 /etc/biolink
chown root:biolink /etc/biolink

# ── 5. Systemd service ────────────────────────────────────────────────────────
install -Dm644 "$(dirname "$0")/biolink.service" /etc/systemd/system/biolink.service
systemctl daemon-reload
systemctl enable --now biolink.service
echo "  -> biolink.service enabled and started"

# ── 6. Reminder ───────────────────────────────────────────────────────────────
echo ""
echo "==> Installation complete."
echo ""
echo "Next steps:"
echo "  1. Open the BioLink app on your Android phone."
echo "  2. Run:  biolink-pair --pubkey '<paste Base64 key here>'"
echo "     or:   biolink-pair  (and paste when prompted)"
echo "  3. Edit /etc/pam.d/<your-lockscreen> and add the BioLink line."
echo "     See arch-daemon/pam-config.example for examples."
echo ""
echo "  To set an emergency bypass token:"
echo "    echo -n 'your-secret-token' | sha256sum | awk '{print \$1}' \\"
echo "      | sudo tee /etc/biolink/bypass_hash > /dev/null"
echo "    Then export BIOLINK_BYPASS_TOKEN='your-secret-token' before logging in."
