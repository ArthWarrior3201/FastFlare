#!/bin/bash
# FastFlare installer for macOS.
#   Double-click this file in Finder, or in Terminal:
#     curl -fsSL https://raw.githubusercontent.com/ArthWarrior3201/FastFlare/main/deploy/install.command | bash
#   Remove it again:  bash install.command uninstall
#
set -euo pipefail

[ "$(uname)" = "Darwin" ] || { echo "This installer is for macOS. On Linux use install.sh."; exit 1; }

DIR="/usr/local/fastflare"
ENVFILE="/usr/local/etc/fastflare.env"
PLIST="/Library/LaunchDaemons/com.fastflare.plist"
LOG="/var/log/fastflare.log"
say() { printf '\n==> %s\n' "$*"; }

echo "FastFlare needs administrator access (to use UDP port 123 and run in the background)."
sudo -v

if [ "${1:-}" = "uninstall" ]; then
  sudo launchctl bootout system "$PLIST" 2>/dev/null || true
  sudo rm -rf "$PLIST" "$DIR" "$ENVFILE" "$LOG"
  echo "FastFlare removed."
  exit 0
fi

node_major() { local m; m="$(node -v 2>/dev/null | sed 's/^v//; s/\..*//')" || true; echo "${m:-0}"; }
if ! command -v node >/dev/null || [ "$(node_major)" -lt 20 ]; then
  say "Installing Node.js"
  if command -v brew >/dev/null; then
    brew install node
  else
    PKG="$(curl -fsSL https://nodejs.org/dist/latest-v22.x/ | grep -o 'node-v22[0-9.]*\.pkg' | head -1)"
    [ -n "$PKG" ] || { echo "Could not find the Node.js installer. Install Node 20+ from nodejs.org and run this again."; exit 1; }
    curl -fL "https://nodejs.org/dist/latest-v22.x/$PKG" -o /tmp/fastflare-node.pkg
    sudo installer -pkg /tmp/fastflare-node.pkg -target /
  fi
fi
NODE="$(command -v node)"
[ "$(node_major)" -ge 20 ] || { echo "Node.js 20 or newer is required."; exit 1; }

say "Downloading FastFlare"
TMP="$(mktemp -d)"
curl -fsSL https://github.com/ArthWarrior3201/FastFlare/archive/refs/heads/main.tar.gz | tar -xz -C "$TMP"
sudo launchctl bootout system "$PLIST" 2>/dev/null || true
sudo mkdir -p /usr/local/etc
sudo rm -rf "$DIR"
sudo mv "$TMP/FastFlare-main" "$DIR"

if [ ! -f "$ENVFILE" ]; then
  say "Creating settings"
  SECRET="$("$NODE" -e "console.log(require('crypto').randomBytes(32).toString('hex'))")"
  sudo tee "$ENVFILE" >/dev/null <<ENV
FF_SECRET=$SECRET
ENV
  sudo chmod 600 "$ENVFILE"
fi

sudo tee "$DIR/run.sh" >/dev/null <<RUN
#!/bin/bash
set -a
. "$ENVFILE"
set +a
cd "$DIR"
exec "$NODE" src/server.js
RUN
sudo chmod +x "$DIR/run.sh"

say "Starting the service"
sudo tee "$PLIST" >/dev/null <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.fastflare</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$DIR/run.sh</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$LOG</string>
  <key>StandardErrorPath</key><string>$LOG</string>
</dict>
</plist>
PL
sudo chown root:wheel "$PLIST"
sudo chmod 644 "$PLIST"
sudo launchctl bootstrap system "$PLIST"
sudo launchctl enable system/com.fastflare

say "Waiting for the first time sync"
ok=0
for _ in $(seq 1 30); do
  if curl -fs localhost:8787/time/status 2>/dev/null | grep -q '"synced":true'; then ok=1; break; fi
  sleep 1
done

IP="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo YOUR.MAC.IP)"
echo
if [ "$ok" = 1 ]; then echo "FastFlare is running and synced."; else echo "FastFlare is running but has not synced yet. Logs: tail -f $LOG"; fi
cat <<DONE

  Web API:     http://$IP:8787/time?tz=Asia/Kolkata
  Time server: $IP   (UDP 123)

  If macOS asks whether "node" may accept incoming connections, choose Allow.
  Other devices on this network can now use $IP as their time server.
  Keep this Mac awake for the server to stay available.
  Remove it later with:  bash install.command uninstall

DONE
