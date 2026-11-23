#!/usr/bin/env bash
# FastFlare one-command installer for Ubuntu / Debian servers.
#
#   curl -fsSL https://raw.githubusercontent.com/ArthWarrior3201/FastFlare/main/deploy/install.sh | sudo bash
#
# Optional settings (put them before "sudo bash"):
#   FF_SWAP_GB=4                                         swap file size when the server has no swap (0 = skip)
#   FF_BRANCH=main                                       branch to install
#
# Safe to run again: it updates the code and restarts the service, and keeps your existing settings.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Run as root: ... | sudo bash"; exit 1; }
command -v apt-get >/dev/null || { echo "This installer supports Ubuntu / Debian (apt)."; exit 1; }

REPO="https://github.com/ArthWarrior3201/FastFlare.git"
BRANCH="${FF_BRANCH:-main}"
DIR="/opt/fastflare"
ENVFILE="/etc/fastflare.env"
SWAP_GB="${FF_SWAP_GB:-4}"
say() { printf '\n==> %s\n' "$*"; }

say "Installing prerequisites"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl ca-certificates git iptables iptables-persistent

if [ "$SWAP_GB" -gt 0 ] && [ -z "$(swapon --show --noheadings)" ]; then
  say "Adding ${SWAP_GB} GB swap file (small servers run out of memory without it)"
  fallocate -l "${SWAP_GB}G" /swapfile
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  swapon /swapfile
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  echo 'vm.swappiness=10' > /etc/sysctl.d/99-swap.conf
  sysctl --system >/dev/null 2>&1 || true
fi

node_major() { node -v 2>/dev/null | sed 's/^v//; s/\..*//' || echo 0; }
if ! command -v node >/dev/null || [ "$(node_major)" -lt 20 ]; then
  say "Installing Node.js 22"
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y nodejs
fi

say "Fetching FastFlare"
id fastflare >/dev/null 2>&1 || useradd --system --home "$DIR" --shell /usr/sbin/nologin fastflare
if [ -d "$DIR/.git" ]; then
  git -C "$DIR" fetch --depth 1 origin "$BRANCH"
  git -C "$DIR" reset --hard FETCH_HEAD
else
  rm -rf "$DIR"
  git clone --depth 1 --branch "$BRANCH" "$REPO" "$DIR"
fi
chown -R fastflare:fastflare "$DIR"

if [ ! -f "$ENVFILE" ]; then
  say "Creating settings in $ENVFILE"
  {
    echo "FF_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")"
  } > "$ENVFILE"
  chmod 600 "$ENVFILE"
  chown root:root "$ENVFILE"
fi

say "Opening the server firewall (UDP 123 for time, TCP 8787 for the web API)"
add_rule() { iptables -C INPUT "$@" 2>/dev/null || iptables -I INPUT 1 "$@"; }
add_rule -p udp --dport 123 -j ACCEPT
add_rule -p tcp --dport 8787 -j ACCEPT
netfilter-persistent save >/dev/null 2>&1 || true
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow 123/udp >/dev/null
  ufw allow 8787/tcp >/dev/null
fi

say "Starting the service"
cat > /etc/systemd/system/fastflare.service <<UNIT
[Unit]
Description=FastFlare
After=network-online.target
Wants=network-online.target

[Service]
User=fastflare
WorkingDirectory=$DIR
EnvironmentFile=$ENVFILE
ExecStart=$(command -v node) src/server.js
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable fastflare >/dev/null
systemctl restart fastflare

say "Waiting for the first time sync"
for _ in $(seq 1 30); do
  if curl -fs localhost:8787/time/status 2>/dev/null | grep -q '"synced":true'; then ok=1; break; fi
  sleep 1
done

IP="$(curl -fs --max-time 5 https://api.ipify.org 2>/dev/null || echo YOUR.SERVER.IP)"
echo
if [ "${ok:-0}" = 1 ]; then
  echo "FastFlare is running and synced."
else
  echo "FastFlare is running but has not synced yet. Check: curl localhost:8787/time/status"
  echo "Logs: sudo journalctl -u fastflare -n 50 --no-pager"
fi
cat <<DONE

  Web API:     http://$IP:8787/time?tz=Asia/Kolkata
  Time server: $IP   (UDP 123)

  Make sure your cloud firewall allows inbound UDP 123 and TCP 8787.
  On Windows (administrator Command Prompt):

    w32tm /config /manualpeerlist:"$IP,0x8" /syncfromflags:manual /reliable:no /update
    net stop w32time && net start w32time
    w32tm /resync /force

DONE
