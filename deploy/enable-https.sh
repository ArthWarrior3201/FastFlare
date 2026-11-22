#!/usr/bin/env bash
# Puts HTTPS in front of FastFlare with Caddy and a free automatic certificate.
# Needed when a website served over HTTPS (such as GitHub Pages) calls your FastFlare server.
#
#   curl -fsSL https://raw.githubusercontent.com/ArthWarrior3201/FastFlare/main/deploy/enable-https.sh | sudo bash
#   (or with your own domain that already points at this server:  ... | sudo bash -s -- time.example.com)
#
# With no domain it uses  <your-ip-with-dashes>.sslip.io , a free name that points at your IP.
# Before running: allow inbound TCP 80 and TCP 443 in your cloud firewall.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run as root: ... | sudo bash"; exit 1; }
[ -f /etc/fastflare.env ] || { echo "Install FastFlare first (deploy/install.sh)."; exit 1; }

IP="$(curl -fs --max-time 8 https://api.ipify.org)"
DOMAIN="${1:-$(echo "$IP" | tr . -).sslip.io}"
echo "==> Using $DOMAIN"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl gpg
curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list
apt-get update -y
apt-get install -y caddy

cat > /etc/caddy/Caddyfile <<CADDY
$DOMAIN {
  reverse_proxy 127.0.0.1:8787
}
CADDY

echo "==> Opening ports 80 and 443 on this server"
for port in 80 443; do
  iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "$port" -j ACCEPT
done
netfilter-persistent save >/dev/null 2>&1 || true

# Behind Caddy FastFlare must trust the forwarded client IP, and should only listen locally
# so nobody can reach it directly and spoof that header. UDP time service is unaffected.
sed -i '/^HOST=/d; /^TRUST_PROXY=/d; /^FF_PUBLIC_URL=/d' /etc/fastflare.env
printf 'HOST=127.0.0.1\nTRUST_PROXY=1\nFF_PUBLIC_URL=https://%s\n' "$DOMAIN" >> /etc/fastflare.env
systemctl restart fastflare
systemctl restart caddy

echo "==> Waiting for the certificate"
for _ in $(seq 1 40); do
  if curl -fs --max-time 5 "https://$DOMAIN/health" >/dev/null 2>&1; then
    echo
    echo "HTTPS is live:  https://$DOMAIN"
    echo "Use this address (not http://IP:8787) in websites and the CAPTCHA widget."
    echo "Windows time sync still uses  $IP  on UDP 123."
    exit 0
  fi
  sleep 3
done
echo
echo "Caddy is running but the certificate is not ready yet. Check:  sudo journalctl -u caddy -n 40 --no-pager"
echo "Most common cause: TCP 80/443 not allowed in the cloud firewall."
