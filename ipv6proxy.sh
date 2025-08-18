#!/bin/bash
set -e
# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
random() { tr </dev/urandom -dc A-Za-z0-9 | head -c5; echo; }

array=( {0..9} {a..f} )
gen64() {
  ip64() { printf "%s" "${array[$RANDOM % 16]}${array[$RANDOM % 16]}${array[$RANDOM % 16]}${array[$RANDOM % 16]}"; }
  echo "$1:$(ip64):$(ip64):$(ip64):$(ip64)"
}

# -----------------------------------------------------------------------------
# 1. Install deps
# -----------------------------------------------------------------------------
echo "==> Installing dependencies ..."
apt-get update -qq
apt-get install -y gcc make wget curl zip bsdtar net-tools

# -----------------------------------------------------------------------------
# 2. Build 3proxy
# -----------------------------------------------------------------------------
WORKDIR="/opt/3proxy-build"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

LATEST_URL=$(curl -s https://api.github.com/repos/3proxy/3proxy/releases/latest | grep "tarball_url" | cut -d '"' -f4)
wget -qO- "$LATEST_URL" | bsdtar -xzf-
cd 3proxy-3proxy-* || cd 3proxy-*

make -f Makefile.Linux
mkdir -p /usr/local/etc/3proxy/{bin,logs,stat}
cp src/3proxy /usr/local/etc/3proxy/bin/3proxy

# systemd service
cat >/etc/systemd/system/3proxy.service <<'EOF'
[Unit]
Description=3proxy
After=network.target
[Service]
Type=forking
ExecStart=/usr/local/etc/3proxy/bin/3proxy /usr/local/etc/3proxy/3proxy.cfg
Restart=on-failure
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable 3proxy

# -----------------------------------------------------------------------------
# 3. Working directory
# -----------------------------------------------------------------------------
INSTALL_DIR="/home/proxy-installer"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

IP4=$(curl -4 -s icanhazip.com)
IP6=$(curl -6 -s icanhazip.com | cut -f1-4 -d':')

echo "==> IPv4: $IP4"
echo "==> IPv6 prefix: $IP6"
read -rp "How many proxies to create? " COUNT

FIRST_PORT=10000
LAST_PORT=$(( FIRST_PORT + COUNT ))

# -----------------------------------------------------------------------------
# 4. Generate config data
# -----------------------------------------------------------------------------
gen_data() {
  for ((p=FIRST_PORT; p<=LAST_PORT; p++)); do
    echo "usr$(random)/pass$(random)/$IP4/$p/$(gen64 "$IP6")"
  done
}
gen_data > "$INSTALL_DIR/data.txt"

gen_3proxy() {
  cat <<EOF
daemon
maxconn 1000
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
setgid 65534
setuid 65534
flush
auth strong
users $(awk -F "/" 'BEGIN{ORS="";}{print $1 ":CL:" $2 " "}' "$INSTALL_DIR/data.txt")
$(awk -F "/" '{
  print "auth strong"
  print "allow " $1
  print "proxy -6 -n -a -p" $4 " -i" $3 " -e" $5
  print "flush"
}' "$INSTALL_DIR/data.txt")
EOF
}
gen_3proxy > /usr/local/etc/3proxy/3proxy.cfg

# -----------------------------------------------------------------------------
# 5. iptables & IPv6 addrs
# -----------------------------------------------------------------------------
gen_iptables() {
  awk -F "/" '{print "iptables -I INPUT -p tcp --dport "$4" -m state --state NEW -j ACCEPT"}' "$INSTALL_DIR/data.txt"
}
gen_iptables > "$INSTALL_DIR/boot_iptables.sh"; chmod +x "$INSTALL_DIR/boot_iptables.sh"

gen_ifconfig() {
  DEV=$(ip -6 route | awk '/default/{print $5; exit}')
  awk -F "/" -v dev="$DEV" '{print "ip -6 addr add "$5"/64 dev "dev}' "$INSTALL_DIR/data.txt"
}
gen_ifconfig > "$INSTALL_DIR/boot_ifconfig.sh"; chmod +x "$INSTALL_DIR/boot_ifconfig.sh"

# -----------------------------------------------------------------------------
# 6. Apply & start
# -----------------------------------------------------------------------------
echo "==> Applying rules & starting 3proxy ..."
bash "$INSTALL_DIR/boot_iptables.sh"
bash "$INSTALL_DIR/boot_ifconfig.sh"
systemctl start 3proxy

# -----------------------------------------------------------------------------
# 7. Create proxy list at /root/proxy.txt
# -----------------------------------------------------------------------------
awk -F "/" '{print $3":"$4":"$1":"$2}' "$INSTALL_DIR/data.txt" > /root/proxy.txt
echo
echo "============================================================"
echo "Proxy list saved to: /root/proxy.txt"
echo "============================================================"
