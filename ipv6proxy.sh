#!/bin/bash
# IPv6 Backconnect Proxy Manager (auto-detect subnet)
# Compatible with Ubuntu 20.04, 22.04, 24.04, Debian, CentOS, etc.
# Builds and runs 3proxy with IPv6 rotation (interval or per-request via ndppd)

set -euo pipefail

# --- Root check ---
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Please run as root" >&2
  exit 1
fi

# --- Help ---
usage() {
  cat >&2 <<'EOF'
Usage: ./ipv6proxy.sh [options]
  [-s | --subnet <auto|16|32|48|56|64|80|96|112>]  subnet size (default: auto)
  [-c | --proxy-count <number>]                    number of proxies (required)
  [-u | --username <string>]                       single username for all proxies
  [-p | --password <string>]                       single password for all proxies
  [--random]                                       random user:pass per proxy
  [-t | --proxies-type <http|socks5>]              proxy protocol (default http)
  [-r | --rotating-interval <0-59>]                rotate IPv6 every N minutes (default 0 = off)
  [--rotate-every-request]                         per-request rotation via ndppd
  [--start-port <5000-65535>]                      starting port (default 30000)
  [-l | --localhost]                               bind backconnect to 127.0.0.1 only
  [-f | --backconnect-proxies-file <path>]         where to write proxies list (default ~/proxyserver/backconnect_proxies.list)
  [-m | --ipv6-mask <ipv6-prefix>]                 fixed IPv6 mask/gateway to base randomization on (optional)
  [-i | --interface <name>]                        interface (auto-detected)
  [-b | --backconnect-ip <IPv4>]                   explicit IPv4 for backconnect (auto-detected)
  [--allowed-hosts <csv>]                          allow list (3proxy format); others denied
  [--denied-hosts <csv>]                           deny list (3proxy format)
  [--uninstall]                                     uninstall proxies and cleanup
  [--info]                                          print running server info
Examples:
  ./ipv6proxy.sh -c 100 --random
  ./ipv6proxy.sh -c 50 -u user -p pass --rotating-interval 10
  ./ipv6proxy.sh -c 20 --rotate-every-request
  ./ipv6proxy.sh -c 30 --interface eth0 --subnet 64
EOF
  exit 1
}

# --- getopt ---
options=$(getopt -o lhs:c:u:p:t:r:m:f:i:b: \
  --long help,rotate-every-request,localhost,random,uninstall,info,subnet:,proxy-count:,username:,password:,proxies-type:,rotating-interval:,ipv6-mask:,interface:,start-port:,backconnect-proxies-file:,backconnect-ip:,allowed-hosts:,denied-hosts: -- "$@") || {
  echo "Error: bad arguments." >&2
  usage
}

eval set -- "$options"

# --- Defaults ---
subnet="auto"
proxies_type="http"
start_port=30000
rotating_interval=0
use_localhost=false
use_random_auth=false
uninstall=false
try_rotate_every_request=false
rotate_every_request=false
print_info=false
backconnect_proxies_file="default"

interface_name=$(ip -br link show | awk '$1 !~ /^(lo|vir|wl|docker|tun)/ && $3 == "UP" { print $1; exit }')
script_log_file="/var/tmp/ipv6-proxy-server-logs.log"
backconnect_ipv4=""
subnet_mask=""
proxy_count=""
user=""
password=""
allowed_hosts=""
denied_hosts=""

while true; do
  case "$1" in
    -h|--help) usage ;;
    -s|--subnet) subnet="$2"; shift 2 ;;
    -c|--proxy-count) proxy_count="$2"; shift 2 ;;
    -u|--username) user="$2"; shift 2 ;;
    -p|--password) password="$2"; shift 2 ;;
    -t|--proxies-type) proxies_type="$2"; shift 2 ;;
    -r|--rotating-interval) rotating_interval="$2"; shift 2 ;;
    -m|--ipv6-mask) subnet_mask="$2"; shift 2 ;;
    -b|--backconnect-ip) backconnect_ipv4="$2"; shift 2 ;;
    -f|--backconnect-proxies-file) backconnect_proxies_file="$2"; shift 2 ;;
    -i|--interface) interface_name="$2"; shift 2 ;;
    -l|--localhost) use_localhost=true; shift ;;
    --allowed-hosts) allowed_hosts="$2"; shift 2 ;;
    --denied-hosts) denied_hosts="$2"; shift 2 ;;
    --uninstall) uninstall=true; shift ;;
    --info) print_info=true; shift ;;
    --start-port) start_port="$2"; shift 2 ;;
    --random) use_random_auth=true; shift ;;
    --rotate-every-request) try_rotate_every_request=true; shift ;;
    --) shift; break ;;
    *) break ;;
  esac
done

# --- Logging helpers ---
log_err() { printf '%s\n' "$1" >&2; printf '%s\n' "$1" >> "$script_log_file"; }
log_err_and_exit() { log_err "$1"; exit 1; }
log_err_print_usage_and_exit() { log_err "$1"; usage; }

# --- Utils ---
is_valid_ip() {
  [[ "$1" =~ ^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]
}

is_auth_used() {
  if [[ -z "$user" && -z "$password" && "$use_random_auth" = false ]]; then
    return 1
  else
    return 0
  fi
}

# --- Paths ---
bash_location="$(command -v bash)"
cd ~
user_home_dir="$HOME"
proxy_dir="$user_home_dir/proxyserver"
proxyserver_config_path="$proxy_dir/3proxy/3proxy.cfg"
proxyserver_info_file="$proxy_dir/running_server.info"
random_ipv6_list_file="$proxy_dir/ipv6.list"
ndppd_routing_file="$proxy_dir/ndppd.routed"
random_users_list_file="$proxy_dir/random_users.list"
[[ "$backconnect_proxies_file" == "default" ]] && backconnect_proxies_file="$proxy_dir/backconnect_proxies.list"
startup_script_path="$proxy_dir/proxy-startup.sh"
cron_script_path="$proxy_dir/proxy-server.cron"
last_port=0

# --- State checks ---
is_proxyserver_installed() { [[ -d "$proxy_dir" && -n "$(ls -A "$proxy_dir" 2>/dev/null || true)" ]]; }
is_proxyserver_running() { pgrep -f "$proxyserver_config_path" >/dev/null; }
is_package_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "ok installed"; }
is_ndppd_running() { pgrep ndppd >/dev/null; }

# --- Arg validation ---
check_startup_parameters() {
  [[ "$proxy_count" =~ ^[0-9]+$ ]] || log_err_print_usage_and_exit "Error: --proxy-count must be a positive integer"
  (( proxy_count > 0 )) || log_err_print_usage_and_exit "Error: --proxy-count must be > 0"

  if [[ "$use_random_auth" = true && ( -n "$user" || -n "$password" ) ]]; then
    log_err_print_usage_and_exit "Error: don't pass --username/--password with --random"
  fi
  if [[ "$use_random_auth" = false && ( -n "$user" || -n "$password" ) && ( -z "$user" || -z "$password" ) ]]; then
    log_err_print_usage_and_exit "Error: both --username and --password are required (or use --random)"
  fi

  [[ "$proxies_type" == "http" || "$proxies_type" == "socks5" ]] || log_err_print_usage_and_exit "Error: --proxies-type must be http or socks5"

  if [[ "$subnet" != "auto" ]]; then
    [[ "$subnet" =~ ^[0-9]+$ ]] || log_err_print_usage_and_exit "Error: --subnet must be a number or 'auto'"
    (( subnet > 0 && subnet <= 128 )) || log_err_print_usage_and_exit "Error: --subnet must be in 1..128"
    (( subnet % 4 == 0 )) || log_err_print_usage_and_exit "Error: --subnet must be divisible by 4"
  fi

  (( rotating_interval >= 0 && rotating_interval <= 59 )) || log_err_print_usage_and_exit "Error: --rotating-interval must be 0..59"

  if (( start_port < 5000 )); then log_err_print_usage_and_exit "Error: --start-port must be >= 5000"; fi
  last_port=$(( start_port + proxy_count - 1 ))
  if (( last_port > 65535 )); then log_err_print_usage_and_exit "Error: start-port + proxy-count - 1 must be <= 65535"; fi

  if [[ -n "$backconnect_ipv4" && ! $(is_valid_ip "$backconnect_ipv4"; echo $?) -eq 0 ]]; then
    log_err_and_exit "Error: invalid IPv4 provided via --backconnect-ip"
  fi

  if [[ -n "$allowed_hosts" && -n "$denied_hosts" ]]; then
    log_err_print_usage_and_exit "Error: use either --allowed-hosts or --denied-hosts, not both"
  fi

  if [[ ! -d "/sys/class/net/$interface_name" ]]; then
    log_err_print_usage_and_exit "Error: interface '$interface_name' does not exist"
  fi
}

# --- System checks & setup helpers ---
kill_3proxy() { pgrep -f "[3]proxy" | xargs -r kill 2>/dev/null || true; }

delete_file_if_exists() { [[ -f "$1" ]] && rm -f "$1"; }

remove_ipv6_addresses_from_iface() {
  if { grep -q "false" "$ndppd_routing_file" 2>/dev/null || { [[ ! -s "$ndppd_routing_file" ]] && [[ -s "$random_ipv6_list_file" ]]; }; }; then
    while IFS= read -r ipv6_address; do
      [[ -n "$ipv6_address" ]] && ip -6 addr del "$ipv6_address" dev "$interface_name" 2>/dev/null || true
    done < "$random_ipv6_list_file"
    rm -f "$random_ipv6_list_file"
  fi
}

install_package() {
  if ! is_package_installed "$1"; then
    apt-get update -yqq || true
    apt-get install -y "$1" || log_err_and_exit "Error: cannot install package '$1'"
  fi
}

check_ipv6() {
  [[ -f /proc/net/if_inet6 ]] || log_err_and_exit "Error: IPv6 not enabled"
  ip -6 addr show scope global | grep -q ':' || log_err_and_exit "Error: no global IPv6 address present"
  ping6 -c1 -W2 google.com >/dev/null 2>&1 || log_err_and_exit "Error: IPv6 connectivity check failed"
}

install_required_packages() {
  local pkgs=(make g++ wget curl cron ndppd procps iproute2 ca-certificates)
  for p in "${pkgs[@]}"; do install_package "$p"; done
}

install_3proxy() {
  mkdir -p "$proxy_dir" && cd "$proxy_dir"
  echo "Downloading 3proxy source..."
  (
    wget -q https://github.com/3proxy/3proxy/archive/refs/tags/0.9.4.tar.gz
    tar -xf 0.9.4.tar.gz
    rm -f 0.9.4.tar.gz
    mv 3proxy-0.9.4 3proxy
  ) >> "$script_log_file" 2>&1
  echo "Building 3proxy..."
  cd 3proxy
  make -f Makefile.Linux >> "$script_log_file" 2>&1
  [[ -f "$proxy_dir/3proxy/bin/3proxy" ]] || log_err_and_exit "Error: 3proxy build failed"
  cd ..
}

configure_ipv6() {
  local opts=("conf.$interface_name.proxy_ndp" "conf.all.proxy_ndp" "conf.default.forwarding" "conf.all.forwarding" "ip_nonlocal_bind")
  for option in "${opts[@]}"; do
    local line="net.ipv6.$option=1"
    grep -q "^$line" /etc/sysctl.conf 2>/dev/null || echo "$line" >> /etc/sysctl.conf
  done
  sysctl -p >> "$script_log_file" 2>&1 || true
  [[ "$(cat /proc/sys/net/ipv6/conf/$interface_name/proxy_ndp 2>/dev/null)" == "1" ]] && \
  [[ "$(cat /proc/sys/net/ipv6/ip_nonlocal_bind 2>/dev/null)" == "1" ]] || \
    log_err_and_exit "Error: IPv6 sysctl config failed"
}

configure_ndppd() {
  ip route add local "$subnet_mask"::/"$subnet" dev "$interface_name" 2>/dev/null || true
  cat > /etc/ndppd.conf <<EOF
route-ttl 30000

proxy $interface_name {
  router no
  timeout 500
  ttl 30000
  rule $subnet_mask::/$subnet {
    static
  }
}
EOF
  systemctl restart ndppd || service ndppd restart || true
  systemctl is-active --quiet ndppd && echo "ndppd is up" || log_err "Warning: ndppd may not be running"
}

# --- Auto-detect subnet & mask ---
autodetect_subnet_and_mask() {
  local ip_with_prefix
  ip_with_prefix=$(ip -6 addr show dev "$interface_name" scope global | awk '/inet6.*global/ && !/fe80/ {print $2; exit}')
  [[ -n "$ip_with_prefix" ]] || log_err_and_exit "Error: cannot detect global IPv6 on $interface_name"
  local full_ip="${ip_with_prefix%/*}"
  local prefixlen="${ip_with_prefix#*/}"

  # Align to 4-bit boundary
  local nibble_aligned=$(( prefixlen - (prefixlen % 4) ))
  if [[ "$subnet" == "auto" ]]; then
    subnet=$nibble_aligned
  fi

  local full_blocks_count=$(( subnet / 16 ))
  subnet_mask=$(echo "$full_ip" | grep -oP '^(?!fe80)([0-9a-fA-F]{1,4}:){'$(($full_blocks_count-1))'}[0-9a-fA-F]{1,4}')
  if (( subnet % 16 != 0 )); then
    local next_block
    next_block=$(echo "$full_ip" | awk -v b=$((full_blocks_count + 1)) -F ':' '{print $b}' | tr -d ' ')
    while ((${#next_block} < 4)); do next_block="0$next_block"; done
    local nibbles=$(( (subnet % 16) / 4 ))
    local partial=$(echo "$next_block" | cut -c1-"$nibbles")
    subnet_mask="$subnet_mask:$partial"
  fi
}

# --- ndppd test ---
is_ndppd_routing_working() {
  is_ndppd_running || { log_err "ndppd isn't running."; return 1; }
  is_package_installed "curl" || install_package "curl"
  [[ "$(cat /proc/sys/net/ipv6/conf/$interface_name/proxy_ndp 2>/dev/null)" == "1" ]] || { log_err "proxy_ndp not set."; return 1; }
  local test_ip="${subnet_mask}::5252"
  curl -m 5 -s --interface "$test_ip" https://ipv6.ip.sb   | grep -q "$test_ip" && return 0
  curl -m 5 -s --interface "$test_ip" https://whatismyv6.com   | grep -q "$test_ip" && return 0
  curl -m 5 -s --interface "$test_ip" http://ip6only.me | grep -q "$test_ip" && return 0
  curl -m 5 -s --interface "$test_ip" https://myipv6.is   | grep -q "$test_ip" && return 0
  curl -m 5 -s --interface "$test_ip" https://dnschecker.org/whats-my-ip-address.php   | grep -q "$test_ip" && return 0
  log_err "Cannot verify ndppd subnet reachability"
  return 1
}

# --- Backconnect IPv4 ---
get_backconnect_ipv4() {
  if ${use_localhost}; then echo "127.0.0.1"; return; fi
  if [[ -n "$backconnect_ipv4" ]]; then echo "$backconnect_ipv4"; return; fi
  local maybe_ipv4
  maybe_ipv4=$(ip addr show "$interface_name" | awk '$1 == "inet" && $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {gsub(/\/.*/, "", $2); print $2; exit}')
  if is_valid_ip "$maybe_ipv4"; then echo "$maybe_ipv4"; return; fi
  is_package_installed "curl" || install_package "curl"
  maybe_ipv4=$(curl -4 -s https://ipinfo.io/ip   || true)
  if is_valid_ip "$maybe_ipv4"; then echo "$maybe_ipv4"; return; fi
  log_err_and_exit "Error: cannot detect server IPv4; specify --backconnect-ip"
}

# --- Random creds ---
create_random_string() { tr -dc A-Za-z0-9 </dev/urandom | head -c "$1"; echo; }

generate_random_users_if_needed() {
  if [[ "$use_random_auth" = true ]]; then
    delete_file_if_exists "$random_users_list_file"
    for i in $(seq 1 "$proxy_count"); do
      echo "$(create_random_string 8):$(create_random_string 10)" >> "$random_users_list_file"
    done
  else
    delete_file_if_exists "$random_users_list_file"
  fi
}

# --- Startup script (3proxy) ---
create_startup_script() {
  delete_file_if_exists "$startup_script_path"
  is_auth_used
  local use_auth=$?

  is_ndppd_routing_working
  local can_route_via_ndppd=$?

  if ${try_rotate_every_request}; then
    if [[ $can_route_via_ndppd -eq 0 ]]; then
      echo "Per-request rotation enabled."
      rotate_every_request=true
    else
      log_err_and_exit "Per-request rotation not possible on this server"
    fi
  fi

  cat > "$startup_script_path" <<'EOSH'
#!/bin/bash
set -euo pipefail
dedent() { local -n ref="$1"; ref="$(echo "$ref" | sed 's/^[[:space:]]*//')"; }
EOSH

  cat >> "$startup_script_path" <<EOSH
proxyserver_process_pids=(\$(pgrep -f [3]proxy))

old_ipv6_list_file="$random_ipv6_list_file.old"
if [[ -f "$random_ipv6_list_file" ]]; then cp "$random_ipv6_list_file" "\$old_ipv6_list_file"; rm -f "$random_ipv6_list_file"; fi

old_ndppd_routing_file="$ndppd_routing_file.old"
if [[ -f "$ndppd_routing_file" ]]; then cp "$ndppd_routing_file" "\$old_ndppd_routing_file"; fi
if [[ $can_route_via_ndppd -eq 0 ]]; then echo "true" > "$ndppd_routing_file"; else echo "false" > "$ndppd_routing_file"; fi

array=(1 2 3 4 5 6 7 8 9 0 a b c d e f)

get_truncated_subnet_mask() {
  redundant_symbols_count=\$(( ($subnet % 16) / 4 ))
  last_subnet_block=\$(echo "$subnet_mask" | awk -F ':' '{print \$NF}')
  symbols_count=\${#last_subnet_block}
  trunc_symbols_count=\$(( redundant_symbols_count - (4 - symbols_count) ))
  mask="$subnet_mask"
  echo \${mask:0:\$((\${#mask}-trunc_symbols_count))}
}

rh() { echo \${array[\$RANDOM%16]}; }

rnd_subnet_ip() {
  echo -n \$(get_truncated_subnet_mask)
  symbol=$subnet
  while (( symbol < 128 )); do
    if (( symbol % 16 == 0 )); then echo -n :; fi
    echo -n \$(rh)
    let "symbol += 4"
  done
  echo
}

immutable_config_part="daemon
  nserver 1.1.1.1
  maxconn 200
  nscache 65536
  timeouts 1 5 30 60 180 1800 15 60
  setgid 65535
  setuid 65535"

auth_part="auth iponly"
EOSH

  if [[ $use_auth -eq 0 && "$use_random_auth" = false ]]; then
    cat >> "$startup_script_path" <<EOSH
auth_part="
  auth strong
  users $user:CL:$password"
EOSH
  fi

  local access_rules_part="allow *"
  if [[ -n "$denied_hosts" ]]; then
    access_rules_part=$'deny * * '"$denied_hosts"$'\nallow *'
  elif [[ -n "$allowed_hosts" ]]; then
    access_rules_part=$'allow * * '"$allowed_hosts"$'\ndeny *'
  fi
  if [[ "$rotate_every_request" = true ]]; then
    access_rules_part+=$'\nparent 1000 extip '"$subnet_mask"'::/'"$subnet"' 0'
  fi

  cat >> "$startup_script_path" <<'EOSH'
dedent immutable_config_part
dedent auth_part
dedent access_rules_part
EOSH

  cat >> "$startup_script_path" <<EOSH
printf '%s\n%s\n%s\n' "\$immutable_config_part" "\$auth_part" "\$access_rules_part" > "$proxyserver_config_path"

port=$start_port
count=0
proxy_startup_depending_on_type="proxy -6 -n -a"
[[ "$proxies_type" = "socks5" ]] && proxy_startup_depending_on_type="socks -6 -a"

if [[ "$use_random_auth" = true ]]; then
  readarray -t proxy_random_credentials < "$random_users_list_file"
fi

while (( count < proxy_count )); do
  if [[ "$use_random_auth" = true ]]; then
    IFS=":" read -r username password <<< "\${proxy_random_credentials[count]}"
    printf 'flush\nusers %s:CL:%s\n%s\n' "\$username" "\$password" "\$access_rules_part" >> "$proxyserver_config_path"
    IFS=$' \t\n'
  fi

  if [[ "$rotate_every_request" = true ]]; then
    printf '%s -p%d -i%s\n' "\$proxy_startup_depending_on_type" "\$port" "\$backconnect_ipv4" >> "$proxyserver_config_path"
  else
    random_gateway_ipv6=\$(rnd_subnet_ip)
    echo "\$random_gateway_ipv6" >> "$random_ipv6_list_file"
    printf '%s -p%d -i%s -e%s\n' "\$proxy_startup_depending_on_type" "\$port" "\$backconnect_ipv4" "\$random_gateway_ipv6" >> "$proxyserver_config_path"
  fi

  ((port++))
  ((count++))
done

ulimit -n 600000 || true
ulimit -u 600000 || true

if [[ $can_route_via_ndppd -ne 0 && -s "$random_ipv6_list_file" ]]; then
  while IFS= read -r ipv6_address; do
    [[ -n "\$ipv6_address" ]] && ip -6 addr add "\$ipv6_address" dev "\$interface_name" 2>/dev/null || true
  done < "$random_ipv6_list_file"
fi

"$user_home_dir"/proxyserver/3proxy/bin/3proxy "$proxyserver_config_path"

for pid in "\${proxyserver_process_pids[@]-}"; do
  kill "\$pid" 2>/dev/null || true
done

if { grep -q "false" "\$old_ndppd_routing_file" 2>/dev/null || { [[ ! -s "\$old_ndppd_routing_file" ]] && [[ -s "\$old_ipv6_list_file" ]]; }; }; then
  while IFS= read -r ipv6_address; do
    [[ -n "\$ipv6_address" ]] && ip -6 addr del "\$ipv6_address" dev "\$interface_name" 2>/dev/null || true
  done < "\$old_ipv6_list_file"
  rm -f "\$old_ipv6_list_file"
fi

exit 0
EOSH

  chmod +x "$startup_script_path"
}

# --- Cron ---
add_to_cron() {
  delete_file_if_exists "$cron_script_path"
  printf '@reboot %s %s\n' "$bash_location" "$startup_script_path" > "$cron_script_path"
  if (( rotating_interval != 0 )); then
    printf '*/%d * * * * %s %s\n' "$rotating_interval" "$bash_location" "$startup_script_path" >> "$cron_script_path"
  fi
  crontab -l 2>/dev/null | grep -v "$startup_script_path" >> "$cron_script_path" 2>/dev/null || true
  crontab "$cron_script_path"
  systemctl restart cron || true
}

remove_from_cron() {
  crontab -l 2>/dev/null | grep -v "$startup_script_path" > "$cron_script_path" 2>/dev/null || true
  crontab "$cron_script_path" 2>/dev/null || true
  systemctl restart cron || true
}

# --- UFW helpers ---
close_ufw_backconnect_ports() {
  if ! command -v ufw >/dev/null || ${use_localhost} || [[ ! -f "$backconnect_proxies_file" ]]; then return; fi
  local first_opened_port last_opened_port
  first_opened_port=$(head -n 1 "$backconnect_proxies_file" | awk -F ':' '{print $2}')
  last_opened_port=$(tail -n 1 "$backconnect_proxies_file" | awk -F ':' '{print $2}')
  ufw delete allow "$first_opened_port:$last_opened_port/tcp" >/dev/null 2>&1 || true
  ufw delete allow "$first_opened_port:$last_opened_port/udp" >/dev/null 2>&1 || true
}

open_ufw_backconnect_ports() {
  close_ufw_backconnect_ports
  ${use_localhost} && return
  if ! command -v ufw >/dev/null; then echo "Firewall not installed; ports considered open."; return; fi
  if ufw status | grep -qw active; then
    ufw allow "$start_port:$last_port/tcp" >/dev/null 2>&1 || true
    ufw allow "$start_port:$last_port/udp" >/dev/null 2>&1 || true
  else
    echo "UFW disabled; ports considered open."
  fi
}

# --- Runner helpers ---
run_proxy_server() {
  [[ -f "$startup_script_path" ]] || log_err_and_exit "Error: startup script missing"
  "$bash_location" "$startup_script_path"
  if is_proxyserver_running; then
    local creds=""
    if is_auth_used && [[ "$use_random_auth" = false ]]; then creds=":$user:$password"; fi
    printf '\nIPv6 proxy server started: %s:%d%s .. %s:%d%s (%s)\n' \
      "$backconnect_ipv4" "$start_port" "$creds" "$backconnect_ipv4" "$last_port" "$creds" "$proxies_type"
    printf 'Proxy list: %s\n' "$backconnect_proxies_file"
  else
    log_err_and_exit "Error: cannot run proxy server"
  fi
}

write_backconnect_proxies_to_file() {
  delete_file_if_exists "$backconnect_proxies_file"
  if ! touch "$backconnect_proxies_file" 2>/dev/null; then
    log_err "Warning: cannot create proxy list file at $backconnect_proxies_file"
    return
  fi
  local count=0
  local proxy_random_credentials=()
  if [[ "$use_random_auth" = true ]]; then
    readarray -t proxy_random_credentials < "$random_users_list_file"
  fi
  for port in $(seq "$start_port" "$last_port"); do
    if [[ "$use_random_auth" = true ]]; then
      printf '%s:%d:%s\n' "$backconnect_ipv4" "$port" "${proxy_random_credentials[count]}" >> "$backconnect_proxies_file"
      ((count++))
    else
      local creds=""
      is_auth_used && creds=":$user:$password"
      printf '%s:%d%s\n' "$backconnect_ipv4" "$port" "$creds" >> "$backconnect_proxies_file"
    fi
  done
}

write_proxyserver_info() {
  delete_file_if_exists "$proxyserver_info_file"
  cat > "$proxyserver_info_file" <<EOF
User info:
  Proxy count: $proxy_count
  Proxy type: $proxies_type
  Proxy IP: $backconnect_ipv4
  Proxy ports: $start_port .. $last_port
  Auth: $( if is_auth_used; then if [[ "$use_random_auth" = true ]]; then echo "random per-proxy"; else echo "user=$user, pass=$password"; fi; else echo "disabled"; fi )
  Rules: $( if [[ -n "$denied_hosts" ]]; then echo "denied=$denied_hosts, others allowed"; elif [[ -n "$allowed_hosts" ]]; then echo "allowed=$allowed_hosts, others denied"; else echo "all allowed"; fi )
  Proxy list file: $backconnect_proxies_file

Technical info:
  Subnet (effective): /$subnet
  Subnet mask: $subnet_mask
  IPv6 list file: $( if [[ "$rotate_every_request" = true ]]; then echo "N/A (per-request)"; else echo "$random_ipv6_list_file"; fi )
  Rotation: $( if (( rotating_interval != 0 )); then echo "every $rotating_interval minutes"; elif [[ "$rotate_every_request" = true ]]; then echo "every request"; else echo "disabled"; fi )
EOF
}

# --- Entry points ---
if ${print_info}; then
  is_proxyserver_installed || log_err_and_exit "Proxy server isn't installed"
  is_proxyserver_running || log_err_and_exit "Proxy server isn't running. See $script_log_file"
  [[ -f "$proxyserver_info_file" ]] || log_err_and_exit "Info file not found"
  cat "$proxyserver_info_file"
  exit 0
fi

if ${uninstall}; then
  is_proxyserver_installed || log_err_and_exit "Proxy server is not installed"
  remove_from_cron
  kill_3proxy
  remove_ipv6_addresses_from_iface
  close_ufw_backconnect_ports
  rm -rf "$proxy_dir"
  delete_file_if_exists "$backconnect_proxies_file"
  echo -e "\nIPv6 proxy server uninstalled."
  exit 0
fi

# --- Main flow ---
delete_file_if_exists "$script_log_file"
check_startup_parameters
check_ipv6
backconnect_ipv4="$(get_backconnect_ipv4)"
autodetect_subnet_and_mask

if is_proxyserver_installed; then
  echo -e "Proxy server already installed, reconfiguring...\n"
else
  configure_ipv6
  install_required_packages
  install_3proxy
  configure_ndppd
fi

generate_random_users_if_needed
create_startup_script
add_to_cron
open_ufw_backconnect_ports
run_proxy_server
write_backconnect_proxies_to_file
write_proxyserver_info

exit 0
