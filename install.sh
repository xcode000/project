#!/bin/bash
clear
export DEBIAN_FRONTEND=noninteractive
FONT='\033[0m'
Green="\e[92;1m"
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE="\033[36m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
IGreen="\033[0;92m"
OK="${LIME}--->${NC}"
EROR="${RED}[ERROR]${NC}"
BIYellow="\033[1;93m"
BICyan="\033[1;96m"
BIWhite="\033[1;97m"
GRAY="\e[1;30m"
WHITE='\033[1;37m'
LIME='\e[38;5;155m'
ungu="\e[38;5;99m"
NC='\033[0m'
MYIPP=$(curl -s https://checkip.amazonaws.com/);
MYIP5="s/xxxxxxxxx/$MYIPP/g";
tampilan() {
    local my_ip allowed_ips_url pass_list_url today matched_line exp_date password_input
    allowed_ips_url="https://script.stunnel.sbs/api/data/ip"
    pass_list_url="https://script.stunnel.sbs/pass.txt"
    clear
    echo -e "${BIYellow}========================================${NC}"
    echo -e "${BICyan}        LOGIN MENU - VPS ACCESS${NC}"
    echo -e "${BIYellow}========================================${NC}"
    echo -e "${BIGreen}[1]${NC} 🔑 Validasi IP / License"
    echo -e "${BIGreen}[2]${NC} 🔐 Login via Password"
    echo -e "${BIYellow}========================================${NC}"
    read -rp "Pilih [1/2]: " pilihan
    case "$pilihan" in
        1)
            echo -e "\n${BIWhite}[ ${BIYellow}INFO${BIWhite} ] Mengecek Izin Akses...${NC}"
            my_ip=$(curl -sS ipv4.icanhazip.com | tr -d ' \t\r\n')
            if [[ -z "$my_ip" ]]; then
                echo -e "${BIWhite}[ ${RED}ERROR${BIWhite} ] Gagal mendapatkan IP publik!${NC}"
                exit 1
            fi
            ip_list=$(curl -sS -H "x-api-key: d92ead44d7ca8202645517e1956442339c2f3263aa425804deaa62d4d0bbd881" "$allowed_ips_url")
            entries=$(echo "$ip_list" | sed 's/###/\n###/g' | sed '/^\s*$/d' | sed 's/^### *//')
            matched_line=$(echo "$entries" | awk -v ip="$my_ip" '$3 == ip { print; exit }')
            if [[ -z "$matched_line" ]]; then
                echo -e "${BIWhite}[ ${BIYellow}DITOLAK${BIWhite} ] IP ${BIYellow}$my_ip${BIWhite} tidak terdaftar dalam izin.${NC}"
                exit 1
            fi
            exp_date=$(echo "$matched_line" | awk '{print $2}' | tr -d ' \t\r\n')
            status_raw=$(echo "$matched_line" | awk '{print $7}' | tr -d ' \t\r\n')
            status="$(tr '[:lower:]' '[:upper:]' <<< ${status_raw:0:1})${status_raw:1}"
            today=$(date +%Y-%m-%d)
            today_epoch=$(date -d "$today" +%s)
            exp_epoch=$(date -d "$exp_date" +%s 2>/dev/null || echo 0)
            if [[ "$status" != "Active" ]]; then
                echo -e "${BIWhite}[ ${RED}DITOLAK${BIWhite} ] Status akun Anda: ${RED}$status${NC}"
                exit 1
            fi
            if (( exp_epoch == 0 )); then
                echo -e "${BIWhite}[ ${RED}ERROR${BIWhite} ] Format tanggal expired tidak valid: $exp_date${NC}"
                exit 1
            fi
            if (( today_epoch > exp_epoch )); then
                echo -e "${BIWhite}[ ${RED}DITOLAK${BIWhite} ] IP ${BIYellow}$my_ip${BIWhite} Expired pada: ${RED}$exp_date${NC}"
                exit 1
            fi
            echo -e "${BIWhite}[ ${LIME}INFO${BIWhite} ] Accepted: ${LIME}$my_ip${BIWhite} Status: ${LIME}$status${BIWhite}, Valid Until: ${BIYellow}$exp_date${NC}"
            echo "LOGIN=IP" > /etc/systemd/methode.conf
            chown root:root /etc/systemd/methode.conf
            chmod 600 /etc/systemd/methode.conf
        ;;
        2)
            echo
            read -rsp "Masukkan Password: " password_input
            echo

            if curl -sS "$pass_list_url" | grep -Fxq "$password_input"; then
                echo -e "${BIWhite}[ ${LIME}INFO${BIWhite} ] Login berhasil via Password!${NC}"
                echo "LOGIN=PASSWORD" > /etc/systemd/methode.conf
                chown root:root /etc/systemd/methode.conf
                chmod 600 /etc/systemd/methode.conf
            else
                echo -e "${BIWhite}[ ${RED}ERROR${BIWhite} ] Password yang Anda masukkan salah!${NC}"
                sleep 1
                tampilan
            fi
        ;;
        *)
            echo -e "${BIWhite}[ ${RED}ERROR${BIWhite} ] Pilihan Tidak Valid!${NC}"
            sleep 1
            tampilan
        ;;
    esac
}
setup_grub_env() {
  echo "Menyiapkan environment dan GRUB..."
  NEW_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  if ! grep -q "^PATH=.*$NEW_PATH" /etc/environment 2>/dev/null; then
    if grep -q "^PATH=" /etc/environment 2>/dev/null; then
      echo ""
    else
      echo "PATH=\"$NEW_PATH\"" >> /etc/environment
      echo ""
    fi
  else
    echo ""
  fi
  if ! grep -q "$NEW_PATH" /root/.bashrc 2>/dev/null; then
    echo "export PATH=\"$NEW_PATH:\$PATH\"" >> /root/.bashrc
    echo ""
  else
    echo ""
  fi
  PROFILE_SCRIPT="/etc/profile.d/custom-path.sh"
  if [ ! -f "$PROFILE_SCRIPT" ]; then
    echo "export PATH=\"$NEW_PATH:\$PATH\"" > "$PROFILE_SCRIPT"
    chmod +x "$PROFILE_SCRIPT" >/dev/null 2>&1
    echo ""
  elif ! grep -q "$NEW_PATH" "$PROFILE_SCRIPT" 2>/dev/null; then
    echo "export PATH=\"$NEW_PATH:\$PATH\"" >> "$PROFILE_SCRIPT"
    echo ""
  else
    echo ""
  fi
  export PATH="$NEW_PATH:$PATH"
  if [ ! -d /boot/grub ]; then
    mkdir -p /boot/grub >/dev/null 2>&1
    echo ""
  else
    echo ""
  fi
  if update-grub >/dev/null 2>&1; then
    echo "update-grub berhasil dijalankan"
  else
    echo "Gagal menjalankan update-grub"
    return 2
  fi
}
sleep 2
clear
if [ "${EUID}" -ne 0 ]; then
    echo -e "${RED}You need to run this script as root"
    exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo -e "${RED}OpenVZ is not supported"
    return
fi
IP=$(curl -sS icanhazip.com)
if [[ -z $IP ]]; then
    echo -e "${RED}IP Address ${YELLOW}Not Detected${NC}"
else
    echo -e "${BIWhite}IP Address ${LIME}${IP}${NC}"
fi
ARCH=$(uname -m)
if [[ $ARCH == "x86_64" ]]; then
    echo -e "${BIWhite}Your Architecture Is Supported ${LIME}${ARCH}${NC}"
else
    echo -e "${RED}Your Architecture Is Not Supported ${YELLOW}${ARCH}${NC}"
    return
fi
OS_ID=$(grep -w ^ID /etc/os-release | cut -d= -f2 | tr -d '"')
OS_NAME=$(grep -w ^PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
if [[ $OS_ID == "ubuntu" || $OS_ID == "debian" ]]; then
    echo -e "${BIWhite}Your OS Is Supported ${LIME}${OS_NAME}${NC}"
else
    echo -e "${RED}Your OS Is Not Supported ${YELLOW}${OS_NAME}${NC}"
    return
fi
echo ""
read -p "$( echo -e "${BIWhite}Press ${LIME}[${BIWhite} Enter ${LIME}]${BIWhite} For Starting Installation${NC}") "
echo ""
clear
REPO="https://script.stunnel.sbs/api/files/"
curl_with_key() {
    local remote_path="$1"
    local local_path="$2"
    remote_path="${remote_path#/}"
    if [[ -z "$local_path" ]]; then
        local_path="$(basename "$remote_path")"
    fi
    curl -sS -H "x-api-key: d92ead44d7ca8202645517e1956442339c2f3263aa425804deaa62d4d0bbd881" \
        "${REPO}${remote_path}" -o "${local_path}" > /dev/null 2>&1
}
start=$(date +%s)
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}
function print_ok() {
    echo -e "${BIWhite}${BLUE}$1${NC}"
}
function print_install() {
    echo -e "${LIME}✥${BIWhite} $1${NC}"
    sleep 1
}
function print_error() {
    echo -e "${RED}${REDBG}$1${NC}"
}
function print_success() {
    if [[ 0 -eq $? ]]; then
        echo -e "${BIWhite}✥${LIME} $1 Berhasil Di Pasang${NC}"
        sleep 2
    fi
}
function mengecek_akses_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root user: Starting installation process"
    else
        print_error "The current user is not the root user. Please switch to root and run the script again."
        return
    fi
}
end=$(date +%s)
secs_to_human $((end-start))
print_install "Install Direktori dan log file Xray"
mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain
mkdir -p /var/log/xray
chown www-data:www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
mkdir -p /var/lib >/dev/null 2>&1
while IFS=":" read -r a b; do
    case $a in
        "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
        "Shmem") ((mem_used+=${b/kB}))  ;;
        "MemFree" | "Buffers" | "Cached" | "SReclaimable")
            mem_used="$((mem_used-=${b/kB}))"
        ;;
    esac
done < /proc/meminfo
Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"
export tanggal=$(date -d "0 days" +"%d-%m-%Y - %X")
export OS_Name=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')
export Kernel=$(uname -r)
export Arch=$(uname -m)
export IP=$(curl -s https://ipinfo.io/ip/)
print_success "Direktori dan log file Xray"
function pengaturan_pertama() {
    clear
    print_install "Mengatur Tanggal,waktu ke WIB"
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Tanggal,waktu ke WIB"
}
function memasang_nginx() {
    clear
    print_install "Install Nginx & konfigurasinya"
    apt install nginx -y
    cat <<EOL | sudo tee /etc/nginx/mime.types > /dev/null 2>&1
types {
    text/html                             html htm shtml;
    text/css                              css;
    text/xml                              xml;
    image/gif                             gif;
    image/jpeg                            jpeg jpg;
    application/javascript                js;
    application/atom+xml                  atom;
    application/rss+xml                   rss;
    application/vnd.ms-fontobject         eot;
    font/ttf                              ttf;
    font/opentype                         otf;
    font/woff                             woff;
    font/woff2                            woff2;
    application/octet-stream              bin exe dll;
    application/x-shockwave-flash         swf;
    application/pdf                       pdf;
    application/json                      json;
    application/zip                       zip;
    application/x-7z-compressed           7z;
}
EOL
    sudo nginx -t
    sudo systemctl restart nginx
    print_success "Nginx & konfigurasinya"
}
function memasang_paket_dasar() {
    clear
    print_install "Install Paket Dasar"
    export DEBIAN_FRONTEND=noninteractive
    apt update -y
    apt upgrade -y
    apt dist-upgrade -y
    apt install -y at htop zip pwgen openssl netcat-openbsd socat cron bash-completion figlet ruby wondershaper
    gem install lolcat > /dev/null 2>&1
    apt install -y iptables iptables-persistent
    apt install -y ntpdate chrony
    ntpdate pool.ntp.org > /dev/null 2>&1
    systemctl enable netfilter-persistent
    systemctl restart netfilter-persistent
    systemctl enable --now chrony > /dev/null 2>&1
    systemctl restart chrony > /dev/null 2>&1
    chronyc sourcestats -v > /dev/null 2>&1
    chronyc tracking -v > /dev/null 2>&1
    apt install -y --no-install-recommends software-properties-common
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    apt install -y \
      speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev \
      libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools \
      libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr \
      libxml-parser-perl build-essential gcc g++ python3 htop lsof tar wget curl git \
      unzip p7zip-full libc6 util-linux msmtp-mta ca-certificates bsd-mailx \
      netfilter-persistent net-tools gnupg lsb-release cmake screen xz-utils apt-transport-https dnsutils jq easy-rsa
    apt clean
    apt autoremove -y
    apt remove --purge -y exim4 ufw firewalld > /dev/null 2>&1
    print_success "Paket Dasar"
}
function memasang_domain() {
    clear
    print_install "Silahkan Atur Domain Anda"
    echo -e "${BIWhite}┌──────────────────────────────────────┐${NC}"
    echo -e "${LIME}            Setup domain Menu         ${NC}"
    echo -e "${BIWhite}└──────────────────────────────────────┘${NC}"
    echo -e "${LIME}[${BIWhite}01${LIME}]${BIWhite} Menggunakan Domain Sendiri${NC}"
    echo -e "${LIME}[${BIWhite}02${LIME}]${BIWhite} Menggunakan Domain Bawaan Dari Script${NC}"
    echo -e "${BIWhite}└──────────────────────────────────────┘${NC}"
    echo -e ""
    while true; do
        read -p "Silahkan Pilih Opsi 1 Atau 2: " host
        echo ""
        if [[ $host == "1" ]]; then
            read -p "Silahkan Masukan Domain Mu: " host1
            echo "IP=$host1" >> /var/lib/ipvps.conf
            echo $host1 > /etc/xray/domain
            echo $host1 > /root/domain
            echo "ns-$host1" > /root/nsdomain
            echo "ns-$host1" > /etc/xray/dns
            echo -e "${BIWhite}Subdomain $host1 Mu Berhasil Di Atur${NC}"
            echo ""
            break
        elif [[ $host == "2" ]]; then
            echo -e "${BIWhite}Mengatur Subdomain Mu${NC}"
            curl_with_key "files/cloudflare" && chmod +x cloudflare && ./cloudflare
            rm -f /root/cloudflare
            clear
            echo -e "${BIWhite}Subdomain Mu Berhasil Di Atur${NC}"
            break
        else
            echo -e "${RED}Pilihan Mu Tidak Valid! Harap Pilih Angka 1 Atau 2.${NC}"
            echo -e "${BIWhite}└──────────────────────────────────────┘${NC}"
        fi
    done
    
    print_success "Hore Domain Mu"
}
memasang_notifikasi_bot() {
  clear
  mkdir -p /etc/bot > /dev/null 2>&1
  local MYIP=$(curl -sS ipv4.icanhazip.com)
  local OS=$(lsb_release -d | cut -f2)
  local RAM=$(free -m | awk '/Mem:/ {print $2" MB"}')
  local UPTIME=$(uptime -p | sed 's/up //')
  local CPU=$(awk -F ': ' '/^model name/ {print $2; exit}' /proc/cpuinfo)
  local domain=$(cat /etc/xray/domain 2>/dev/null || echo "undefined")
  local TIMEZONE=$(date +'%Y-%m-%d %H:%M:%S %Z')
  local CITY=$(curl -s ipinfo.io/city)
  local ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10)
  local CHATID="1496322138"
  local KEY="5813428539:AAGYOn5lRxkQGLPztqywj4ePcyNrSOgMDSE"
  local URL="https://api.telegram.org/bot$KEY/sendMessage"
  local TIME="10"

  local username=""
  local EXPIRE_INFO=""
  sudo touch /etc/bot/.bot.db
  sudo chmod 644 /etc/bot/.bot.db
  echo "#bot# 5813428539:AAGYOn5lRxkQGLPztqywj4ePcyNrSOgMDSE 1496322138" >> /etc/bot/.bot.db

  if [[ -f /etc/systemd/methode.conf ]]; then
      login_method=$(grep '^LOGIN=' /etc/systemd/methode.conf | cut -d'=' -f2 | tr -d ' \t\r\n')
  else
      login_method="PASSWORD"
  fi
  if [[ "$login_method" == "PASSWORD" ]]; then
      username="Install Via Password"
      EXPIRE_INFO="<code>Lifetime (Unlimited Days) (Active)</code>"
  else
      local izinsc="https://script.stunnel.sbs/api/data/ip"
      local IP_DATA_LINE=$(curl -s -H "x-api-key: d92ead44d7ca8202645517e1956442339c2f3263aa425804deaa62d4d0bbd881" "$izinsc" | grep -w "$MYIP" | head -1)

      username=$(echo "$IP_DATA_LINE" | awk '{print $2}')
      local exp=$(echo "$IP_DATA_LINE" | awk '{print $3}')

      if [[ "$exp" == "lifetime" ]]; then
        EXPIRE_INFO="<code>Lifetime (Unlimited Days) (Active)</code>"
      elif [[ -n "$exp" ]]; then
        local exp_timestamp=$(date -d "$exp" +%s 2>/dev/null)
        if [[ $? -eq 0 ]]; then
          local today_timestamp=$(date +%s)
          local DAYS_LEFT=$(( (exp_timestamp - today_timestamp) / 86400 ))
          local sts="(Active)"
          if [[ "$today_timestamp" -ge "$exp_timestamp" ]]; then
            sts="(Expired)"
          fi
          EXPIRE_INFO="<code>$exp ($DAYS_LEFT Days) $sts</code>"
        else
          EXPIRE_INFO="<code>Invalid / Unknown Date</code>"
        fi
      else
        EXPIRE_INFO="<code>Not Set</code>"
      fi
  fi
  local TEXT="
<b>━━━━━━━━━━━━━━━━━</b>
<b🏷️ NOTIFICATIONS🏷️</b>
<b>━━━━━━━━━━━━━━━━━</b>
<b>Autoscript Installation v25.8.3</b>
<b>Name :</b> <code>$username</code>
<b>Time :</b> <code>$TIMEZONE</code>
<b>Domain :</b> <code>$domain</code>
<b>IP :</b> <code>$MYIP</code>
<b>ISP :</b> <code>$ISP</code>
<b>City :</b> <code>$CITY</code>
<b>OS :</b> <code>$OS</code>
<b>RAM :</b> <code>$RAM</code>
<b>Uptime :</b> <code>$UPTIME</code>
<b>CPU :</b> <code>$CPU</code>
<b>Expiration :</b> $EXPIRE_INFO
<b>━━━━━━━━━━━━━━━━━</b>
<b>Automatic Notification From Installer Client...</b>
"

  local INLINE_KEYBOARD='{"inline_keyboard":[[{"text":"Telegram","url":"https://t.me/xcode001"}]]}'

  curl -s --max-time "$TIME" -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html&reply_markup=$INLINE_KEYBOARD" "$URL" >/dev/null
}
function install_firwall() {
interface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
cat >/etc/iptables/rules.v4 <<-END
# Generated by iptables-save v1.8.10 (nf_tables) on Fri Aug  8 07:35:38 2025
*filter
:INPUT ACCEPT [13020:1346840]
:FORWARD ACCEPT [41:12387]
:OUTPUT ACCEPT [18332:6991542]
:fail2ban_dump - [0:0]
:fail2ban_rest - [0:0]
-A INPUT -i wg0 -j ACCEPT
-A INPUT -p udp -m udp --dport 5300 -j ACCEPT
-A INPUT -p udp -m udp --dport 36712 -j ACCEPT
-A INPUT -p tcp -j fail2ban_rest
-A INPUT -p tcp -j fail2ban_dump
-A INPUT -i $interface -p udp -m udp --dport 443 -j ACCEPT
-A FORWARD -i wg0 -o $interface -j ACCEPT
-A FORWARD -m string --string "BitTorrent" --algo bm -j DROP
-A FORWARD -m string --string "BitTorrent protocol" --algo bm -j DROP
-A FORWARD -m string --string "peer_id=" --algo bm -j DROP
-A FORWARD -m string --string ".torrent" --algo bm -j DROP
-A FORWARD -m string --string "announce.php?passkey=" --algo bm -j DROP
-A FORWARD -m string --string "torrent" --algo bm -j DROP
-A FORWARD -m string --string "announce" --algo bm -j DROP
-A FORWARD -m string --string "info_hash" --algo bm -j DROP
-A FORWARD -m string --string "/default.ida?" --algo bm -j DROP
-A FORWARD -m string --string ".exe?/c+dir" --algo bm -j DROP
-A FORWARD -m string --string ".exe?/c_tftp" --algo bm -j DROP
-A FORWARD -m string --string "peer_id" --algo kmp -j DROP
-A FORWARD -m string --string "BitTorrent" --algo kmp -j DROP
-A FORWARD -m string --string "BitTorrent protocol" --algo kmp -j DROP
-A FORWARD -m string --string "bittorrent-announce" --algo kmp -j DROP
-A FORWARD -m string --string "announce.php?passkey=" --algo kmp -j DROP
-A FORWARD -m string --string "find_node" --algo kmp -j DROP
-A FORWARD -m string --string "info_hash" --algo kmp -j DROP
-A FORWARD -m string --string "get_peers" --algo kmp -j DROP
-A FORWARD -m string --string "announce" --algo kmp -j DROP
-A FORWARD -m string --string "announce_peers" --algo kmp -j DROP
-A FORWARD -s 10.8.0.0/24 -o $interface -j ACCEPT
-A FORWARD -s 20.8.0.0/24 -o $interface -j ACCEPT
-A FORWARD -i $interface -o wg0 -j ACCEPT
-A FORWARD -i wg0 -j ACCEPT
-A FORWARD -i $interface -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -j fail2ban_rest
-A OUTPUT -p tcp -j fail2ban_dump
COMMIT
# Completed on Fri Aug  8 07:35:38 2025
# Generated by iptables-save v1.8.10 (nf_tables) on Fri Aug  8 07:35:38 2025
*nat
:PREROUTING ACCEPT [1067:93233]
:INPUT ACCEPT [1188:71569]
:OUTPUT ACCEPT [1764:110876]
:POSTROUTING ACCEPT [1609:97203]
-A PREROUTING -p udp -m udp --dport 53 -j REDIRECT --to-ports 5300
-A PREROUTING -i $interface -p udp -m multiport ! --dports 53,5300,7100,7200,7300,25000,14040,443 -j DNAT --to-destination :36712
-A PREROUTING -p tcp -m tcp --dport 1194 -j ACCEPT
-A POSTROUTING -s 10.66.66.0/24 -o $interface -j MASQUERADE
-A POSTROUTING -s 20.8.0.0/24 -o $interface -j MASQUERADE
-A POSTROUTING -s 10.8.0.0/24 -o $interface -j MASQUERADE
-A POSTROUTING -o $interface -j MASQUERADE
COMMIT
# Completed on Fri Aug  8 07:35:38 2025
END

cat >/etc/iptables/rules.v6 <<-END
# Generated by ip6tables-save v1.8.10 (nf_tables) on Fri Aug  8 07:35:40 2025
*filter
:INPUT ACCEPT [35:9917]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [47:10589]
-A INPUT -p udp -m udp --dport 36712 -j ACCEPT
COMMIT
# Completed on Fri Aug  8 07:35:40 2025
# Generated by ip6tables-save v1.8.10 (nf_tables) on Fri Aug  8 07:35:40 2025
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [2:136]
:POSTROUTING ACCEPT [2:136]
-A PREROUTING -i $interface -p udp -m udp --dport 1:21 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 23:52 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 54 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 56:68 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 70:79 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 81:142 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 144:442 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 444:443 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 445:807 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 809:1193 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 1195:2051 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 2053:2221 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 2223:2442 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 2444:5299 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 5301:5354 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 5356:7099 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 7101:7199 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 7201:7299 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 7301:7399 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 7401:7499 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 7501:7599 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 7601:8487 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 8489:9089 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 9091:9999 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 10001:14021 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 14023:24999 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 25001:65535 -j DNAT --to-destination :36712
-A PREROUTING -i $interface -p udp -m udp --dport 1:65535 -j DNAT --to-destination :36712
COMMIT
# Completed on Fri Aug  8 07:35:40 2025
END

netfilter-persistent reload >> /dev/null 2>&1
systemctl restart netfilter-persistent >> /dev/null 2>&1
}
function memasang_ssl() {
    clear
    print_install "Install Sertifikat SSL Pada Domain"
    rm -rf /etc/xray/xray.key
    rm -rf /etc/xray/xray.crt
    country=SG
    state=Singapore
    locality=Central
    organization=KPNTunnel
    organizationalunit=KPNTunnel
    commonname=xCode001
    email=support@kpntunnel.com
    openssl genrsa -out /etc/xray/xray.key 2048 > /dev/null 2>&1
    yes '' | openssl req -new -x509 -key /etc/xray/xray.key -out /etc/xray/xray.crt -days 1095 -subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email" > /dev/null 2>&1
    chmod 777 /etc/xray/xray.key
    print_success "Sertifikat SSL Pada Domain"
}
function memasang_folder_xray() {
    clear
    print_install "Membuat Folder Tambahan Untuk SSH & Xray"
    rm -rf /etc/user_locks.db
    rm -rf /etc/ssh/.ssh.db
    rm -rf /etc/vmess/.vmess.db
    rm -rf /etc/vless/.vless.db
    rm -rf /etc/trojan/.trojan.db
    rm -rf /etc/shadowsocks/.shadowsocks.db
    rm -rf /etc/bot/.bot.db
    rm -rf /etc/user-create/user.log
    mkdir -p /etc/bot
    mkdir -p /etc/ssh
    mkdir -p /etc/xray
    mkdir -p /etc/vmess
    mkdir -p /etc/vless
    mkdir -p /etc/trojan
    mkdir -p /etc/shadowsocks
    mkdir -p /usr/bin/xray/
    mkdir -p /var/log/xray/
    mkdir -p /var/www/html
    mkdir -p /etc/limit/ssh/ip
    mkdir -p /etc/limit/vmess/ip
    mkdir -p /etc/limit/vless/ip
    mkdir -p /etc/limit/trojan/ip
    mkdir -p /etc/limit/shadowsocks/ip
    mkdir -p /etc/limit/ssh/
    mkdir -p /etc/limit/vmess
    mkdir -p /etc/limit/vless
    mkdir -p /etc/limit/trojan
    mkdir -p /etc/limit/shadowsocks
    mkdir -p /etc/user-create
    chmod +x /var/log/xray
    touch /etc/xray/domain
    touch /etc/user_locks.db
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    touch /etc/ssh/.ssh.db
    touch /etc/vmess/.vmess.db
    touch /etc/vless/.vless.db
    touch /etc/trojan/.trojan.db
    touch /etc/shadowsocks/.shadowsocks.db
    touch /etc/bot/.bot.db
    chmod 644 /etc/user_locks.db
    echo "& plughin Account" >>/etc/ssh/.ssh.db
    echo "& plughin Account" >>/etc/vmess/.vmess.db
    echo "& plughin Account" >>/etc/vless/.vless.db
    echo "& plughin Account" >>/etc/trojan/.trojan.db
    echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
    echo "echo -e 'Vps Config User Account'" >> /etc/user-create/user.log
    print_install "Folder Tambahan Untuk SSH & Xray"
}
function memasang_xray() {
    clear
    print_install "Install Core Xray Versi 25.8.3"
    domainSock_dir="/run/xray"
    ! [ -d $domainSock_dir ] && mkdir -p $domainSock_dir
    chown www-data.www-data $domainSock_dir
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 25.8.3 >/dev/null 2>&1
    curl_with_key "config/config.json" "/etc/xray/config.json"
    curl_with_key "files/runn.service" "/etc/systemd/system/runn.service"
    olduuid="1d1c1d94-6987-4658-a4dc-8821a30fe7e0"
    newuuid=$(cat /proc/sys/kernel/random/uuid)
    sed -i "s/$olduuid/$newuuid/g" "/etc/xray/config.json"
    domain=$(cat /etc/xray/domain)
    IPVS=$(cat /etc/xray/ipvps)
    print_success "Core Xray Versi 25.8.3"
    clear
    curl -s ipinfo.io/city >> /etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >> /etc/xray/isp
    print_install "Install Konfigurasi Paket"
    curl_with_key "config/xray.conf" "/etc/nginx/conf.d/xray.conf"
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    rm -rf /etc/nginx/nginx.conf
    curl_with_key "config/nginx.conf" "/etc/nginx/nginx.conf"
    chmod +x /etc/systemd/system/runn.service
    rm -rf /etc/systemd/system/xray.service.d
    cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service By KPNTunnel
Documentation=https://github.com
After=network.target nss-lookup.target
[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000
[Install]
WantedBy=multi-user.target
EOF
    print_success "Konfigurasi Paket"
}
function memasang_password_ssh(){
    clear
    print_install "Install Config SSH"
    curl_with_key "files/password" "/etc/pam.d/common-password"
    chmod +x /etc/pam.d/common-password
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "
cd
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END
cat > /etc/rc.local <<-END
#!/bin/sh -e
exit 0
END
chmod +x /etc/rc.local
systemctl enable rc-local
systemctl start rc-local.service
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
print_success "SSH"
}
function memasang_pembatas(){
clear
print_install "Install Service Pembatasan IP & Quota"
curl_with_key "config/limiter.sh" && chmod +x limiter.sh && ./limiter.sh
print_success "Service Pembatasan IP & Quota"
}
function memasang_sshd(){
clear
print_install "Install SSHD"
curl_with_key "files/sshd" "/etc/ssh/sshd_config"
chmod 700 /etc/ssh/sshd_config
systemctl restart ssh > /dev/null 2>&1
rm -rf /etc/security/limits.conf > /dev/null 2>&1
curl_with_key "config/limits.conf" "/etc/security/limits.conf"
rm -rf /etc/sysctl.conf > /dev/null 2>&1
curl_with_key "config/sysctl.conf" "/etc/sysctl.conf"
sysctl -p > /dev/null 2>&1
ulimit -n 67108864
print_success "SSHD Success Dipasang"
}
function memasang_vnstat(){
clear
print_install "Install Vnstat"
apt -y install vnstat > /dev/null 2>&1
apt -y install libsqlite3-dev > /dev/null 2>&1
wget -q https://humdi.net/vnstat/vnstat-2.6.tar.gz > /dev/null 2>&1
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc > /dev/null 2>&1 && make >/dev/null 2>&1 && make install > /dev/null 2>&1
cd
sed -i 's/Interface "'""$interface""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
rm -f /root/vnstat-2.6.tar.gz > /dev/null 2>&1
rm -rf /root/vnstat-2.6 > /dev/null 2>&1
print_success "Vnstat"
}
get_rclone_config_base64() {
  local config_content="[dr]
type = drive
scope = drive
token = {\"access_token\":\"ya29.a0Aa4xrXMPV1knwJYo1qRyshFvggrEvUHYxilF3Oc0iaC-0p762eTzkEYBdmCjR2KwDabzbbZXIM3Svw0sLrXjvkPtkDuBfGx4Den9d81Ow2iDoOTOatFozLAecoM3tYZf_gi6Ae4TP3ihKRY_bMQOgSmmRV8aCgYKATASARISFQEjDvL9oVrYgGh_ET41TJzHH-o8kA0163\",\"token_type\":\"Bearer\",\"refresh_token\":\"1//0grQ5ja__cHVYCgYIARAAGBASNwF-L9IrID7_Slumh-27S23f5CWyT7s8xLXwrXrIetDSNcaNcRCunfDagoB6cJCH1hUekmhvZJk\",\"expiry\":\"2022-10-25T12:15:50.5813586+08:00\"}"
  echo "$config_content" | base64 -w 0
}

memasang_pencadangan() {
  clear
  print_install "Install Pencadangan Server"
  export DEBIAN_FRONTEND=noninteractive
  apt update && apt install rclone -y

  local rclone_b64_config=$(get_rclone_config_base64)
  mkdir -p /root/.config/rclone/
  echo "$rclone_b64_config" | base64 -d > /root/.config/rclone/rclone.conf
  
  cd /bin
  git clone https://github.com/magnific0/wondershaper.git >/dev/null 2>&1
  cd wondershaper
  sudo make install
  cd
  rm -rf wondershaper
  echo > /home/limit

  apt install msmtp-mta ca-certificates bsd-mailx -y > /dev/null 2>&1
  cat <<EOF>>/etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account default
host smtp.gmail.com
port 587
auth on
user xiaolitekyt@gmail.com
from xiaolitekyt@gmail.com
password cwmbmtnushnfrlup
logfile ~/.msmtp.log
EOF
  chown -R www-data:www-data /etc/msmtprc
  print_success "Pencadangan Server"
}
function memasang_bbr_hybla(){
  clear
  print_install "Install BBR Hybla"

  apt install -y ethtool net-tools haveged htop iftop >/dev/null 2>&1

  systemctl enable haveged >/dev/null 2>&1
  systemctl start haveged >/dev/null 2>&1

  echo -e "${YELLOW} Mengoptimasi parameter kernel...${NC}"
  cat > /etc/sysctl.d/99-network-tune.conf << EOF
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 65536
net.core.somaxconn = 32768
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_mem = 65536 131072 262144
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.ip_local_port_range = 1024 65535
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 2
net.core.busy_poll = 50
net.core.busy_read = 50
EOF

  sysctl -p /etc/sysctl.d/99-network-tune.conf >/dev/null 2>&1

  echo -e "${YELLOW} Memeriksa dan mengaktifkan BBR congestion control...${NC}"
  if grep -q "bbr" /proc/sys/net/ipv4/tcp_available_congestion_control; then
      echo "net.core.default_qdisc=fq" >> /etc/sysctl.d/99-network-tune.conf
      echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-network-tune.conf
      sysctl -p /etc/sysctl.d/99-network-tune.conf >/dev/null 2>&1
      echo -e "${GREEN} BBR congestion control berhasil diaktifkan${NC}"
  else
      echo -e "${RED} BBR tidak tersedia pada kernel ini${NC}"
  fi

  echo -e "${YELLOW} Mengoptimasi network interfaces...${NC}"
  for interface in $(ip -o -4 addr show | awk '{print $2}' | grep -v "lo" | cut -d/ -f1); do
      echo -e "${GREEN} Mengoptimasi $interface ${NC}"
      ethtool -s $interface gso off gro off tso off
      ethtool --offload $interface rx off tx off
      CURRENT_RX=$(ethtool -g $interface > /dev/null 2>&1 | grep "RX:" | head -1 | awk '{print $2}')
      CURRENT_TX=$(ethtool -g $interface > /dev/null 2>&1 | grep "TX:" | head -1 | awk '{print $2}')
      if [ ! -z "$CURRENT_RX" ] && [ ! -z "$CURRENT_TX" ]; then
          ethtool -G $interface rx $CURRENT_RX tx $CURRENT_TX
      fi
  done

  echo -e "${YELLOW} Mengkonfigurasi QoS untuk prioritas paket...${NC}"
  cat > /usr/local/sbin/network-tune.sh << 'EOF'
#!/bin/bash
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags ACK ACK -j CLASSIFY --set-class 1:1
iptables -t mangle -A PREROUTING -p tcp -m length --length 0:128 -j CLASSIFY --set-class 1:1
iptables -t mangle -A PREROUTING -p udp -m length --length 0:128 -j CLASSIFY --set-class 1:1
iptables -t mangle -A PREROUTING -p icmp -j CLASSIFY --set-class 1:1
INTERFACES=$(ip -o -4 addr show | awk '{print $2}' | grep -v "lo" | cut -d/ -f1)
for IFACE in $INTERFACES; do
    tc qdisc del dev $IFACE root 2 > /dev/null 2>&1
    tc qdisc add dev $IFACE root handle 1: htb default 10
    tc class add dev $IFACE parent 1: classid 1:1 htb rate 1000mbit ceil 1000mbit prio 1
    tc qdisc add dev $IFACE parent 1:1 fq_codel quantum 300 ecn
done
EOF

  chmod +x /usr/local/sbin/network-tune.sh
  /usr/local/sbin/network-tune.sh >/dev/null 2>&1

  echo -e "${YELLOW} Membuat systemd service...${NC}"
  cat > /etc/systemd/system/network-tune.service << EOF
[Unit]
Description=Network Optimization for Low Latency
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/network-tune.sh
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload >/dev/null 2>&1
  systemctl enable network-tune.service >/dev/null 2>&1
  systemctl start network-tune.service >/dev/null 2>&1

  total_ram=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
  if [ "$total_ram" -le 4096 ]; then
    echo -e "${YELLOW}RAM terdeteksi ${total_ram}MB. Mengaktifkan swap 2GB untuk kestabilan sistem.${NC}"
    SWAP_SIZE_MB=2048

    if swapon --show | grep -q "/swapfile"; then
      echo -e "${RED}Swapfile sudah aktif, lewati pembuatan swap.${NC}"
    else
      echo -e "${CYAN}Membuat swap file sebesar ${SWAP_SIZE_MB}MB...${NC}"

      if command -v fallocate > /dev/null 2>&1 && fallocate -l "${SWAP_SIZE_MB}M" /swapfile; then
        echo -e "${GREEN}Berhasil menggunakan fallocate.${NC}"
      else
        echo -e "${YELLOW}fallocate gagal, menggunakan dd...${NC}"
        dd if=/dev/zero of=/swapfile bs=1M count=$SWAP_SIZE_MB status=progress
      fi

      chmod 600 /swapfile
      mkswap /swapfile
      swapon /swapfile
      chown root:root /swapfile

      if ! grep -q "/swapfile" /etc/fstab; then
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
        echo -e "${GREEN}Swap ditambahkan ke /etc/fstab${NC}"
      fi

      sysctl -w vm.swappiness=10 > /dev/null 2>&1
      sysctl -w vm.vfs_cache_pressure=50 > /dev/null 2>&1
      sed -i '/vm.swappiness/d' /etc/sysctl.conf
      sed -i '/vm.vfs_cache_pressure/d' /etc/sysctl.conf
      echo "vm.swappiness=10" >> /etc/sysctl.conf
      echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.conf
      sysctl -p > /dev/null 2>&1
    fi
  else
    echo -e "${GREEN}RAM ${total_ram}MB terdeteksi cukup besar. Melewati pembuatan swap.${NC}"
  fi

  clear
  print_success "BBR Hybla"
}
function memasang_fail2ban(){
    clear
    print_install "Install Fail2ban"
    apt update -y && apt install -y fail2ban > /dev/null 2>&1
    if [ -d "/usr/local/ddos" ]; then
        echo -e "\nUninstalling The Previous Version First..."
        rm -rf /usr/local/ddos
    fi
    mkdir -p /usr/local/ddos
    for file in ddos.conf LICENSE ignore.ip.list ddos.sh; do
        curl_with_key "ddos/$file" "/usr/local/ddos/$file" || \
        curl_with_key "ddos/$file" "/usr/local/ddos/$file"
        echo -n '.'
    done
    echo ""
    chmod +x /usr/local/ddos/ddos.sh
    ln -sf /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
    /usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
    systemctl enable --now fail2ban
    systemctl restart fail2ban
    print_success "Fail2ban"
}
function memasang_netfilter(){
clear
print_install "Install Netfilter & IPtables"
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" > /dev/null 2>&1
wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" > /dev/null 2>&1
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload
cd
apt autoclean -y > /dev/null 2>&1
apt autoremove -y > /dev/null 2>&1
print_success "Netfilter & IPtables"
}
function memasang_badvpn(){
clear
print_install "Install BadVPN"
curl_with_key "files/newudpgw" "/usr/bin/badvpn-udpgw"
chmod +x /usr/bin/badvpn-udpgw
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500' /etc/rc.local
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500
print_success "BadVPN"
}
function memasang_restart(){
clear
print_install "Memulai Semua Services"
systemctl daemon-reload > /dev/null 2>&1
systemctl restart ssh > /dev/null 2>&1
systemctl restart dropbear > /dev/null 2>&1
systemctl restart ws-stunnel > /dev/null 2>&1
systemctl restart fail2ban > /dev/null 2>&1
systemctl restart vnstat > /dev/null 2>&1
systemctl restart cron > /dev/null 2>&1
systemctl restart atd > /dev/null 2>&1
systemctl restart server-sldns > /dev/null 2>&1
systemctl restart client-sldns > /dev/null 2>&1
systemctl restart udp-custom > /dev/null 2>&1
systemctl restart noobzvpns > /dev/null 2>&1
systemctl start netfilter-persistent > /dev/null 2>&1
systemctl enable --now nginx > /dev/null 2>&1
systemctl enable --now xray > /dev/null 2>&1
systemctl enable --now haproxy > /dev/null 2>&1
systemctl enable --now udp-custom > /dev/null 2>&1
systemctl enable --now noobzvpns > /dev/null 2>&1
systemctl enable --now server-sldns > /dev/null 2>&1
systemctl enable --now client-sldns > /dev/null 2>&1
systemctl enable --now dropbear > /dev/null 2>&1
systemctl enable --now ws-stunnel > /dev/null 2>&1
systemctl enable --now rc-local > /dev/null 2>&1
systemctl enable --now cron > /dev/null 2>&1
systemctl enable --now atd > /dev/null 2>&1
systemctl enable --now netfilter-persistent > /dev/null 2>&1
systemctl enable --now fail2ban > /dev/null 2>&1
history -c
echo "unset HISTFILE" >> /etc/profile
cd
rm -f /root/openvpn
rm -f /root/key.pem
rm -f /root/cert.pem
print_success "Semua Services"
}
function memasang_menu(){
    clear
    print_install "Install Menu"
    curl_with_key "speedtest.sh" && chmod +x speedtest.sh
    curl_with_key "menu/menu.zip"
    unzip -P kpntunnelenc01 menu.zip > /dev/null 2>&1
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    sleep 2
    sudo dos2unix /usr/local/sbin/* > /dev/null 2>&1
    rm -rf menu
    rm -rf menu.zip
    print_success "Menu"
}
function memasang_profile(){
    clear
    print_install "Install Profil"
    cat >/root/.profile <<EOF
if [ "$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF
cat >/etc/cron.d/xp_all <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		2 0 * * * root /usr/local/sbin/xp
	END
	cat >/etc/cron.d/logclean <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		*/20 * * * * root /usr/local/sbin/clearlog
		END
    chmod 644 /root/.profile
    cat >/etc/cron.d/daily_reboot <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		0 5 * * * root /sbin/reboot
	END
    echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
    systemctl restart cron
    cat >/home/daily_reboot <<-END
		5
	END
cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF
echo "/bin/false" >>/etc/shells
echo "/usr/sbin/nologin" >>/etc/shells
cat >/etc/rc.local <<EOF
#!/bin/sh -e
# rc.local
# By default this script does nothing.
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF
    chmod +x /etc/rc.local
    AUTOREB=$(cat /home/daily_reboot)
    SETT=11
    if [ $AUTOREB -gt $SETT ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi
    print_success "Profil"
}
function memasang_dropbear(){
clear
print_install "Install Dropbear"
export DEBIAN_FRONTEND=noninteractive
apt -y install dropbear
systemctl stop dropbear >> /dev/null 2>&1
rm -rf /etc/default/dropbear >/dev/null 2>&1
rm -rf /usr/sbin/dropbear >/dev/null 2>&1
curl_with_key "config/dropbear.conf" "/etc/default/dropbear"
curl_with_key "files/dropbear" "/usr/sbin/dropbear"
chmod +x /etc/default/dropbear
chmod +x /usr/sbin/dropbear
curl_with_key "files/issue.net" "/etc/banner-ssh.txt"
chmod +x /etc/banner-ssh.txt
echo "Banner /etc/banner-ssh.txt" >> /etc/ssh/sshd_config > /dev/null 2>&1
systemctl enable dropbear >> /dev/null 2>&1
apt -y install squid >> /dev/null 2>&1
curl_with_key "files/squid3.conf" "/etc/squid/squid.conf"
sed -i $MYIP5 /etc/squid/squid.conf >> /dev/null 2>&1
print_success "Dropbear"
}
function memasang_sshws(){
    clear
    print_install "Install Websocket"
    curl_with_key "files/ws-stunnel" "/usr/local/bin/ws-stunnel"
    curl_with_key "config/tun.conf" "/usr/bin/tun.conf"
    curl_with_key "config/ws" "/usr/local/bin/ws"
    chmod +x /usr/local/bin/ws-stunnel
    chmod +x /usr/local/bin/ws
    curl_with_key "files/ws-stunnel.service" "/etc/systemd/system/ws-stunnel.service" && chmod +x /etc/systemd/system/ws-stunnel.service
    curl_with_key "files/ws.service" "/etc/systemd/system/ws.service" && chmod +x /etc/systemd/system/ws.service
    systemctl daemon-reload
    systemctl enable ws-stunnel.service
    systemctl start ws-stunnel.service
    systemctl restart ws-stunnel.service
    systemctl enable ws.service
    systemctl start ws.service
    systemctl restart ws.service
    chmod 644 /usr/bin/tun.conf
    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >> /dev/null 2>&1
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >> /dev/null 2>&1
    iptables-save > /etc/iptables.up.rules
    iptables-restore -t < /etc/iptables.up.rules
    netfilter-persistent save
    netfilter-persistent reload
    cd
    apt autoclean -y >> /dev/null 2>&1
    apt autoremove -y >> /dev/null 2>&1
    print_success "Websocket"
}
function memasang_slowdns() {
clear
print_install "Install Slowdns"
cd
rm -rf /root/nsdomain
rm nsdomain
clear
sub=$(cat /etc/xray/domain)
SUB_DOMAIN=${sub}
NS_DOMAIN=ns-${SUB_DOMAIN}
echo $NS_DOMAIN > /root/nsdomain
nameserver=$(cat /root/nsdomain)
domen=$(cat /etc/xray/domain)
cd
echo "Port 2222" >> /etc/ssh/sshd_config
echo "Port 2269" >> /etc/ssh/sshd_config
sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding yes/g' /etc/ssh/sshd_config
service ssh restart > /dev/null 2>&1
service sshd restart > /dev/null 2>&1
rm -rf /etc/slowdns
mkdir -m 777 /etc/slowdns
curl_with_key "slowdns/dnstt-server" "/etc/slowdns/dnstt-server"
curl_with_key "slowdns/dnstt-client" "/etc/slowdns/dnstt-client"
cd /etc/slowdns
chmod +x *
./dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub >/dev/null 2>&1
chmod +x *
cd
cat > /etc/systemd/system/server-sldns.service <<-EOF
[Unit]
Description=SlowDNS Server by KPNTunnel
Documentation=https://t.me/xcode001
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/etc/slowdns/dnstt-server -udp 0.0.0.0:5300 -privkey-file /etc/slowdns/server.key $nameserver 127.0.0.1:444
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/client-sldns.service <<-EOF
[Unit]
Description=SlowDNS Client by KPNTunnel
Documentation=https://t.me/xcode001
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/etc/slowdns/dnstt-client -doh https://cloudflare-dns.com/dns-query --pubkey-file /etc/slowdns/server.pub $nameserver 127.0.0.1:2269
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
cd
chmod +x /etc/systemd/system/client-sldns.service
chmod +x /etc/systemd/system/server-sldns.service
pkill dnstt-server >/dev/null 2>&1
pkill dnstt-client >/dev/null 2>&1
systemctl daemon-reload >/dev/null 2>&1
systemctl stop server-sldns >/dev/null 2>&1
systemctl enable server-sldns >/dev/null 2>&1
systemctl start server-sldns >/dev/null 2>&1
systemctl restart server-sldns >/dev/null 2>&1
systemctl stop client-sldns >/dev/null 2>&1
systemctl enable client-sldns >/dev/null 2>&1
systemctl start client-sldns >/dev/null 2>&1
systemctl restart client-sldns >/dev/null 2>&1
clear
cd
print_success "Slowdns"
}
function loading() {
  clear
  local pid=$1
  local delay=0.1
  local spin='-\|/'
  while ps -p $pid > /dev/null 2>&1; do
    local temp=${spin:0:1}
    printf "[%c] " "$spin"
    local spin=$temp${spin%"$temp"}
    sleep $delay
    printf "\b\b\b\b\b\b"
  done
  printf "    \b\b\b\b"
}
function memasang_udepe() {
clear
print_install "Install UDP Custom"
clear
cd
rm -rf /root/udp
mkdir -p /root/udp
sleep 1
echo -e "${BIWhite}downloading udp-custom${NC}"
wget -q --show-progress --load-cookies /tmp/cookies.txt "https://docs.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://docs.google.com/uc?export=download&id=1ixz82G_ruRBnEEp4vLPNF2KZ1k8UfrkV' -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=1ixz82G_ruRBnEEp4vLPNF2KZ1k8UfrkV" -O /root/udp/udp-custom && rm -rf /tmp/cookies.txt
chmod +x /root/udp/udp-custom
sleep 1
echo -e "${BIWhite}downloading default config${NC}"
wget -q --show-progress --load-cookies /tmp/cookies.txt "https://docs.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://docs.google.com/uc?export=download&id=1klXTiKGUd2Cs5cBnH3eK2Q1w50Yx3jbf' -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=1klXTiKGUd2Cs5cBnH3eK2Q1w50Yx3jbf" -O /root/udp/config.json && rm -rf /tmp/cookies.txt
chmod 644 /root/udp/config.json
if [ -z "$1" ]; then
cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=UDP CUSTOM BY KPNTunnel
[Service]
User=root
Type=simple
ExecStart=/root/udp/udp-custom server
WorkingDirectory=/root/udp/
Restart=always
RestartSec=2s
[Install]
WantedBy=default.target
EOF
else
cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=UDP CUSTOM BY KPNTunnel
[Service]
User=root
Type=simple
ExecStart=/root/udp/udp-custom server -exclude $1
WorkingDirectory=/root/udp/
Restart=always
RestartSec=2s
[Install]
WantedBy=default.target
EOF
fi
echo -e "${BIWhite}start service udp-custom${NC}"
systemctl start udp-custom > /dev/null 2>&1
sleep 1
echo -e "${BIWhite}enable service udp-custom${NC}"
systemctl enable udp-custom > /dev/null 2>&1
sleep 3 & loading $!
cd
print_success "UDP Custom"
}
function memasang_noobz() {
  clear
  print_install "Install Noobzvpns"
  curl_with_key "noobzvpns.zip"
  unzip noobzvpns.zip
  rm -rf noobzvpns.zip noobzvpns.zip.1 noobzvpns.zip.2 noobzvpns.zip.3 noobzvpns.zip.4
  cd noobzvpns
  chmod +x install.sh
  ./install.sh > /dev/null 2>&1
  systemctl start noobzvpns > /dev/null 2>&1
  systemctl restart noobzvpns > /dev/null 2>&1
  cd
  curl_with_key "config/vpn.sh" && chmod +x vpn.sh && ./vpn.sh
  curl_with_key "config/wg.sh" && chmod +x wg.sh && ./wg.sh
  print_success "Noobzvpns"
}
function memasang_haproxy() {
clear
print_install "Install Haproxy"
if [ "$EUID" -ne 0 ]; then
  echo -e "${BIWhite}Jalankan script ini sebagai root!${NC}"
  exit 1
fi
systemctl stop haproxy > /dev/null 2>&1
systemctl disable haproxy > /dev/null 2>&1
apt purge -y haproxy > /dev/null 2>&1
apt autoremove -y
rm -f /etc/haproxy/haproxy.cfg
rm -f /etc/haproxy/hap.pem
rm -rf /etc/haproxy/errors
rm -rf /var/lib/haproxy
rm -f /run/haproxy.pid
echo -e "${BIWhite}✥Instalasi ulang HAProxy...${NC}"
sudo apt update && sudo apt install haproxy -y
mkdir -p /etc/haproxy
cd
country=SG
state=Singapore
locality=Central
organization=KPNTunnel
organizationalunit=KPNTunnel
commonname=xCode001
email=support@kpntunnel.com
openssl genrsa -out key.pem 2048 > /dev/null 2>&1
yes '' | openssl req -new -x509 -key key.pem -out cert.pem -days 1095 -subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email" > /dev/null 2>&1
cat key.pem cert.pem >> /etc/haproxy/hap.pem
rm -rf /root/cert.pem > /dev/null 2>&1
rm -rfv /root/key.pem > /dev/null 2>&1
echo -e "${BIWhite}✥Buat konfigurasi HAProxy baru...${NC}"
cat > /etc/haproxy/haproxy.cfg << 'EOF'
global
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 1d
    log /dev/log local0
    log /dev/log local1 notice
    log /dev/log local0 info
    tune.h2.initial-window-size 2147483647
    tune.ssl.default-dh-param 2048
    pidfile /run/haproxy.pid
    chroot /var/lib/haproxy
    user haproxy
    group haproxy
    daemon
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11
    ca-base /etc/ssl/certs
    crt-base /etc/ssl/private
defaults
    log global
    mode tcp
    option dontlognull
    timeout connect 200ms
    timeout client  300s
    timeout server  300s
frontend multiport
    mode tcp
    bind *:222-1000 tfo
    tcp-request inspect-delay 500ms
    tcp-request content accept if HTTP
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend recir_http if HTTP
    default_backend recir_https
frontend multiports
    mode tcp
    bind abns@haproxy-http accept-proxy tfo
    default_backend recir_https_www
frontend ssl
    mode tcp
    bind *:444 tfo
    bind *:777 tfo
    bind abns@haproxy-https accept-proxy ssl crt /etc/haproxy/hap.pem alpn h2,http/1.1 tfo
    tcp-request inspect-delay 500ms
    tcp-request content capture req.ssl_sni len 100
    tcp-request content accept if { req.ssl_hello_type 1 }
    acl chk-02_up hdr(Connection) -i upgrade
    acl chk-02_ws hdr(Upgrade) -i websocket
    acl this_payload payload(0,7) -m bin 5353482d322e30
    acl up-to ssl_fc_alpn -i h2
    use_backend GRUP_LITE if up-to
    use_backend LITE if chk-02_up chk-02_ws
    use_backend LITE if { path_reg -i ^\/(.*) }
    use_backend BOT_LITE if this_payload
    default_backend CHANNEL_LITE
backend recir_https_www
    mode tcp
    server misssv-bau 127.0.0.1:2223 check
backend LITE
    mode http
    server lite-vermilion 127.0.0.1:1010 send-proxy check
backend GRUP_LITE
    mode tcp
    server lite-vermilions 127.0.0.1:1013 send-proxy check
backend CHANNEL_LITE
    mode tcp
    balance roundrobin
    server y-lite 127.0.0.1:1194 check
    server lite-x 127.0.0.1:1012 send-proxy check
backend BOT_LITE
    mode tcp
    server xiao-lite 127.0.0.1:2222 check
backend recir_http
    mode tcp
    server loopback-for-http abns@haproxy-http send-proxy-v2 check
backend recir_https
    mode tcp
    server loopback-for-https abns@haproxy-https send-proxy-v2 check
EOF
echo -e "${BIWhite}✥Cek konfigurasi HAProxy...${NC}"
haproxy -c -f /etc/haproxy/haproxy.cfg > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${BIWhite}✥Konfigurasi valid. Menyalakan HAProxy...${NC}"
    systemctl enable haproxy >/dev/null 2>&1
    echo -e "${BIWhite}✥HAProxy berhasil dipasang dan diperbarui!${NC}"
else
    echo -e "${BIWhite}✥Konfigurasi tidak valid. Cek file: /etc/haproxy/haproxy.cfg${NC}"
fi
print_success "Haproxy"
}
function memasang_index_page() {
  cat <<EOF > /var/www/html/index.html
<!DOCTYPE html>
<html lang="en" >
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Project xCode001</title>
  <script src="https://cdn.tailwindcss.com" type="text/javascript"></script>
  <style>
    /* Cursor blink animation */
    @keyframes blink {
      0%, 50%, 100% { opacity: 1; }
      25%, 75% { opacity: 0; }
    }
    .blink-caret {
      animation: blink 1s step-start infinite;
    }
  </style>
</head>
<body class="bg-gray-900 text-green-400 font-mono h-screen flex items-center justify-center p-4">

  <div class="w-full max-w-3xl bg-black bg-opacity-90 rounded-lg shadow-lg p-6">
    <div>
      <span class="text-red-500 font-bold">user@xcode001</span>
      <span class="text-gray-500">:~$</span>
      <span> <span id="typed-text"></span><span class="blink-caret">|</span></span>
    </div>
  </div>

  <script type="text/javascript">
    const text = "welcome to xcode001 project";
    const typedText = document.getElementById("typed-text");
    let index = 0;

    function type() {
      if (index < text.length) {
        typedText.textContent += text.charAt(index);
        index++;
        setTimeout(type, 100);
      }
    }
    type();
  </script>
</body>
</html>
EOF
}
function mulai_penginstallan(){
    clear
    setup_grub_env
    tampilan
    mengecek_akses_root
    memasang_paket_dasar
    pengaturan_pertama
    memasang_nginx
    memasang_folder_xray
    memasang_domain
    memasang_ssl
    memasang_xray
    memasang_password_ssh
    memasang_pembatas
    memasang_sshd
    memasang_vnstat
    memasang_pencadangan
    memasang_menu
    memasang_fail2ban
    memasang_netfilter
    memasang_dropbear
    memasang_sshws
    memasang_profile
    memasang_badvpn
    memasang_slowdns
    memasang_udepe
    memasang_noobz
    memasang_haproxy
    memasang_bbr_hybla
    memasang_index_page
    memasang_restart
    memasang_notifikasi_bot
    install_firwall
}
mulai_penginstallan
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/domain
clear
secs_to_human "$(($(date +%s) - ${start}))"
echo -e "${BIWhite}Script Successfully Installed${NC}"
read -p "$( echo -e "${BIYellow}Press ${BIWhite}[ ${NC}${LIME}Enter${NC} ${BIWhite}]${BIYellow} For reboot${NC}") "
reboot