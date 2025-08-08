#!/bin/bash
# Debian 9 & 10 64bit
# Ubuntu 18.04 & 20.04 bit
# Centos 7 & 8 64bit 
# Mod By Jrtunnel
# ==========================================
# Color
PERMISSION() {
    if [[ -f /etc/systemd/methode.conf ]]; then
        login_method=$(grep '^LOGIN=' /etc/systemd/methode.conf | cut -d'=' -f2 | tr -d ' \t\r\n')
    else
        echo -e "\033[1;91mPermission Denied (Please Register)\033[0m"
        exit 1
    fi
    if [[ "$login_method" == "PASSWORD" ]]; then
        echo -e "\033[1;92mPermission Accepted (Login via Password)\033[0m"
        return 0
    fi
    MYIP=$(curl -sS ipv4.icanhazip.com | tr -d ' \t\r\n')
    TODAY_DATE=$(date +'%Y-%m-%d')
    ALL_ENTRIES_RAW=$(curl -sS -H "x-api-key: d92ead44d7ca8202645517e1956442339c2f3263aa425804deaa62d4d0bbd881" \
        "https://script.ipserver.my/api/data/ip")
    ALL_ENTRIES=$(echo "$ALL_ENTRIES_RAW" | sed 's/###/\n###/g' | sed '/^\s*$/d')
    FILTERED_ENTRIES=$(echo "$ALL_ENTRIES" | sed 's/^### *//')

    AUTHORIZED_ENTRY=$(echo "$FILTERED_ENTRIES" | awk -v ip="$MYIP" '$3 == ip { print; exit }')

    if [[ -z "$AUTHORIZED_ENTRY" ]]; then
        echo -e "\033[1;91mPermission Denied (IP Not Found)\033[0m"
        exit 1
    fi
    EXP_DATE=$(echo "$AUTHORIZED_ENTRY" | awk '{print $2}' | tr -d ' \t\r\n')
    IP_FROM_ENTRY=$(echo "$AUTHORIZED_ENTRY" | awk '{print $3}' | tr -d ' \t\r\n')
    STATUS_RAW=$(echo "$AUTHORIZED_ENTRY" | awk '{print $7}' | tr -d ' \t\r\n')
    STATUS="$(tr '[:lower:]' '[:upper:]' <<< ${STATUS_RAW:0:1})${STATUS_RAW:1}"
    if [[ "$MYIP" != "$IP_FROM_ENTRY" ]]; then
        echo -e "\033[1;91mPermission Denied (IP Mismatch)\033[0m"
        exit 1
    fi
    TODAY_SECONDS=$(date -d "$TODAY_DATE" +%s)
    EXP_SECONDS=$(date -d "$EXP_DATE" +%s)

    if (( TODAY_SECONDS > EXP_SECONDS )); then
        echo -e "\033[1;91mPermission Denied (Expired: $EXP_DATE)\033[0m"
        exit 1
    fi
    echo -e "\033[1;92mPermission Accepted (Status: $STATUS, Expired: $EXP_DATE)\033[0m"
}
PERMISSION
clear
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHT='\033[0;37m'
# ==========================================
# Getting
MYIP=$(wget -qO- ipinfo.io/ip);
echo "Checking VPS"
IZIN=$( curl ipinfo.io/ip | grep $MYIP )
if [ $MYIP = $MYIP ]; then
echo -e "${NC}${GREEN}Permission Accepted...${NC}"
else
echo -e "${NC}${RED}Permission Denied!${NC}";
echo -e "${NC}${LIGHT}Fuck You!!"
exit 0
fi
# ==================================================

# Check OS version
if [[ -e /etc/debian_version ]]; then
	source /etc/os-release
	OS=$ID # debian or ubuntu
elif [[ -e /etc/centos-release ]]; then
	source /etc/os-release
	OS=centos
fi

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[information]${Font_color_suffix}"

if [[ -e /etc/wireguard/params ]]; then
	echo -e "${Info} WireGuard sudah diinstal, silahkan ketik addwg untuk menambah client."
	exit 1
fi

echo -e "${Info} Wireguard Script Mod By Jrtunnel"
# Detect public IPv4 address and pre-fill for the user

# Detect public interface and pre-fill for the user
SERVER_PUB_NIC=$(ip -o $ANU -4 route show to default | awk '{print $5}');

# Install WireGuard tools and module
	if [[ $OS == 'ubuntu' ]]; then
	apt install -y wireguard
elif [[ $OS == 'debian' ]]; then
	echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
	apt-get update
	apt-get install -y iptables resolvconf qrencode
        apt-get install -y -t buster-backports wireguard
	apt install -y wireguard-tools iptables iptables-persistent
	apt install -y linux-headers-$(uname -r)
elif [[ ${OS} == 'centos' ]]; then
	curl -Lo /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
	yum -y update
	yum -y install wireguard-dkms wireguard-tools
	fi
apt install iptables iptables-persistent -y
# Make sure the directory exists (this does not seem the be the case on fedora)
mkdir /etc/wireguard >/dev/null 2>&1

chmod 600 -R /etc/wireguard/

SERVER_PRIV_KEY=$(wg genkey)
SERVER_PUB_KEY=$(echo "$SERVER_PRIV_KEY" | wg pubkey)

# Save WireGuard settings
echo "SERVER_PUB_NIC=$SERVER_PUB_NIC
SERVER_WG_NIC=wg0
SERVER_WG_IPV4=10.66.66.1
SERVER_PORT=443
SERVER_PRIV_KEY=$SERVER_PRIV_KEY
SERVER_PUB_KEY=$SERVER_PUB_KEY" >/etc/wireguard/params

source /etc/wireguard/params

# Add server interface
echo "[Interface]
Address = $SERVER_WG_IPV4/24
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIV_KEY
PostUp = iptables -A FORWARD -i $SERVER_PUB_NIC -o wg0 -j ACCEPT; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE
PostDown = iptables -D FORWARD -i $SERVER_PUB_NIC -o wg0 -j ACCEPT; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE" >>"/etc/wireguard/wg0.conf"


iptables -t nat -I POSTROUTING -s 10.66.66.1/24 -o $SERVER_PUB_NIC -j MASQUERADE
iptables -I INPUT 1 -i wg0 -j ACCEPT
iptables -I FORWARD 1 -i $SERVER_PUB_NIC -o wg0 -j ACCEPT
iptables -I FORWARD 1 -i wg0 -o $SERVER_PUB_NIC -j ACCEPT
iptables -I INPUT 1 -i $SERVER_PUB_NIC -p udp --dport 443 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4
sudo iptables-save > /etc/iptables/rules.v6
netfilter-persistent save
netfilter-persistent reload

systemctl start "wg-quick@wg0"
systemctl enable "wg-quick@wg0"

# Check if WireGuard is running
systemctl is-active --quiet "wg-quick@wg0"
WG_RUNNING=$?

# Tambahan
# cd /usr/bin
# wget -O addwg "https://raw.githubusercontent.com/khairunisya/ssh/main/wireguard/addwg.sh"
# wget -O delwg "https://raw.githubusercontent.com/khairunisya/ssh/main/wireguard/delwg.sh"
# wget -O renewwg "https://raw.githubusercontent.com/khairunisya/ssh/main/wireguard/renewwg.sh"
# wget https://raw.githubusercontent.com/khairunisya/ssh/main/wireguard/xpwg
# chmod +x addwg
# chmod +x delwg
# chmod +x renewwg
# chmod +x xpwg
# cd
# echo "0 0 * * * root xpwg" >> /etc/crontab
rm -f /root/wg.sh