#!/bin/bash
# PortalSSH Server
# ==================================================
# initialisasi var
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
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(curl -s https://checkip.amazonaws.com/);
MYIP2="s/xxxxxxxxx/$MYIP/g";
ANU=$(ip -o $ANU -4 route show to default | awk '{print $5}');
# Install OpenVPN dan Easy-RSA
apt install openvpn easy-rsa unzip -y
apt install openssl iptables iptables-persistent -y
rm -rfv /etc/openvpn/server/easy-rsa/
mkdir -p /etc/openvpn/server/easy-rsa/
cd /etc/openvpn/
wget --no-cache https://raw.githubusercontent.com/xcode000/project/main/config/vpn.zip >> /dev/null 2>&1
unzip vpn.zip
rm -f vpn.zip
chown -R root:root /etc/openvpn/server/easy-rsa/
cd
mkdir -p /usr/lib/openvpn/
cp /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /usr/lib/openvpn/openvpn-plugin-auth-pam.so
# nano /etc/default/openvpn
sed -i 's/#AUTOSTART="all"/AUTOSTART="all"/g' /etc/default/openvpn
# restart openvpn dan cek status openvpn
systemctl enable --now openvpn-server@server-tcp-1194
systemctl enable --now openvpn-server@server-udp-25000
/etc/init.d/openvpn restart
/etc/init.d/openvpn status

# aktifkan ip4 forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf

# Buat config client TCP 1194
cat > /etc/openvpn/client-tcp-1194.ovpn <<-END
client
dev tun
proto tcp
sndbuf 0
rcvbuf 0
remote xxxxxxxxx 1194
resolv-retry 5
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
comp-lzo yes
setenv opt block-outside-dns
key-direction 1
verb 3
auth-user-pass
keepalive 10 120
float
END

sed -i $MYIP2 /etc/openvpn/client-tcp-1194.ovpn;

# # Buat config client UDP 25000
cat > /etc/openvpn/client-udp-25000.ovpn <<-END
client
dev tun
proto udp
sndbuf 0
rcvbuf 0
remote xxxxxxxxx 25000
resolv-retry 5
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
comp-lzo yes
setenv opt block-outside-dns
key-direction 1
verb 3
auth-user-pass
keepalive 10 120
float
END

sed -i $MYIP2 /etc/openvpn/client-udp-25000.ovpn;

# # # Buat config client SSL
# cat > /etc/openvpn/client-ohp.ovpn <<-END
# # THANKS TO KPNTUNNEL.COM
# # Experimental Config only
# # Examples demonstrated below on how to Play with OHPServer
# client
# dev tun
# proto tcp
# sndbuf 0
# rcvbuf 0
# # We can also play with CRLFs
# # Working Port 443, 80, 1194
# remote bug.com 1194
# #remote "HEAD https://ajax.googleapis.com HTTP/1.1/r/n/r/n"
# # Every types of Broken remote line setups/crlfs/payload are accepted, just put them inside of double-quotes
# # This proxy uses as our main forwarder for OpenVPN tunnel.
# http-proxy xxxxxxxxx 9088
# port 443
# resolv-retry 5
# nobind
# persist-key
# persist-tun
# remote-cert-tls server
# cipher AES-256-CBC
# comp-lzo yes
# setenv opt block-outside-dns
# key-direction 1
# verb 3
# auth-user-pass
# keepalive 10 120
# float
# END

# sed -i $MYIP2 /etc/openvpn/client-ohp.ovpn;

cd
# pada tulisan xxx ganti dengan alamat ip address VPS anda
/etc/init.d/openvpn restart

# masukkan Ca ke dalam config client TCP 1194
echo '<ca>' >> /etc/openvpn/client-tcp-1194.ovpn
cat /etc/openvpn/server/ca.crt >> /etc/openvpn/client-tcp-1194.ovpn
echo '</ca>' >> /etc/openvpn/client-tcp-1194.ovpn

# masukkan Crt ke dalam config client TCP 1194
echo '<cert>' >> /etc/openvpn/client-tcp-1194.ovpn
cat /etc/openvpn/server/easy-rsa/pki/issued/client.crt >> /etc/openvpn/client-tcp-1194.ovpn
echo '</cert>' >> /etc/openvpn/client-tcp-1194.ovpn

# masukkan Key ke dalam config client TCP 1194
echo '<key>' >> /etc/openvpn/client-tcp-1194.ovpn
cat /etc/openvpn/server/easy-rsa/pki/private/client.key >> /etc/openvpn/client-tcp-1194.ovpn
echo '</key>' >> /etc/openvpn/client-tcp-1194.ovpn

# masukkan Tls-Auth ke dalam config client TCP 1194
echo '<tls-crypt>' >> /etc/openvpn/client-tcp-1194.ovpn
cat /etc/openvpn/server/tc.key >> /etc/openvpn/client-tcp-1194.ovpn
echo '</tls-crypt>' >> /etc/openvpn/client-tcp-1194.ovpn

# Copy config OpenVPN client ke home directory root agar mudah didownload ( TCP 1194 )
cp /etc/openvpn/client-tcp-1194.ovpn /var/www/html/tcp.ovpn

# # masukkan certificatenya ke dalam config client UDP 25000
echo '<ca>' >> /etc/openvpn/client-udp-25000.ovpn
cat /etc/openvpn/server/ca.crt >> /etc/openvpn/client-udp-25000.ovpn
echo '</ca>' >> /etc/openvpn/client-udp-25000.ovpn

# masukkan Crt ke dalam config client udp 25000
echo '<cert>' >> /etc/openvpn/client-udp-25000.ovpn
cat /etc/openvpn/server/easy-rsa/pki/issued/client.crt >> /etc/openvpn/client-udp-25000.ovpn
echo '</cert>' >> /etc/openvpn/client-udp-25000.ovpn

# masukkan Key ke dalam config client udp 25000
echo '<key>' >> /etc/openvpn/client-udp-25000.ovpn
cat /etc/openvpn/server/easy-rsa/pki/private/client.key >> /etc/openvpn/client-udp-25000.ovpn
echo '</key>' >> /etc/openvpn/client-udp-25000.ovpn

# masukkan Tls-Auth ke dalam config client udp 25000
echo '<tls-crypt>' >> /etc/openvpn/client-udp-25000.ovpn
cat /etc/openvpn/server/tc.key >> /etc/openvpn/client-udp-25000.ovpn
echo '</tls-crypt>' >> /etc/openvpn/client-udp-25000.ovpn

# Copy config OpenVPN client ke home directory root agar mudah didownload ( udp 25000 )
cp /etc/openvpn/client-udp-25000.ovpn /var/www/html/udp.ovpn


# # # masukkan certificatenya ke dalam config client ohp
# echo '<ca>' >> /etc/openvpn/client-ohp.ovpn
# cat /etc/openvpn/server/ca.crt >> /etc/openvpn/client-ohp.ovpn
# echo '</ca>' >> /etc/openvpn/client-ohp.ovpn

# # masukkan Crt ke dalam config client TLS ohp
# echo '<cert>' >> /etc/openvpn/client-ohp.ovpn
# cat /etc/openvpn/server/easy-rsa/pki/issued/client.crt >> /etc/openvpn/client-ohp.ovpn
# echo '</cert>' >> /etc/openvpn/client-ohp.ovpn

# # masukkan Key ke dalam config clientTLS ohp
# echo '<key>' >> /etc/openvpn/client-ohp.ovpn
# cat /etc/openvpn/server/easy-rsa/pki/private/client.key >> /etc/openvpn/client-ohp.ovpn
# echo '</key>' >> /etc/openvpn/client-ohp.ovpn

# # masukkan Tls-Auth ke dalam config client TLS ohp
# echo '<tls-crypt>' >> /etc/openvpn/client-ohp.ovpn
# cat /etc/openvpn/server/tc.key >> /etc/openvpn/client-ohp.ovpn
# echo '</tls-crypt>' >> /etc/openvpn/client-ohp.ovpn

# # # Copy config OpenVPN client ke home directory root agar mudah didownload
# cp /etc/openvpn/client-ohp.ovpn /var/www/html/ohp.ovpn

# cd /var/www/html/
# zip openvpn-config.zip tcp.ovpn udp.ovpn ohp.ovpn > /dev/null 2>&1
cd
# Restart service openvpn
systemctl enable openvpn
systemctl start openvpn
/etc/init.d/openvpn restart

# Delete script
rm -f /root/vpn.sh