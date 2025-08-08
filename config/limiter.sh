#!/bin/bash
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
if [[ $EUID -ne 0 ]]; then
    echo "Skrip ini harus dijalankan sebagai root."
    exit 1
fi

install_services() {
    local REPO="https://raw.githubusercontent.com/xcode000/project/main/files/"
    local LIMIT_IP_SERVICES=("limiter-vm" "limiter-vl" "limiter-trj" "limiter-shd" "limiter-ssh")
    local LIMIT_IP_REMOTE_FILES=("lite-vm" "lite-vl" "lite-trj" "lite-shd" "lite-ssh")
    local LIMIT_QUOTA_SERVICES=("limitvmess" "limitvless" "limittrojan" "limitshadowsocks")
    local LIMIT_QUOTA_REMOTE_FILES=("vmess" "vless" "trojan" "shadowsocks")
    local ALL_SERVICES=("${LIMIT_IP_SERVICES[@]}" "${LIMIT_QUOTA_SERVICES[@]}")

    echo "Memulai instalasi layanan systemd..."

    echo "1. Menghapus layanan lama dan file terkait..."
    for service in "${ALL_SERVICES[@]}"; do
        systemctl disable --now "${service}.timer" > /dev/null 2>&1
        systemctl disable --now "${service}.service" > /dev/null 2>&1
        rm -f "/etc/systemd/system/${service}.service"
        rm -f "/etc/systemd/system/${service}.timer"
        echo "- ${service} dihapus."
    done

    rm -f "/usr/local/bin/"{lite-vm,lite-vl,lite-trj,lite-shd,lite-ssh} > /dev/null 2>&1
    rm -f "/etc/xray/limit."{vmess,vless,trojan,shadowsocks} > /dev/null 2>&1
    echo "- File biner lama dihapus."

    echo "2. Menginstal skrip dan membuat layanan Limit IP..."
    for i in "${!LIMIT_IP_SERVICES[@]}"; do
        local service="${LIMIT_IP_SERVICES[$i]}"
        local remote_file="${LIMIT_IP_REMOTE_FILES[$i]}"
        local binary_path="/usr/local/bin/${remote_file}"

        echo "- Mengunduh skrip ${remote_file}..."
        wget -q -O "${binary_path}" "${REPO}/${remote_file}" || {
            echo "Gagal mengunduh ${remote_file}. Lanjut ke layanan berikutnya."
            continue
        }
        chmod +x "${binary_path}"

        cat > "/etc/systemd/system/${service}.service" << EOF
[Unit]
Description=${service} Service
After=network.target

[Service]
Type=oneshot
ExecStart=${binary_path}

[Install]
WantedBy=multi-user.target
EOF

        cat > "/etc/systemd/system/${service}.timer" << EOF
[Unit]
Description=Run ${service} every minute

[Timer]
OnCalendar=minutely
Persistent=true
Unit=${service}.service

[Install]
WantedBy=timers.target
EOF
        echo "- Layanan ${service} dibuat."
    done

    echo "3. Menginstal skrip dan membuat layanan Limit Kuota..."
    mkdir -p /etc/xray/
    for i in "${!LIMIT_QUOTA_SERVICES[@]}"; do
        local service="${LIMIT_QUOTA_SERVICES[$i]}"
        local remote_file="${LIMIT_QUOTA_REMOTE_FILES[$i]}"
        local binary_path="/etc/xray/limit.${remote_file}"

        echo "- Mengunduh skrip limit.${remote_file}..."
        wget -q -O "${binary_path}" "${REPO}/${remote_file}" || {
            echo "Gagal mengunduh ${remote_file}. Lanjut ke layanan berikutnya."
            continue
        }
        chmod +x "${binary_path}"

        cat > "/etc/systemd/system/${service}.service" << EOF
[Unit]
Description=${service} Service
After=network.target

[Service]
Type=oneshot
ExecStart=${binary_path}

[Install]
WantedBy=multi-user.target
EOF

        cat > "/etc/systemd/system/${service}.timer" << EOF
[Unit]
Description=Run ${service} every minute

[Timer]
OnCalendar=minutely
Persistent=true
Unit=${service}.service

[Install]
WantedBy=timers.target
EOF
        echo "- Layanan ${service} dibuat."
    done

    echo "4. Memuat ulang systemd dan mengaktifkan semua timer..."
    systemctl daemon-reload
    for service in "${ALL_SERVICES[@]}"; do
        systemctl enable --now "${service}.timer" > /dev/null 2>&1
        echo "- ${service}.timer diaktifkan."
    done

    echo "Semua layanan berhasil dipasang dan diaktifkan."
}

install_services

rm -f "$0"