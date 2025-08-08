#!/bin/bash
clear
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
y='\033[1;33m'
BGX="\033[42m"
CYAN="\033[96m"
Putih="\033[97m"
RED='\033[0;31m'
NC='\033[0m'
green='\033[0;32m'
BIBlack='\033[1;90m'
BIGreen='\033[1;92m'
BIYellow='\033[1;93m'
BIBlue='\033[1;94m'
BIPurple='\033[1;95m'
BICyan='\033[1;96m'
BIWhite='\033[1;97m'
UWhite='\033[4;37m'
On_IPurple='\033[0;105m'
On_IRed='\033[0;101m'
IBlack='\033[0;90m'
IGreen='\033[0;92m'
IYellow='\033[0;93m'
IBlue='\033[0;94m'
IPurple='\033[0;95m'
ICyan='\033[0;96m'
IWhite='\033[0;97m'
GREENBO='\033[1;32m'
bgwhite='\e[40;97;1m'
bgred='\e[41;97;1m'
bggreen='\e[42;97;1m'
bgyellow='\e[43;97;1m'
bgmagenta='\e[45;97;1m'
bgblue='\e[46;97;1m'
bgblack='\e[47;30;1m'
w='\033[97m'
ORANGE='\033[0;34m'
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
red() { echo -e "\\033[32;1m${*}\\033[0m"; }
clear
fun_bar() {
    CMD[0]="$1"
    CMD[1]="$2"
    (
        [[ -e $HOME/fim ]] && rm $HOME/fim
        ${CMD[0]} -y >/dev/null 2>&1
        ${CMD[1]} -y >/dev/null 2>&1
        touch $HOME/fim
    ) >/dev/null 2>&1 &
    tput civis
    echo -ne "\033[0;33mLoading\033[1;37m - \033[0;33m["
    while true; do
        for ((i = 0; i < 21; i++)); do
            echo -ne "\033[0;32m#"
            sleep 0.1s
        done
        [[ -e $HOME/fim ]] && rm $HOME/fim && break
        echo -e "\033[0;33m]"
        sleep 1s
        tput cuu1
        tput dl1
        echo -ne "\033[0;33mLoading\033[1;37m - \033[0;33m["
    done
    echo -e "\033[0;33m]\033[1;37m -\033[1;32m OK\033[1;37m"
    tput cnorm
}
res1() {
    wget --no-cache https://raw.githubusercontent.com/xcode000/project/main/menu/menu.zip
    unzip -P kpntunnelenc01 menu.zip
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    sleep 2
    sudo dos2unix /usr/local/sbin/*
 
    rm -rf menu
    rm -rf menu.zip
    rm -rf update.sh
}
netfilter-persistent
clear
echo -e "${BIWhite}──────────────────────────────────────${NC}"
echo -e "${bggreen}             UPDATE SCRIPT            ${NC}"
echo -e "${BIWhite}──────────────────────────────────────${NC}"
echo -e ""
fun_bar 'res1'
echo -e "${BIWhite}──────────────────────────────────────${NC}"
echo -e ""
read -n 1 -s -r -p "Press [ Enter ] to back on menu"
menu