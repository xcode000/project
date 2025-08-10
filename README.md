We Work Only Detok , Not Only Tok Detok

```
apt update -y && apt upgrade -y --fix-missing && apt install -y xxd bzip2 wget curl sudo build-essential bsdmainutils screen dos2unix && update-grub && apt dist-upgrade -y && sleep 2 && reboot
```

```
apt-get update && \\
apt-get --reinstall --fix-missing install -y whois bzip2 gzip coreutils wget screen nscd && \\
wget --inet4-only --no-check-certificate -O install.sh "https://raw.githubusercontent.com/xcode000/project/main/install.sh" && \\
chmod +x install.sh && \\
screen -S setup ./install.sh
```

Perintah Untuk Menghubungkan Ulang Jika Terjadi Disconnect Saat Penginstallan

```
screen -r -d setup
```