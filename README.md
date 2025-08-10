# 🚀 xCode001 Installer Script

## 📦 Installation Preparation

Jalankan perintah berikut untuk memperbarui paket, menginstal dependensi penting, mengunduh script installer, dan menjalankan proses instalasi di dalam sesi `screen`:

```
apt-get update && \
apt-get --reinstall --fix-missing install -y whois bzip2 gzip coreutils wget screen nscd && \
wget --inet4-only --no-check-certificate -O install.sh "https://raw.githubusercontent.com/xcode000/project/main/install.sh" && \
chmod +x install.sh && \
screen -S setup ./install.sh
```

```
### 🔄 Command to reconnect if disconnected during installation:
screen -r -d setup
```