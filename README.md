# 🚀 xCode001 Installer Script

### 📦 Installation Preparation
apt-get update && \
apt-get --reinstall --fix-missing install -y whois bzip2 gzip coreutils wget screen nscd && \
wget --inet4-only --no-check-certificate -O install.sh "https://raw.githubusercontent.com/xcode000/project/main/install.sh" && \
chmod +x install.sh && \
screen -S setup ./install.sh

---

### 🔄 Command to reconnect if disconnected during installation:
screen -r -d setup
