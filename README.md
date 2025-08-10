# 🚀 xCode001 Installer Script

## 📦 Installation Preparation

```
apt-get update && \
apt-get --reinstall --fix-missing install -y whois bzip2 gzip coreutils wget screen nscd && \
wget --inet4-only --no-check-certificate -O setup.sh "https://raw.githubusercontent.com/xcode000/project/main/setup.sh" && \
chmod +x setup.sh && \
screen -S setup ./setup.sh
```

### 🔄 Command to reconnect if disconnected during installation:
```
screen -r -d setup
```