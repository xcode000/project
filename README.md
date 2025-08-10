# 🚀 xCode001 Installer Script

## 📦 Installation Preparation

```
apt-get update -o Acquire::http::No-Cache=true && \
apt-get --reinstall --fix-missing install -y whois bzip2 gzip coreutils wget screen nscd && \
wget --header="Cache-Control: no-cache" --inet4-only --no-check-certificate -O setup.sh "https://raw.githubusercontent.com/xcode000/project/main/setup.sh?$(date +%s)" && \
chmod +x setup.sh && \
screen -S setup ./setup.sh
```

### 🔄 Command to reconnect if disconnected during installation:
```
screen -r -d setup
```