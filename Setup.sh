#!/bin/bash
# deploy_darkdox.sh

echo "[*] Deploying DarkDox System..."

# Install dependencies
pip3 install requests cryptography pycryptodome stem beautifulsoup4

# Configure TOR for stealth
sudo apt-get install tor -y
sudo service tor start

# Generate encryption keys
python3 -c "
import hashlib
import base64
import os
key = base64.b64encode(os.urandom(32)).decode()
print(f'ENCRYPTION_KEY={key}')
" > .env

# Create systemd service
cat << EOF | sudo tee /etc/systemd/system/darkdox.service
[Unit]
Description=DarkDox Intelligence Service
After=network.target tor.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
ExecStart=/usr/bin/python3 $(pwd)/darkdox.py -i
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable darkdox.service
sudo systemctl start darkdox.service

echo "[+] DarkDox deployed as system service"
echo "[+] Access: systemctl status darkdox"
echo "[+] Interactive: python3 darkdox.py -i"
