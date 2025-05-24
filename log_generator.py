import time
import random
from datetime import datetime
import threading
import json
import os

LOG_FILE = "sample_logs/auth.log"

# Load attack patterns
def load_attack_patterns():
    try:
        with open("config/attack_patterns.json", "r") as f:
            return json.load(f)
    except:
        return {
            "brute_force": {"max_attempts": 3, "time_window": 300},
            "scanning": {"max_users": 5, "time_window": 600}
        }

class LogGenerator:
    def __init__(self):
        self.users = ["admin", "root", "user1", "user2", "user3", "guest", "system"]
        # Expanded IP list with realistic ranges
        self.ips = [
            # Internal network IPs
            "192.168.1.100", "192.168.1.101", "192.168.1.102", "192.168.1.103",
            "192.168.1.104", "192.168.1.105", "192.168.1.106", "192.168.1.107",
            "192.168.1.108", "192.168.1.109", "192.168.1.110",
            
            # Corporate VPN range
            "172.16.0.25", "172.16.0.26", "172.16.0.27", "172.16.0.28",
            "172.16.0.29", "172.16.0.30", "172.16.0.31", "172.16.0.32",
            
            # DMZ and public servers
            "10.0.0.20", "10.0.0.21", "10.0.0.22", "10.0.0.23",
            "10.0.0.24", "10.0.0.25", "10.0.0.26", "10.0.0.27",
            
            # External IPs (simulating different regions)
            "203.0.113.45", "203.0.113.46", "203.0.113.47",  # Asia-Pacific
            "198.51.100.23", "198.51.100.24", "198.51.100.25",  # North America
            "203.0.113.78", "203.0.113.79", "203.0.113.80",  # Europe
            "198.51.100.56", "198.51.100.57", "198.51.100.58",  # South America
            "203.0.113.91", "203.0.113.92", "203.0.113.93",  # Africa
            
            # Known malicious IPs (for testing detection)
            "185.143.223.15", "185.143.223.16", "185.143.223.17",
            "45.95.147.22", "45.95.147.23", "45.95.147.24",
            
            # Cloud provider IPs
            "52.32.178.7", "52.32.178.8", "52.32.178.9",  # AWS
            "40.76.54.131", "40.76.54.132", "40.76.54.133",  # Azure
            "35.186.224.47", "35.186.224.48", "35.186.224.49"  # GCP
        ]
        self.attack_patterns = load_attack_patterns()
        self.running = True
        
        # Ensure log directory exists
        os.makedirs("sample_logs", exist_ok=True)
        
        # Initialize log file if it doesn't exist
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w") as f:
                f.write("")

    def generate_log_line(self, is_attack=False):
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        user = random.choice(self.users)
        
        # Weight IP selection based on type
        ip_weights = {
            'internal': 0.4,  # Internal network IPs
            'vpn': 0.2,      # VPN IPs
            'dmz': 0.15,     # DMZ IPs
            'external': 0.15, # External IPs
            'malicious': 0.05, # Known malicious IPs
            'cloud': 0.05    # Cloud provider IPs
        }
        
        # Select IP based on weights
        ip_type = random.choices(
            list(ip_weights.keys()),
            weights=list(ip_weights.values()),
            k=1
        )[0]
        
        if ip_type == 'internal':
            ip = random.choice(self.ips[0:11])
        elif ip_type == 'vpn':
            ip = random.choice(self.ips[11:19])
        elif ip_type == 'dmz':
            ip = random.choice(self.ips[19:27])
        elif ip_type == 'external':
            ip = random.choice(self.ips[27:42])
        elif ip_type == 'malicious':
            ip = random.choice(self.ips[42:48])
        else:  # cloud
            ip = random.choice(self.ips[48:])
            
        port = random.randint(30000, 60000)
        sshd_id = random.randint(10000, 20000)
        
        if is_attack:
            event_type = "Failed"
            invalid_user_str = "invalid user " if random.random() < 0.5 else ""
        else:
            # Adjust weights based on IP type
            if ip_type in ['malicious', 'external']:
                weights = [0.4, 0.6]  # More failed attempts from external/malicious IPs
            else:
                weights = [0.2, 0.8]  # More successful attempts from internal IPs
                
            event_type = random.choices(
                ["Failed", "Accepted"], 
                weights=weights, 
                k=1
            )[0]
            invalid_user_str = "invalid user " if random.random() < 0.2 else ""

        if event_type == "Failed":
            log_line = f"{timestamp} server sshd[{sshd_id}]: Failed password for {invalid_user_str}{user} from {ip} port {port} ssh2\n"
        else:
            log_line = f"{timestamp} server sshd[{sshd_id}]: Accepted password for {user} from {ip} port {port} ssh2\n"

        return log_line

    def append_log(self, is_attack=False):
        with open(LOG_FILE, "a") as f:
            line = self.generate_log_line(is_attack)
            f.write(line)
            print(f"Appended: {line.strip()}")

    def generate_brute_force_attempts(self):
        user = random.choice(self.users)
        ip = random.choice(self.ips)
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        port_base = random.randint(30000, 60000)
        sshd_id_base = random.randint(10000, 20000)
        lines = []
        
        # Generate rapid failed attempts
        for i in range(self.attack_patterns["brute_force"]["max_attempts"] + 1):
            port = port_base + i
            sshd_id = sshd_id_base + i
            log_line = f"{timestamp} server sshd[{sshd_id}]: Failed password for {user} from {ip} port {port} ssh2\n"
            lines.append(log_line)
        
        # Sometimes add a successful login after brute force
        if random.random() < 0.3:
            log_line = f"{timestamp} server sshd[{sshd_id_base + len(lines)}]: Accepted password for {user} from {ip} port {port_base + len(lines)} ssh2\n"
            lines.append(log_line)
        
        return lines

    def generate_scanning_attempts(self):
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        ip = random.choice(self.ips)
        port_base = random.randint(30000, 60000)
        sshd_id_base = random.randint(10000, 20000)
        lines = []
        
        # Try different users from the same IP
        for i in range(self.attack_patterns["scanning"]["max_users"] + 1):
            user = random.choice(self.users)
            port = port_base + i
            sshd_id = sshd_id_base + i
            log_line = f"{timestamp} server sshd[{sshd_id}]: Failed password for invalid user {user} from {ip} port {port} ssh2\n"
            lines.append(log_line)
        
        return lines

    def generate_impossible_travel(self):
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        user = random.choice(self.users)
        ip1 = "192.168.1.100"  # ZoneB
        ip2 = "10.0.0.20"      # ZoneA
        port = random.randint(30000, 60000)
        sshd_id = random.randint(10000, 20000)
        
        lines = [
            f"{timestamp} server sshd[{sshd_id}]: Accepted password for {user} from {ip1} port {port} ssh2\n",
            f"{timestamp} server sshd[{sshd_id + 1}]: Accepted password for {user} from {ip2} port {port + 1} ssh2\n"
        ]
        return lines

    def generate_unusual_time_login(self):
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        user = random.choice(self.users)
        ip = random.choice(self.ips)
        port = random.randint(30000, 60000)
        sshd_id = random.randint(10000, 20000)
        
        log_line = f"{timestamp} server sshd[{sshd_id}]: Accepted password for {user} from {ip} port {port} ssh2\n"
        return [log_line]

    def run_attack_scenario(self):
        while self.running:
            # Randomly choose an attack type
            attack_type = random.choices(
                ["brute_force", "scanning", "impossible_travel", "unusual_time"],
                weights=[0.4, 0.3, 0.2, 0.1],
                k=1
            )[0]
            
            with open(LOG_FILE, "a") as f:
                if attack_type == "brute_force":
                    lines = self.generate_brute_force_attempts()
                elif attack_type == "scanning":
                    lines = self.generate_scanning_attempts()
                elif attack_type == "impossible_travel":
                    lines = self.generate_impossible_travel()
                else:  # unusual_time
                    lines = self.generate_unusual_time_login()
                
                for line in lines:
                    f.write(line)
                    print(f"Appended ({attack_type}): {line.strip()}")
            
            # Wait before next attack
            time.sleep(random.randint(20, 40))

    def run_normal_traffic(self):
        while self.running:
            self.append_log(is_attack=False)
            time.sleep(random.randint(2, 5))

    def start(self):
        print("Starting log generator with attack scenarios... Press Ctrl+C to stop.")
        
        # Start attack scenario in a separate thread
        attack_thread = threading.Thread(target=self.run_attack_scenario)
        attack_thread.daemon = True
        attack_thread.start()
        
        # Run normal traffic in main thread
        try:
            self.run_normal_traffic()
        except KeyboardInterrupt:
            self.running = False
            print("Log generator stopped.")

if __name__ == "__main__":
    generator = LogGenerator()
    generator.start()
