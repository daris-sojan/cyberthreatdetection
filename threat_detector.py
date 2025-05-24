import re
from datetime import datetime, timedelta
import numpy as np
from collections import defaultdict
import json
import os
from ml_detector import MLDetector
from behavioral_analyzer import BehavioralAnalyzer

class ThreatDetector:
    def __init__(self):
        self.failed_logins = {}  # {(ip, user): [timestamps]}
        self.successful_logins = {}  # {user: [(timestamp, ip)]}
        self.failed_logins_by_ip = {}  # {ip: [timestamps]}
        self.blacklist_ips = self._load_blacklist()
        self.time_window = timedelta(minutes=5)
        self.business_hours = (8, 23)  # 8 AM to 6 PM
        self.ip_zones = {
            "10.0.0.": "ZoneA",
            "192.168.1.": "ZoneB",
            "172.16.0.": "ZoneC"
        }
        
        # Initialize ML and Behavioral Analysis
        self.ml_detector = MLDetector()
        self.behavioral_analyzer = BehavioralAnalyzer()
        
        # Enhanced detection parameters
        self.login_patterns = defaultdict(list)  # Track login patterns per user
        self.ip_behavior = defaultdict(lambda: {"total_attempts": 0, "success_rate": 0.0})
        self.user_risk_scores = defaultdict(float)
        self.ip_risk_scores = defaultdict(float)
        
        # Machine learning features
        self.feature_window = 100  # Number of events to consider for ML features
        self.recent_events = []
        
        # Load known attack patterns
        self.attack_patterns = self._load_attack_patterns()

    def _load_blacklist(self):
        try:
            with open("config/blacklist.json", "r") as f:
                return set(json.load(f))
        except:
            return {"10.0.0.99"}  # Default blacklist

    def _load_attack_patterns(self):
        try:
            with open("config/attack_patterns.json", "r") as f:
                return json.load(f)
        except:
            return {
                "brute_force": {
                    "max_attempts": 3,
                    "time_window": 300  # 5 minutes
                },
                "scanning": {
                    "max_users": 5,
                    "time_window": 600  # 10 minutes
                }
            }

    def get_geo_zone(self, ip):
        for prefix in self.ip_zones:
            if ip.startswith(prefix):
                return self.ip_zones[prefix]
        return "Unknown"

    def parse_log_line(self, line):
        pattern = re.compile(
            r'(?P<month>\w+) (?P<day>\d+) (?P<time>\d+:\d+:\d+) \S+ sshd\[\d+\]: (?P<status>Failed|Accepted) password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+ ssh2'
        )
        match = pattern.search(line)
        if not match:
            return None
        month_str = match.group('month')
        day = int(match.group('day'))
        time_str = match.group('time')
        dt_str = f"{datetime.now().year} {month_str} {day} {time_str}"
        event_time = datetime.strptime(dt_str, "%Y %b %d %H:%M:%S")
        return {
            'time': event_time,
            'status': match.group('status'),
            'user': match.group('user'),
            'ip': match.group('ip')
        }

    def update_risk_scores(self, event):
        # Update user risk score
        if event['status'] == "Failed":
            self.user_risk_scores[event['user']] += 0.1
        else:
            self.user_risk_scores[event['user']] *= 0.9

        # Update IP risk score
        ip = event['ip']
        self.ip_behavior[ip]['total_attempts'] += 1
        if event['status'] == "Accepted":
            self.ip_behavior[ip]['success_rate'] = (
                (self.ip_behavior[ip]['success_rate'] * (self.ip_behavior[ip]['total_attempts'] - 1) + 1) /
                self.ip_behavior[ip]['total_attempts']
            )
        else:
            self.ip_behavior[ip]['success_rate'] = (
                self.ip_behavior[ip]['success_rate'] * (self.ip_behavior[ip]['total_attempts'] - 1) /
                self.ip_behavior[ip]['total_attempts']
            )
        
        # Calculate IP risk score based on behavior
        self.ip_risk_scores[ip] = (
            (1 - self.ip_behavior[ip]['success_rate']) * 0.7 +  # Failed attempts weight
            (self.ip_behavior[ip]['total_attempts'] / 100) * 0.3  # Total attempts weight
        )

    def detect_anomalies(self, event):
        anomalies = []
        
        # Check for unusual login patterns
        if event['status'] == "Accepted":
            user_patterns = self.login_patterns[event['user']]
            if len(user_patterns) >= 2:
                last_login = user_patterns[-1]
                time_diff = (event['time'] - last_login['time']).total_seconds()
                
                # Detect impossible travel
                if time_diff < 3600 and last_login['ip'] != event['ip']:
                    if self.get_geo_zone(last_login['ip']) != self.get_geo_zone(event['ip']):
                        anomalies.append(("Impossible Travel", 0.9))
                
                # Detect unusual login time
                if not (self.business_hours[0] <= event['time'].hour < self.business_hours[1]):
                    anomalies.append(("Unusual Login Time", 0.7))
            
            # Update login patterns
            self.login_patterns[event['user']].append({
                'time': event['time'],
                'ip': event['ip']
            })
            
            # Keep only last 10 logins
            self.login_patterns[event['user']] = self.login_patterns[event['user']][-10:]
        
        return anomalies

    def detect(self, log_line):
        event = self.parse_log_line(log_line)
        if not event:
            return ("Normal", f"Ignored line (unparsable): {log_line.strip()}")
        
        now = event['time']
        user = event['user']
        ip = event['ip']
        status = event['status']
        
        # Check if IP is already blocked
        if hasattr(self, 'response_engine') and self.response_engine.is_ip_blocked(ip):
            return ("Blocked", f"Blocked IP {ip} attempted access")
        
        # Update risk scores
        self.update_risk_scores(event)
        
        # Check blacklist
        if ip in self.blacklist_ips:
            return ("Alert", f"[Blacklisted IP] Access attempt from blacklisted IP {ip}")
        
        # Track failed logins
        if status == "Failed":
            self.failed_logins.setdefault((ip, user), []).append(now)
            self.failed_logins_by_ip.setdefault(ip, []).append(now)
            
            # Clean old entries
            self.failed_logins[(ip, user)] = [t for t in self.failed_logins[(ip, user)] if now - t < self.time_window]
            self.failed_logins_by_ip[ip] = [t for t in self.failed_logins_by_ip[ip] if now - t < self.time_window]
            
            # Check for brute force
            if len(self.failed_logins[(ip, user)]) >= self.attack_patterns['brute_force']['max_attempts']:
                return ("Alert", f"[Brute Force] User: {user} IP: {ip} - Multiple failed login attempts ({len(self.failed_logins[(ip, user)])})")
            
            # Check for scanning
            users_failed_from_ip = {k[1] for k in self.failed_logins if k[0] == ip and len(self.failed_logins[k]) > 0}
            if len(users_failed_from_ip) >= self.attack_patterns['scanning']['max_users']:
                return ("Alert", f"[Scanning] Multiple failed login attempts on different users ({len(users_failed_from_ip)}) from IP {ip}")
            
            return ("Normal", f"Failed login attempt for user {user} from IP {ip}")
        
        elif status == "Accepted":
            self.successful_logins.setdefault(user, []).append((now, ip))
            
            # Clean old entries
            cutoff = now - timedelta(hours=24)
            self.successful_logins[user] = [(t, i) for t, i in self.successful_logins[user] if t > cutoff]
            
            # Check for suspicious patterns
            recent_ips = {i for t, i in self.successful_logins[user] if now - t < timedelta(hours=1)}
            if len(recent_ips) > 3:
                return ("Alert", f"[Suspicious] Multiple successful logins for user {user} from different IPs in last hour: {recent_ips}")
            
            # Check for anomalies
            anomalies = self.detect_anomalies(event)
            if anomalies:
                highest_risk = max(anomalies, key=lambda x: x[1])
                return ("Alert", f"[{highest_risk[0]}] User {user} logged in from {ip}")
            
            # Check for credential guessing
            fails = self.failed_logins.get((ip, user), [])
            if len(fails) >= 3 and (now - fails[-1]) < timedelta(minutes=2):
                return ("Alert", f"[Credential Guessing] User {user} succeeded login from IP {ip} after multiple failed attempts")
            
            return ("Normal", f"Successful login for user {user} from IP {ip}")
        
        else:
            return ("Normal", f"Ignored event: {log_line.strip()}")

    def get_risk_assessment(self):
        """Generate a comprehensive risk assessment combining all detection methods"""
        # Get ML-based risk assessment
        ml_risk = self.ml_detector.get_anomaly_patterns(self.recent_events)
        
        # Get behavioral analysis risk assessment
        behavioral_risk = self.behavioral_analyzer.get_risk_assessment()
        
        # Combine risk assessments
        combined_risk = {
            "high_risk_users": [],
            "high_risk_ips": [],
            "suspicious_patterns": [],
            "ml_anomalies": ml_risk,
            "behavioral_anomalies": behavioral_risk
        }
        
        # Add high-risk users
        for user, score in self.user_risk_scores.items():
            if score > 0.7:
                combined_risk["high_risk_users"].append({
                    "user": user,
                    "risk_score": score,
                    "suspicious_activities": self.login_patterns.get(user, [])
                })
        
        # Add high-risk IPs
        for ip, score in self.ip_risk_scores.items():
            if score > 0.7:
                combined_risk["high_risk_ips"].append({
                    "ip": ip,
                    "risk_score": score,
                    "behavior": self.ip_behavior[ip]
                })
        
        return combined_risk
