import logging
import json
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from datetime import datetime
import subprocess
import socket
import threading
import time

logging.basicConfig(
    filename="alerts.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

class ResponseEngine:
    def __init__(self):
        self.config = self._load_config()
        self.setup_logging()
        self.alert_history = []
        self.blocked_ips = {}
        self._load_blocked_ips()
        self.blocked_connections = set()  # Track blocked connections in memory
        
        # Start background tasks
        self._start_background_tasks()

    def _load_config(self):
        try:
            with open("config/response_config.json", "r") as f:
                return json.load(f)
        except:
            return {
                "email": {
                    "enabled": False,
                    "smtp_server": "smtp.gmail.com",
                    "smtp_port": 587,
                    "sender": "alerts@example.com",
                    "password": "",
                    "recipients": ["admin@example.com"]
                },
                "slack": {
                    "enabled": False,
                    "webhook_url": ""
                },
                "actions": {
                    "block_ip": True,
                    "notify_admin": True,
                    "log_incident": True
                },
                "block_duration": 3600  # 1 hour in seconds
            }

    def setup_logging(self):
        # Add console handler
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)

    def _load_blocked_ips(self):
        try:
            with open("config/blocked_ips.json", "r") as f:
                data = json.load(f)
                # Convert list to dictionary with current time
                self.blocked_ips = {ip: time.time() for ip in data}
        except:
            self.blocked_ips = {}

    def _save_blocked_ips(self):
        """Save blocked IPs to file with proper error handling"""
        try:
            # Ensure we have a valid list of IPs
            if not isinstance(self.blocked_ips, dict):
                logging.error("Invalid blocked_ips data structure")
                return
                
            # Convert to list of IPs
            ip_list = list(self.blocked_ips.keys())
            
            # Ensure the config directory exists
            os.makedirs("config", exist_ok=True)
            
            # Save to file with proper error handling
            with open("config/blocked_ips.json", "w") as f:
                json.dump(ip_list, f, indent=4)
                
            logging.info(f"Successfully saved {len(ip_list)} blocked IPs to file")
            
        except Exception as e:
            logging.error(f"Error saving blocked IPs: {str(e)}")
            raise

    def _start_background_tasks(self):
        # Start IP unblocking task
        threading.Thread(target=self._unblock_ips_task, daemon=True).start()
        
        # Start alert history cleanup task
        threading.Thread(target=self._cleanup_alert_history, daemon=True).start()

    def _unblock_ips_task(self):
        while True:
            current_time = time.time()
            to_unblock = set()
            
            for ip, block_time in self.blocked_ips.items():
                if current_time - block_time > self.config["block_duration"]:
                    to_unblock.add(ip)
            
            for ip in to_unblock:
                self.unblock_ip(ip)
            
            time.sleep(60)  # Check every minute

    def _cleanup_alert_history(self):
        while True:
            current_time = time.time()
            self.alert_history = [
                alert for alert in self.alert_history
                if current_time - alert["timestamp"] < 86400  # Keep last 24 hours
            ]
            time.sleep(3600)  # Cleanup every hour

    def block_ip(self, ip):
        """Block an IP address at application level"""
        if ip in self.blocked_ips:
            logging.info(f"IP {ip} is already blocked")
            return
        
        try:
            # Add to blocked IPs list
            self.blocked_ips[ip] = time.time()
            self.blocked_connections.add(ip)
            
            # Ensure the config directory exists
            os.makedirs("config", exist_ok=True)
            
            # Save blocked IPs with proper error handling
            try:
                self._save_blocked_ips()
                logging.info(f"Successfully saved blocked IPs to file")
            except Exception as e:
                logging.error(f"Failed to save blocked IPs to file: {str(e)}")
                raise
            
            # Log the block action
            logging.info(f"Blocked IP: {ip}")
            
            # Create a detailed incident report
            incident_details = {
                "timestamp": datetime.now().isoformat(),
                "ip": ip,
                "action": "blocked",
                "reason": "Suspicious activity detected",
                "recommendation": "Review and consider adding to firewall rules"
            }
            
            # Save detailed incident report
            self._save_incident_report(incident_details)
            
            # If email notifications are enabled, send a detailed report
            if self.config["email"]["enabled"]:
                self.send_email_alert(
                    f"IP Blocked: {ip}",
                    f"IP {ip} has been blocked due to suspicious activity.\n"
                    f"Time: {incident_details['timestamp']}\n"
                    f"Reason: {incident_details['reason']}\n"
                    f"Recommendation: {incident_details['recommendation']}"
                )
            
        except Exception as e:
            logging.error(f"Failed to block IP {ip}: {str(e)}")
            # Re-raise the exception to ensure the error is not silently ignored
            raise

    def unblock_ip(self, ip):
        """Unblock an IP address"""
        if ip not in self.blocked_ips:
            return
        
        try:
            # Remove from blocked lists
            del self.blocked_ips[ip]
            self.blocked_connections.discard(ip)
            self._save_blocked_ips()
            
            # Log the unblock action
            logging.info(f"Unblocked IP: {ip}")
            
            # Create unblock report
            incident_details = {
                "timestamp": datetime.now().isoformat(),
                "ip": ip,
                "action": "unblocked",
                "reason": "Block duration expired",
                "recommendation": "Monitor for suspicious activity"
            }
            
            # Save unblock report
            self._save_incident_report(incident_details)
            
        except Exception as e:
            logging.error(f"Failed to unblock IP {ip}: {str(e)}")

    def _save_incident_report(self, incident_details):
        """Save detailed incident report to a JSON file"""
        try:
            report_file = "config/incident_reports.json"
            reports = []
            
            # Load existing reports if file exists
            if os.path.exists(report_file):
                with open(report_file, "r") as f:
                    reports = json.load(f)
            
            # Add new report
            reports.append(incident_details)
            
            # Save updated reports
            with open(report_file, "w") as f:
                json.dump(reports, f, indent=4)
                
        except Exception as e:
            logging.error(f"Failed to save incident report: {str(e)}")

    def is_ip_blocked(self, ip):
        """Check if an IP is currently blocked"""
        return ip in self.blocked_connections

    def get_blocked_ips_report(self):
        """Get a detailed report of currently blocked IPs"""
        current_time = time.time()
        active_blocks = []
        
        for ip, block_time in self.blocked_ips.items():
            time_remaining = self.config["block_duration"] - (current_time - block_time)
            if time_remaining > 0:
                active_blocks.append({
                    "ip": ip,
                    "blocked_at": datetime.fromtimestamp(block_time).isoformat(),
                    "time_remaining": int(time_remaining),
                    "status": "active"
                })
        
        return active_blocks

    def send_email_alert(self, subject, message):
        """Send email alert"""
        if not self.config["email"]["enabled"]:
            return
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config["email"]["sender"]
            msg['To'] = ", ".join(self.config["email"]["recipients"])
            msg['Subject'] = subject
            
            msg.attach(MIMEText(message, 'plain'))
            
            server = smtplib.SMTP(self.config["email"]["smtp_server"], self.config["email"]["smtp_port"])
            server.starttls()
            server.login(self.config["email"]["sender"], self.config["email"]["password"])
            server.send_message(msg)
            server.quit()
            
            logging.info(f"Email alert sent: {subject}")
        except Exception as e:
            logging.error(f"Failed to send email alert: {str(e)}")

    def send_slack_alert(self, message):
        """Send Slack alert"""
        if not self.config["slack"]["enabled"]:
            return
        
        try:
            payload = {"text": message}
            response = requests.post(
                self.config["slack"]["webhook_url"],
                json=payload
            )
            response.raise_for_status()
            logging.info("Slack alert sent")
        except Exception as e:
            logging.error(f"Failed to send Slack alert: {str(e)}")

    def send_alert(self, message):
        """Handle alert events"""
        print("ALERT:", message)
        logging.warning(message)
        
        # Add to alert history
        self.alert_history.append({
            "timestamp": time.time(),
            "message": message
        })
        
        # Extract IP if present
        ip = None
        if "IP: " in message:
            ip = message.split("IP: ")[1].split()[0]
        
        # Take automated actions
        if self.config["actions"]["block_ip"] and ip:
            self.block_ip(ip)
        
        if self.config["actions"]["notify_admin"]:
            # Send email alert
            self.send_email_alert(
                "Security Alert",
                f"Time: {datetime.now()}\nAlert: {message}"
            )
            
            # Send Slack alert
            self.send_slack_alert(f"🚨 *Security Alert*\n{message}")
        
        if self.config["actions"]["log_incident"]:
            self._log_incident(message)

    def send_normal(self, message):
        """Handle normal events"""
        print("INFO:", message)
        logging.info(message)

    def _log_incident(self, message):
        """Log incident details to a separate file"""
        try:
            with open("incidents.log", "a") as f:
                f.write(f"{datetime.now()} - {message}\n")
        except Exception as e:
            logging.error(f"Failed to log incident: {str(e)}")

    def get_alert_history(self, hours=24):
        """Get alert history for the specified time period"""
        current_time = time.time()
        return [
            alert for alert in self.alert_history
            if current_time - alert["timestamp"] < hours * 3600
        ]

    def get_blocked_ips(self):
        """Get currently blocked IPs"""
        return list(self.blocked_ips.keys())

    def get_system_status(self):
        """Get current system status including blocked IPs and recent alerts"""
        current_time = time.time()
        recent_alerts = [
            alert for alert in self.alert_history
            if current_time - alert["timestamp"] < 3600  # Last hour
        ]
        
        # Calculate system status based on recent alerts
        status = "normal"
        if len(recent_alerts) > 10:
            status = "critical"
        elif len(recent_alerts) > 5:
            status = "warning"
            
        return {
            "status": status,
            "blocked_ips": len(self.blocked_ips),
            "recent_alerts": len(recent_alerts),
            "last_alert": recent_alerts[-1]["message"] if recent_alerts else None,
            "timestamp": datetime.now().isoformat()
        }

    def get_alerts(self):
        """Get recent alerts"""
        current_time = time.time()
        recent_alerts = [
            {
                "id": i,
                "message": alert["message"],
                "timestamp": alert["timestamp"],
                "time_ago": int(current_time - alert["timestamp"])
            }
            for i, alert in enumerate(self.alert_history)
            if current_time - alert["timestamp"] < 86400  # Last 24 hours
        ]
        return recent_alerts

    def acknowledge_alert(self, alert_id):
        """Acknowledge an alert by its ID"""
        try:
            alert_id = int(alert_id)
            if 0 <= alert_id < len(self.alert_history):
                # You could add an 'acknowledged' field to the alert here
                logging.info(f"Alert {alert_id} acknowledged")
                return True
        except (ValueError, IndexError):
            pass
        return False
