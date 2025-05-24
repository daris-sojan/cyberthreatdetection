import json
import os
from datetime import datetime
import time

def show_blocked_ips():
    # Check blocked_ips.json
    blocked_ips = []
    if os.path.exists("config/blocked_ips.json"):
        with open("config/blocked_ips.json", "r") as f:
            blocked_ips = json.load(f)
    
    # Check incident_reports.json
    incidents = []
    if os.path.exists("config/incident_reports.json"):
        with open("config/incident_reports.json", "r") as f:
            incidents = json.load(f)
    
    # Get current time
    current_time = time.time()
    
    print("\n=== Currently Blocked IPs ===")
    if not blocked_ips:
        print("No IPs are currently blocked")
    else:
        for ip in blocked_ips:
            # Find incident report for this IP
            ip_incidents = [inc for inc in incidents if inc.get('ip') == ip]
            if ip_incidents:
                latest_incident = ip_incidents[-1]
                print(f"\nIP: {ip}")
                print(f"Blocked at: {latest_incident.get('timestamp', 'Unknown')}")
                print(f"Reason: {latest_incident.get('reason', 'Unknown')}")
                print(f"Recommendation: {latest_incident.get('recommendation', 'None')}")
            else:
                print(f"\nIP: {ip}")
                print("No incident details available")
    
    print("\n=== Recent Blocking Incidents ===")
    if not incidents:
        print("No blocking incidents recorded")
    else:
        # Show last 5 incidents
        for incident in incidents[-5:]:
            print(f"\nIP: {incident.get('ip', 'Unknown')}")
            print(f"Time: {incident.get('timestamp', 'Unknown')}")
            print(f"Action: {incident.get('action', 'Unknown')}")
            print(f"Reason: {incident.get('reason', 'Unknown')}")

if __name__ == "__main__":
    show_blocked_ips() 