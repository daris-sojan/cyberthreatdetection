import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
import json
import os

class BehavioralAnalyzer:
    def __init__(self):
        self.user_profiles = defaultdict(lambda: {
            'login_times': [],
            'ip_addresses': set(),
            'failed_attempts': 0,
            'successful_logins': 0,
            'last_login': None,
            'login_frequency': [],
            'suspicious_activities': []
        })
        self.ip_profiles = defaultdict(lambda: {
            'users_attempted': set(),
            'success_rate': 0.0,
            'total_attempts': 0,
            'last_attempt': None,
            'geographic_consistency': True,
            'time_patterns': []
        })
        self.config = self._load_config()
        
    def _load_config(self):
        try:
            with open("config/behavior_config.json", "r") as f:
                return json.load(f)
        except:
            return {
                "suspicious_thresholds": {
                    "failed_attempts": 3,
                    "ip_changes": 3,
                    "time_deviation": 2,  # hours
                    "success_rate": 0.3
                },
                "profile_window": 30,  # days
                "update_frequency": 3600  # seconds
            }
    
    def update_user_profile(self, event):
        user = event['user']
        profile = self.user_profiles[user]
        
        # Update login times
        profile['login_times'].append(event['time'])
        profile['login_times'] = [t for t in profile['login_times'] 
                                if event['time'] - t < timedelta(days=self.config['profile_window'])]
        
        # Update IP addresses
        profile['ip_addresses'].add(event['ip'])
        
        # Update success/failure counts
        if event['status'] == 'Failed':
            profile['failed_attempts'] += 1
        else:
            profile['successful_logins'] += 1
            profile['last_login'] = event['time']
        
        # Calculate login frequency
        if len(profile['login_times']) > 1:
            time_diffs = [(profile['login_times'][i] - profile['login_times'][i-1]).total_seconds()/3600 
                         for i in range(1, len(profile['login_times']))]
            profile['login_frequency'] = time_diffs
        
        return self._analyze_user_behavior(user)
    
    def update_ip_profile(self, event):
        ip = event['ip']
        profile = self.ip_profiles[ip]
        
        # Update user attempts
        profile['users_attempted'].add(event['user'])
        
        # Update success rate
        profile['total_attempts'] += 1
        if event['status'] == 'Accepted':
            profile['success_rate'] = ((profile['success_rate'] * (profile['total_attempts'] - 1)) + 1) / profile['total_attempts']
        else:
            profile['success_rate'] = (profile['success_rate'] * (profile['total_attempts'] - 1)) / profile['total_attempts']
        
        # Update time patterns
        profile['time_patterns'].append(event['time'])
        profile['time_patterns'] = [t for t in profile['time_patterns'] 
                                  if event['time'] - t < timedelta(days=self.config['profile_window'])]
        
        profile['last_attempt'] = event['time']
        
        return self._analyze_ip_behavior(ip)
    
    def _analyze_user_behavior(self, user):
        profile = self.user_profiles[user]
        anomalies = []
        
        # Check for unusual login times
        if len(profile['login_times']) > 1:
            avg_hour = np.mean([t.hour for t in profile['login_times']])
            std_hour = np.std([t.hour for t in profile['login_times']])
            if abs(profile['login_times'][-1].hour - avg_hour) > self.config['suspicious_thresholds']['time_deviation']:
                anomalies.append(('Unusual Login Time', 0.7))
        
        # Check for multiple IP addresses
        if len(profile['ip_addresses']) > self.config['suspicious_thresholds']['ip_changes']:
            anomalies.append(('Multiple IP Addresses', 0.8))
        
        # Check for high failure rate
        total_attempts = profile['failed_attempts'] + profile['successful_logins']
        if total_attempts > 0:
            failure_rate = profile['failed_attempts'] / total_attempts
            if failure_rate > (1 - self.config['suspicious_thresholds']['success_rate']):
                anomalies.append(('High Failure Rate', 0.9))
        
        return anomalies
    
    def _analyze_ip_behavior(self, ip):
        profile = self.ip_profiles[ip]
        anomalies = []
        
        # Check for multiple user attempts
        if len(profile['users_attempted']) > 3:
            anomalies.append(('Multiple User Attempts', 0.8))
        
        # Check for low success rate
        if profile['success_rate'] < self.config['suspicious_thresholds']['success_rate']:
            anomalies.append(('Low Success Rate', 0.9))
        
        # Check for rapid attempts
        if len(profile['time_patterns']) > 1:
            time_diffs = [(profile['time_patterns'][i] - profile['time_patterns'][i-1]).total_seconds() 
                         for i in range(1, len(profile['time_patterns']))]
            if any(diff < 60 for diff in time_diffs):  # Less than 1 minute between attempts
                anomalies.append(('Rapid Attempts', 0.85))
        
        return anomalies
    
    def get_risk_assessment(self):
        """Generate a comprehensive risk assessment"""
        risk_assessment = {
            'high_risk_users': [],
            'high_risk_ips': [],
            'suspicious_patterns': []
        }
        
        # Analyze user risks
        for user, profile in self.user_profiles.items():
            risk_score = 0
            if len(profile['suspicious_activities']) > 0:
                risk_score = max(activity[1] for activity in profile['suspicious_activities'])
            if risk_score > 0.7:
                risk_assessment['high_risk_users'].append({
                    'user': user,
                    'risk_score': risk_score,
                    'suspicious_activities': profile['suspicious_activities']
                })
        
        # Analyze IP risks
        for ip, profile in self.ip_profiles.items():
            risk_score = 0
            if profile['total_attempts'] > 0:
                risk_score = (1 - profile['success_rate']) * 0.7 + \
                           (len(profile['users_attempted']) / 10) * 0.3
            if risk_score > 0.7:
                risk_assessment['high_risk_ips'].append({
                    'ip': ip,
                    'risk_score': risk_score,
                    'total_attempts': profile['total_attempts'],
                    'success_rate': profile['success_rate']
                })
        
        return risk_assessment 