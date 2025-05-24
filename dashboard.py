import streamlit as st
import time
from collections import Counter
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime, timedelta
import json
from ml_detector import MLDetector
from plotly.subplots import make_subplots
import networkx as nx
import requests

# Page config
st.set_page_config(
    page_title="Cyber Threat Monitor",
    page_icon="🛡️",
    layout="wide"
)

# Constants
ALERTS_LOG_FILE = "alerts.log"
REFRESH_INTERVAL = 2  # Default refresh interval in seconds

# Custom CSS
st.markdown("""
    <style>
    .main {
        background-color: #0E1117;
    }
    .stAlert {
        padding: 1rem;
        border-radius: 0.5rem;
    }
    .metric-card {
        background-color: #1E1E1E;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    </style>
    """, unsafe_allow_html=True)

# Initialize ML detector
ml_detector = MLDetector()

def read_alerts():
    try:
        with open(ALERTS_LOG_FILE, "r") as f:
            return f.readlines()
    except FileNotFoundError:
        return []

def parse_alert_line(line):
    try:
        # Parse timestamp and message
        parts = line.split(" - ", 2)
        if len(parts) != 3:
            return None
        timestamp_str, level, message = parts
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S,%f")
        
        # Extract alert type and details
        alert_type = "Other"
        details = {}
        is_security_alert = False
        
        if "[Brute Force]" in message:
            alert_type = "Brute Force"
            details = parse_brute_force(message)
            is_security_alert = True
        elif "[Scanning]" in message:
            alert_type = "Scanning"
            details = parse_scanning(message)
            is_security_alert = True
        elif "[Suspicious]" in message:
            alert_type = "Suspicious Login"
            details = parse_suspicious(message)
            is_security_alert = True
        elif "[Impossible Travel]" in message:
            alert_type = "Impossible Travel"
            details = parse_impossible_travel(message)
            is_security_alert = True
        elif "[Unusual Login Time]" in message:
            alert_type = "Unusual Login Time"
            details = parse_unusual_time(message)
            is_security_alert = True
        elif "[Blacklisted IP]" in message:
            alert_type = "Blacklisted IP"
            details = parse_blacklisted(message)
            is_security_alert = True
        elif "[Login]" in message:
            alert_type = "Login"
            details = parse_login(message)
        elif "[Logout]" in message:
            alert_type = "Logout"
            details = parse_logout(message)
        elif "[System]" in message:
            alert_type = "System"
            details = parse_system(message)
            
        return {
            "timestamp": timestamp,
            "level": level,
            "type": alert_type,
            "message": message.strip(),
            "details": details,
            "is_security_alert": is_security_alert
        }
    except Exception as e:
        return None

def parse_brute_force(message):
    try:
        # Extract user and IP from message
        user = message.split("User: ")[1].split(" IP:")[0]
        ip = message.split("IP: ")[1].split(" -")[0]
        attempts = int(message.split("attempts (")[1].split(")")[0])
        return {"user": user, "ip": ip, "attempts": attempts}
    except:
        return {}

def parse_scanning(message):
    try:
        users = int(message.split("users (")[1].split(")")[0])
        ip = message.split("from IP ")[1]
        return {"users_affected": users, "ip": ip}
    except:
        return {}

def parse_suspicious(message):
    try:
        user = message.split("user ")[1].split(" from")[0]
        ips = message.split("IPs in last hour: ")[1].strip("{}").split(", ")
        return {"user": user, "ips": ips}
    except:
        return {}

def parse_impossible_travel(message):
    try:
        user = message.split("User ")[1].split(" logged")[0]
        zones = message.split("zones in short time: ")[1].strip("{}").split(", ")
        return {"user": user, "zones": zones}
    except:
        return {}

def parse_unusual_time(message):
    try:
        user = message.split("User ")[1].split(" logged")[0]
        hour = int(message.split("hour ")[1].split(":")[0])
        return {"user": user, "hour": hour}
    except:
        return {}

def parse_blacklisted(message):
    try:
        ip = message.split("IP ")[1]
        return {"ip": ip}
    except:
        return {}

def parse_login(message):
    try:
        user = message.split("User ")[1].split(" logged")[0]
        ip = message.split("from IP ")[1]
        return {"user": user, "ip": ip}
    except:
        return {}

def parse_logout(message):
    try:
        user = message.split("User ")[1].split(" logged")[0]
        return {"user": user}
    except:
        return {}

def parse_system(message):
    try:
        return {"message": message}
    except:
        return {}

def create_alert_dataframe(alerts):
    parsed_alerts = [parse_alert_line(line) for line in alerts]
    # Filter out None values but keep all types of events
    parsed_alerts = [a for a in parsed_alerts if a is not None]
    return pd.DataFrame(parsed_alerts)

def plot_alert_timeline(df):
    if df.empty:
        return go.Figure()
    
    fig = go.Figure()
    for alert_type in df['type'].unique():
        type_df = df[df['type'] == alert_type]
        fig.add_trace(go.Scatter(
            x=type_df['timestamp'],
            y=[alert_type] * len(type_df),
            mode='markers',
            name=alert_type,
            marker=dict(size=10)
        ))
    
    fig.update_layout(
        title="Alert Timeline",
        xaxis_title="Time",
        yaxis_title="Alert Type",
        height=300,
        template="plotly_dark"
    )
    return fig

def plot_alert_distribution(df):
    if df.empty:
        return go.Figure()
    
    alert_counts = df['type'].value_counts()
    fig = px.pie(
        values=alert_counts.values,
        names=alert_counts.index,
        title="Alert Distribution",
        template="plotly_dark"
    )
    return fig

def plot_hourly_distribution(df):
    if df.empty:
        return go.Figure()
    
    df['hour'] = df['timestamp'].dt.hour
    hourly_counts = df.groupby('hour').size()
    
    fig = px.bar(
        x=hourly_counts.index,
        y=hourly_counts.values,
        title="Alerts by Hour",
        labels={'x': 'Hour of Day', 'y': 'Number of Alerts'},
        template="plotly_dark"
    )
    return fig

def get_threat_intelligence(ip):
    """Get threat intelligence data for an IP"""
    try:
        response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", 
                              headers={'Key': 'YOUR_API_KEY', 'Accept': 'application/json'})
        if response.status_code == 200:
            return response.json()
    except:
        return None

def format_anomaly_patterns(patterns):
    """Format anomaly patterns into a more readable format"""
    formatted_patterns = []
    for pattern in patterns:
        formatted_pattern = {
            "Cluster ID": pattern['cluster_id'],
            "Size": pattern['size'],
            "Common IPs": ", ".join(pattern['common_ips']),
            "Time Range": f"{pattern['time_range']['start'].strftime('%Y-%m-%d %H:%M:%S')} to {pattern['time_range']['end'].strftime('%Y-%m-%d %H:%M:%S')}",
            "Anomaly Score": f"{pattern['avg_anomaly_score']:.2f}"
        }
        formatted_patterns.append(formatted_pattern)
    return formatted_patterns

def create_network_graph(df):
    """Create a network graph of IPs and users"""
    G = nx.Graph()
    
    # Add nodes and edges
    for _, row in df.iterrows():
        if 'details' in row and isinstance(row['details'], dict):
            if 'ip' in row['details']:
                G.add_node(row['details']['ip'], type='ip', count=1)
            if 'user' in row['details']:
                G.add_node(row['details']['user'], type='user', count=1)
            if 'ip' in row['details'] and 'user' in row['details']:
                G.add_edge(row['details']['ip'], row['details']['user'])
    
    # Update node counts
    for node in G.nodes():
        G.nodes[node]['count'] = sum(1 for _, row in df.iterrows() 
                                   if row.get('details', {}).get('ip') == node or 
                                   row.get('details', {}).get('user') == node)
    
    # Create plot
    pos = nx.spring_layout(G, k=1, iterations=50)
    
    # Create figure
    fig = go.Figure()
    
    # Add edges
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
    
    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1, color='#888'),
        hoverinfo='none',
        mode='lines'))
    
    # Add nodes
    node_x = []
    node_y = []
    node_text = []
    node_color = []
    node_size = []
    
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_text.append(f"{node}<br>Count: {G.nodes[node]['count']}")
        node_color.append('red' if G.nodes[node]['type'] == 'ip' else 'blue')
        node_size.append(10 + G.nodes[node]['count'] * 2)  # Size based on count
    
    fig.add_trace(go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=node_text,
        textposition="top center",
        marker=dict(
            showscale=False,
            color=node_color,
            size=node_size,
            line_width=2)))
    
    fig.update_layout(
        title="Network of IPs and Users",
        showlegend=False,
        hovermode='closest',
        margin=dict(b=20,l=5,r=5,t=40),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        height=600)  # Increased height for better visibility
    
    return fig

def create_advanced_metrics(df):
    """Create advanced metrics visualization"""
    if df.empty:
        return go.Figure()
    
    # Calculate metrics only for security alerts
    security_df = df[df['is_security_alert'] == True]
    total_alerts = len(security_df)
    unique_ips = security_df['details'].apply(lambda x: x.get('ip', '')).nunique()
    unique_users = security_df['details'].apply(lambda x: x.get('user', '')).nunique()
    
    # Create subplot
    fig = make_subplots(
        rows=2, cols=2,
        specs=[[{"type": "indicator"}, {"type": "indicator"}],
               [{"type": "indicator"}, {"type": "indicator"}]]
    )
    
    # Add indicators
    fig.add_trace(
        go.Indicator(
            mode="number",
            value=total_alerts,
            title="Security Alerts",
            domain={'row': 0, 'column': 0}
        ),
        row=1, col=1
    )
    
    fig.add_trace(
        go.Indicator(
            mode="number",
            value=unique_ips,
            title="Suspicious IPs",
            domain={'row': 0, 'column': 1}
        ),
        row=1, col=2
    )
    
    fig.add_trace(
        go.Indicator(
            mode="number",
            value=unique_users,
            title="Affected Users",
            domain={'row': 1, 'column': 0}
        ),
        row=2, col=1
    )
    
    # Add threat level indicator
    threat_level = "High" if total_alerts > 100 else "Medium" if total_alerts > 50 else "Low"
    fig.add_trace(
        go.Indicator(
            mode="gauge+number",
            value=total_alerts,
            title="Threat Level",
            gauge={'axis': {'range': [0, 100]},
                  'bar': {'color': "red" if threat_level == "High" else "orange" if threat_level == "Medium" else "green"}},
            domain={'row': 1, 'column': 1}
        ),
        row=2, col=2
    )
    
    fig.update_layout(height=400, showlegend=False)
    return fig

# Update main dashboard layout
st.title("🛡️ Advanced Cyber Threat Monitor Dashboard")

# Add sidebar for settings
st.sidebar.title("Settings")
refresh_interval = st.sidebar.slider("Refresh interval (seconds)", 1, 10, REFRESH_INTERVAL)
st.sidebar.markdown("---")
st.sidebar.markdown("### System Status")
st.sidebar.markdown("🟢 System Active")
st.sidebar.markdown("### Quick Actions")
if st.sidebar.button("Export Alert Log"):
    st.sidebar.download_button(
        label="Download Alert Log",
        data="\n".join(read_alerts()),
        file_name="alerts_export.log",
        mime="text/plain"
    )

# Add tabs for different views
tab1, tab2, tab3 = st.tabs(["Overview", "Network Analysis", "Threat Intelligence"])

with tab1:
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### Real-time Alert Feed")
        alerts_placeholder = st.empty()
    
    with col2:
        st.markdown("### Advanced Metrics")
        metrics_placeholder = st.empty()
    
    # Charts
    st.markdown("### Analytics")
    col3, col4 = st.columns(2)
    with col3:
        timeline_placeholder = st.empty()
    with col4:
        distribution_placeholder = st.empty()
    
    st.markdown("### Hourly Distribution")
    hourly_placeholder = st.empty()

with tab2:
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### Network Analysis")
        network_placeholder = st.empty()
    
    with col2:
        st.markdown("### Anomaly Detection")
        anomaly_placeholder = st.empty()

with tab3:
    st.markdown("### Threat Intelligence")
    st.markdown("Enter an IP address to check its threat intelligence:")
    ip_to_check = st.text_input("IP Address")
    if ip_to_check:
        threat_data = get_threat_intelligence(ip_to_check)
        if threat_data:
            st.json(threat_data)
        else:
            st.error("Could not fetch threat intelligence data")

# Main loop
while True:
    alerts = read_alerts()
    df = create_alert_dataframe(alerts)
    current_time = datetime.now().strftime("%Y%m%d%H%M%S")
    
    # Update real-time alert feed
    if alerts:
        last_alerts = alerts[-10:]  # Show last 10 alerts
        last_alerts.reverse()
        alerts_text = ""
        for alert in last_alerts:
            parsed = parse_alert_line(alert)
            if parsed:
                # Determine color based on event type
                if parsed["is_security_alert"]:
                    color = "red" if parsed["level"] == "WARNING" else "orange"
                else:
                    color = "blue" if parsed["type"] in ["Login", "Logout"] else "green"
                
                alerts_text += f"""
                <div style='background-color: #1E1E1E; padding: 10px; margin: 5px 0; border-radius: 5px;'>
                    <div style='color: {color}; font-weight: bold;'>{parsed['type']}</div>
                    <div style='color: #888;'>{parsed['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}</div>
                    <div style='color: #fff;'>{parsed['message']}</div>
                </div>
                """
        alerts_placeholder.markdown(alerts_text, unsafe_allow_html=True)
    
    # Update metrics
    if not df.empty:
        metrics_placeholder.plotly_chart(
            create_advanced_metrics(df), 
            use_container_width=True,
            key=f"metrics_chart_{current_time}"
        )
    
    # Update network graph and anomaly detection
    if not df.empty:
        network_placeholder.plotly_chart(
            create_network_graph(df), 
            use_container_width=True,
            key=f"network_chart_{current_time}"
        )
        
        # Update anomaly detection
        log_entries = df.to_dict('records')
        anomalies = ml_detector.detect_anomalies(log_entries)
        if anomalies:
            patterns = ml_detector.get_anomaly_patterns(anomalies)
            formatted_patterns = format_anomaly_patterns(patterns)
            
            # Create a table for anomaly patterns
            pattern_df = pd.DataFrame(formatted_patterns)
            anomaly_placeholder.dataframe(
                pattern_df,
                use_container_width=True,
                hide_index=True,
                height=400  # Limit the height of the table
            )
    
    # Update other visualizations
    if not df.empty:
        timeline_placeholder.plotly_chart(
            plot_alert_timeline(df), 
            use_container_width=True, 
            key=f"timeline_chart_{current_time}"
        )
        distribution_placeholder.plotly_chart(
            plot_alert_distribution(df), 
            use_container_width=True, 
            key=f"distribution_chart_{current_time}"
        )
        hourly_placeholder.plotly_chart(
            plot_hourly_distribution(df), 
            use_container_width=True, 
            key=f"hourly_chart_{current_time}"
        )
    
    time.sleep(refresh_interval)
