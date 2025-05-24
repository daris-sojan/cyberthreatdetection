from log_watcher import LogWatcher
from threat_detector import ThreatDetector
from response_engine import ResponseEngine
import subprocess
import threading
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import json
from ml_detector import MLDetector
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import uvicorn
import asyncio
import websockets
import time

# Initialize shared components
threat_detector = ThreatDetector()
response_engine = ResponseEngine()
ml_detector = MLDetector()

# Create FastAPI app
app = FastAPI()

# Add CORS middleware with more permissive configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
    expose_headers=["*"],
    max_age=3600,  # Cache preflight requests for 1 hour
)

# Add trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # Allow all hosts
)

# WebSocket server
class WebSocketServer:
    def __init__(self, host='0.0.0.0', port=8765):
        self.host = host
        self.port = port
        self.clients = set()
        
    async def register(self, websocket):
        self.clients.add(websocket)
        try:
            # Send initial state
            await websocket.send(json.dumps({
                'type': 'init',
                'data': {
                    'risk_assessment': threat_detector.get_risk_assessment(),
                    'system_status': response_engine.get_system_status()
                }
            }))
        except websockets.exceptions.ConnectionClosed:
            pass
        
    async def unregister(self, websocket):
        self.clients.remove(websocket)
        
    async def broadcast(self, message):
        if self.clients:
            await asyncio.gather(
                *[client.send(json.dumps(message)) for client in self.clients]
            )
            
    async def handle_client(self, websocket, path=None):
        # Add CORS headers to the WebSocket connection
        websocket.headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': '*',
            'Access-Control-Allow-Headers': '*'
        }
        
        await self.register(websocket)
        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                    if data['type'] == 'action':
                        await self.handle_action(data)
                except json.JSONDecodeError:
                    print(f"Invalid JSON received: {message}")
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            await self.unregister(websocket)
            
    async def handle_action(self, data):
        action = data.get('action')
        alert_id = data.get('alert_id')
        
        if action and alert_id:
            if action == 'acknowledge':
                response_engine.acknowledge_alert(alert_id)
            elif action == 'block_ip':
                ip = data.get('ip')
                if ip:
                    response_engine.block_ip(ip)
                    
            # Broadcast the action result
            await self.broadcast({
                'type': 'action_result',
                'data': {
                    'action': action,
                    'alert_id': alert_id,
                    'status': 'success',
                    'timestamp': datetime.now().isoformat()
                }
            })
            
    async def monitor_threats(self):
        while True:
            # Get latest risk assessment
            risk_assessment = threat_detector.get_risk_assessment()
            
            # Get alerts
            alerts = response_engine.get_alerts()
            if alerts:
                await self.broadcast({
                    'type': 'alerts',
                    'data': alerts
                })
            
            # Check for high-risk items
            if risk_assessment['high_risk_users'] or risk_assessment['high_risk_ips']:
                await self.broadcast({
                    'type': 'risk_update',
                    'data': risk_assessment
                })
                
            # Get system status
            system_status = response_engine.get_system_status()
            if system_status['status'] != 'normal':
                await self.broadcast({
                    'type': 'status_update',
                    'data': system_status
                })
                
            await asyncio.sleep(5)  # Check every 5 seconds
            
    async def start(self):
        async with websockets.serve(self.handle_client, self.host, self.port):
            print(f"WebSocket server started on ws://{self.host}:{self.port}")
            await self.monitor_threats()

# API endpoints
@app.get("/api/risk-assessment")
async def get_risk_assessment():
    try:
        data = threat_detector.get_risk_assessment()
        return JSONResponse(
            content=data,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/alerts")
async def get_alerts():
    try:
        data = response_engine.get_alerts()
        return JSONResponse(
            content=data,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/status")
async def get_status():
    try:
        data = response_engine.get_system_status()
        return JSONResponse(
            content=data,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.options("/{full_path:path}")
async def options_route(full_path: str):
    return JSONResponse(
        content={},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Max-Age": "3600",
        }
    )

def run_dashboard():
    subprocess.run(["streamlit", "run", "dashboard.py"])

def run_api_server():
    uvicorn.run(app, host="0.0.0.0", port=8501)

def run_websocket_server():
    server = WebSocketServer()
    asyncio.run(server.start())

def process_logs():
    """Process logs in a separate thread"""
    watcher = LogWatcher("sample_logs/auth.log")
    print("Monitoring logs for security threats...")
    try:
        for line in watcher.watch():
            level, message = threat_detector.detect(line)
            if level == "Alert":
                print(f"ALERT: {message}")
                response_engine.send_alert(message)
            else:
                print(f"INFO: {message}")
                response_engine.send_normal(message)
    except Exception as e:
        print(f"Error in log processing: {str(e)}")
        raise

def main():
    print("Starting Cyber Threat Monitor...")

    # Start the Streamlit dashboard in a daemon thread
    dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
    dashboard_thread.start()

    # Start the FastAPI server in a daemon thread
    api_thread = threading.Thread(target=run_api_server, daemon=True)
    api_thread.start()

    # Start the WebSocket server in a daemon thread
    websocket_thread = threading.Thread(target=run_websocket_server, daemon=True)
    websocket_thread.start()

    # Start log processing in a daemon thread
    log_thread = threading.Thread(target=process_logs, daemon=True)
    log_thread.start()

    try:
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")

if __name__ == "__main__":
    main()
