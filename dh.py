# dashboard.py - Dashboard Backend untuk Monitoring
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import json
import asyncio
from datetime import datetime, timedelta
import requests
from typing import List, Dict
import logging
from collections import defaultdict, deque
import statistics

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="DDoS Detection Dashboard")

# Mount static files (CSS, JS, images)
app.mount("/static", StaticFiles(directory="static"), name="static")

# WebSocket connections manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Client connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        logger.info(f"Client disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        if self.active_connections:
            message_str = json.dumps(message)
            for connection in self.active_connections.copy():
                try:
                    await connection.send_text(message_str)
                except Exception as e:
                    logger.error(f"Error sending message: {e}")
                    self.active_connections.remove(connection)

manager = ConnectionManager()

# Data storage untuk dashboard
class DashboardData:
    def __init__(self):
        self.anomaly_history = deque(maxlen=1000)  # 1000 anomali terakhir
        self.traffic_stats = deque(maxlen=100)     # 100 data traffic terakhir
        self.ip_stats = defaultdict(lambda: {"count": 0, "last_seen": None})
        self.protocol_stats = defaultdict(int)
        self.hourly_stats = defaultdict(int)
        
    def add_anomaly(self, anomaly_data):
        anomaly_data['timestamp'] = datetime.now().isoformat()
        self.anomaly_history.append(anomaly_data)
        
        # Update IP statistics
        src_ip = anomaly_data.get('src_ip', 'Unknown')
        self.ip_stats[src_ip]['count'] += 1
        self.ip_stats[src_ip]['last_seen'] = datetime.now().isoformat()
        
        # Update protocol statistics
        protocol = anomaly_data.get('protocol', 'Unknown')
        self.protocol_stats[protocol] += 1
        
        # Update hourly statistics
        hour = datetime.now().strftime('%H:00')
        self.hourly_stats[hour] += 1
    
    def add_traffic_data(self, total_requests, anomaly_count):
        self.traffic_stats.append({
            'timestamp': datetime.now().isoformat(),
            'total_requests': total_requests,
            'anomaly_count': anomaly_count,
            'normal_count': total_requests - anomaly_count
        })
    
    def get_dashboard_stats(self):
        now = datetime.now()
        last_hour = now - timedelta(hours=1)
        last_24h = now - timedelta(hours=24)
        
        # Recent anomalies (last hour)
        recent_anomalies = [
            a for a in self.anomaly_history 
            if datetime.fromisoformat(a['timestamp']) > last_hour
        ]
        
        # Top attacking IPs
        top_ips = sorted(
            [(ip, data['count']) for ip, data in self.ip_stats.items()],
            key=lambda x: x[1], reverse=True
        )[:10]
        
        # Protocol distribution
        protocol_dist = dict(self.protocol_stats)
        
        # Traffic trend (last 24 hours)
        traffic_trend = list(self.traffic_stats)[-24:]
        
        return {
            'total_anomalies': len(self.anomaly_history),
            'recent_anomalies_count': len(recent_anomalies),
            'top_attacking_ips': top_ips,
            'protocol_distribution': protocol_dist,
            'traffic_trend': traffic_trend,
            'recent_anomalies': list(self.anomaly_history)[-20:],  # 20 terbaru
            'hourly_distribution': dict(self.hourly_stats)
        }

dashboard_data = DashboardData()

# API Endpoints
@app.get("/")
async def dashboard_home():
    """Serve main dashboard page"""
    return HTMLResponse(content=get_dashboard_html(), media_type="text/html")

@app.get("/api/stats")
async def get_stats():
    """Get dashboard statistics"""
    return dashboard_data.get_dashboard_stats()

@app.get("/api/anomalies")
async def get_recent_anomalies(limit: int = 50):
    """Get recent anomalies"""
    recent = list(dashboard_data.anomaly_history)[-limit:]
    return {"anomalies": recent, "total": len(dashboard_data.anomaly_history)}

@app.get("/api/top-ips")
async def get_top_ips(limit: int = 20):
    """Get top attacking IPs"""
    top_ips = sorted(
        [(ip, data['count'], data['last_seen']) for ip, data in dashboard_data.ip_stats.items()],
        key=lambda x: x[1], reverse=True
    )[:limit]
    
    return {"top_ips": [{"ip": ip, "count": count, "last_seen": last_seen} 
                       for ip, count, last_seen in top_ips]}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time updates"""
    await manager.connect(websocket)
    try:
        while True:
            # Send periodic updates
            stats = dashboard_data.get_dashboard_stats()
            await websocket.send_text(json.dumps({
                "type": "stats_update",
                "data": stats
            }))
            await asyncio.sleep(5)  # Update every 5 seconds
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Background task untuk polling data dari API deteksi
async def poll_detection_api():
    """Background task untuk mengambil data dari detection API"""
    DETECTION_API_URL = "http://localhost:8000"
    
    while True:
        try:
            # Get anomalies from detection API
            response = requests.get(f"{DETECTION_API_URL}/anomalies", timeout=5)
            if response.status_code == 200:
                data = response.json()
                recent_anomalies = data.get("recent", [])
                
                # Process new anomalies
                for anomaly in recent_anomalies:
                    if anomaly not in [dict(a) for a in dashboard_data.anomaly_history]:
                        dashboard_data.add_anomaly(anomaly)
                        
                        # Broadcast to WebSocket clients
                        await manager.broadcast({
                            "type": "new_anomaly",
                            "data": anomaly
                        })
                
                # Update traffic stats
                total_requests = len(recent_anomalies) + 100  # Mock total requests
                anomaly_count = len([a for a in recent_anomalies if a.get('result') == -1])
                dashboard_data.add_traffic_data(total_requests, anomaly_count)
                
        except Exception as e:
            logger.error(f"Error polling detection API: {e}")
        
        await asyncio.sleep(10)  # Poll every 10 seconds

# Start background task
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(poll_detection_api())

def get_dashboard_html():
    """Generate dashboard HTML"""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDoS Detection Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
        }
        .dashboard { padding: 20px; }
        .header { 
            background: rgba(255,255,255,0.95);
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(255,255,255,0.95);
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-number { font-size: 2.5em; font-weight: bold; color: #667eea; }
        .stat-label { font-size: 0.9em; color: #666; margin-top: 5px; }
        .charts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        .chart-container {
            background: rgba(255,255,255,0.95);
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }
        .anomalies-list {
            background: rgba(255,255,255,0.95);
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }
        .anomaly-item {
            padding: 10px;
            border-left: 4px solid #ff4757;
            background: #fff5f5;
            margin: 10px 0;
            border-radius: 5px;
        }
        .status { 
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
        }
        .status.connected { background: #2ed573; color: white; }
        .status.disconnected { background: #ff4757; color: white; }
        .ip-list { max-height: 300px; overflow-y: auto; }
        .ip-item { 
            display: flex; 
            justify-content: space-between; 
            padding: 8px 0; 
            border-bottom: 1px solid #eee; 
        }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <h1>🛡️ DDoS Detection Dashboard</h1>
            <p>Real-time network anomaly monitoring</p>
            <span id="connection-status" class="status disconnected">Disconnected</span>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number" id="total-anomalies">0</div>
                <div class="stat-label">Total Anomalies</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="recent-anomalies">0</div>
                <div class="stat-label">Last Hour</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="unique-ips">0</div>
                <div class="stat-label">Unique IPs</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="detection-rate">0%</div>
                <div class="stat-label">Detection Rate</div>
            </div>
        </div>
        
        <div class="charts-grid">
            <div class="chart-container">
                <h3>Traffic Trend</h3>
                <canvas id="traffic-chart" width="400" height="200"></canvas>
            </div>
            <div class="chart-container">
                <h3>Protocol Distribution</h3>
                <canvas id="protocol-chart" width="400" height="200"></canvas>
            </div>
        </div>
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div class="anomalies-list">
                <h3>Recent Anomalies</h3>
                <div id="anomalies-container"></div>
            </div>
            <div class="anomalies-list">
                <h3>Top Attacking IPs</h3>
                <div id="top-ips-container" class="ip-list"></div>
            </div>
        </div>
    </div>

    <script>
        // WebSocket connection
        const ws = new WebSocket(`ws://${window.location.host}/ws`);
        const statusEl = document.getElementById('connection-status');
        
        ws.onopen = () => {
            statusEl.textContent = 'Connected';
            statusEl.className = 'status connected';
        };
        
        ws.onclose = () => {
            statusEl.textContent = 'Disconnected';
            statusEl.className = 'status disconnected';
        };
        
        ws.onmessage = (event) => {
            const message = JSON.parse(event.data);
            if (message.type === 'stats_update') {
                updateDashboard(message.data);
            } else if (message.type === 'new_anomaly') {
                showNewAnomalyAlert(message.data);
            }
        };
        
        // Charts
        const trafficCtx = document.getElementById('traffic-chart').getContext('2d');
        const protocolCtx = document.getElementById('protocol-chart').getContext('2d');
        
        const trafficChart = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Total Requests',
                    data: [],
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    tension: 0.4
                }, {
                    label: 'Anomalies',
                    data: [],
                    borderColor: '#ff4757',
                    backgroundColor: 'rgba(255, 71, 87, 0.1)',
                    tension: 0.4
                }]
            },
            options: { responsive: true, scales: { y: { beginAtZero: true } } }
        });
        
        const protocolChart = new Chart(protocolCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: ['#667eea', '#ff4757', '#2ed573', '#ffa502', '#747d8c']
                }]
            },
            options: { responsive: true }
        });
        
        function updateDashboard(data) {
            // Update stats
            document.getElementById('total-anomalies').textContent = data.total_anomalies || 0;
            document.getElementById('recent-anomalies').textContent = data.recent_anomalies_count || 0;
            document.getElementById('unique-ips').textContent = data.top_attacking_ips?.length || 0;
            
            // Update traffic chart
            if (data.traffic_trend) {
                const labels = data.traffic_trend.map(t => new Date(t.timestamp).toLocaleTimeString());
                const totalRequests = data.traffic_trend.map(t => t.total_requests);
                const anomalies = data.traffic_trend.map(t => t.anomaly_count);
                
                trafficChart.data.labels = labels.slice(-20);
                trafficChart.data.datasets[0].data = totalRequests.slice(-20);
                trafficChart.data.datasets[1].data = anomalies.slice(-20);
                trafficChart.update();
            }
            
            // Update protocol chart
            if (data.protocol_distribution) {
                protocolChart.data.labels = Object.keys(data.protocol_distribution);
                protocolChart.data.datasets[0].data = Object.values(data.protocol_distribution);
                protocolChart.update();
            }
            
            // Update anomalies list
            updateAnomaliesList(data.recent_anomalies || []);
            
            // Update top IPs
            updateTopIPs(data.top_attacking_ips || []);
        }
        
        function updateAnomaliesList(anomalies) {
            const container = document.getElementById('anomalies-container');
            container.innerHTML = anomalies.slice(-10).reverse().map(anomaly => `
                <div class="anomaly-item">
                    <strong>${anomaly.src_ip}</strong> → ${anomaly.dst_ip}
                    <br><small>Score: ${anomaly.score?.toFixed(2)} | Protocol: ${anomaly.protocol}</small>
                </div>
            `).join('');
        }
        
        function updateTopIPs(topIPs) {
            const container = document.getElementById('top-ips-container');
            container.innerHTML = topIPs.slice(0, 10).map(([ip, count]) => `
                <div class="ip-item">
                    <span>${ip}</span>
                    <strong>${count} attacks</strong>
                </div>
            `).join('');
        }
        
        function showNewAnomalyAlert(anomaly) {
            // Flash notification for new anomaly
            document.body.style.boxShadow = 'inset 0 0 50px rgba(255, 71, 87, 0.3)';
            setTimeout(() => {
                document.body.style.boxShadow = 'none';
            }, 1000);
        }
        
        // Load initial data
        fetch('/api/stats')
            .then(response => response.json())
            .then(data => updateDashboard(data));
    </script>
</body>
</html>
    """
