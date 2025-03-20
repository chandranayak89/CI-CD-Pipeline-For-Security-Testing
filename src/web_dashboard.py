"""
Web dashboard module for the Security Testing Pipeline.
This module provides a web interface to visualize security alerts and network traffic.
"""

import logging
import time
import json
import os
import threading
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_from_directory

logger = logging.getLogger("Security-Pipeline-WebDashboard")

class WebDashboard:
    """
    Web interface to visualize security alerts and network traffic.
    """
    def __init__(self, traffic_analyzer, alert_system, config=None):
        """
        Initialize the web dashboard.
        
        Args:
            traffic_analyzer: The traffic analyzer to get data from
            alert_system: The alert system to get alerts from
            config: Configuration dictionary with dashboard settings
        """
        self.traffic_analyzer = traffic_analyzer
        self.alert_system = alert_system
        
        # Default configuration
        self.config = {
            "host": "0.0.0.0",
            "port": 8080,
            "debug": False,
            "static_folder": os.path.join(os.path.dirname(__file__), "static"),
            "template_folder": os.path.join(os.path.dirname(__file__), "templates"),
            "log_folder": os.path.join(os.path.dirname(__file__), "logs"),
            "refresh_interval": 5000,  # milliseconds
            "max_data_points": 100
        }
        
        # Update with provided configuration
        if config:
            self.config.update(config)
        
        # Create folders if they don't exist
        for folder in [self.config["static_folder"], self.config["template_folder"], self.config["log_folder"]]:
            os.makedirs(folder, exist_ok=True)
        
        # Initialize Flask app
        self.app = Flask(
            __name__,
            static_folder=self.config["static_folder"],
            template_folder=self.config["template_folder"]
        )
        
        # Traffic data for charts
        self.traffic_data = {
            "timestamps": [],
            "packet_counts": [],
            "unique_ips": []
        }
        
        # Last update time
        self.last_update = time.time()
        
        # Register routes
        self._register_routes()
        
        # Dashboard server thread
        self.server_thread = None
        self.is_running = False
    
    def _register_routes(self):
        """Register Flask routes."""
        
        @self.app.route('/')
        def index():
            """Render the dashboard homepage."""
            return render_template('index.html', config=self.config)
        
        @self.app.route('/api/traffic')
        def api_traffic():
            """API endpoint to get traffic data."""
            return jsonify(self.traffic_data)
        
        @self.app.route('/api/traffic/summary')
        def api_traffic_summary():
            """API endpoint to get traffic summary."""
            return jsonify(self.traffic_analyzer.get_traffic_summary())
        
        @self.app.route('/api/alerts')
        def api_alerts():
            """API endpoint to get alerts."""
            count = request.args.get('count', 10, type=int)
            min_severity = request.args.get('min_severity', None)
            alerts = self.alert_system.get_recent_alerts(count, min_severity)
            return jsonify(alerts)
        
        @self.app.route('/logs')
        def logs():
            """Render the logs page."""
            return render_template('logs.html', config=self.config)
        
        @self.app.route('/api/logs')
        def api_logs():
            """API endpoint to get log files."""
            log_files = []
            log_dir = self.config["log_folder"]
            
            for filename in os.listdir(log_dir):
                if filename.endswith('.log'):
                    file_path = os.path.join(log_dir, filename)
                    log_files.append({
                        'name': filename,
                        'size': os.path.getsize(file_path),
                        'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
                    })
            
            return jsonify(log_files)
        
        @self.app.route('/api/logs/<path:filename>')
        def api_log_file(filename):
            """API endpoint to get contents of a log file."""
            return send_from_directory(self.config["log_folder"], filename)
        
        @self.app.route('/health')
        def health_check():
            """Health check endpoint for container monitoring."""
            health_status = {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "services": {
                    "traffic_analyzer": "available" if self.traffic_analyzer else "unavailable",
                    "alert_system": "available" if self.alert_system else "unavailable"
                }
            }
            return jsonify(health_status)
    
    def start(self):
        """Start the web dashboard server."""
        self._create_default_templates()
        self._create_static_files()
        
        # Start in a separate thread
        self.server_thread = threading.Thread(
            target=self.app.run,
            kwargs={
                'host': self.config["host"],
                'port': self.config["port"],
                'debug': self.config["debug"],
                'use_reloader': False
            }
        )
        self.server_thread.daemon = True
        self.server_thread.start()
        
        logger.info(f"Web dashboard started at http://{self.config['host']}:{self.config['port']}")
    
    def update_traffic_data(self):
        """Update traffic data for charts."""
        current_time = time.time()
        
        # Only update if enough time has passed
        if current_time - self.last_update < 1:  # Update at most once per second
            return
        
        self.last_update = current_time
        
        # Get current traffic summary
        summary = self.traffic_analyzer.get_traffic_summary()
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        # Update data
        self.traffic_data["timestamps"].append(timestamp)
        self.traffic_data["packet_counts"].append(summary.get("packet_count", 0))
        self.traffic_data["unique_ips"].append(summary.get("unique_ips", 0))
        
        # Limit data points
        max_points = self.config["max_data_points"]
        if len(self.traffic_data["timestamps"]) > max_points:
            self.traffic_data["timestamps"] = self.traffic_data["timestamps"][-max_points:]
            self.traffic_data["packet_counts"] = self.traffic_data["packet_counts"][-max_points:]
            self.traffic_data["unique_ips"] = self.traffic_data["unique_ips"][-max_points:]
    
    def _create_default_templates(self):
        """Create default HTML templates if they don't exist."""
        templates_dir = self.config["template_folder"]
        
        # Create index.html
        index_path = os.path.join(templates_dir, "index.html")
        if not os.path.exists(index_path):
            with open(index_path, "w") as f:
                f.write("""<!DOCTYPE html>
<html>
<head>
    <title>Security Testing Pipeline - Dashboard</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/main.css') }}">
    <script src="{{ url_for('static', filename='js/chart.min.js') }}"></script>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Testing Pipeline</h1>
            <nav>
                <ul>
                    <li><a href="/" class="active">Dashboard</a></li>
                    <li><a href="/logs">Logs</a></li>
                </ul>
            </nav>
        </header>
        
        <div class="main">
            <div class="row">
                <div class="card">
                    <h2>Network Traffic Overview</h2>
                    <div class="chart-container">
                        <canvas id="trafficChart"></canvas>
                    </div>
                </div>
            </div>
            
            <div class="row">
                <div class="card">
                    <h2>Security Alerts</h2>
                    <div class="alert-container">
                        <div id="alertList" class="alert-list">
                            <p class="loading">Loading alerts...</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="row">
                <div class="column">
                    <div class="card">
                        <h2>Top IPs</h2>
                        <div id="topIPs" class="data-list">
                            <p class="loading">Loading data...</p>
                        </div>
                    </div>
                </div>
                <div class="column">
                    <div class="card">
                        <h2>Top Ports</h2>
                        <div id="topPorts" class="data-list">
                            <p class="loading">Loading data...</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Dashboard configuration
        const config = {
            refreshInterval: {{ config.refresh_interval }}
        };
        
        // Initialize charts when page loads
        document.addEventListener('DOMContentLoaded', () => {
            initTrafficChart();
            fetchAlerts();
            fetchTrafficSummary();
            
            // Set up periodic updates
            setInterval(() => {
                updateTrafficChart();
                fetchAlerts();
                fetchTrafficSummary();
            }, config.refreshInterval);
        });
        
        // Traffic chart
        let trafficChart;
        
        function initTrafficChart() {
            const ctx = document.getElementById('trafficChart').getContext('2d');
            trafficChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Packets',
                        borderColor: 'rgb(75, 192, 192)',
                        data: [],
                        fill: false,
                        tension: 0.1
                    }, {
                        label: 'Unique IPs',
                        borderColor: 'rgb(255, 99, 132)',
                        data: [],
                        fill: false,
                        tension: 0.1
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
            
            updateTrafficChart();
        }
        
        function updateTrafficChart() {
            fetch('/api/traffic')
                .then(response => response.json())
                .then(data => {
                    trafficChart.data.labels = data.timestamps;
                    trafficChart.data.datasets[0].data = data.packet_counts;
                    trafficChart.data.datasets[1].data = data.unique_ips;
                    trafficChart.update();
                });
        }
        
        function fetchAlerts() {
            fetch('/api/alerts?count=10')
                .then(response => response.json())
                .then(alerts => {
                    const alertList = document.getElementById('alertList');
                    
                    if (alerts.length === 0) {
                        alertList.innerHTML = '<p class="empty">No alerts detected</p>';
                        return;
                    }
                    
                    let html = '';
                    alerts.forEach(alert => {
                        const time = new Date(alert.timestamp * 1000).toLocaleTimeString();
                        html += `
                            <div class="alert-item alert-${alert.severity.toLowerCase()}">
                                <div class="alert-header">
                                    <span class="alert-type">${alert.type}</span>
                                    <span class="alert-time">${time}</span>
                                    <span class="alert-severity">${alert.severity}</span>
                                </div>
                                <div class="alert-message">${alert.message}</div>
                                <div class="alert-source">
                                    <span>Source: ${alert.source}</span>
                                    <span>Target: ${alert.target}</span>
                                </div>
                            </div>
                        `;
                    });
                    
                    alertList.innerHTML = html;
                });
        }
        
        function fetchTrafficSummary() {
            fetch('/api/traffic/summary')
                .then(response => response.json())
                .then(summary => {
                    // Update Top IPs
                    const topIPsContainer = document.getElementById('topIPs');
                    if (summary.top_ips && summary.top_ips.length > 0) {
                        let ipHtml = '<ul>';
                        summary.top_ips.forEach(item => {
                            ipHtml += `<li><span class="ip">${item[0]}</span> <span class="count">${item[1]}</span></li>`;
                        });
                        ipHtml += '</ul>';
                        topIPsContainer.innerHTML = ipHtml;
                    } else {
                        topIPsContainer.innerHTML = '<p class="empty">No IP data available</p>';
                    }
                    
                    // Update Top Ports
                    const topPortsContainer = document.getElementById('topPorts');
                    if (summary.top_ports && summary.top_ports.length > 0) {
                        let portHtml = '<ul>';
                        summary.top_ports.forEach(item => {
                            portHtml += `<li><span class="port">${item[0]}</span> <span class="count">${item[1]}</span></li>`;
                        });
                        portHtml += '</ul>';
                        topPortsContainer.innerHTML = portHtml;
                    } else {
                        topPortsContainer.innerHTML = '<p class="empty">No port data available</p>';
                    }
                });
        }
    </script>
</body>
</html>""")
        
        # Create logs.html
        logs_path = os.path.join(templates_dir, "logs.html")
        if not os.path.exists(logs_path):
            with open(logs_path, "w") as f:
                f.write("""<!DOCTYPE html>
<html>
<head>
    <title>Security Testing Pipeline - Logs</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/main.css') }}">
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Testing Pipeline</h1>
            <nav>
                <ul>
                    <li><a href="/">Dashboard</a></li>
                    <li><a href="/logs" class="active">Logs</a></li>
                </ul>
            </nav>
        </header>
        
        <div class="main">
            <div class="row">
                <div class="card">
                    <h2>Log Files</h2>
                    <div class="log-files">
                        <table id="logFilesTable">
                            <thead>
                                <tr>
                                    <th>Filename</th>
                                    <th>Size</th>
                                    <th>Modified</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td colspan="4" class="loading">Loading log files...</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <div class="row" id="logContentContainer" style="display: none;">
                <div class="card">
                    <h2 id="logFilename">Log Content</h2>
                    <div class="log-content">
                        <pre id="logContent"></pre>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Load log files when page loads
        document.addEventListener('DOMContentLoaded', () => {
            loadLogFiles();
        });
        
        function loadLogFiles() {
            fetch('/api/logs')
                .then(response => response.json())
                .then(files => {
                    const tbody = document.querySelector('#logFilesTable tbody');
                    
                    if (files.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="4">No log files found</td></tr>';
                        return;
                    }
                    
                    let html = '';
                    files.forEach(file => {
                        const sizeKB = (file.size / 1024).toFixed(2);
                        html += `
                            <tr>
                                <td>${file.name}</td>
                                <td>${sizeKB} KB</td>
                                <td>${file.modified}</td>
                                <td>
                                    <button onclick="viewLogFile('${file.name}')">View</button>
                                    <a href="/api/logs/${file.name}" download>Download</a>
                                </td>
                            </tr>
                        `;
                    });
                    
                    tbody.innerHTML = html;
                });
        }
        
        function viewLogFile(filename) {
            fetch(`/api/logs/${filename}`)
                .then(response => response.text())
                .then(content => {
                    document.getElementById('logFilename').textContent = `Log Content: ${filename}`;
                    document.getElementById('logContent').textContent = content;
                    document.getElementById('logContentContainer').style.display = 'block';
                });
        }
    </script>
</body>
</html>""")
    
    def _create_static_files(self):
        """Create necessary static files if they don't exist."""
        static_dir = self.config["static_folder"]
        css_dir = os.path.join(static_dir, "css")
        js_dir = os.path.join(static_dir, "js")
        
        # Create directories
        os.makedirs(css_dir, exist_ok=True)
        os.makedirs(js_dir, exist_ok=True)
        
        # Create CSS file
        css_path = os.path.join(css_dir, "main.css")
        if not os.path.exists(css_path):
            with open(css_path, "w") as f:
                f.write("""/* Security Testing Pipeline Dashboard Styles */
* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background-color: #f7f9fc;
    color: #333;
    line-height: 1.6;
}

.container {
    width: 100%;
    max-width: 1400px;
    margin: 0 auto;
    padding: 20px;
}

header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 20px 0;
    border-bottom: 1px solid #e1e5ee;
    margin-bottom: 30px;
}

header h1 {
    color: #2c3e50;
    font-size: 24px;
}

nav ul {
    display: flex;
    list-style: none;
}

nav ul li {
    margin-left: 20px;
}

nav ul li a {
    text-decoration: none;
    color: #7f8c8d;
    font-weight: 500;
    padding: 10px;
    transition: color 0.3s;
}

nav ul li a:hover, nav ul li a.active {
    color: #3498db;
}

nav ul li a.active {
    border-bottom: 2px solid #3498db;
}

.main {
    display: flex;
    flex-direction: column;
    gap: 20px;
}

.row {
    display: flex;
    gap: 20px;
    margin-bottom: 20px;
}

.column {
    flex: 1;
}

.card {
    background-color: #fff;
    border-radius: 8px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
    padding: 20px;
    margin-bottom: 20px;
}

.card h2 {
    color: #2c3e50;
    margin-bottom: 15px;
    font-size: 18px;
    border-bottom: 1px solid #ecf0f1;
    padding-bottom: 10px;
}

.chart-container {
    height: 300px;
    position: relative;
}

.alert-container {
    max-height: 500px;
    overflow-y: auto;
}

.alert-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
}

.alert-item {
    border-left: 4px solid #3498db;
    padding: 10px 15px;
    background-color: #f8f9fa;
    border-radius: 4px;
}

.alert-item.alert-low {
    border-left-color: #2ecc71;
}

.alert-item.alert-medium {
    border-left-color: #f39c12;
}

.alert-item.alert-high {
    border-left-color: #e74c3c;
}

.alert-item.alert-critical {
    border-left-color: #c0392b;
    background-color: #fdedec;
}

.alert-header {
    display: flex;
    justify-content: space-between;
    margin-bottom: 5px;
}

.alert-type {
    font-weight: bold;
}

.alert-severity {
    font-size: 12px;
    text-transform: uppercase;
    font-weight: bold;
    padding: 2px 6px;
    border-radius: 3px;
    background-color: #ecf0f1;
}

.alert-message {
    margin-bottom: 5px;
}

.alert-source {
    font-size: 12px;
    color: #7f8c8d;
    display: flex;
    justify-content: space-between;
}

.data-list ul {
    list-style: none;
}

.data-list ul li {
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
    border-bottom: 1px solid #ecf0f1;
}

.data-list .ip, .data-list .port {
    font-family: monospace;
}

.data-list .count {
    background-color: #ecf0f1;
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 12px;
}

.log-files table {
    width: 100%;
    border-collapse: collapse;
}

.log-files th, .log-files td {
    padding: 10px;
    text-align: left;
    border-bottom: 1px solid #ecf0f1;
}

.log-files th {
    background-color: #f8f9fa;
}

.log-content pre {
    background-color: #f8f9fa;
    padding: 15px;
    border-radius: 4px;
    overflow-x: auto;
    font-family: monospace;
    height: 400px;
    overflow-y: auto;
}

.loading, .empty {
    text-align: center;
    color: #7f8c8d;
    padding: 20px;
}

/* Responsive layouts */
@media (max-width: 768px) {
    .row {
        flex-direction: column;
    }
    
    .card {
        margin-bottom: 15px;
    }
    
    header {
        flex-direction: column;
        text-align: center;
    }
    
    nav ul {
        margin-top: 10px;
    }
}""")
        
        # Create Chart.js file or download it
        chart_js_path = os.path.join(js_dir, "chart.min.js")
        if not os.path.exists(chart_js_path):
            try:
                import requests
                # Download Chart.js from CDN
                response = requests.get("https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.js")
                with open(chart_js_path, "wb") as f:
                    f.write(response.content)
            except Exception as e:
                logger.error(f"Failed to download Chart.js: {str(e)}")
                # Create a placeholder file with a comment
                with open(chart_js_path, "w") as f:
                    f.write("// Please download Chart.js and place it here: https://cdn.jsdelivr.net/npm/chart.js") 