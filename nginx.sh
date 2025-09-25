#!/bin/bash

# nginx.sh - Setup script untuk DDoS Detection Dashboard
# Project: DDoS Detection menggunakan LSTM dengan SDN ONOS dan Mininet

echo "=== Setting up Nginx for DDoS Detection Dashboard ==="

# Update system
apt-get update -y

# Install Nginx dan dependencies
apt-get install -y nginx python3-pip python3-dev build-essential

# Install Python packages untuk dashboard
pip3 install flask flask-socketio requests numpy pandas matplotlib seaborn

# Stop nginx service sementara
systemctl stop nginx

# Backup konfigurasi nginx default
cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.backup

# Buat direktori untuk project
mkdir -p /var/www/ddos-dashboard
mkdir -p /var/www/ddos-dashboard/static
mkdir -p /var/www/ddos-dashboard/templates
mkdir -p /var/www/ddos-dashboard/logs
mkdir -p /var/www/ddos-dashboard/models

# Set permissions
chown -R www-data:www-data /var/www/ddos-dashboard
chmod -R 755 /var/www/ddos-dashboard

# Copy project files ke direktori web
# (Asumsi file-file sudah ada di direktori saat ini)
if [ -f "dashboard.py" ]; then
    cp dashboard.py /var/www/ddos-dashboard/
    echo "✓ dashboard.py copied"
fi

if [ -f "deteksi.py" ]; then
    cp deteksi.py /var/www/ddos-dashboard/
    echo "✓ deteksi.py copied"
fi

if [ -f "mitigasi.py" ]; then
    cp mitigasi.py /var/www/ddos-dashboard/
    echo "✓ mitigasi.py copied"
fi

if [ -d "templates" ]; then
    cp -r templates/* /var/www/ddos-dashboard/templates/
    echo "✓ Templates copied"
fi

if [ -d "static" ]; then
    cp -r static/* /var/www/ddos-dashboard/static/
    echo "✓ Static files copied"
fi

# Copy model LSTM jika ada
if [ -f "lstm_model.h5" ]; then
    cp lstm_model.h5 /var/www/ddos-dashboard/models/
    echo "✓ LSTM model copied"
fi

# Buat konfigurasi Nginx untuk dashboard
cat > /etc/nginx/sites-available/ddos-dashboard << 'EOF'
server {
    listen 80;
    server_name localhost;
    
    # Static files
    location /static/ {
        alias /var/www/ddos-dashboard/static/;
        expires 30d;
    }
    
    # Dashboard aplikasi Flask
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support untuk real-time updates
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # API endpoint untuk ONOS controller
    location /onos/ {
        proxy_pass http://127.0.0.1:8181/onos/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Authorization "Basic a2FyYWY6a2FyYWY=";  # karaf:karaf base64
    }
    
    # REST API untuk deteksi dan mitigasi
    location /api/ {
        proxy_pass http://127.0.0.1:5000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Content-Type application/json;
    }
    
    # Logs access
    access_log /var/log/nginx/ddos-dashboard.access.log;
    error_log /var/log/nginx/ddos-dashboard.error.log;
}
EOF

# Enable site
ln -sf /etc/nginx/sites-available/ddos-dashboard /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test konfigurasi nginx
nginx -t

if [ $? -eq 0 ]; then
    echo "✓ Nginx configuration is valid"
else
    echo "✗ Nginx configuration error!"
    exit 1
fi

# Buat systemd service untuk dashboard
cat > /etc/systemd/system/ddos-dashboard.service << 'EOF'
[Unit]
Description=DDoS Detection Dashboard
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/ddos-dashboard
ExecStart=/usr/bin/python3 dashboard.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd dan enable service
systemctl daemon-reload
systemctl enable ddos-dashboard

# Start services
systemctl start nginx
systemctl start ddos-dashboard

# Check status
echo "=== Service Status ==="
systemctl status nginx --no-pager -l
systemctl status ddos-dashboard --no-pager -l

# Show network status
echo "=== Network Status ==="
netstat -tulpn | grep :80
netstat -tulpn | grep :5000

# Create startup script untuk development
cat > /var/www/ddos-dashboard/start_system.sh << 'EOF'
#!/bin/bash
echo "Starting DDoS Detection System..."

# Start ONOS Controller (jika belum running)
if ! pgrep -f "onos" > /dev/null; then
    echo "Starting ONOS Controller..."
    cd ~/onos && ./tools/dev/bin/onos-service start &
    sleep 10
fi

# Start Mininet topology (dalam screen session)
echo "Starting Mininet topology..."
screen -dmS mininet python3 topology.py

# Start detection system
echo "Starting detection system..."
python3 deteksi.py &

# Start dashboard
echo "Dashboard available at: http://localhost"
echo "ONOS GUI available at: http://localhost/onos/ui"
EOF

chmod +x /var/www/ddos-dashboard/start_system.sh

echo "=== Setup Complete ==="
echo "Dashboard URL: http://localhost"
echo "ONOS GUI: http://localhost/onos/ui"
echo "Dashboard service: systemctl status ddos-dashboard"
echo "Nginx service: systemctl status nginx"
echo ""
echo "To start the complete system:"
echo "cd /var/www/ddos-dashboard && ./start_system.sh"
