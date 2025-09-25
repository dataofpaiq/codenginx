# nginx.conf - DDoS Detection Dashboard Configuration

user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log warn;

    # Performance settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript 
               application/x-javascript application/xml+rss 
               application/javascript application/json;

    # Rate limiting for API endpoints
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=dashboard:10m rate=5r/s;

    # Upstream servers (FastAPI applications)
    upstream detection_api {
        server 127.0.0.1:8000;
        keepalive 32;
    }

    upstream dashboard_api {
        server 127.0.0.1:8001;
        keepalive 32;
    }

    # Main server block
    server {
        listen 80;
        listen [::]:80;
        server_name localhost ddos-monitor.local;

        # Security headers
        add_header X-Frame-Options DENY always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;

        # Root location - Dashboard
        location / {
            limit_req zone=dashboard burst=10 nodelay;
            
            proxy_pass http://dashboard_api;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_cache_bypass $http_upgrade;
            
            # Timeouts
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }

        # WebSocket for real-time updates
        location /ws {
            proxy_pass http://dashboard_api;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "Upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # WebSocket specific settings
            proxy_buffering off;
            proxy_cache off;
            proxy_read_timeout 86400s;
            proxy_send_timeout 86400s;
        }

        # Detection API endpoints
        location /api/detection/ {
            limit_req zone=api burst=20 nodelay;
            
            # Remove /api/detection prefix before forwarding
            rewrite ^/api/detection/(.*)$ /$1 break;
            
            proxy_pass http://detection_api;
            proxy_http_version 1.1;
            proxy_set_header Connection '';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # API timeouts
            proxy_connect_timeout 30s;
            proxy_send_timeout 30s;
            proxy_read_timeout 30s;
        }

        # Dashboard API endpoints
        location /api/ {
            limit_req zone=api burst=15 nodelay;
            
            proxy_pass http://dashboard_api;
            proxy_http_version 1.1;
            proxy_set_header Connection '';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Static files (CSS, JS, images)
        location /static/ {
            alias /path/to/your/project/static/;
            expires 1y;
            add_header Cache-Control "public, immutable";
            access_log off;
        }

        # Health check endpoint
        location /health {
            proxy_pass http://dashboard_api/health;
            access_log off;
        }

        # Favicon
        location = /favicon.ico {
            log_not_found off;
            access_log off;
        }

        # Deny access to hidden files
        location ~ /\. {
            deny all;
            access_log off;
            log_not_found off;
        }
    }

    # HTTPS server (optional)
    # server {
    #     listen 443 ssl http2;
    #     listen [::]:443 ssl http2;
    #     server_name localhost ddos-monitor.local;
    #     
    #     ssl_certificate /path/to/your/cert.pem;
    #     ssl_certificate_key /path/to/your/key.pem;
    #     
    #     # Modern SSL configuration
    #     ssl_protocols TLSv1.2 TLSv1.3;
    #     ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    #     ssl_prefer_server_ciphers off;
    #     ssl_session_cache shared:SSL:10m;
    #     ssl_session_timeout 10m;
    #     
    #     # Include the same location blocks as HTTP server
    #     # ... (copy all location blocks from above)
    # }
}
