# SSL Certificate Setup Instructions

## File Structure Created
- `docker-compose.prod.yml` - Production overrides (HTTPS port + cert mounts)
- `nginx/nginx.prod.conf` - Nginx config with SSL enabled and HTTP→HTTPS redirects

## On Your Linode Server

### 1. Stop Docker containers
```bash
cd ~/crawlerHoneyPot/localTesting
docker-compose down
```

### 2. Install Certbot
```bash
apt update
apt install certbot -y
```

### 3. Get SSL certificates (nginx must be stopped)
```bash
# For honeypot domain
certbot certonly --standalone -d classified-mil.duckdns.org --email your@email.com --agree-tos

# For dashboard domain
certbot certonly --standalone -d bot-traffic-analysis.io --email your@email.com --agree-tos
```

Certbot will create certificates at:
- `/etc/letsencrypt/live/classified-mil.duckdns.org/`
- `/etc/letsencrypt/live/bot-traffic-analysis.io/`

### 4. Start with production config
```bash
cd ~/crawlerHoneyPot/localTesting
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### 5. Set up auto-renewal
Certbot automatically creates a systemd timer. Verify it:
```bash
systemctl status certbot.timer
```

## Local Development (No Changes Needed)

Just use the regular command:
```bash
docker-compose up -d
```

This uses only `docker-compose.yml` and `nginx/nginx.conf` (HTTP only, no certs needed).

## What Happens

### Production (Linode)
- Port 80: Redirects all HTTP → HTTPS
- Port 443: Serves both domains with SSL
- Honeypot: `https://classified-mil.duckdns.org`
- Dashboard: `https://bot-traffic-analysis.io`

### Local
- Port 80: Both domains work via HTTP
- No HTTPS, no certificates required

